"""The shipped shell scripts parse, and the ones that must refuse actually refuse.

These scripts run on the worst day of the year, usually at 3am, usually by
somebody who has not read them since they were written. A syntax error found
then is a syntax error found too late, so `bash -n` runs in CI instead.

The failover, failback and sync scripts are *executed* here, against fake
`docker`, `ssh`, `curl`, `ping` and `infra` binaries on PATH that record their
argument vectors. Grep-level assertions were how the biggest defect in this
package survived review: every `infra` command ran on the host, against
`./data`, while the compose stack keeps the platform's state in the `infra-data`
volume - so the promoted standby came up on empty state and, worse, not frozen.
A test that only greps for "dr import" cannot see that. One that records argv
can.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
STANDBY = REPO / "deploy" / "standby"
SCRIPTS = sorted(
    [
        STANDBY / "sync.sh",
        STANDBY / "failover.sh",
        STANDBY / "failback.sh",
        STANDBY / "prune.sh",
        REPO / "deploy" / "oob" / "heartbeat.sh",
    ]
)

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


def read(path: Path) -> str:
    return path.read_text()


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_every_shipped_script_exists(script: Path):
    assert script.is_file(), f"{script} is referenced by a runbook but is not in the repository"


@needs_bash
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_every_shipped_script_parses(script: Path):
    proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)

    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_every_script_has_a_shebang_and_stops_on_error(script: Path):
    """`set -e` matters more here than usual: a failover that carries on after
    the restore step failed is a failover that starts a platform with no state."""
    text = read(script)

    assert text.startswith("#!/"), "no shebang"
    assert "set -e" in text


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_every_script_is_executable(script: Path):
    """The runbooks and the crontab lines run these by path."""
    assert os.access(script, os.X_OK), f"chmod +x {script}"


# -- the harness --------------------------------------------------------------
#
# A throwaway copy of the repository's deploy tree, plus fake binaries that
# record what they were called with. Nothing here touches the real checkout,
# the real Docker, or the network.

FAKE = """#!/usr/bin/env bash
{{ printf '{name}'; for a in "$@"; do printf '\\t%s' "$a"; done; printf '\\n'; }} >> "$FAKE_LOG"
{body}
exit "${{{exit_var}:-{default_exit}}}"
"""

DOCKER_BODY = """
case "$*" in
  *"test -f /app/data/FROZEN"*) exit "${FAKE_FROZEN_EXIT:-0}" ;;
esac
"""

# curl answers for 127.0.0.1 (this host's own agent, once it is up) and not for
# the primary, which is the situation a failover is for.
CURL_BODY = """
case "$*" in
  *127.0.0.1*) exit "${FAKE_CURL_LOCAL_EXIT:-0}" ;;
esac
exit "${FAKE_CURL_REMOTE_EXIT:-1}"
"""

# `ssh <primary> "docker compose ps --status running -q"` must print nothing
# for failback to proceed: an empty answer is "the primary's stack is stopped".
SSH_BODY = """
cat >/dev/null 2>&1 || true
"""


@dataclass
class Harness:
    root: Path
    log: Path
    env: dict[str, str]

    def calls(self, program: str | None = None) -> list[list[str]]:
        if not self.log.exists():
            return []
        rows = [line.split("\t") for line in self.log.read_text().splitlines() if line]
        return [row for row in rows if program is None or row[0] == program]

    def flat(self, program: str | None = None) -> list[str]:
        return [" ".join(row) for row in self.calls(program)]

    def run(self, script: str, *args: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.update(self.env)
        env.update(overrides)
        return subprocess.run(
            ["bash", str(self.root / "deploy" / "standby" / script), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(self.root),
            timeout=120,
        )


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    root = tmp_path / "infra-agent"
    (root / "deploy" / "standby").mkdir(parents=True)
    for name in ("sync.sh", "failover.sh", "failback.sh", "prune.sh", "dr.compose.yml"):
        shutil.copy2(STANDBY / name, root / "deploy" / "standby" / name)
    shutil.copy2(REPO / "deploy" / "docker-compose.yml", root / "deploy" / "docker-compose.yml")

    home = tmp_path / "home"
    (home / ".config" / "sops" / "age").mkdir(parents=True)
    (home / ".config" / "sops" / "age" / "keys.txt").write_text("AGE-SECRET-KEY-1TEST\n")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "infra-dr").write_text("key\n")
    (home / ".ssh" / "known_hosts").write_text("standby ssh-ed25519 AAAA\n")

    # Deliberately not called "inbox": the container path is /inbox, and a host
    # directory of the same name would let a test pass on the wrong one.
    inbox = tmp_path / "standby-dropbox"
    inbox.mkdir()
    (root / "deploy" / ".env").write_text(
        f"INFRA_DR_INBOX={inbox}\nINFRA_PRIMARY_SSH_USER=root\nPOSTGRES_USER=infra\n"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "argv.log"
    for name, body, exit_var, default in (
        ("docker", DOCKER_BODY, "FAKE_DOCKER_EXIT", "0"),
        ("ssh", SSH_BODY, "FAKE_SSH_EXIT", "1"),
        ("curl", CURL_BODY, "FAKE_CURL_EXIT", "0"),
        ("ping", "", "FAKE_PING_EXIT", "1"),
        ("infra", "", "FAKE_INFRA_EXIT", "0"),
        ("sleep", "", "FAKE_SLEEP_EXIT", "0"),
    ):
        path = bin_dir / name
        path.write_text(FAKE.format(name=name, body=body, exit_var=exit_var, default_exit=default))
        path.chmod(0o755)

    return Harness(
        root=root,
        log=log,
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(home),
            "FAKE_LOG": str(log),
            "INFRA_DR_INBOX": str(inbox),
        },
    )


def put_bundle(harness: Harness, name: str = "infra-dr-mgmt-01-20260908T021500Z.tar.gz") -> Path:
    inbox = Path(harness.env["INFRA_DR_INBOX"])
    bundle = inbox / name
    bundle.write_bytes(b"not a real tarball; the fake CLI does not read it")
    (inbox / (name + ".sha256")).write_text("deadbeef  " + name + "\n")
    return bundle


# -- failover: the pre-flight -------------------------------------------------


@needs_bash
def test_failover_refuses_while_the_primary_still_answers(harness: Harness):
    """Two live mgmt-01s is a worse incident than none: two agents triaging the
    same alerts and both willing to reconfigure the same FortiGate."""
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10", FAKE_PING_EXIT="0")

    assert result.returncode == 1
    assert "REFUSING to fail over" in result.stdout
    assert not any("dr import" in call for call in harness.flat()), "it restored anyway"


@needs_bash
@pytest.mark.parametrize(
    ("channel", "value"),
    [("FAKE_PING_EXIT", "0"), ("FAKE_CURL_REMOTE_EXIT", "0"), ("FAKE_SSH_EXIT", "0")],
)
def test_any_one_channel_answering_is_enough_to_refuse(harness: Harness, channel: str, value: str):
    """Each channel goes quiet on its own for reasons that have nothing to do
    with a dead host, so all three have to be silent."""
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10", **{channel: value})

    assert result.returncode == 1
    assert "REFUSING to fail over" in result.stdout


@needs_bash
def test_the_override_flag_says_out_loud_what_it_is_overriding(harness: Harness):
    put_bundle(harness)

    result = harness.run(
        "failover.sh",
        "--primary",
        "10.0.10.10",
        "--i-have-confirmed-the-primary-is-down",
        FAKE_PING_EXIT="0",
    )

    assert result.returncode == 0
    assert "ICMP: ANSWERS" in result.stdout
    assert any("dr import" in call for call in harness.flat("docker"))


# -- failover: the restore happens where the platform's state actually is -----


@needs_bash
def test_failover_restores_into_the_stack_not_into_the_checkout(harness: Harness):
    """The compose stack keeps everything in the `infra-data` volume. A host
    `infra dr import` restores into ./data, which no container reads, and
    writes FROZEN where nothing looks for it - so the promoted agent comes up
    unfrozen, on whatever test state the volume happened to hold."""
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10")

    assert result.returncode == 0, result.stdout + result.stderr
    assert harness.calls("infra") == [], "the CLI must not run on the host, against ./data"
    docker = harness.flat("docker")
    restore = [call for call in docker if "dr import" in call]
    assert restore, "nothing was restored"
    assert (
        "run --rm dr infra dr import /inbox/infra-dr-mgmt-01-20260908T021500Z.tar.gz"
        in (restore[0])
    )
    assert "deploy/standby/dr.compose.yml" in restore[0], "the DR overlay mounts infra-data"
    assert "--force" in restore[0]


@needs_bash
def test_failover_verifies_the_bundle_before_restoring_from_it(harness: Harness):
    put_bundle(harness)

    harness.run("failover.sh", "--primary", "10.0.10.10")

    docker = harness.flat("docker")
    verify = next(i for i, call in enumerate(docker) if "dr verify" in call)
    restore = next(i for i, call in enumerate(docker) if "dr import" in call)
    assert verify < restore


@needs_bash
def test_failover_proves_the_freeze_where_the_running_agent_reads_it(harness: Harness):
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10")

    docker = harness.flat("docker")
    assert any("up -d" in call for call in docker)
    check = [call for call in docker if "test -f /app/data/FROZEN" in call]
    assert check, "nothing confirmed the marker inside the container"
    assert "exec -T infra-agent" in check[0]
    assert docker.index(check[0]) > next(i for i, c in enumerate(docker) if "up -d" in c)
    assert "PROMOTED, and FROZEN" in result.stdout


@needs_bash
def test_a_restored_stack_that_is_not_frozen_is_stopped_again(harness: Harness):
    """An unfrozen agent on restored state is the two-administrators failure
    this whole directory exists to prevent. Better no platform than that one."""
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10", FAKE_FROZEN_EXIT="1")

    assert result.returncode == 2
    assert "NOT frozen" in result.stdout
    assert "PROMOTED" not in result.stdout
    assert any(
        call.endswith(
            "docker compose -f " + str(harness.root / "deploy/docker-compose.yml") + " down"
        )
        for call in harness.flat("docker")
    )


@needs_bash
def test_failover_stops_before_the_restore_when_the_env_file_is_missing(harness: Harness):
    """Every compose invocation reads deploy/.env; failing at the first one,
    half way through a restore, is the worst place to discover it is gone."""
    put_bundle(harness)
    (harness.root / "deploy" / ".env").unlink()

    result = harness.run("failover.sh", "--primary", "10.0.10.10")

    assert result.returncode == 3
    assert "deploy/.env is missing" in result.stdout
    assert harness.calls("docker") == []


@needs_bash
def test_failover_stops_when_the_age_key_is_not_on_this_host(harness: Harness):
    put_bundle(harness)
    (Path(harness.env["HOME"]) / ".config" / "sops" / "age" / "keys.txt").unlink()

    result = harness.run("failover.sh", "--primary", "10.0.10.10")

    assert result.returncode == 3
    assert "age key" in result.stdout


@needs_bash
def test_failover_prefers_the_encrypted_bundle_and_never_a_sidecar(harness: Harness):
    put_bundle(harness)
    put_bundle(harness, "infra-dr-mgmt-01-20260908T021500Z.tar.gz.age")

    harness.run("failover.sh", "--primary", "10.0.10.10")

    restore = next(call for call in harness.flat("docker") if "dr import" in call)
    assert "/inbox/infra-dr-mgmt-01-20260908T021500Z.tar.gz.age" in restore
    assert ".sha256" not in restore


@needs_bash
def test_failover_with_a_host_cli_uses_the_host_paths(harness: Harness):
    """`INFRA_DR_CLI` is the escape hatch for an installation without compose,
    and it has to be a word list, not one string: `uv run infra` was previously
    executed as a single command name and failed with "command not found"."""
    put_bundle(harness)

    result = harness.run("failover.sh", "--primary", "10.0.10.10", INFRA_DR_CLI="infra dr-wrapper")

    assert result.returncode == 0
    calls = harness.flat("infra")
    assert any("dr-wrapper dr import" in call for call in calls)
    assert all("/inbox/" not in call for call in calls), "a host CLI cannot see the container path"
    assert any(harness.env["INFRA_DR_INBOX"] in call for call in calls)


# -- sync ---------------------------------------------------------------------


@needs_bash
def test_sync_refuses_without_a_target(harness: Harness):
    result = harness.run("sync.sh")

    assert result.returncode == 3
    assert "INFRA_DR_TARGET is not set" in result.stdout
    assert harness.calls("docker") == []


@needs_bash
def test_sync_exports_and_verifies_through_the_stack(harness: Harness):
    result = harness.run("sync.sh", INFRA_DR_TARGET=str(harness.root / "local-dr"))

    assert result.returncode == 0, result.stdout + result.stderr
    assert harness.calls("infra") == [], "a host export would bundle an empty ./data"
    docker = harness.flat("docker")
    assert any("run --rm dr infra dr export --to" in call for call in docker)
    assert any("dr verify" in call for call in docker)
    export = next(i for i, call in enumerate(docker) if "dr export" in call)
    verify = next(i for i, call in enumerate(docker) if "dr verify" in call)
    assert export < verify, "verifying before exporting proves nothing about tonight"


@needs_bash
def test_sync_can_skip_the_verification_when_asked(harness: Harness):
    harness.run("sync.sh", "--no-verify", INFRA_DR_TARGET=str(harness.root / "local-dr"))

    assert not any("dr verify" in call for call in harness.flat("docker"))


@needs_bash
def test_sync_refuses_an_ssh_target_when_the_push_key_is_missing(harness: Harness):
    """Docker bind-mounts a *directory* over a source that does not exist, and
    an ssh key that is a directory fails in a way nobody enjoys debugging."""
    (Path(harness.env["HOME"]) / ".ssh" / "infra-dr").unlink()

    result = harness.run("sync.sh", INFRA_DR_TARGET="ssh://infra@standby/srv/infra-dr")

    assert result.returncode == 3
    assert "no push key" in result.stdout
    assert harness.calls("docker") == []


@needs_bash
def test_sync_refuses_an_ssh_target_with_no_pinned_host_key(harness: Harness):
    (Path(harness.env["HOME"]) / ".ssh" / "known_hosts").unlink()

    result = harness.run("sync.sh", INFRA_DR_TARGET="ssh://infra@standby/srv/infra-dr")

    assert result.returncode == 3
    assert "known_hosts" in result.stdout


@needs_bash
def test_sync_never_probes_a_restricted_key_with_a_plain_ssh_command(harness: Harness):
    """The standby's authorized_keys forces rrsync: `ssh standby true` exits
    non-zero even when the push works perfectly, so a pre-flight built on it
    fails every night."""
    harness.run("sync.sh", INFRA_DR_TARGET="ssh://infra@standby/srv/infra-dr")

    assert harness.calls("ssh") == []


@needs_bash
def test_sync_reports_a_failed_export_rather_than_verifying_nothing(harness: Harness):
    result = harness.run(
        "sync.sh",
        INFRA_DR_TARGET=str(harness.root / "local-dr"),
        FAKE_DOCKER_EXIT="1",
    )

    assert result.returncode == 1
    assert "export failed" in result.stdout


# -- failback -----------------------------------------------------------------


@needs_bash
def test_failback_freezes_here_before_it_exports_anywhere(harness: Harness):
    """Order is the whole safety property: freeze here, export from here,
    import there, start there, stop here."""
    result = harness.run("failback.sh", "--primary", "10.0.10.10", FAKE_SSH_EXIT="0")

    assert result.returncode == 0, result.stdout + result.stderr
    docker = harness.flat("docker")
    freeze = next(i for i, call in enumerate(docker) if "change freeze" in call)
    export = next(i for i, call in enumerate(docker) if "dr export" in call)
    down = next(i for i, call in enumerate(docker) if call.endswith(" down"))
    assert freeze < export < down
    assert "run --rm dr infra change freeze" in docker[freeze]


@needs_bash
def test_failback_refuses_a_primary_it_cannot_reach(harness: Harness):
    result = harness.run("failback.sh", "--primary", "10.0.10.10", FAKE_SSH_EXIT="255")

    assert result.returncode == 1
    assert "cannot reach" in result.stdout
    assert harness.calls("docker") == []


@needs_bash
def test_failback_tells_the_operator_which_key_this_direction_needs(harness: Harness):
    result = harness.run("failback.sh", "--primary", "10.0.10.10", FAKE_SSH_EXIT="255")

    assert "failback key" in result.stdout.lower()


@needs_bash
def test_failback_restores_on_the_primary_inside_its_stack(harness: Harness):
    harness.run("failback.sh", "--primary", "10.0.10.10", FAKE_SSH_EXIT="0")

    remote = read(STANDBY / "failback.sh")
    assert "dr.compose.yml run --rm dr infra" in remote
    assert "test -f /app/data/FROZEN" in remote
    assert "--force" in remote


# -- prune (runs on the standby, from its own cron) ---------------------------


@needs_bash
def test_prune_removes_expired_bundles_and_keeps_the_newest(tmp_path: Path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    old = inbox / "infra-dr-mgmt-01-20260101T021500Z.tar.gz"
    older = inbox / "infra-dr-mgmt-01-20251201T021500Z.tar.gz"
    newest = inbox / "infra-dr-mgmt-01-20260908T021500Z.tar.gz"
    for path in (old, older, newest):
        path.write_bytes(b"bundle")
        (inbox / (path.name + ".sha256")).write_text("deadbeef  " + path.name + "\n")
    ancient = time.time() - 40 * 86400
    for path in (old, older):
        os.utime(path, (ancient, ancient))

    result = subprocess.run(
        ["bash", str(STANDBY / "prune.sh"), "--dir", str(inbox), "--days", "14"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert newest.exists()
    assert not old.exists() and not older.exists()
    assert not (inbox / (old.name + ".sha256")).exists()
    assert (inbox / (newest.name + ".sha256")).exists()


@needs_bash
def test_prune_keeps_the_only_bundle_however_old_it_is(tmp_path: Path):
    """One stale backup is worth incomparably more than none, and "the newest
    bundle is old" already has an alert."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    only = inbox / "infra-dr-mgmt-01-20240101T021500Z.tar.gz"
    only.write_bytes(b"bundle")
    ancient = time.time() - 900 * 86400
    os.utime(only, (ancient, ancient))

    subprocess.run(
        ["bash", str(STANDBY / "prune.sh"), "--dir", str(inbox), "--days", "14"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert only.exists()


@needs_bash
def test_prune_leaves_everything_that_is_not_one_of_our_bundles(tmp_path: Path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "notes.txt").write_text("do not delete me")
    (inbox / "infra-dr-mgmt-01-20260908T021500Z.tar.gz").write_bytes(b"bundle")
    ancient = time.time() - 900 * 86400
    os.utime(inbox / "notes.txt", (ancient, ancient))

    subprocess.run(
        ["bash", str(STANDBY / "prune.sh"), "--dir", str(inbox), "--days", "1"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert (inbox / "notes.txt").exists()


# -- the guards the runbooks promise ------------------------------------------


def test_failover_leaves_the_platform_frozen_and_says_how_to_unfreeze():
    text = read(STANDBY / "failover.sh")

    assert "FROZEN" in text
    assert "infra change unfreeze" in text
    assert "docker compose" in text


def test_failover_names_the_two_things_the_bundle_deliberately_does_not_carry():
    text = read(STANDBY / "failover.sh")

    assert "deploy/.env" in text
    assert "age key" in text


def test_failback_moves_the_primarys_old_state_aside_rather_than_deleting_it():
    """It is the only record of whatever happened between the last bundle and
    the crash. `infra dr import --force` moves it into data/pre-import/<stamp>/
    inside the volume; nothing here deletes anything."""
    text = read(STANDBY / "failback.sh")

    assert "pre-import" in text
    assert "rm -rf" not in text
    assert "down -v" not in text, "-v would delete the volume this is trying to hand back"


def test_the_documented_layout_is_the_one_the_scripts_use():
    """`dr.compose.yml` mounts the inbox at /inbox and the platform state at
    /app/data; the scripts and the runbooks name those paths."""
    overlay = read(STANDBY / "dr.compose.yml")

    assert "infra-data:/app/data" in overlay
    assert ":/inbox" in overlay
    assert "profiles:" in overlay, "it must not start with `docker compose up`"
    for script in ("failover.sh", "failback.sh", "sync.sh"):
        assert "dr.compose.yml" in read(STANDBY / script)


def test_the_oob_heartbeat_only_pings_while_it_can_see_the_wan():
    """A heartbeat sent from a box with no uplink says "the site is fine" at the
    exact moment it is not, and nobody gets paged."""
    text = read(REPO / "deploy" / "oob" / "heartbeat.sh")

    assert "wan_visible" in text
    assert "NOT pinging" in text
    ping_line = next(
        line for line in text.splitlines() if "HEARTBEAT_URL" in line and "wget" in line
    )
    assert ping_line.strip().startswith("if wget")


def test_the_oob_heartbeat_refuses_to_start_without_a_url():
    """Silently doing nothing is the one failure mode a dead-man ping must not
    have."""
    text = read(REPO / "deploy" / "oob" / "heartbeat.sh")

    assert "HEARTBEAT_URL is not set" in text
    assert "exit 1" in text


def test_the_oob_heartbeat_publishes_the_metric_the_main_alert_reads():
    """`OOBHeartbeatMissing` in infra_agent/monitoring/rules/dr.yaml alerts on
    this series; if the name drifts the alert silently never fires."""
    text = read(REPO / "deploy" / "oob" / "heartbeat.sh")
    rules = read(REPO / "infra_agent" / "monitoring" / "rules" / "dr.yaml")

    assert "infra_oob_heartbeat_last_ok_timestamp_seconds" in text
    assert "infra_oob_heartbeat_last_ok_timestamp_seconds" in rules
    assert "infra_oob_wan_visible" in text
    assert "infra_oob_wan_visible" in read(REPO / "deploy" / "oob" / "rules.yaml")


def test_a_failed_ping_never_advances_the_last_success_time():
    """From this box a dead-man service that does not answer is
    indistinguishable from a dead-man service that is down. Claiming a
    heartbeat we did not get is the one lie this script must never tell."""
    text = read(REPO / "deploy" / "oob" / "heartbeat.sh")

    assert 'last_ok="$(date -u +%s)"' in text
    assert text.count('last_ok="$(date -u +%s)"') == 1


# -- the deployment artifacts the scripts and the runbooks depend on ----------


def yaml_of(path: Path) -> dict:
    import yaml

    return yaml.safe_load(read(path))


def test_the_dr_overlay_mounts_the_volume_the_stack_actually_uses():
    """If this drifts from deploy/docker-compose.yml, every DR command starts
    operating on a different directory from the one the platform writes to -
    silently, and only visibly on the day it matters."""
    base = yaml_of(REPO / "deploy" / "docker-compose.yml")
    overlay = yaml_of(STANDBY / "dr.compose.yml")

    assert "infra-data" in base["volumes"]
    agent_mounts = set(base["services"]["infra-agent"]["volumes"])
    dr_mounts = set(overlay["services"]["dr"]["volumes"])
    assert "infra-data:/app/data" in agent_mounts & dr_mounts
    assert "../secrets:/app/secrets:ro" in dr_mounts
    assert "../inventory:/app/inventory:ro" in dr_mounts
    assert overlay["services"]["dr"]["profiles"] == ["dr"]


def test_the_dr_image_carries_the_four_tools_the_main_image_does_not():
    """pg_dump, ssh, rsync and age. The audit's failure mode was a nightly duty
    that could not dump, could not push, and left an unpruned bundle behind
    every time it failed."""
    dockerfile = read(STANDBY / "Dockerfile.dr")

    for tool in ("postgresql-client", "openssh-client", "rsync", "age"):
        assert tool in dockerfile
    assert "INFRA_DATA_DIR=/app/data" in dockerfile


def test_the_main_stack_override_completes_the_alertmanager_cluster():
    """`--cluster.peer` on the OOB side alone makes two one-node clusters:
    every alert both see is delivered twice and silences are not shared."""
    override = yaml_of(REPO / "deploy" / "oob" / "main-stack.override.yml")
    oob = yaml_of(REPO / "deploy" / "oob" / "docker-compose.yml")

    command = " ".join(override["services"]["alertmanager"]["command"])
    assert "--cluster.listen-address=0.0.0.0:9094" in command
    assert "--cluster.advertise-address=" in command
    assert "--cluster.peer=" in command
    ports = override["services"]["alertmanager"]["ports"]
    assert "9094:9094" in ports and "9094:9094/udp" in ports, "memberlist needs both"
    assert ports == oob["services"]["alertmanager"]["ports"][1:], "both sides, same ports"


def test_the_shipped_scrape_job_is_the_one_the_alert_reads():
    job = yaml_of(REPO / "deploy" / "oob" / "prometheus-job.snippet.yml")[0]
    heartbeat = read(REPO / "deploy" / "oob" / "heartbeat.sh")

    assert job["job_name"] == "oob-heartbeat"
    assert "9105" in str(job["static_configs"]), "the busybox httpd port in the OOB compose file"
    assert "9105" in heartbeat or "9105" in read(REPO / "deploy" / "oob" / "docker-compose.yml")


def test_every_dr_alert_is_gated_on_a_configured_target():
    """A fresh install with no standby has nowhere to export to. Two
    permanently firing criticals on day one teach the owner to silence the
    whole group, which is how the alerts that matter later get lost."""
    rules = yaml_of(REPO / "infra_agent" / "monitoring" / "rules" / "dr.yaml")
    by_name = {rule["alert"]: rule for group in rules["groups"] for rule in group["rules"]}

    for name in ("DRExportStale", "DRVerifyStale", "StandbyStale"):
        assert "infra_dr_configured" in by_name[name]["expr"], name
    assert "infra_dr_last_verify_timestamp_seconds" in by_name["DRVerifyFailed"]["expr"], (
        "a process that never armed its gauges reads 0, which is not a failed verification"
    )
    assert by_name["OOBHeartbeatNeverSeen"]["labels"]["severity"] == "warning"
    assert by_name["OOBHeartbeatMissing"]["labels"]["severity"] == "critical"


def test_every_alert_says_what_to_do_about_it():
    rules = yaml_of(REPO / "infra_agent" / "monitoring" / "rules" / "dr.yaml")

    for group in rules["groups"]:
        for rule in group["rules"]:
            assert rule["labels"]["severity"] in ("critical", "warning"), rule["alert"]
            assert rule["annotations"]["summary"], rule["alert"]
            assert len(rule["annotations"]["description"]) > 60, rule["alert"]
