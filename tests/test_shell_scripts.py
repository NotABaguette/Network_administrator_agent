"""The shipped shell scripts parse, and the ones that must refuse actually refuse.

These scripts run on the worst day of the year, usually at 3am, usually by
somebody who has not read them since they were written. A syntax error found
then is a syntax error found too late, so `bash -n` runs in CI instead.

The refusal checks are grep-level rather than executed: `failover.sh` talks to a
live primary and starts a compose stack, which is not something a unit test may
do. What the tests hold is that the guards are still present and still spelled
the way the runbooks promise.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = sorted(
    [
        REPO / "deploy" / "standby" / "sync.sh",
        REPO / "deploy" / "standby" / "failover.sh",
        REPO / "deploy" / "standby" / "failback.sh",
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


# -- the guards the runbooks promise -----------------------------------------


def test_failover_refuses_while_the_primary_still_answers():
    """Two live mgmt-01s is a worse incident than none: two agents triaging the
    same alerts and both willing to reconfigure the same FortiGate."""
    text = read(REPO / "deploy" / "standby" / "failover.sh")

    assert "REFUSING to fail over" in text
    for channel in ("ping ", "/healthz", "ssh "):
        assert channel in text, f"the pre-flight no longer checks {channel!r}"
    assert "--i-have-confirmed-the-primary-is-down" in text


def test_failover_verifies_the_bundle_before_restoring_from_it():
    text = read(REPO / "deploy" / "standby" / "failover.sh")

    assert "dr verify" in text
    assert text.index("dr verify") < text.index("dr import")


def test_failover_leaves_the_platform_frozen_and_says_how_to_unfreeze():
    text = read(REPO / "deploy" / "standby" / "failover.sh")

    assert "FROZEN" in text
    assert "infra change unfreeze" in text
    assert "docker compose" in text


def test_failover_names_the_two_things_the_bundle_deliberately_does_not_carry():
    text = read(REPO / "deploy" / "standby" / "failover.sh")

    assert "deploy/.env" in text
    assert "age key" in text


def test_failback_freezes_before_it_exports():
    """Order is the whole safety property: freeze here, export from here,
    import there, start there, stop here."""
    text = read(REPO / "deploy" / "standby" / "failback.sh")

    assert text.index("change freeze") < text.index("dr export")
    assert text.index("dr export") < text.index("docker compose -f deploy/docker-compose.yml up -d")


def test_failback_refuses_to_start_a_primary_that_is_already_running():
    text = read(REPO / "deploy" / "standby" / "failback.sh")

    assert "already running" in text
    assert "ps --status running" in text


def test_failback_moves_the_primarys_old_data_aside_rather_than_deleting_it():
    """It is the only record of whatever happened between the last bundle and
    the crash."""
    text = read(REPO / "deploy" / "standby" / "failback.sh")

    assert "data.pre-failback." in text
    assert "rm -rf data" not in text


def test_the_sync_script_never_lets_ssh_prompt_for_a_password():
    """A cron job that hangs on a prompt is a job that never finishes and never
    alerts, which looks exactly like a job that is working."""
    text = read(REPO / "deploy" / "standby" / "sync.sh")

    assert "BatchMode=yes" in text
    assert "dr export --to" in text


def test_the_sync_script_verifies_what_it_shipped():
    text = read(REPO / "deploy" / "standby" / "sync.sh")

    assert "dr verify" in text
    assert "--no-verify" in text


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
