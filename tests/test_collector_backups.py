"""The backup-freshness collector: parsers on recorded output, and the collector
itself against a fake SSH runner.

The platform does not take VM backups; it watches whichever solution the owner
chose (`docs/architecture.md`, "Known gap"). These tests are about the two
things that go wrong with such a watcher: it reports a backup that did not
happen, and it copies a credential out of somebody's restic status file.
"""

from __future__ import annotations

import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from infra_agent.collectors.backups import (
    SCHEDULE_DAILY,
    SCHEDULE_NONE,
    SCHEDULE_UNSPECIFIED,
    SCHEDULE_WEEKLY,
    BackupsCollector,
    backup_root,
    parse_agent_status,
    parse_du,
    parse_ghettovcb_log,
    parse_restore_point,
    schedule_of,
)
from infra_agent.config import Settings
from infra_agent.models.common import Credential, DeviceKind, SeedDevice, Snapshot
from infra_agent.monitoring import metrics
from infra_agent.store.snapshots import FileSnapshotStore

FIXTURES = Path(__file__).parent / "fixtures" / "backups"
NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)

HOST = SeedDevice(
    name="esx-01",
    kind=DeviceKind.esxi,
    mgmt_ip="10.0.0.21",
    credential_ref="esx-01",
    license="free",
)
KEYED = Credential(username="root", ssh_key_path="/root/.ssh/id_ed25519")
PASSWORD_ONLY = Credential(username="root", password="hunter2")  # noqa: S106 - test fixture

DU_OUTPUT = """\
41943040\t/vmfs/volumes/backup/backups/web-01/web-01-2026-09-05_02-00-01
41947136\t/vmfs/volumes/backup/backups/web-01/web-01-2026-09-06_02-00-01
41961472\t/vmfs/volumes/backup/backups/web-01/web-01-2026-09-07_02-00-01
209715200\t/vmfs/volumes/backup/backups/db-01/db-01-2026-09-06_02-00-01
209729536\t/vmfs/volumes/backup/backups/db-01/db-01-2026-09-07_02-00-01
8388608\t/vmfs/volumes/backup/backups/file-01/file-01-2026-09-06_02-00-01
du: /vmfs/volumes/backup/backups/lost+found: Permission denied
"""


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


LOG_DIR = "/vmfs/volumes/backup/ghettoVCB-logs"
STATUS_DIR = "/vmfs/volumes/backup/agent-status"


class FakeSsh:
    """A read-only ESXi shell: `ls -1 <dir>`, `cat <file>`, `du -sk <glob>`.

    Dispatching on the verb rather than on a substring keeps the fake honest
    about which command produced which answer, which is what the two-newest-logs
    test depends on.
    """

    def __init__(
        self,
        listings: dict[str, str] | None = None,
        files: dict[str, str] | None = None,
        du: str = DU_OUTPUT,
        failures: tuple[str, ...] = (),
    ) -> None:
        self.listings = listings or {}
        self.files = files or {}
        self.du = du
        self.failures = failures
        self.commands: list[str] = []

    def __call__(self, command: str) -> str:
        self.commands.append(command)
        for needle in self.failures:
            if needle in command:
                raise RuntimeError(f"cannot read {needle}")
        if command.startswith("ls -1 "):
            path = shlex.split(command)[2]
            if path not in self.listings:
                raise RuntimeError(f"ls: {path}: No such file or directory")
            return self.listings[path]
        if command.startswith("cat "):
            path = shlex.split(command)[1]
            if path not in self.files:
                raise RuntimeError(f"cat: {path}: No such file or directory")
            return self.files[path]
        if command.startswith("du "):
            return self.du
        raise RuntimeError(f"unexpected command: {command}")


def default_ssh(**kwargs: Any) -> FakeSsh:
    listings = {
        LOG_DIR: (
            "ghettoVCB-2026-09-06_02-00-01.log\nghettoVCB-2026-09-07_02-00-01.log\nold-notes.txt\n"
        )
    }
    files = {
        f"{LOG_DIR}/ghettoVCB-2026-09-07_02-00-01.log": fixture(
            "ghettoVCB-2026-09-07_02-00-01.log"
        ),
        f"{LOG_DIR}/ghettoVCB-2026-09-06_02-00-01.log": fixture(
            "ghettoVCB-2026-09-06_02-00-01.log"
        ),
    }
    listings.update(kwargs.pop("listings", {}))
    files.update(kwargs.pop("files", {}))
    return FakeSsh(listings=listings, files=files, **kwargs)


def collector(
    tmp_path: Path, ssh: FakeSsh | None = None, *, status_dir: Path | None = None
) -> tuple[BackupsCollector, FakeSsh]:
    runner = ssh or default_ssh()
    settings = Settings(data_dir=tmp_path / "data", dr_backup_status_dir=status_dir)
    return (
        BackupsCollector(
            settings=settings,
            snapshots=FileSnapshotStore(settings.snapshot_dir),
            runner_factory=lambda _device, _cred: runner,
            now=lambda: NOW,
        ),
        runner,
    )


def with_annotations(store: FileSnapshotStore, **annotations: str) -> None:
    """An `esxi` snapshot for esx-01 carrying the VM annotations."""
    store.save(
        Snapshot(
            device="esx-01",
            collector="esxi",
            taken_at=NOW,
            data={
                "vms": [{"name": name, "annotation": text} for name, text in annotations.items()]
            },
        )
    )


# -- ghettoVCB log parsing ----------------------------------------------------


def test_a_partial_run_reports_the_vm_that_failed_and_the_two_that_did_not():
    run = parse_ghettovcb_log(fixture("ghettoVCB-2026-09-07_02-00-01.log"))

    rows = {row["vm"]: row for row in run["vms"]}
    assert rows["web-01"]["status"] == "ok"
    assert rows["db-01"]["status"] == "ok"
    assert rows["file-01"]["status"] == "failed"
    assert "snapshot creation" in rows["file-01"]["error"]
    assert run["final_status"] == "ERROR: Only some of the VMs backed up!"
    assert run["started_at"] == datetime(2026, 9, 7, 2, 0, 1, tzinfo=UTC)
    assert run["finished_at"] == datetime(2026, 9, 7, 2, 19, 26, tzinfo=UTC)


def test_the_success_time_is_the_end_of_that_vms_backup_not_the_end_of_the_run():
    """db-01 finished at 02:19; a 26-hour alert measured from the run's end
    would be off by however long the rest of the job took."""
    run = parse_ghettovcb_log(fixture("ghettoVCB-2026-09-07_02-00-01.log"))

    rows = {row["vm"]: row for row in run["vms"]}
    assert rows["web-01"]["finished_at"] == datetime(2026, 9, 7, 2, 4, 41, tzinfo=UTC)
    assert rows["db-01"]["finished_at"] == datetime(2026, 9, 7, 2, 19, 11, tzinfo=UTC)


def test_durations_are_seconds_and_belong_to_the_vm_they_follow():
    run = parse_ghettovcb_log(fixture("ghettoVCB-2026-09-07_02-00-01.log"))

    rows = {row["vm"]: row for row in run["vms"]}
    assert rows["web-01"]["duration_seconds"] == pytest.approx(279.0)
    assert rows["db-01"]["duration_seconds"] == pytest.approx(870.0)
    assert "duration_seconds" not in rows["file-01"]


def test_a_clean_run_reports_every_vm_ok():
    run = parse_ghettovcb_log(fixture("ghettoVCB-2026-09-06_02-00-01.log"))

    assert {row["vm"]: row["status"] for row in run["vms"]} == {
        "web-01": "ok",
        "db-01": "ok",
        "file-01": "ok",
    }
    assert run["final_status"] == "All VMs backed up OK!"


def test_garbage_is_not_a_backup():
    run = parse_ghettovcb_log("this file is not a ghettoVCB log\n\n\n")

    assert run["vms"] == []
    assert run["started_at"] is None
    assert run["final_status"] is None


# -- restore points on disk ---------------------------------------------------


def test_du_output_becomes_restore_points_with_sizes():
    points = parse_du(DU_OUTPUT)

    web = [p for p in points if p["vm"] == "web-01"]
    assert len(web) == 3
    assert max(p["at"] for p in web) == datetime(2026, 9, 7, 2, 0, 1, tzinfo=UTC)
    assert web[0]["bytes"] == 41943040 * 1024


def test_du_noise_and_unparseable_directories_are_dropped():
    assert parse_du("du: /x: Permission denied\n") == []
    assert parse_du("123\t/vmfs/volumes/backup/backups/web-01/scratch") == []
    assert parse_restore_point("web-01-2026-13-45_99-99-99") is None


# -- the agent contract -------------------------------------------------------


def test_a_restic_status_file_never_carries_its_repository_password_into_the_snapshot():
    """The fixture deliberately contains a repository URL with a password in it,
    a password file path and RESTIC_PASSWORD, because that is what a real one
    looks like. The collector reads an allowlist of fields; everything else is
    dropped rather than copied into a snapshot the model may later read."""
    row = parse_agent_status(fixture("status-app-01.json"))

    assert row is not None
    assert row["vm"] == "app-01"
    assert row["tool"] == "restic"
    assert row["status"] == "ok"
    assert row["last_success_at"] == datetime(2026, 9, 7, 2, 14, 3, tzinfo=UTC)
    assert row["bytes"] == 51234567890
    assert row["snapshots"] == 42
    serialised = repr(row)
    assert "hunter2" not in serialised
    assert "correct-horse-battery-staple" not in serialised
    assert "repository" not in row
    assert "password_file" not in row
    assert "env" not in row


def test_a_failed_agent_run_keeps_the_older_success_time():
    """The alert is built on the last SUCCESS, so a failure must not advance it."""
    row = parse_agent_status(fixture("status-mail-01.json"))

    assert row is not None
    assert row["status"] == "failed"
    assert row["last_success_at"] == datetime(2026, 8, 30, 3, 2, 11, tzinfo=UTC)
    assert row["last_attempt_at"] == datetime(2026, 9, 6, 3, 0, 44, tzinfo=UTC)
    assert row["error"] == "repository lock held by another process"


@pytest.mark.parametrize("text", ["", "not json", "[]", '"a string"', '{"tool": "restic"}'])
def test_a_status_file_without_a_host_is_not_a_status_file(text: str):
    assert parse_agent_status(text) is None


def test_the_filename_names_the_vm_when_the_document_does_not():
    row = parse_agent_status(
        '{"status": "ok", "last_success": "2026-09-07T01:00:00Z"}', name="k8s-01"
    )

    assert row is not None and row["vm"] == "k8s-01"


# -- schedules ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("annotation", "expected"),
    [
        ("backup:daily", SCHEDULE_DAILY),
        ("Production web head.\nbackup:weekly expect:on", SCHEDULE_WEEKLY),
        ("BACKUP:NONE - scratch", SCHEDULE_NONE),
        ("nothing to say", SCHEDULE_UNSPECIFIED),
        (None, SCHEDULE_UNSPECIFIED),
    ],
)
def test_the_schedule_comes_from_the_vm_annotation(annotation, expected):
    assert schedule_of(annotation) == expected


def test_a_device_tag_overrides_the_configured_backup_root():
    settings = Settings(dr_backup_root="/vmfs/volumes/backup")
    tagged = HOST.model_copy(update={"tags": ["backup-root:/vmfs/volumes/nfs-backup"]})

    assert backup_root(HOST, settings) == "/vmfs/volumes/backup"
    assert backup_root(tagged, settings) == "/vmfs/volumes/nfs-backup"


# -- the collector ------------------------------------------------------------


def test_it_joins_the_log_the_datastore_and_the_vm_tags(tmp_path):
    coll, _ssh = collector(tmp_path)
    with_annotations(
        coll.snapshots,
        **{"web-01": "backup:daily", "db-01": "backup:daily", "file-01": "backup:weekly"},
    )

    data = coll.collect(HOST, KEYED)

    rows = {row["vm"]: row for row in data["vms"]}
    assert rows["web-01"]["schedule"] == SCHEDULE_DAILY
    assert rows["web-01"]["status"] == "ok"
    assert rows["web-01"]["restore_points"] == 3
    assert rows["web-01"]["bytes"] == 41961472 * 1024
    assert rows["file-01"]["schedule"] == SCHEDULE_WEEKLY
    assert data["job"]["ok"] is False
    assert data["job"]["failed_vms"] == ["file-01"]


def test_a_vm_that_failed_tonight_keeps_last_nights_success_time(tmp_path):
    """file-01 failed in the newest log and succeeded in the previous one. The
    freshness gauge must be yesterday's success, not tonight's attempt, or
    BackupMissing would clear itself every time the job merely ran."""
    coll, _ssh = collector(tmp_path)

    data = coll.collect(HOST, KEYED)

    rows = {row["vm"]: row for row in data["vms"]}
    assert rows["file-01"]["status"] == "failed"
    assert rows["file-01"]["last_success_at"] == datetime(2026, 9, 6, 2, 26, 33, tzinfo=UTC)
    assert rows["file-01"]["last_attempt_at"] == datetime(2026, 9, 7, 2, 19, 26, tzinfo=UTC)


def test_a_vm_that_is_tagged_but_has_no_backup_at_all_is_named(tmp_path):
    coll, _ssh = collector(tmp_path)
    with_annotations(
        coll.snapshots,
        **{"web-01": "backup:daily", "dc-01": "backup:daily", "scratch-01": ""},
    )

    data = coll.collect(HOST, KEYED)

    assert "dc-01" in data["unprotected"]
    assert "scratch-01" not in data["unprotected"]
    assert "web-01" not in data["unprotected"]


def test_templates_are_never_expected_to_have_a_backup(tmp_path):
    coll, _ssh = collector(tmp_path)
    coll.snapshots.save(
        Snapshot(
            device="esx-01",
            collector="esxi",
            taken_at=NOW,
            data={
                "vms": [{"name": "ubuntu-template", "template": True, "annotation": "backup:daily"}]
            },
        )
    )

    data = coll.collect(HOST, KEYED)

    assert data["unprotected"] == []


def test_without_an_ssh_key_it_says_so_instead_of_reporting_no_backups(tmp_path):
    """ESXi gives a shell only to Administrator-role users, so the read-only
    collector credential often has no key. Reporting "no backups found" then
    would be a lie that fires every BackupMissing alert on the estate."""
    settings = Settings(data_dir=tmp_path / "data")
    coll = BackupsCollector(
        settings=settings, snapshots=FileSnapshotStore(settings.snapshot_dir), now=lambda: NOW
    )

    data = coll.collect(HOST, PASSWORD_ONLY)

    assert data["vms"] == []
    assert "no SSH key" in data["errors"]["ssh"]


def test_a_missing_log_directory_is_an_error_not_an_empty_success(tmp_path):
    coll, _ = collector(tmp_path, FakeSsh())

    data = coll.collect(HOST, KEYED)

    assert "logs" in data["errors"]
    # The restore points on disk are still reported: they are the ground truth.
    assert {row["vm"] for row in data["vms"]} == {"web-01", "db-01", "file-01"}


def test_a_datastore_that_cannot_be_read_does_not_lose_the_log(tmp_path):
    coll, _ = collector(tmp_path, default_ssh(failures=("du -sk",)))

    data = coll.collect(HOST, KEYED)

    assert "datastore" in data["errors"]
    assert {row["vm"] for row in data["vms"]} == {"web-01", "db-01", "file-01"}
    assert all("bytes" not in row for row in data["vms"])


def test_it_reads_only_the_two_newest_logs(tmp_path):
    ssh = default_ssh(
        listings={
            LOG_DIR: "\n".join(f"ghettoVCB-2026-09-{day:02d}_02-00-01.log" for day in range(1, 8))
        }
    )
    coll, _ = collector(tmp_path, ssh)

    coll.collect(HOST, KEYED)

    reads = [c for c in ssh.commands if c.startswith("cat ")]
    assert len(reads) == 2
    assert "ghettoVCB-2026-09-07" in reads[0]


def test_agent_status_files_on_the_shared_target_are_read_over_ssh(tmp_path):
    ssh = default_ssh(
        listings={STATUS_DIR: "app-01.json\nmail-01.json\nREADME\n"},
        files={
            f"{STATUS_DIR}/app-01.json": fixture("status-app-01.json"),
            f"{STATUS_DIR}/mail-01.json": fixture("status-mail-01.json"),
        },
    )
    coll, _ = collector(tmp_path, ssh)
    with_annotations(coll.snapshots, **{"app-01": "backup:daily", "mail-01": "backup:weekly"})

    data = coll.collect(HOST, KEYED)

    rows = {row["vm"]: row for row in data["vms"]}
    assert rows["app-01"]["method"] == "agent"
    assert rows["app-01"]["schedule"] == SCHEDULE_DAILY
    assert rows["mail-01"]["status"] == "failed"
    assert "hunter2" not in repr(data)


def test_agent_status_files_mounted_locally_are_read_too(tmp_path):
    status_dir = tmp_path / "backup-status"
    status_dir.mkdir()
    (status_dir / "app-01.json").write_text(fixture("status-app-01.json"))
    coll, _ = collector(tmp_path, status_dir=status_dir)

    data = coll.collect(HOST, KEYED)

    rows = {row["vm"]: row for row in data["vms"]}
    assert rows["app-01"]["last_success_at"] == datetime(2026, 9, 7, 2, 14, 3, tzinfo=UTC)


def test_ghettovcb_refines_an_agent_row_rather_than_replacing_it(tmp_path):
    """web-01 is backed up by ghettoVCB and also reports an agent status. The
    later source adds the size and the restore-point count; it must not blank
    the fields the earlier one supplied."""
    status_dir = tmp_path / "backup-status"
    status_dir.mkdir()
    (status_dir / "web-01.json").write_text(
        '{"host": "web-01", "tool": "restic", "status": "ok", '
        '"last_success": "2026-09-07T01:00:00Z", "snapshots": 9}'
    )
    coll, _ = collector(tmp_path, status_dir=status_dir)

    data = coll.collect(HOST, KEYED)

    row = next(r for r in data["vms"] if r["vm"] == "web-01")
    assert row["snapshots"] == 9
    assert row["restore_points"] == 3
    assert row["bytes"] == 41961472 * 1024


# -- metrics ------------------------------------------------------------------


def gauge(metric: Any, **labels: str) -> float | None:
    try:
        return metric.labels(**labels)._value.get()
    except Exception:  # pragma: no cover - a missing series is the answer
        return None


def test_the_gauges_carry_the_schedule_so_one_series_serves_both_thresholds(tmp_path):
    """BackupMissing is 26h for daily and 8d for weekly. Both alerts read the
    same gauge and select on the `schedule` label."""
    coll, _ = collector(tmp_path)
    with_annotations(coll.snapshots, **{"web-01": "backup:daily", "file-01": "backup:weekly"})

    coll.collect(HOST, KEYED)

    assert gauge(
        metrics.BACKUP_LAST_SUCCESS, device="esx-01", vm="web-01", schedule="daily"
    ) == pytest.approx(datetime(2026, 9, 7, 2, 4, 41, tzinfo=UTC).timestamp())
    assert gauge(
        metrics.BACKUP_LAST_SUCCESS, device="esx-01", vm="file-01", schedule="weekly"
    ) == pytest.approx(datetime(2026, 9, 6, 2, 26, 33, tzinfo=UTC).timestamp())
    assert gauge(metrics.BACKUP_JOB_OK, device="esx-01") == 0.0
    assert gauge(metrics.BACKUP_JOB_LAST_RUN, device="esx-01") == pytest.approx(
        datetime(2026, 9, 7, 2, 19, 26, tzinfo=UTC).timestamp()
    )


def test_the_collector_is_not_in_the_kind_registry(tmp_path):
    """COLLECTORS holds one collector per DeviceKind and ESXi already has one.
    Registering this would silently replace the ESXi collector, so it runs on
    its own scheduler job instead (`scheduler.run_backups_once`)."""
    from infra_agent.collectors.base import COLLECTORS
    from infra_agent.collectors.esxi import EsxiCollector

    assert COLLECTORS.get(DeviceKind.esxi) is EsxiCollector
    assert BackupsCollector.name == "backups"
    assert BackupsCollector.interval_seconds == 3600


def test_the_sources_field_names_only_what_actually_answered(tmp_path):
    """`sources` is what the digest reads to say where a number came from; a
    source listed because some other source produced rows is a lie."""
    status_dir = tmp_path / "backup-status"
    status_dir.mkdir()
    (status_dir / "app-01.json").write_text(fixture("status-app-01.json"))
    coll, _ = collector(tmp_path, FakeSsh(du=""), status_dir=status_dir)

    data = coll.collect(HOST, KEYED)

    assert data["sources"] == ["agent-local"]
    assert "ghettovcb" not in data["sources"]


def test_a_host_with_both_ghettovcb_and_shared_agent_files_names_both(tmp_path):
    ssh = default_ssh(
        listings={STATUS_DIR: "mail-01.json\n"},
        files={f"{STATUS_DIR}/mail-01.json": fixture("status-mail-01.json")},
    )
    coll, _ = collector(tmp_path, ssh)

    data = coll.collect(HOST, KEYED)

    assert data["sources"] == ["ghettovcb", "agent-shared"]


# -- the VM nobody added to the job list --------------------------------------


def series(metric: Any) -> dict[tuple[str, ...], float]:
    """Every labelset currently published for a gauge."""
    return {labels: child._value.get() for labels, child in metric._metrics.items()}


def test_a_vm_tagged_for_backup_that_has_never_had_one_publishes_a_firing_sample(tmp_path):
    """The VM most likely to be missing is the one nobody added to vms.txt. It
    produces no log line and no restore point, so a gauge that is only set from
    rows would leave BackupMissing with nothing to fire on - and
    `time() - <absent series>` is not an alert, it is silence."""
    coll, _ssh = collector(tmp_path)
    with_annotations(coll.snapshots, **{"web-01": "backup:daily", "dc-01": "backup:daily"})

    coll.collect(HOST, KEYED)

    assert ("esx-01", "dc-01", "daily") in series(metrics.BACKUP_LAST_SUCCESS)
    assert gauge(metrics.BACKUP_LAST_SUCCESS, device="esx-01", vm="dc-01", schedule="daily") == 0.0
    assert NOW.timestamp() - 0.0 > 26 * 3600, "0 is the epoch: BackupMissing fires on it"


def test_a_weekly_vm_that_has_never_had_a_backup_carries_its_own_threshold(tmp_path):
    coll, _ssh = collector(tmp_path)
    with_annotations(coll.snapshots, **{"archive-01": "backup:weekly"})

    coll.collect(HOST, KEYED)

    assert (
        gauge(metrics.BACKUP_LAST_SUCCESS, device="esx-01", vm="archive-01", schedule="weekly")
        == 0.0
    )


def test_an_untagged_vm_never_gets_a_series_of_its_own(tmp_path):
    """Guessing that every VM needs a nightly backup produces an alert nobody
    can act on."""
    coll, _ssh = collector(tmp_path)
    with_annotations(coll.snapshots, **{"scratch-01": "", "lab-01": "backup:none"})

    coll.collect(HOST, KEYED)

    for vm in ("scratch-01", "lab-01"):
        assert all(labels[1] != vm for labels in series(metrics.BACKUP_LAST_SUCCESS))


# -- stale series -------------------------------------------------------------


WEB_ONLY_LOG = """\
2026-09-07 02:00:01 -- info: CONFIG - VM_BACKUP_VOLUME = /vmfs/volumes/backup/backups
2026-09-07 02:00:02 -- info: Initiate backup for web-01
2026-09-07 02:04:41 -- info: Successfully completed backup for web-01!
2026-09-07 02:04:43 -- info: ###### Final status: All VMs backed up OK! ######
"""
WEB_ONLY_DU = "41961472\t/vmfs/volumes/backup/backups/web-01/web-01-2026-09-07_02-00-01\n"


def web_only_ssh() -> FakeSsh:
    """A host where db-01 has been unregistered: gone from the log and the tree."""
    return FakeSsh(
        listings={LOG_DIR: "ghettoVCB-2026-09-07_02-00-01.log\n"},
        files={f"{LOG_DIR}/ghettoVCB-2026-09-07_02-00-01.log": WEB_ONLY_LOG},
        du=WEB_ONLY_DU,
    )


def test_a_vm_that_is_gone_loses_its_series(tmp_path):
    """prometheus_client keeps a labelset until it is removed. An unregistered
    VM would otherwise alert for ever on a value that can never move again."""
    coll, _ssh = collector(tmp_path)
    with_annotations(coll.snapshots, **{"web-01": "backup:daily", "db-01": "backup:daily"})
    coll.collect(HOST, KEYED)
    assert ("esx-01", "db-01", "daily") in series(metrics.BACKUP_LAST_SUCCESS)

    coll2, _ = collector(tmp_path, web_only_ssh())
    with_annotations(coll2.snapshots, **{"web-01": "backup:daily"})
    coll2.collect(HOST, KEYED)

    published = series(metrics.BACKUP_LAST_SUCCESS)
    assert all(labels[1] != "db-01" for labels in published)
    assert published[("esx-01", "web-01", "daily")] > 0


def test_a_re_tagged_vm_does_not_keep_its_old_schedule_series(tmp_path):
    coll, _ssh = collector(tmp_path, web_only_ssh())
    with_annotations(coll.snapshots, **{"web-01": "backup:daily"})
    coll.collect(HOST, KEYED)

    coll2, _ = collector(tmp_path, web_only_ssh())
    with_annotations(coll2.snapshots, **{"web-01": "backup:weekly"})
    coll2.collect(HOST, KEYED)

    published = series(metrics.BACKUP_LAST_SUCCESS)
    assert ("esx-01", "web-01", "daily") not in published, (
        "the daily series would keep alerting on a threshold the VM no longer has"
    )
    assert published[("esx-01", "web-01", "weekly")] > 0


def test_a_host_that_refused_the_connection_keeps_its_last_known_series(tmp_path):
    """Absent rows mean "not collected", not "gone": sweeping here - or
    publishing an epoch timestamp for every expected VM - would make one
    refused SSH connection look like every VM on the host losing its backup at
    once, and the alert that should fire (the collector is broken) is a
    different one."""
    coll, _ssh = collector(tmp_path)
    with_annotations(coll.snapshots, **{"web-01": "backup:daily"})
    coll.collect(HOST, KEYED)

    coll2, _ = collector(tmp_path, FakeSsh(failures=("",)))
    with_annotations(coll2.snapshots, **{"web-01": "backup:daily"})
    coll2.collect(HOST, KEYED)

    assert gauge(metrics.BACKUP_LAST_SUCCESS, device="esx-01", vm="web-01", schedule="daily")


# -- a run that did not do what it was asked to -------------------------------


SNAPSHOT_FOUND_LOG = """\
2026-09-07 02:00:01 -- info: ============================== ghettoVCB LOG START ==============================
2026-09-07 02:00:02 -- info: CONFIG - VM_BACKUP_VOLUME = /vmfs/volumes/backup
2026-09-07 02:00:03 -- info: Initiate backup for web-01
2026-09-07 02:04:41 -- info: Successfully completed backup for web-01!
2026-09-07 02:04:42 -- info: ERROR: Snapshot found for db-01, backup will not take place
2026-09-07 02:04:43 -- info: ###### Final status: ERROR: Only some of the VMs backed up! ######
"""


def test_a_vm_ghettovcb_refused_to_touch_is_a_failure_whatever_the_log_calls_it():
    """ "backup will not take place" is not a backup. Counting it as one leaves
    infra_backup_job_ok at 1 and the VM on yesterday's timestamp."""
    parsed = parse_ghettovcb_log(SNAPSHOT_FOUND_LOG)

    rows = {row["vm"]: row for row in parsed["vms"]}
    assert rows["db-01"]["status"] == "failed"
    assert "Snapshot found" in rows["db-01"]["error"]
    assert rows["web-01"]["status"] == "ok"


def test_the_runs_own_final_status_is_believed(tmp_path):
    coll, _ = collector(
        tmp_path,
        default_ssh(
            listings={LOG_DIR: "ghettoVCB-2026-09-07_02-00-01.log\n"},
            files={f"{LOG_DIR}/ghettoVCB-2026-09-07_02-00-01.log": SNAPSHOT_FOUND_LOG},
        ),
    )

    data = coll.collect(HOST, KEYED)

    assert data["job"]["ok"] is False
    assert "db-01" in data["job"]["failed_vms"]
    assert gauge(metrics.BACKUP_JOB_OK, device="esx-01") == 0.0


CLEAN_BUT_ERRORED = SNAPSHOT_FOUND_LOG.replace(
    "2026-09-07 02:04:42 -- info: ERROR: Snapshot found for db-01, backup will not take place\n", ""
)


def test_a_run_whose_summary_says_error_is_not_ok_even_with_no_failed_vm_line(tmp_path):
    coll, _ = collector(
        tmp_path,
        default_ssh(
            listings={LOG_DIR: "ghettoVCB-2026-09-07_02-00-01.log\n"},
            files={f"{LOG_DIR}/ghettoVCB-2026-09-07_02-00-01.log": CLEAN_BUT_ERRORED},
        ),
    )

    data = coll.collect(HOST, KEYED)

    assert data["job"]["failed_vms"] == []
    assert data["job"]["ok"] is False


# -- where the logs are, and what time the host thinks it is ------------------


def test_logs_are_found_where_the_stock_cron_line_leaves_them(tmp_path):
    """ghettoVCB's default -l is /tmp. A collector that only looked in
    <root>/ghettoVCB-logs reported "no ghettoVCB logs" for ever on a host
    running the stock line, and only the datastore listing drove the gauges."""
    coll, ssh = collector(
        tmp_path,
        FakeSsh(
            listings={"/tmp": "ghettoVCB-2026-09-07_02-00-01.log\n"},
            files={
                "/tmp/ghettoVCB-2026-09-07_02-00-01.log": fixture(
                    "ghettoVCB-2026-09-07_02-00-01.log"
                )
            },
        ),
    )

    data = coll.collect(HOST, KEYED)

    assert data["job"]["log_dir"] == "/tmp"
    assert "logs" not in data["errors"]


def test_a_device_tag_points_the_collector_at_a_local_log_directory(tmp_path):
    tagged = HOST.model_copy(update={"tags": ["backup-logs:/var/log/ghettovcb"]})
    coll, _ = collector(
        tmp_path,
        FakeSsh(
            listings={"/var/log/ghettovcb": "ghettoVCB-2026-09-07_02-00-01.log\n"},
            files={
                "/var/log/ghettovcb/ghettoVCB-2026-09-07_02-00-01.log": fixture(
                    "ghettoVCB-2026-09-07_02-00-01.log"
                )
            },
        ),
    )

    data = coll.collect(tagged, KEYED)

    assert data["job"]["log_dir"] == "/var/log/ghettovcb"


def test_no_logs_anywhere_names_every_place_it_looked(tmp_path):
    coll, _ = collector(tmp_path, FakeSsh())

    data = coll.collect(HOST, KEYED)

    assert "ghettoVCB-logs" in data["errors"]["logs"]
    assert "/tmp" in data["errors"]["logs"]
    assert "backup-logs:" in data["errors"]["logs"]


def test_the_collector_reports_what_the_host_says_it_is_doing(tmp_path):
    """CONFIG - VM_BACKUP_VOLUME out of the log is the fastest way to see the
    host and the settings disagreeing about where backups go."""
    coll, _ = collector(tmp_path)

    data = coll.collect(HOST, KEYED)

    assert data["job"]["config"]["VM_BACKUP_VOLUME"] == "/vmfs/volumes/backup/backups"
    assert data["backup_volume"] == "/vmfs/volumes/backup/backups"
    assert "BACKUP_LOG_OUTPUT" in data["job"]["config"]


def test_a_host_on_local_time_is_read_in_local_time(tmp_path):
    """ESXi is UTC out of the box, but a host somebody set to local time skews
    every BackupMissing threshold by its offset - up to twelve hours early, or
    twelve hours blind."""
    berlin = HOST.model_copy(update={"tags": ["backup-tz:Europe/Berlin"]})
    coll, _ = collector(tmp_path)
    with_annotations(coll.snapshots, **{"web-01": "backup:daily"})

    data = coll.collect(berlin, KEYED)

    row = next(row for row in data["vms"] if row["vm"] == "web-01")
    # 02:04:41 written by a host on CEST (UTC+2) is 00:04:41 UTC.
    assert row["last_success_at"] == datetime(2026, 9, 7, 0, 4, 41, tzinfo=UTC)
    assert data["timezone"] == "Europe/Berlin"


def test_an_unknown_timezone_degrades_to_utc_rather_than_failing(tmp_path):
    nonsense = HOST.model_copy(update={"tags": ["backup-tz:Middle/Earth"]})
    coll, _ = collector(tmp_path)

    data = coll.collect(nonsense, KEYED)

    assert data["timezone"] == "UTC"
    assert data["vms"], "a typo in a tag must not stop the collector"
