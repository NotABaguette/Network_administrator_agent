"""Replay the recorded guest command output through the guest collector.

`tests/fixtures/guest/linux/` holds what `ss`, `systemctl`, `dnf`, `df` and
`openssl` really printed on a guest. This script replays those files through
`infra_agent.collectors.guest.collect_linux` exactly as the collector does over
SSH, and writes the resulting snapshot to `snapshots/<device>.json`.

    uv run python tests/fixtures/guest/regenerate.py

Two consumers share it, so the recorded answers are defined once:

* `tests/test_collector_guest.py` builds its edge cases on top of `answers()`;
* `tests/test_correlate_guest.py` asserts the committed snapshot still equals
  what the collector produces, so a parser change cannot quietly leave the
  application layer being built from a shape production no longer emits.

The hand-written snapshots next to the generated one (`db-01`, `app-win-01`)
are the *other* side of the dependencies and are not replayed from anything.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
LINUX = HERE / "linux"
SNAPSHOTS = HERE / "snapshots"

if __package__ is None and str(HERE.parents[2]) not in sys.path:  # standalone run
    sys.path.insert(0, str(HERE.parents[2]))

from infra_agent.collectors import guest as guest_collector  # noqa: E402
from infra_agent.models.common import DeviceKind, SeedDevice  # noqa: E402

#: Devices whose snapshot is generated, with the seed tags the collector reads.
DEVICES: dict[str, list[str]] = {
    "web-01": ["vm:web-01", "service:nginx", "service:postgresql"],
}


def read(name: str) -> str:
    return (LINUX / f"{name}.txt").read_text()


def answers() -> dict[str, Any]:
    """Recorded output keyed by the plain command (no `sudo -n` prefix).

    A healthy Debian-family guest: nginx on 80/443 with a Let's Encrypt
    certificate, a legacy certificate with no SAN in /etc/nginx, PostgreSQL on
    loopback, node_exporter, and outbound connections to a database, a metrics
    collector and one address on the internet.
    """
    cert = "/etc/letsencrypt/live/app.example.com/cert.pem"
    legacy = "/etc/nginx/ssl/internal-ca-signed.crt"
    read_cert = guest_collector.CERT_READ_TEMPLATE.format
    return {
        guest_collector.WHOAMI_COMMAND: "1001\n",
        guest_collector.OS_RELEASE_COMMAND: read("os-release"),
        guest_collector.KERNEL_COMMAND: read("uname"),
        guest_collector.HOSTNAME_COMMAND: read("hostname"),
        guest_collector.UPTIME_COMMAND: read("proc-uptime"),
        guest_collector.CPU_COMMAND: read("nproc"),
        guest_collector.MEMINFO_COMMAND: read("meminfo"),
        guest_collector.DPKG_COMMAND: read("dpkg-query"),
        guest_collector.APT_UPGRADABLE_COMMAND: read("apt-upgradable"),
        guest_collector.SYSTEMD_UNITS_COMMAND: read("systemctl-units"),
        guest_collector.SYSTEMD_UNIT_FILES_COMMAND: read("systemctl-unit-files"),
        guest_collector.SS_TCP_LISTEN_COMMAND: read("ss-tcp-listen"),
        guest_collector.SS_UDP_LISTEN_COMMAND: read("ss-udp-listen"),
        guest_collector.SS_ESTABLISHED_COMMAND: read("ss-established"),
        guest_collector.DF_COMMAND: read("df"),
        # `find` exits 1 because /etc/httpd does not exist on this guest; its
        # stdout is still the list of everything it did find.
        guest_collector.CERT_FIND_COMMAND: (1, read("find-certs")),
        read_cert(path=cert): read("openssl-cert"),
        read_cert(path=legacy): read("openssl-cert-nosan"),
        guest_collector.TLS_PROBE_TEMPLATE.format(
            host="127.0.0.1", port=443, timeout=guest_collector.TLS_PROBE_TIMEOUT_SECONDS
        ): read("openssl-s-client"),
    }


class ReplayRunner:
    """A `CommandRunner` that answers from the recorded output.

    `sudo -n` is stripped before the lookup: whether a command needs root is
    the collector's decision, not something the recorded output knows about.
    Anything unanswered is `command not found`, which is what a minimal guest
    does and what the collector's fallbacks have to survive.
    """

    def __init__(self, recorded: dict[str, Any] | None = None) -> None:
        self.recorded = answers() if recorded is None else recorded
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str) -> Any:
        self.commands.append(command)
        plain = command if command in self.recorded else command.removeprefix("sudo -n ")
        answer = self.recorded.get(plain)
        if answer is None:
            answer = next(
                (
                    value
                    for key, value in self.recorded.items()
                    if key.endswith("*") and plain.startswith(key[:-1])
                ),
                None,
            )
        if answer is None:
            return guest_collector.CommandResult(
                command=command,
                status=guest_collector.COMMAND_NOT_FOUND_STATUS,
                stderr=f"bash: {plain.split()[0]}: command not found",
            )
        if isinstance(answer, guest_collector.CommandResult):
            return guest_collector.CommandResult(
                command=command,
                status=answer.status,
                stdout=answer.stdout,
                stderr=answer.stderr,
            )
        if isinstance(answer, tuple):
            status, stdout = answer
            return guest_collector.CommandResult(command=command, status=status, stdout=stdout)
        return guest_collector.CommandResult(command=command, status=0, stdout=str(answer))

    def close(self) -> None:
        self.closed = True


def device(name: str) -> SeedDevice:
    return SeedDevice(
        name=name,
        kind=DeviceKind.guest_linux,
        mgmt_ip="10.20.0.11",
        credential_ref=name,
        tags=DEVICES[name],
    )


def build(name: str, now: Any = None) -> dict[str, Any]:
    """The snapshot data the collector produces for `name`."""
    from datetime import UTC, datetime

    moment = now or datetime(2026, 9, 6, 12, 0, 0, tzinfo=UTC)
    return guest_collector.collect_linux(ReplayRunner(), device(name), now=moment)


def main() -> None:
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    for name in DEVICES:
        path = SNAPSHOTS / f"{name}.json"
        path.write_text(json.dumps(build(name), indent=1, sort_keys=False) + "\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
