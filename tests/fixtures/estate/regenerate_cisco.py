"""Regenerate the Catalyst snapshot fixtures from the recorded CLI text.

The Cisco collector parses every `show` command with ntc-templates, so a fixture
written by hand drifts from the shape the pinned parser actually emits. This
script replays `tests/fixtures/estate/cli/<device>/<command>.txt` through
`ntc_templates.parse.parse_output` exactly as `infra_agent.collectors.cisco`
does and writes the resulting snapshot JSON.

    uv run python tests/fixtures/estate/regenerate_cisco.py

`tests/test_correlate.py::test_cisco_fixtures_match_the_pinned_parser` asserts
the committed JSON still equals what the installed parser produces, so a
templates upgrade that renames a key fails the suite instead of silently
emptying the graph.

A file named `<command>@<stamp>.txt` belongs to the history snapshot taken at
`<stamp>`; everything else belongs to the current snapshot.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ESTATE = Path(__file__).parent
CLI = ESTATE / "cli"
SNAPSHOTS = ESTATE / "snapshots"

#: Recorded file name -> (snapshot section, command the collector sends).
COMMANDS: dict[str, tuple[str, str]] = {
    "show_version.txt": ("version", "show version"),
    "show_vlan_brief.txt": ("vlans", "show vlan brief"),
    "show_interfaces_status.txt": ("interfaces_status", "show interfaces status"),
    "show_interfaces.txt": ("interfaces", "show interfaces"),
    "show_ip_interface_brief.txt": ("ip_int_brief", "show ip interface brief"),
    "show_interfaces_trunk.txt": ("trunks", "show interfaces trunk"),
    "show_cdp_neighbors_detail.txt": ("cdp", "show cdp neighbors detail"),
    "show_lldp_neighbors_detail.txt": ("lldp", "show lldp neighbors detail"),
    "show_mac_address-table.txt": ("mac_table", "show mac address-table"),
    "show_ip_arp.txt": ("arp", "show ip arp"),
    "show_spanning-tree.txt": ("stp", "show spanning-tree"),
    "show_etherchannel_summary.txt": ("etherchannel", "show etherchannel summary"),
}

#: device -> {stamp: taken_at}. The first stamp is the current snapshot.
DEVICES: dict[str, dict[str, str]] = {
    "sw-core-01": {
        "20260906T120000000000Z": "2026-09-06T12:00:00+00:00",
        "20260906T080000000000Z": "2026-09-06T08:00:00+00:00",
    },
    "sw-acc-01": {"20260906T120000000000Z": "2026-09-06T12:00:00+00:00"},
}

PLATFORM = "cisco_ios"


def parse(command: str, text: str) -> list[dict[str, Any]] | str:
    """Exactly what `infra_agent.collectors.cisco.parse` does."""
    from infra_agent.collectors.cisco import parse as collector_parse

    return collector_parse(PLATFORM, command, text)


def recorded(device: str, stamp: str) -> dict[str, Path]:
    """Recorded CLI files for one snapshot; `<name>@<stamp>.txt` wins over `<name>.txt`."""
    files: dict[str, Path] = {}
    for path in sorted((CLI / device).glob("*.txt")):
        name, _, suffix = path.stem.partition("@")
        if suffix and suffix != stamp:
            continue
        if suffix or f"{name}.txt" not in files:
            files[f"{name}.txt"] = path
    return dict(sorted(files.items()))


def build(device: str, stamp: str, taken_at: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for name, path in recorded(device, stamp).items():
        section, command = COMMANDS[name]
        data[section] = parse(command, path.read_text())
    data["errors"] = {}
    return {"device": device, "collector": "cisco", "taken_at": taken_at, "data": data}


def main() -> None:
    for device, stamps in DEVICES.items():
        for stamp, taken_at in stamps.items():
            snapshot = build(device, stamp, taken_at)
            target = SNAPSHOTS / device / "cisco" / f"{stamp}.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(snapshot, indent=1) + "\n")
            print(f"wrote {target}")


if __name__ == "__main__":
    main()
