"""`infra onboard ...` — the human-present onboarding harness. Secrets are read
with getpass and go straight to SOPS; nothing here is reachable by the model."""

from __future__ import annotations

import secrets as pysecrets
from getpass import getpass
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from infra_agent.config import get_settings
from infra_agent.models.common import Credential, DeviceKind, SeedDevice, SeedInventory
from infra_agent.onboarding import check as check_mod
from infra_agent.onboarding.accounts import account_commands
from infra_agent.onboarding.probes import get_probe
from infra_agent.onboarding.scan import scan as scan_cidr
from infra_agent.onboarding.secrets import (
    DEFAULT_AGE_KEY,
    SecretsStore,
    SopsError,
    ensure_age_key,
    set_sops_recipient,
    sops_available,
)
from infra_agent.store.snapshots import FileSnapshotStore

app = typer.Typer(help="Onboard devices and platform secrets (human present; secrets stay local)")
console = Console()


@app.command()
def init(
    age_key: Path = typer.Option(DEFAULT_AGE_KEY, help="age private key file (outside the repo)"),
) -> None:
    """Create the age key, configure SOPS, store platform secrets."""
    settings = get_settings()
    if not sops_available():
        raise typer.BadParameter("sops is not installed (https://github.com/getsops/sops)")
    try:
        recipient = ensure_age_key(age_key)
    except SopsError as exc:
        raise typer.BadParameter(str(exc)) from exc
    set_sops_recipient(Path(".sops.yaml"), recipient)
    console.print(f"[green]age recipient[/] {recipient}")
    store = SecretsStore(settings.secrets_dir, age_key)
    data = store.read("platform")
    for key, prompt, secret in (
        ("anthropic_api_key", "Anthropic API key", True),
        ("telegram_bot_token", "Telegram bot token", True),
        ("telegram_owner_id", "Your Telegram user id (numeric)", False),
        ("heartbeat_url", "Dead-man heartbeat ping URL", False),
    ):
        current = "set" if key in data else "unset"
        value = (
            getpass(f"{prompt} [{current}, enter to keep]: ")
            if secret
            else typer.prompt(
                f"{prompt} [{current}]", default=data.get(key, ""), show_default=False
            )
        )
        if value:
            data[key] = int(value) if key == "telegram_owner_id" else value
    store.write("platform", data)
    console.print(f"[green]wrote[/] {settings.secrets_dir}/platform.enc.yaml")


@app.command("add-device")
def add_device(
    kind: DeviceKind,
    mgmt_ip: str,
    name: str = typer.Option(..., help="device name, e.g. fw-01"),
    port: int | None = typer.Option(None),
    tags: str = typer.Option("", help="comma-separated tags, e.g. edge,mgmt-path"),
    legacy_ssh: bool = typer.Option(False, help="old 2960: legacy SSH KEX/ciphers"),
    token: bool = typer.Option(False, help="credential is an API token (FortiGate)"),
    ssh_key: str = typer.Option(
        "",
        help="path to the SSH private key: how a Linux guest is authenticated, and "
        "what the ESXi host-config backup needs. For a guest the password is the "
        "key's passphrase; everywhere else it is still the API password.",
    ),
    skip_probe: bool = typer.Option(False),
) -> None:
    """Prompt locally for a credential, probe it, store it, add the device to the seed inventory."""
    settings = get_settings()
    store = SecretsStore(settings.secrets_dir)
    if not store.available():
        raise typer.BadParameter("run `infra onboard init` first")
    if token or kind is DeviceKind.fortigate:
        cred = Credential(token=getpass("API token: "))
    else:
        username = typer.prompt("username")
        # Only a guest authenticates with the key alone. An ESXi host onboarded
        # with `--ssh-key` (for the host-config backup) still logs into hostd
        # with `cred.password`, so asking for a passphrase there would leave the
        # API password unset and every collector cycle failing.
        prompt = (
            "key passphrase (blank if the key has none): "
            if ssh_key and kind.platform == "guest"
            else "password: "
        )
        cred = Credential(
            username=username, password=getpass(prompt) or None, ssh_key_path=ssh_key or None
        )
    device = SeedDevice(
        name=name,
        kind=kind,
        mgmt_ip=mgmt_ip,
        credential_ref=name,
        port=port,
        tags=[t.strip() for t in tags.split(",") if t.strip()],
        legacy_ssh=legacy_ssh,
    )
    if not skip_probe:
        console.print(f"probing {kind.value} at {mgmt_ip} ...")
        device.probe = get_probe(kind).probe(device, cred)
        if not device.probe.ok:
            console.print(f"[red]probe failed:[/] {device.probe.error}")
            if not typer.confirm("store the credential anyway?", default=False):
                raise typer.Exit(1)
        else:
            console.print(f"[green]identity[/] {device.probe.identity}")
            console.print(
                f"[green]privilege[/] {device.probe.privilege} read_only={device.probe.read_only}"
            )
            for w in device.probe.warnings:
                console.print(f"[yellow]warning[/] {w}")
            if device.probe.read_only is False:
                console.print(
                    "[yellow]this credential can write; collectors should use a read-only one. "
                    f"Run `infra onboard accounts {name}`.[/]"
                )
            if kind is DeviceKind.esxi and device.probe.identity.get("license"):
                device.license = (
                    "free" if "Hypervisor" in str(device.probe.identity["license"]) else "licensed"
                )
    store.update(
        "devices",
        name,
        cred.model_dump(mode="json")
        | {
            "password": cred.password.get_secret_value() if cred.password else None,
            "token": cred.token.get_secret_value() if cred.token else None,
        },
    )
    inv = SeedInventory.load(settings.seed_inventory)
    inv.upsert(device)
    inv.save(settings.seed_inventory)
    console.print(f"[green]stored[/] credential '{name}' and device in {settings.seed_inventory}")


@app.command()
def accounts(device: str, username: str = "infra-ro") -> None:
    """Print least-privilege account commands for a device; password is generated and stored."""
    settings = get_settings()
    inv = SeedInventory.load(settings.seed_inventory)
    d = inv.get(device)
    if d is None:
        raise typer.BadParameter(f"unknown device {device}")
    store = SecretsStore(settings.secrets_dir)
    password = pysecrets.token_urlsafe(18)
    mgmt_ip = typer.prompt("mgmt-01 IP (trusted host)")
    if d.kind is not DeviceKind.fortigate:
        store.update(
            "devices", f"{device}:{username}", {"username": username, "password": password}
        )
        console.print(f"[green]password stored as[/] devices/{device}:{username}")
    for line in account_commands(d.kind, username, password, mgmt_ip):
        console.print(line)


@app.command("seed-guests")
def seed_guests(
    dry_run: bool = typer.Option(False, "--dry-run", help="list the candidates and stop"),
    skip_probe: bool = typer.Option(False),
    write_files: bool = typer.Option(
        True, help="rewrite ansible/inventory/guests.yml and the Prometheus targets"
    ),
) -> None:
    """Offer the VMs that look like guests, from the latest ESXi snapshots.

    A VM qualifies when its guest IP is known and its annotation (VM Notes,
    which is where a standalone host keeps a tag without vCenter) carries
    `guest:linux` or `guest:windows`. Any other `key:value` token in the
    annotation - `service:nginx`, `auto:restart` - is copied onto the seed
    device, because that is what the collector's gauges and the Tier 0
    allowlists key off.
    """
    from infra_agent.guest_inventory import guest_candidates, seed_device_for, write_all

    settings = get_settings()
    inv = SeedInventory.load(settings.seed_inventory)
    store = FileSnapshotStore(settings.snapshot_dir)
    candidates = guest_candidates(store, inv)
    if not candidates:
        console.print(
            "[yellow]no candidates[/]: run `infra collect` first, then tag the VMs you want "
            "collected with `guest:linux` or `guest:windows` in their Notes."
        )
        raise typer.Exit(0)

    table = Table("vm", "host", "kind", "address", "tags", "status")
    for candidate in candidates:
        table.add_row(
            candidate.vm,
            candidate.host,
            candidate.kind.value,
            candidate.address or "-",
            ",".join(candidate.tags),
            candidate.reason or "ready",
        )
    console.print(table)
    if dry_run:
        raise typer.Exit(0)

    store_secrets = SecretsStore(settings.secrets_dir)
    if not store_secrets.available():
        raise typer.BadParameter("run `infra onboard init` first")

    added = 0
    for candidate in candidates:
        if candidate.onboarded or not candidate.address:
            continue
        if not typer.confirm(f"onboard {candidate.vm} ({candidate.address})?", default=False):
            continue
        name = typer.prompt("device name", default=candidate.suggested_name)
        device = seed_device_for(candidate, name)
        username = typer.prompt("username", default="infra-ro")
        key_path = (
            typer.prompt("SSH private key path (blank for password)", default="")
            if candidate.kind is DeviceKind.guest_linux
            else ""
        )
        cred = Credential(
            username=username,
            ssh_key_path=key_path or None,
            password=getpass("password (blank if the key needs none): ") or None,
        )
        if not skip_probe:
            console.print(f"probing {candidate.kind.value} at {device.mgmt_ip} ...")
            device.probe = get_probe(device.kind).probe(device, cred)
            if not device.probe.ok:
                console.print(f"[red]probe failed:[/] {device.probe.error}")
                if not typer.confirm("store the credential anyway?", default=False):
                    continue
            else:
                console.print(f"[green]identity[/] {device.probe.identity}")
                console.print(f"[green]privilege[/] {device.probe.privilege}")
                for warning in device.probe.warnings:
                    console.print(f"[yellow]warning[/] {warning}")
        store_secrets.update(
            "devices",
            device.credential_ref,
            {
                "username": cred.username,
                "password": cred.password.get_secret_value() if cred.password else None,
                "ssh_key_path": cred.ssh_key_path,
            },
        )
        inv.upsert(device)
        added += 1
        console.print(f"[green]added[/] {device.name} ({device.kind.value})")

    if added:
        inv.save(settings.seed_inventory)
        console.print(f"[green]wrote[/] {added} guest(s) to {settings.seed_inventory}")
    if write_files:
        for path in write_all(inv, settings):
            console.print(f"[green]generated[/] {path}")


@app.command()
def scan(cidr: str) -> None:
    """TCP-connect scan of a management CIDR for SSH/HTTPS/Redfish services."""
    inv = SeedInventory.load(get_settings().seed_inventory)
    known = {d.mgmt_ip for d in inv.devices}
    table = Table("ip", "ports", "hint", "onboarded")
    for hit in scan_cidr(cidr):
        table.add_row(
            hit.ip,
            ",".join(map(str, hit.open_ports)),
            hit.hint or "",
            "yes" if hit.ip in known else "",
        )
    console.print(table)


@app.command()
def check() -> None:
    """Prerequisites report with remediation."""
    colors = {"ok": "green", "warn": "yellow", "fail": "red", "pending": "blue"}
    table = Table("check", "status", "detail", "remediation")
    failures = 0
    for r in check_mod.run_checks(get_settings()):
        table.add_row(r.name, f"[{colors[r.status]}]{r.status}[/]", r.detail, r.remediation)
        failures += r.status == "fail"
    console.print(table)
    raise typer.Exit(1 if failures else 0)


@app.command()
def status() -> None:
    """Onboarding status (same data the MCP tool exposes)."""
    from infra_agent.tools import onboarding_tools

    console.print_json(data=onboarding_tools.status())
    console.print_json(data=onboarding_tools.next_step())
