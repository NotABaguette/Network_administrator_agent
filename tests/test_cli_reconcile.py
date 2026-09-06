"""The owner-facing Phase 2 commands: `infra netbox`, `infra baseline`, `infra drift`.

Driven through typer's CliRunner against a synthetic snapshot tree, so exit
codes -- which is what a scheduled run and a human alike act on -- are covered
without a NetBox instance or a device.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from infra_agent.cli import app
from infra_agent.config import get_settings
from tests.test_reconcile import esxi_data, write_estate

runner = CliRunner()


@pytest.fixture
def estate_env(tmp_path, monkeypatch):
    """Point the settings-driven CLI at a synthetic snapshot tree, no NetBox."""
    settings = write_estate(tmp_path)
    monkeypatch.setenv("INFRA_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("INFRA_SEED_INVENTORY", str(settings.seed_inventory))
    for name in ("INFRA_NETBOX_URL", "INFRA_NETBOX_TOKEN", "INFRA_FROZEN"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()
    yield settings
    get_settings.cache_clear()


def invoke(*args: str):
    return runner.invoke(app, list(args))


def json_payload(output: str) -> dict:
    """`console.print_json` pretty-prints; find the object it printed."""
    start = output.index("{")
    return json.loads(output[start : output.rindex("}") + 1])


# --------------------------------------------------------------------------- netbox
def test_netbox_bootstrap_previews_without_a_netbox(estate_env):
    result = invoke("netbox", "bootstrap", "--dry-run")
    assert result.exit_code == 0, result.output
    assert "NetBox not configured" in result.output
    assert "would create" in result.output
    assert "dcim.interfaces" in result.output


def test_netbox_bootstrap_refuses_to_guess_at_a_netbox(estate_env):
    result = invoke("netbox", "bootstrap")
    assert result.exit_code == 2
    assert "INFRA_NETBOX_URL" in result.output


def test_netbox_sync_limits_itself_to_one_device(estate_env):
    result = invoke("netbox", "sync", "--device", "sw-core-01", "--dry-run")
    assert result.exit_code == 0, result.output
    assert "would create" in result.output


def test_netbox_sync_is_refused_while_frozen(estate_env, monkeypatch):
    monkeypatch.setenv("INFRA_FROZEN", "1")
    get_settings.cache_clear()

    assert invoke("netbox", "sync").exit_code == 3
    blocked = invoke("netbox", "bootstrap")
    assert blocked.exit_code == 3
    assert "frozen" in blocked.output

    preview = invoke("netbox", "bootstrap", "--dry-run")
    assert preview.exit_code == 0, "a dry run reads only, so the freeze does not block it"


# --------------------------------------------------------------------------- baseline
def test_baseline_show_before_and_after_acceptance(estate_env):
    missing = invoke("baseline", "show")
    assert missing.exit_code == 1
    assert "no baseline accepted" in missing.output

    accepted = invoke("baseline", "accept", "--by", "owner", "--note", "post-install")
    assert accepted.exit_code == 0, accepted.output
    payload = json_payload(accepted.output)
    assert payload["accepted_by"] == "owner"
    assert payload["counts"]["devices"] == 3
    assert payload["netbox_journal_id"] is None

    shown = invoke("baseline", "show")
    assert shown.exit_code == 0
    assert json_payload(shown.output)["fingerprint"] == payload["fingerprint"]


# --------------------------------------------------------------------------- drift
def test_drift_is_clean_and_explains_itself_without_an_intended_state(estate_env):
    result = invoke("drift")
    assert result.exit_code == 0, result.output
    assert "no drift" in result.output
    assert "baseline" in result.output, "it says why there is nothing to compare against"


def test_drift_exits_one_when_the_estate_moved(estate_env, tmp_path):
    assert invoke("baseline", "accept").exit_code == 0

    esxi = esxi_data()
    esxi["vms"][0]["num_cpu"] = 8
    write_estate(tmp_path, {"esx-01": esxi})  # a newer snapshot in the same tree

    result = invoke("drift")
    assert result.exit_code == 1, result.output
    assert "app-01" in result.output
    assert "drift item" in result.output


def test_drift_json_carries_the_structured_report(estate_env, tmp_path):
    assert invoke("baseline", "accept").exit_code == 0
    esxi = esxi_data()
    esxi["vms"][0]["num_cpu"] = 8
    write_estate(tmp_path, {"esx-01": esxi})

    result = invoke("drift", "--json")
    assert result.exit_code == 1
    payload = json_payload(result.output)
    assert payload["source"] == "baseline"
    item = payload["by_device"]["esx-01"][0]
    assert (item["object"], item["field"]) == ("app-01", "vcpus")
    assert "running-config" not in result.output


def test_drift_for_one_device_warns_when_the_name_is_unknown(estate_env):
    assert invoke("baseline", "accept").exit_code == 0

    result = invoke("drift", "--device", "sw-core-99")
    assert result.exit_code == 0
    assert "sw-core-99" in result.output
    assert "not in the observed estate" in result.output
