"""Disaster recovery for the platform itself: export, verify, import, health.

The estate has backups because this platform watches them. This package is the
answer to the other half of the question - what happens when the machine doing
the watching is the one that burns.

* `infra dr export --to <dir|ssh://host/path>` writes a dated, checksummed
  tarball with a manifest and ships it to the standby.
* `infra dr verify <bundle>` unpacks it into a temporary directory and proves
  it would restore: hashes, plan store, config repository, seed inventory,
  topology graph, database dumps.
* `infra dr import <bundle>` restores in place onto empty ground and leaves the
  platform frozen until a human says otherwise.
* `infra dr health` answers "could this platform recover right now", from local
  state only, so it still answers when everything else is down.

Runbooks: `docs/runbooks/dr-mgmt-01.md`, `docs/runbooks/restore-test.md`,
`docs/runbooks/freeze.md`. Standby and out-of-band box: `deploy/standby/`,
`deploy/oob/`.
"""

from __future__ import annotations

# Re-exported under `*_bundle` names so that `from infra_agent.dr import export`
# still gives the submodule rather than a function that shadows it.
from infra_agent.dr.errors import DRError
from infra_agent.dr.export import ExportResult, build_bundle, export_bundle
from infra_agent.dr.health import HealthReport, health_report
from infra_agent.dr.manifest import Manifest
from infra_agent.dr.restore import ImportReport, import_bundle
from infra_agent.dr.state import DRState
from infra_agent.dr.transfer import Target, newest_bundle, parse_target
from infra_agent.dr.verify import VerifyReport, verify_and_record
from infra_agent.dr.verify import verify as verify_bundle

__all__ = [
    "DRError",
    "DRState",
    "ExportResult",
    "HealthReport",
    "ImportReport",
    "Manifest",
    "Target",
    "VerifyReport",
    "build_bundle",
    "export_bundle",
    "health_report",
    "import_bundle",
    "newest_bundle",
    "parse_target",
    "verify_bundle",
    "verify_and_record",
]
