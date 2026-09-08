#!/usr/bin/env bash
#
# Return service to the repaired primary. Runs ON THE STANDBY, while the
# standby is the one carrying the platform.
#
# Failback is the same manoeuvre as failover with the roles swapped, and it has
# the same single failure mode: two live mgmt-01s. So it goes in this order and
# no other - freeze here, export from here, import there, start there, and only
# then stop here.
#
#   ./failback.sh --primary 10.0.10.10
#   ./failback.sh --primary 10.0.10.10 --keep-running   # leave this one up for a bake
#
# Exit codes: 0 handed back, 1 refused, 2 a step failed, 3 configuration missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker-compose.yml"
INFRA="${INFRA_CLI:-infra}"
SSH_USER="${INFRA_PRIMARY_SSH_USER:-root}"
PRIMARY=""
KEEP_RUNNING=0
FLIP_HOOK="${SCRIPT_DIR}/flip-address.sh"

log() { printf '%s failback: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() {
  log "$1"
  exit "${2:-2}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --primary)
      PRIMARY="${2:-}"
      shift 2
      ;;
    --keep-running)
      KEEP_RUNNING=1
      shift
      ;;
    -h | --help)
      sed -n '2,14p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" 3 ;;
  esac
done

[ -n "$PRIMARY" ] || die "--primary <ip-or-host> is required" 3
[ -f "$COMPOSE_FILE" ] || die "no compose file at ${COMPOSE_FILE}" 3

log "pre-flight: the repaired primary has to be reachable AND stopped"
ssh -o BatchMode=yes -o ConnectTimeout=10 "${SSH_USER}@${PRIMARY}" true ||
  die "cannot reach ${PRIMARY} over SSH with key auth; repair it first" 1

if ssh -o BatchMode=yes "${SSH_USER}@${PRIMARY}" \
  "docker compose -f '${REPO_ROOT}/deploy/docker-compose.yml' ps --status running -q" |
  grep -q .; then
  die "the primary's stack is already running. Stop it there first:
  ssh ${SSH_USER}@${PRIMARY} 'docker compose -f deploy/docker-compose.yml down'
Bringing it up against a state older than this host's would silently lose
everything that happened during the outage." 1
fi

# 1. Freeze here first. From this moment nothing changes the estate until the
#    primary is back and a human unfreezes it there.
log "freezing this host"
"$INFRA" change freeze || die "could not write the freeze marker" 2

# 2. Export the state this host accumulated during the outage.
log "exporting the current state to the primary"
"$INFRA" dr export --to "ssh://${SSH_USER}@${PRIMARY}${INFRA_DR_INBOX:-/srv/infra-dr}" ||
  die "export to the primary failed" 2

BUNDLE="$("$INFRA" dr list 2>/dev/null | awk '/infra-dr-/ {print $2; exit}')"
log "newest bundle: ${BUNDLE:-unknown}"

# 3. Restore it there, into a data_dir that is deliberately moved aside rather
#    than deleted: the primary's pre-outage state is evidence.
log "restoring on the primary"
ssh -o BatchMode=yes "${SSH_USER}@${PRIMARY}" bash -s <<REMOTE || die "remote restore failed" 2
set -euo pipefail
cd '${REPO_ROOT}'
if [ -d data ] && [ -n "\$(ls -A data 2>/dev/null)" ]; then
  mv data "data.pre-failback.\$(date -u +%Y%m%dT%H%M%SZ)"
fi
BUNDLE="\$(find '${INFRA_DR_INBOX:-/srv/infra-dr}' -maxdepth 1 -name 'infra-dr-*.tar.gz' | sort | tail -n 1)"
[ -n "\$BUNDLE" ] || { echo "no bundle arrived"; exit 2; }
${INFRA} dr verify "\$BUNDLE"
${INFRA} dr import "\$BUNDLE"
docker compose -f deploy/docker-compose.yml up -d
REMOTE

# 4. Give the address back before stopping here, so the gap is seconds and not
#    however long it takes somebody to notice.
if [ -x "$FLIP_HOOK" ]; then
  log "handing the management address back"
  "$FLIP_HOOK" demote || log "WARNING: the address flip hook failed; do it by hand"
else
  log "flip the mgmt-01 DNS record / management IP back to ${PRIMARY} by hand"
fi

if [ "$KEEP_RUNNING" -eq 0 ]; then
  log "stopping the stack on this host (it is the standby again)"
  docker compose -f "$COMPOSE_FILE" down
else
  log "leaving this host running as asked; remember it is frozen and must NOT be unfrozen"
fi

log ""
log "Handed back. On the primary:"
log "  1. infra dr health"
log "  2. infra collect && infra drift"
log "  3. infra change unfreeze"
log "The restored primary is frozen by the import; the standby stays frozen for good."
