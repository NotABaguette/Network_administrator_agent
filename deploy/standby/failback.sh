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
# Every `infra` step runs inside the stack, here and on the primary: the state
# lives in the `infra-data` volume, not in ./data (see dr.compose.yml).
#
#   ./failback.sh --primary 10.0.10.10
#   ./failback.sh --primary 10.0.10.10 --keep-running   # leave this one up for a bake
#
# THE KEY THIS NEEDS: unlike the nightly push, failback logs in to the primary
# and runs commands there, so it needs a standby -> primary key with a shell
# (root, or a user in the docker group), in the primary's authorized_keys, and
# the primary's host key in this host's known_hosts. That is a second key, in
# the opposite direction to the restricted rrsync one, and it is deliberately
# not installed until you need it: deploy/standby/README.md, "The failback key".
#
# Exit codes: 0 handed back, 1 refused, 2 a step failed, 3 configuration missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker-compose.yml"
DR_COMPOSE_FILE="${SCRIPT_DIR}/dr.compose.yml"
SSH_USER="${INFRA_PRIMARY_SSH_USER:-root}"
PRIMARY=""
KEEP_RUNNING=0
FLIP_HOOK="${SCRIPT_DIR}/flip-address.sh"

cd "$REPO_ROOT"

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
      sed -n '2,24p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" 3 ;;
  esac
done

[ -n "$PRIMARY" ] || die "--primary <ip-or-host> is required" 3
[ -f "$COMPOSE_FILE" ] || die "no compose file at ${COMPOSE_FILE}" 3
[ -f "$DR_COMPOSE_FILE" ] || die "no DR overlay at ${DR_COMPOSE_FILE}" 3
[ -f "${REPO_ROOT}/deploy/.env" ] || die "deploy/.env is missing on this host" 3
# shellcheck disable=SC1091
set -a && . "${REPO_ROOT}/deploy/.env" && set +a

INBOX="${INFRA_DR_INBOX:-/srv/infra-dr}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
if [ -n "${INFRA_DR_CLI:-}" ]; then
  read -ra INFRA <<<"$INFRA_DR_CLI"
else
  INFRA=(docker compose --profile dr -f "$COMPOSE_FILE" -f "$DR_COMPOSE_FILE" run --rm dr infra)
fi

log "pre-flight: the repaired primary has to be reachable AND stopped"
ssh -o BatchMode=yes -o ConnectTimeout=10 "${SSH_USER}@${PRIMARY}" true ||
  die "cannot reach ${PRIMARY} over SSH with key auth; repair it first, and see
'The failback key' in deploy/standby/README.md - this direction needs its own key" 1

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
"${INFRA[@]}" change freeze || die "could not write the freeze marker" 2

# 2. Export the state this host accumulated during the outage, straight into
#    the primary's inbox.
log "exporting the current state to the primary"
"${INFRA[@]}" dr export --to "ssh://${SSH_USER}@${PRIMARY}${INBOX}" ||
  die "export to the primary failed" 2

# 3. Restore it there, in the stack's own context. `--force` moves whatever the
#    primary still had into data/pre-import/<stamp>/ inside its volume rather
#    than deleting it: the primary's pre-outage state is evidence.
log "restoring on the primary"
ssh -o BatchMode=yes "${SSH_USER}@${PRIMARY}" bash -s <<REMOTE || die "remote restore failed" 2
set -euo pipefail
cd '${REPO_ROOT}'
BUNDLE="\$(find '${INBOX}' -maxdepth 1 -name 'infra-dr-*.tar.gz*' ! -name '*.sha256' |
  sort | tail -n 1)"
[ -n "\$BUNDLE" ] || { echo "no bundle arrived"; exit 2; }
NAME="\$(basename "\$BUNDLE")"
DR=(docker compose --profile dr -f deploy/docker-compose.yml
  -f deploy/standby/dr.compose.yml run --rm dr infra)
"\${DR[@]}" dr verify "/inbox/\$NAME"
"\${DR[@]}" dr import "/inbox/\$NAME" --force
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml exec -T infra-agent test -f /app/data/FROZEN
REMOTE
log "the primary is up, on this host's state, and frozen"

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
  "${COMPOSE[@]}" down
else
  log "leaving this host running as asked; remember it is frozen and must NOT be unfrozen"
fi

log ""
log "Handed back. On the primary:"
log "  1. docker compose -f deploy/docker-compose.yml exec infra-agent infra dr health"
log "  2. ... infra collect && ... infra drift"
log "  3. ... infra change unfreeze"
log "The restored primary is frozen by the import; the standby stays frozen for good."
