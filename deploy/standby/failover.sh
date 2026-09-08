#!/usr/bin/env bash
#
# Promote the cold standby to primary. Runs ON THE STANDBY.
#
# The dangerous failure here is not "the failover did not work". It is two
# mgmt-01s: two agents triaging the same alerts, two Telegram bots minting
# approval tokens, two processes willing to reconfigure the same FortiGate.
# So this script refuses to run while the primary answers on any of three
# independent channels, and when it does run it leaves the platform FROZEN.
#
# Every `infra` step runs INSIDE the stack (deploy/standby/dr.compose.yml), on
# the `infra-data` volume the containers actually read. A host-side import
# would restore into a ./data directory nothing reads and write the FROZEN
# marker where nothing looks for it - and the promoted agent would come up
# unfrozen, on stale state, willing to change the estate. Before printing
# PROMOTED this script checks the marker where the running agent reads it.
#
#   ./failover.sh --primary 10.0.10.10                  # pre-flight + restore
#   ./failover.sh --primary 10.0.10.10 --bundle <file>  # a specific bundle
#   ./failover.sh --primary 10.0.10.10 --i-have-confirmed-the-primary-is-down
#
# Unfreezing is a separate, human step. `infra change unfreeze` after you have
# read `infra dr health` and confirmed the estate looks like you expect.
#
# Exit codes: 0 promoted (frozen), 1 pre-flight refused, 2 restore failed,
#             3 configuration missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker-compose.yml"
DR_COMPOSE_FILE="${SCRIPT_DIR}/dr.compose.yml"
PRIMARY=""
BUNDLE=""
OVERRIDE=0
FLIP_HOOK="${SCRIPT_DIR}/flip-address.sh"

cd "$REPO_ROOT"

log() { printf '%s failover: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() {
  log "$1"
  exit "${2:-1}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --primary)
      PRIMARY="${2:-}"
      shift 2
      ;;
    --bundle)
      BUNDLE="${2:-}"
      shift 2
      ;;
    --i-have-confirmed-the-primary-is-down)
      OVERRIDE=1
      shift
      ;;
    -h | --help)
      sed -n '2,26p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *) die "unknown argument: $1" 3 ;;
  esac
done

[ -n "$PRIMARY" ] || die "--primary <ip-or-host> is required: it is what the pre-flight checks" 3
[ -f "$COMPOSE_FILE" ] || die "no compose file at ${COMPOSE_FILE}" 3
[ -f "$DR_COMPOSE_FILE" ] || die "no DR overlay at ${DR_COMPOSE_FILE}" 3

# deploy/.env first: every compose invocation below reads it, and it is
# deliberately NOT in the bundle (it holds every platform password in
# plaintext). Failing here beats failing half way through a restore.
if [ ! -f "${REPO_ROOT}/deploy/.env" ]; then
  die "deploy/.env is missing. It is deliberately NOT in the bundle (it holds every
platform password in plaintext). Recreate it from deploy/.env.example and the
owner's password manager, then re-run." 3
fi
# shellcheck disable=SC1091
set -a && . "${REPO_ROOT}/deploy/.env" && set +a

if [ ! -f "${SOPS_AGE_KEY_FILE:-$HOME/.config/sops/age/keys.txt}" ]; then
  die "no age key on this host. The bundle's secrets are encrypted and useless
without it - and if the bundle itself is age-encrypted, so is all of it.
Restore the key from the owner's offline copy and re-run." 3
fi

BUNDLE_DIR="${INFRA_DR_INBOX:-/srv/infra-dr}"
COMPOSE=(docker compose -f "$COMPOSE_FILE")
if [ -n "${INFRA_DR_CLI:-}" ]; then
  read -ra INFRA <<<"$INFRA_DR_CLI"
  INBOX_IN_CLI="$BUNDLE_DIR"
else
  INFRA=(docker compose --profile dr -f "$COMPOSE_FILE" -f "$DR_COMPOSE_FILE" run --rm dr infra)
  # dr.compose.yml mounts $INFRA_DR_INBOX at /inbox inside the container.
  INBOX_IN_CLI="/inbox"
fi

# ---------------------------------------------------------------------------
# Pre-flight. Three channels, because each one fails on its own for reasons
# that have nothing to do with the primary being dead: ICMP is filtered, the
# stack is restarting, SSH is up but the disk is full.
# ---------------------------------------------------------------------------
reachable=0
log "pre-flight: is ${PRIMARY} still alive?"

if ping -c 3 -W 2 "$PRIMARY" >/dev/null 2>&1; then
  log "  ICMP: ANSWERS"
  reachable=1
else
  log "  ICMP: silent"
fi

if curl -fsS --max-time 5 "http://${PRIMARY}:9102/healthz" >/dev/null 2>&1; then
  log "  agent /healthz: ANSWERS"
  reachable=1
else
  log "  agent /healthz: silent"
fi

# accept-new here on purpose: this is a liveness probe, not a data channel,
# and a host key we have never seen must not be reported as "the primary is
# silent" - that reads as permission to fail over.
if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
  "${INFRA_PRIMARY_SSH_USER:-root}@${PRIMARY}" true >/dev/null 2>&1; then
  log "  SSH: ANSWERS"
  reachable=1
else
  log "  SSH: silent"
fi

if [ "$reachable" -eq 1 ] && [ "$OVERRIDE" -eq 0 ]; then
  log ""
  log "REFUSING to fail over: the primary still answers."
  log "Two live mgmt-01s is worse than none - both would triage the same alerts"
  log "and both would be willing to change the same FortiGate."
  log ""
  log "If the primary is up but broken, stop it first:"
  log "    ssh ${PRIMARY} 'docker compose -f deploy/docker-compose.yml down'"
  log "and re-run. If you have already made sure it is off the network, re-run"
  log "with --i-have-confirmed-the-primary-is-down."
  exit 1
fi
[ "$reachable" -eq 0 ] && log "  primary is silent on all three channels"

# ---------------------------------------------------------------------------
# Restore, into the volume the stack reads
# ---------------------------------------------------------------------------
if [ -z "$BUNDLE" ]; then
  # Plain and age-encrypted bundles; never a .sha256 sidecar.
  BUNDLE="$(find "$BUNDLE_DIR" -maxdepth 1 -name 'infra-dr-*.tar.gz*' \
    ! -name '*.sha256' 2>/dev/null | sort | tail -n 1)"
fi
[ -n "$BUNDLE" ] || die "no bundle in ${BUNDLE_DIR}; nothing to restore from" 2
BUNDLE_NAME="$(basename "$BUNDLE")"
BUNDLE_PATH="${INBOX_IN_CLI%/}/${BUNDLE_NAME}"
log "restoring from ${BUNDLE_NAME}"

log "verifying before restoring - a bundle that does not verify is not a backup"
"${INFRA[@]}" dr verify "$BUNDLE_PATH" || die "the bundle failed verification; do not restore it" 2

# --force because the standby has been started at least once for testing, so
# its data volume is rarely pristine. Whatever is in it is moved aside into
# data/pre-import/<stamp>/ rather than merged or deleted. Manifest checksums
# are still enforced, --force or not.
"${INFRA[@]}" dr import "$BUNDLE_PATH" --force || die "import failed" 2

# ---------------------------------------------------------------------------
# Start, prove the freeze took, then take the address
# ---------------------------------------------------------------------------
log "starting the stack"
"${COMPOSE[@]}" up -d

log "waiting for the agent to answer"
for _ in $(seq 1 60); do
  if curl -fsS --max-time 3 http://127.0.0.1:9102/healthz >/dev/null 2>&1; then
    log "  agent is up"
    break
  fi
  sleep 5
done

# The single most important check in this file. If the marker is not where the
# running agent reads it, this promotion produced a live, unfrozen platform on
# restored state - exactly the thing the header refuses to allow.
if ! "${COMPOSE[@]}" exec -T infra-agent test -f /app/data/FROZEN; then
  log "the restored stack is NOT frozen: /app/data/FROZEN is missing inside the"
  log "running agent. Stopping the stack rather than leaving an unfrozen agent"
  log "loose on the estate."
  "${COMPOSE[@]}" down || true
  die "freeze marker missing after import; investigate before re-running" 2
fi
log "freeze marker confirmed inside the running agent"

if [ -x "$FLIP_HOOK" ]; then
  log "flipping the management address / DNS record via $(basename "$FLIP_HOOK")"
  "$FLIP_HOOK" promote || log "WARNING: the address flip hook failed; do it by hand"
else
  log "no ${FLIP_HOOK}; flip the address by hand:"
  log "  - point the mgmt-01 DNS A record at this host, or"
  log "  - take the primary's management IP on this VM (only after it is truly off)"
  log "  - update the FortiGate policy that allows mgmt-01 to reach the device"
  log "    management planes, or nothing will be able to collect"
fi

log ""
log "PROMOTED, and FROZEN. Nothing will change the estate until you say so."
log "Next (all inside the stack - the state is in the infra-data volume):"
log "  1. docker compose -f deploy/docker-compose.yml exec infra-agent infra dr health"
log "  2. docker compose -f deploy/docker-compose.yml exec infra-agent infra collect"
log "  3. docker compose -f deploy/docker-compose.yml exec infra-agent infra drift"
log "  4. NetBox history, if you want it back (the dumps are staged in the volume):"
log "       docker compose -f deploy/docker-compose.yml exec -T infra-agent \\"
log "         cat /app/data/dr-restore/postgres/netbox.dump |"
log "       docker compose -f deploy/docker-compose.yml exec -T postgres \\"
log "         pg_restore -U \"\${POSTGRES_USER:-infra}\" -d netbox --clean --if-exists"
log "  5. docker compose -f deploy/docker-compose.yml exec infra-agent infra change unfreeze"
log "     (only when the four above look right)"
