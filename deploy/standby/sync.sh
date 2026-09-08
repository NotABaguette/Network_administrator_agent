#!/usr/bin/env bash
#
# Nightly DR export from the primary mgmt-01 to the cold standby.
#
# The agent service already runs this as a scheduled duty (`dr-export` in
# infra_agent/agent/duties.py). This script is the same job for an operator who
# would rather own the schedule in cron or a systemd timer than in the agent -
# and it is what runs when the agent itself is the thing that is broken.
#
#   ./sync.sh                     # export to $INFRA_DR_TARGET, prune, verify
#   ./sync.sh --no-verify         # export only (faster, for a manual pre-change copy)
#
# Exit codes: 0 all good, 1 export failed, 2 verification failed,
#             3 configuration missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INFRA="${INFRA_CLI:-infra}"
VERIFY=1
LOG_TAG="dr-sync"

for arg in "$@"; do
  case "$arg" in
    --no-verify) VERIFY=0 ;;
    -h | --help)
      sed -n '2,20p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 3
      ;;
  esac
done

log() { printf '%s %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOG_TAG" "$*"; }

# Settings come from the same place the platform reads them, so the script and
# the agent can never disagree about where bundles go.
if [ -f "${REPO_ROOT}/deploy/.env" ]; then
  # shellcheck disable=SC1091
  set -a && . "${REPO_ROOT}/deploy/.env" && set +a
fi

TARGET="${INFRA_DR_TARGET:-}"
if [ -z "$TARGET" ]; then
  log "INFRA_DR_TARGET is not set; nothing to sync to. Set it in deploy/.env to"
  log "a directory or ssh://user@standby/srv/infra-dr and re-run."
  exit 3
fi

# The standby must be reachable with key auth alone. A password prompt in a
# cron job is a job that hangs until the next one starts.
case "$TARGET" in
  ssh://* | *@*:*)
    SSH_HOST="${TARGET#ssh://}"
    SSH_HOST="${SSH_HOST%%/*}"
    SSH_HOST="${SSH_HOST%%:*}"
    log "checking key auth to ${SSH_HOST}"
    if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_HOST" true; then
      log "cannot reach ${SSH_HOST} with key auth; fix the key before trusting this backup"
      exit 1
    fi
    ;;
esac

log "exporting to ${TARGET}"
if ! "$INFRA" dr export --to "$TARGET"; then
  log "export failed"
  exit 1
fi

if [ "$VERIFY" -eq 1 ]; then
  log "verifying the newest local bundle"
  if ! "$INFRA" dr verify; then
    log "verification FAILED - the bundle on the standby does not restore"
    exit 2
  fi
fi

log "done"
