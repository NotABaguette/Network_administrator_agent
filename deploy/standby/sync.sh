#!/usr/bin/env bash
#
# Nightly DR export from the primary mgmt-01 to the cold standby.
#
# Runs the platform's own CLI INSIDE the stack (deploy/standby/dr.compose.yml),
# because that is where the state is: the compose stack keeps everything in the
# named volume `infra-data`, and a host-side `infra dr export` would bundle an
# empty ./data and fail to reach the `postgres` service, which publishes no
# host port. Same reason the agent's own `dr-export` duty needs that overlay.
#
#   ./sync.sh                     # export to $INFRA_DR_TARGET, prune, verify
#   ./sync.sh --no-verify         # export only (faster, for a manual pre-change copy)
#
# INFRA_DR_CLI overrides how the CLI is invoked, for an installation that does
# not use compose:  INFRA_DR_CLI="uv run infra" ./sync.sh
#
# Exit codes: 0 all good, 1 export failed, 2 verification failed,
#             3 configuration missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker-compose.yml"
DR_COMPOSE_FILE="${SCRIPT_DIR}/dr.compose.yml"
VERIFY=1
LOG_TAG="dr-sync"

# Relative settings (data_dir, secrets, inventory) are resolved from the
# working directory, so stand in the checkout rather than wherever cron did.
cd "$REPO_ROOT"

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
# the agent can never disagree about where bundles go. Every compose invocation
# below reads the same file, so a missing one is a hard stop rather than an
# export that runs with half the configuration.
if [ ! -f "${REPO_ROOT}/deploy/.env" ] && [ -z "${INFRA_DR_CLI:-}" ]; then
  log "no ${REPO_ROOT}/deploy/.env; copy deploy/.env.example and fill it in"
  exit 3
fi
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

# How the CLI is invoked. The default is one container on the stack's network
# with the stack's data volume mounted; an array so a multi-word override
# ("uv run infra") works.
if [ -n "${INFRA_DR_CLI:-}" ]; then
  read -ra INFRA <<<"$INFRA_DR_CLI"
else
  [ -f "$COMPOSE_FILE" ] || { log "no compose file at ${COMPOSE_FILE}"; exit 3; }
  [ -f "$DR_COMPOSE_FILE" ] || { log "no ${DR_COMPOSE_FILE}"; exit 3; }
  INFRA=(docker compose --profile dr -f "$COMPOSE_FILE" -f "$DR_COMPOSE_FILE"
    run --rm dr infra)
fi

# The standby must be reachable with the key alone. Note what is NOT checked
# here: `ssh standby true`. The DR account's authorized_keys entry forces
# rrsync, so every session runs rsync whatever was asked for and a plain
# command exits non-zero even when the push works perfectly.
case "$TARGET" in
  ssh://* | *@*:*)
    KEY="${INFRA_DR_SSH_KEY:-$HOME/.ssh/infra-dr}"
    if [ -z "${INFRA_DR_CLI:-}" ] && [ ! -f "$KEY" ]; then
      log "no push key at ${KEY}. Create it (ssh-keygen -t ed25519 -f ${KEY}) and"
      log "install the public half on the standby before trusting this backup;"
      log "Docker would otherwise bind-mount a directory over it."
      exit 3
    fi
    KNOWN="${INFRA_DR_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
    if [ -z "${INFRA_DR_CLI:-}" ] && [ ! -f "$KNOWN" ]; then
      log "no known_hosts at ${KNOWN}: host key checking is strict, so the push"
      log "would fail. Add the standby's key (ssh-keyscan) and check the"
      log "fingerprint against the standby's console before you trust it."
      exit 3
    fi
    ;;
esac

log "exporting to ${TARGET}"
if ! "${INFRA[@]}" dr export --to "$TARGET"; then
  log "export failed"
  exit 1
fi

if [ "$VERIFY" -eq 1 ]; then
  log "verifying the newest bundle"
  if ! "${INFRA[@]}" dr verify; then
    log "verification FAILED - the bundle on the standby does not restore"
    exit 2
  fi
fi

log "done"
