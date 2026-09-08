#!/usr/bin/env bash
#
# Retention for the standby's inbox. Runs ON THE STANDBY, from its own cron.
#
# The primary cannot do this. Its key is restricted to a forced `rrsync`
# command, so it can write bundles into one directory and nothing else - no
# shell, no `rm`, no `ls`. That restriction is the reason a compromised primary
# cannot wipe the only off-box copy of the platform, and it is worth more than
# the convenience of remote pruning.
#
#   0 4 * * *  /opt/infra-agent/deploy/standby/prune.sh >> /var/log/infra-dr-prune.log 2>&1
#
#   ./prune.sh                     # /srv/infra-dr, 14 days
#   ./prune.sh --dir /srv/infra-dr --days 30
#   ./prune.sh --dry-run
#
# The newest bundle is NEVER deleted, whatever the window says: one stale
# backup is worth incomparably more than none, and "the newest bundle is old"
# already has an alert (DRExportStale, StandbyStale).
set -euo pipefail

DIR="${INFRA_DR_INBOX:-/srv/infra-dr}"
DAYS="${INFRA_DR_RETENTION_DAYS:-14}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dir)
      DIR="${2:-}"
      shift 2
      ;;
    --days)
      DAYS="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY=1
      shift
      ;;
    -h | --help)
      sed -n '2,20p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 3
      ;;
  esac
done

log() { printf '%s dr-prune: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

[ -d "$DIR" ] || {
  log "no such directory: ${DIR}"
  exit 3
}
case "$DAYS" in
  '' | *[!0-9]*)
    log "--days must be a whole number of days, not '${DAYS}'"
    exit 3
    ;;
esac

# Newest first. Bundle names carry their own UTC timestamp, so sorting by name
# is sorting by age, with no dependency on mtime surviving the copy.
mapfile -t bundles < <(
  find "$DIR" -maxdepth 1 -type f -name 'infra-dr-*.tar.gz*' ! -name '*.sha256' |
    sort -r
)

if [ "${#bundles[@]}" -eq 0 ]; then
  log "no bundles in ${DIR}"
  exit 0
fi

newest="${bundles[0]}"
log "keeping the newest: $(basename "$newest")"

removed=0
for bundle in "${bundles[@]:1}"; do
  # -mtime +N is "older than N days"; the file's own name is authoritative for
  # WHEN it was exported, but its arrival time is what retention is about.
  if [ -n "$(find "$bundle" -maxdepth 0 -mtime "+${DAYS}" 2>/dev/null)" ]; then
    if [ "$DRY" -eq 1 ]; then
      log "would remove $(basename "$bundle")"
    else
      rm -f -- "$bundle" "${bundle}.sha256"
      log "removed $(basename "$bundle")"
    fi
    removed=$((removed + 1))
  fi
done

log "done: ${removed} bundle(s) older than ${DAYS} days, $((${#bundles[@]} - removed)) kept"
