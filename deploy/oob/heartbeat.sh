#!/bin/sh
#
# Dead-man ping from the out-of-band box, sent ONLY while this box can see the
# WAN itself.
#
# The point of an out-of-band heartbeat is to distinguish "the site is dark"
# from "mgmt-01 is dark". A box that pings unconditionally destroys that
# distinction: during a full outage its ping would keep the dead-man service
# quiet and nobody would be paged. So each cycle checks the WAN first, and when
# the WAN is gone it stops pinging and lets the external service page the owner.
#
# It also writes a Prometheus textfile that both this box's Prometheus and the
# main one scrape (`infra_oob_heartbeat_last_ok_timestamp_seconds`), so the main
# side can alert on this box going quiet - OOBHeartbeatMissing in
# infra_agent/monitoring/rules/dr.yaml.
#
# Environment:
#   HEARTBEAT_URL      the dead-man service URL to GET (required)
#   WAN_CHECK_HOSTS    space-separated IPs to ping (default 1.1.1.1 9.9.9.9 8.8.8.8)
#   INTERVAL_SECONDS   seconds between cycles (default 300)
#   METRICS_FILE       textfile to write (default /metrics/heartbeat.prom)
set -eu

WAN_CHECK_HOSTS="${WAN_CHECK_HOSTS:-1.1.1.1 9.9.9.9 8.8.8.8}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-300}"
METRICS_FILE="${METRICS_FILE:-/metrics/heartbeat.prom}"

log() { printf '%s oob-heartbeat: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

if [ -z "${HEARTBEAT_URL:-}" ]; then
  log "HEARTBEAT_URL is not set; refusing to run so this is loud, not silent"
  exit 1
fi

last_ok=0

# Several targets, because one of them being down is not the WAN being down.
# Anycast resolvers on three different networks is about as independent as a
# single uplink allows.
wan_visible() {
  for host in $WAN_CHECK_HOSTS; do
    if ping -c 1 -W 3 "$host" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

write_metrics() {
  wan="$1"
  ok="$2"
  tmp="${METRICS_FILE}.tmp"
  {
    echo "# HELP infra_oob_wan_visible 1 when the out-of-band box can reach the internet"
    echo "# TYPE infra_oob_wan_visible gauge"
    echo "infra_oob_wan_visible ${wan}"
    echo "# HELP infra_oob_heartbeat_last_ok_timestamp_seconds Last dead-man ping the OOB box sent successfully"
    echo "# TYPE infra_oob_heartbeat_last_ok_timestamp_seconds gauge"
    echo "infra_oob_heartbeat_last_ok_timestamp_seconds ${ok}"
  } >"$tmp"
  mv "$tmp" "$METRICS_FILE"
}

log "starting: every ${INTERVAL_SECONDS}s, WAN checked against ${WAN_CHECK_HOSTS}"

while true; do
  if wan_visible; then
    if wget -q -O /dev/null -T 15 "$HEARTBEAT_URL" 2>/dev/null; then
      last_ok="$(date -u +%s)"
      write_metrics 1 "$last_ok"
    else
      # The WAN is up but the dead-man service did not answer. Do not record a
      # success: from here that is indistinguishable from the service being
      # down, and claiming a heartbeat we did not get is the one lie this
      # script must never tell.
      log "WAN is up but the heartbeat URL did not answer"
      write_metrics 1 "$last_ok"
    fi
  else
    log "no WAN from this box; NOT pinging, so the dead-man service pages the owner"
    write_metrics 0 "$last_ok"
  fi
  sleep "$INTERVAL_SECONDS"
done
