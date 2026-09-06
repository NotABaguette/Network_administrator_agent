# Redaction policy

Scope: every byte that leaves mgmt-01 for the Claude API, whatever tool or
duty produced it. Implemented by `infra_agent/redaction/gateway.py` with rules
in `infra_agent/redaction/redaction.yaml`.

## Always stripped, from every payload type

Configs, logs, `show` output, tool results and chat text alike:
password hashes, enable secrets, PSKs, SNMP communities and SNMPv3 keys, API
keys and bearer tokens, certificates and private keys, RADIUS/TACACS/NTP
authentication keys, VPN secrets, `username … secret/password` lines, FortiOS
`ENC` blobs. Known leak paths that the rules target explicitly: Cisco
`archive log config` lines and FortiOS configuration-change logs.

## Never sent

Raw device configs and raw config diffs. The model receives parsed rows and
structured diffs. The `device.show` allowlist excludes `show run*`,
`show tech*`, `show archive*`, `show startup*`, and FortiOS `diagnose`,
`show full-configuration`, `execute backup`.

## Optional masks

Public IPs are replaced by stable pseudonyms (`PUBIP_1`) and reversed on the
way back so the model's output remains usable.

## Audit

Every outbound payload is logged locally with a SHA-256 of the redacted text,
its size, the calling tool and a timestamp, so it is provable what left the
network. Review the log after the first week of agent operation.

## Tests

`tests/test_redaction.py` holds a corpus of secret patterns per platform. The
gateway must strip 100% of the corpus; any new pattern found in the wild is
added to the corpus first, then to the rules.
