# ADR 0003: Cloud LLM with a single redaction gateway

Status: accepted

## Context
The owner allows a cloud LLM to see metadata but not raw device configs.
Secrets must never leave the network.

## Decision
Use the Claude API (`claude-opus-5`) through one redaction gateway that every
outbound payload passes through. The gateway strips secret patterns from all
payload types including logs and show output, refuses raw configs and raw
config diffs, optionally pseudonymises public IPs, and writes an egress audit
log. Raw configs are parsed into structured rows before the model sees them.

## Consequences
Collectors must produce structured representations of configs, which is also
what the correlation engine needs. A redaction corpus test is part of CI and
must strip 100%.
