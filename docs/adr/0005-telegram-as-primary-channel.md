# ADR 0005: Telegram bot as the primary owner channel

Status: accepted

## Context
A single owner needs alerts, reports, questions and approvals on a phone,
without opening inbound ports on the edge firewall.

## Decision
A Telegram bot using long polling (outbound only). Only the owner's Telegram
user id is accepted. Tier 1 approvals are inline buttons; Tier 2 additionally
requires typing a confirmation phrase. Claude Code over MCP, Grafana and the
dead-man heartbeat's own notifications are secondary channels.

## Consequences
The approval path depends on WAN connectivity through the FortiGate, so Tier 2
changes on the edge require the out-of-band box and a healthy dead-man
heartbeat before execution.
