# ADR 0006: Onboarding harness with local secret entry and credential probes

Status: accepted

## Context
Discovery cannot start without management IPs, credentials and API keys, and
the safety model assumes accounts have exactly the privileges the design
expects. Typing secrets into a chat with a cloud model would violate ADR 0003.

## Decision
`infra onboard` is a CLI harness run with the human present. Secrets are
prompted locally and written straight to SOPS-encrypted files. Each device
credential is probed for identity and privilege level before it is accepted.
The language model only sees redacted status and check reports through
`onboarding.status` and `onboarding.next_step`.

## Consequences
`inventory/seed.yaml` is the pre-NetBox inventory that Phase 1 collectors run
from and Phase 2 bootstraps NetBox with.
