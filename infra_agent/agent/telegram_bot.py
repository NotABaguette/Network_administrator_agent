"""Telegram bot: the owner's primary channel.

Design constraints (ADR 0005):
- long polling only: no inbound port on the firewall;
- only OWNER_ID is accepted, everything else is ignored and logged;
- Tier 1 approvals are inline buttons whose callback carries the plan id; the
  approval token is looked up server-side from the pending request and bound
  to the plan id and the owner id;
- Tier 2 additionally requires the owner to type the confirmation phrase.

Phase 3 implements this on python-telegram-bot. Kept as a typed skeleton so
the approval contract is fixed now.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OwnerGate:
    owner_id: int

    def allows(self, sender_id: int) -> bool:
        return sender_id == self.owner_id


COMMANDS = {
    "/status": "platform and estate summary",
    "/ask <question>": "route a question to the agent",
    "/pending": "list changes awaiting approval",
    "/freeze": "break-glass: stop all automation, agent read-only",
    "/unfreeze": "lift the freeze",
    "/digest": "send today's digest now",
}
