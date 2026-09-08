"""Owner notification contract. The Telegram bot implements it; the agent
service and the change engine only depend on this protocol."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from infra_agent.change.plan import ChangePlan


@runtime_checkable
class Notifier(Protocol):
    def send(self, text: str, *, critical: bool = False) -> None:
        """Plain message to the owner. `critical` may bypass quiet hours."""

    def send_approval_request(
        self, plan: ChangePlan, token: str, phrase: str | None = None
    ) -> None:
        """Present a Tier 1/2 plan with Approve / Reject controls. The token is
        for the human channel only and must never be echoed into any LLM-visible
        payload or log. `phrase` is the Tier 2 confirmation phrase the owner has
        to type back; it is for the owner's eyes only and is never logged."""

    def send_report(self, title: str, body_markdown: str) -> None:
        """Digest, weekly or monthly report."""


class LogNotifier:
    """Fallback when no chat channel is configured: logs everything, keeps tokens out."""

    def __init__(self) -> None:
        import logging

        self.log = logging.getLogger("infra.notify")

    def send(self, text: str, *, critical: bool = False) -> None:
        self.log.warning("[critical] %s" if critical else "%s", text)

    def send_approval_request(
        self, plan: ChangePlan, token: str, phrase: str | None = None
    ) -> None:
        self.log.warning(
            "approval requested for %s (%s, tier %s); token%s delivered out of band",
            plan.id,
            plan.title,
            plan.tier.name,
            " and confirmation phrase" if phrase else "",
        )

    def send_report(self, title: str, body_markdown: str) -> None:
        self.log.info("%s\n%s", title, body_markdown)
