# ADR 0002: Tiered autonomy with computed risk tiers

Status: accepted

## Context
The owner wants low-risk actions automated and everything else approved. A
static list of "safe" actions is unsafe because the same action has different
blast radius depending on the target (an access port versus the port that
feeds the management VM).

## Decision
Every change is a ChangePlan. Its tier is the maximum of the action's base
tier and escalations derived from impact analysis. Tier 0 requires opt-in
tags, cause allowlists, cooldowns and retry caps. Approval for Tier 1 and 2 is
a human-only channel; the approve and execute operations are not exposed to
the language model and the approval token is never in any LLM-visible payload.

## Consequences
The correlation graph is a dependency of the change engine, so Phase 2 must
land before Phase 4. Tier 0 actions are introduced one at a time after a week
of shadow mode.
