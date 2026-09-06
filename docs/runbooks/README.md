# Runbooks

Human- and agent-readable procedures. Each runbook states its tier, the
pre-checks, the steps, the post-checks and the rollback. The agent may run a
runbook through `runbook.run` only within its tier rules.
