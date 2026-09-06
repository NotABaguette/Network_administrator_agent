# ADR 0001: NetBox as the source of truth

Status: accepted

## Context
The system needs a durable model of intended state covering physical
(devices, interfaces, cables, power), logical (VLANs, prefixes, IPs) and
virtual (clusters, VMs, VM interfaces) layers, with an API the agent can
query and a history of who changed what.

## Decision
Use NetBox, pinned to a specific release with a pinned `pynetbox`. Discovery
reconciles observed state into it; the baseline is the first human-accepted
snapshot. A custom schema or a graph database is not used for intended state.

## Consequences
NetBox is the largest single component in the stack and must be backed up
nightly. The derived topology graph (networkx) is rebuilt from NetBox plus
observed state and is not itself authoritative.
