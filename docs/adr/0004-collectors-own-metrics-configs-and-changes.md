# ADR 0004: Collectors expose metrics and back up configs; native executors, no Oxidized or device Ansible

Status: accepted

## Context
Initial drafts used Oxidized for config backup, separate exporters
(`fortigate_exporter`, `vmware_exporter`, `redfish_exporter`) for metrics,
and Ansible for changes. That meant two or three pollers per device, a Ruby
service, a third credential set, and an unmaintained exporter.

## Decision
Each collector exposes `/metrics` and commits configs to a local git repo.
Change executors are native Python per platform. Ansible is used only for
guest operating systems in Phase 5. `snmp_exporter` (switches) and
`blackbox_exporter` (probes) remain because they are standard and cheap.

## Consequences
One poller per device, which matters on the 60F and on iLO4. The collectors
are on the critical path for monitoring, so their own freshness is alerted on.
