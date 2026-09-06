# snmp_exporter configuration

Generate `snmp.yml` with the snmp_exporter generator using `generator.yml`
here (modules `if_mib` and the Cisco CPU/memory/temperature MIBs). The
`cisco_v3` auth block takes its SNMPv3 credentials from environment variables
injected at container start by `infra collect --write-targets`, never from
this file in git.
