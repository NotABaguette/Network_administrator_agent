"""Native per-platform executors (Phase 4).

Rollback strategy, fixed by design:
- cisco:     `configure terminal revert timer N` + `configure confirm` from the post-check.
             Never `reload in`.
- fortigate: inverse REST object operations. Never revision restore (reboots the 60F).
- esxi:      host-config backup before host changes; VM snapshot before VM changes
             except disk extends; SSH path when the license blocks API writes.
"""
