# Guest exporters (Phase 5)

Ansible is used for exactly one thing in this platform: installing and keeping
the operating-system exporters inside the guests. Device changes are native
executors (`docs/adr/0004-collectors-own-metrics-configs-and-changes.md`), and
the guest *collector* reads over SSH and WinRM without Ansible. What lives here
is deployment, not change management.

| Playbook | What it does |
|---|---|
| `playbooks/node_exporter.yml` | Installs `node_exporter` on the Linux guests as a systemd unit bound to the guest's own address, and opens nothing else. |
| `playbooks/windows_exporter.yml` | Installs `windows_exporter` on the Windows guests as a service, with the default collector set plus `service` and `logical_disk`. |
| `playbooks/site.yml` | Both of the above. |

## Inventory

`inventory/guests.yml` is **generated** from `inventory/seed.yaml` by
`infra onboard seed-guests` (see `infra_agent/guest_inventory.py`). Do not edit
it: it is rewritten wholesale, and the seed inventory is the source.

It carries connection settings only — addresses, transport, ports. **No
credential is ever written into it.** The platform's secrets live in SOPS
(`docs/onboarding.md`), and Ansible is run by a human who supplies the
credential on the command line or from their own vault:

```bash
cd ansible
ansible-playbook -i inventory/guests.yml playbooks/node_exporter.yml \
  --user infra-deploy --private-key ~/.ssh/infra-deploy --become

ansible-playbook -i inventory/guests.yml playbooks/windows_exporter.yml \
  --extra-vars "ansible_user=lab\\infra-deploy" --ask-pass
```

The deploy account is **not** the collector's read-only account: installing an
exporter needs root or Administrator, and the collector account deliberately has
neither (`infra onboard accounts <guest>`).

## Scraping

The same command writes `deploy/prometheus/targets/guests.json`, which the
`guests` job in `deploy/prometheus/prometheus.yml` reads with `file_sd`. Linux
guests are scraped on 9100 and Windows guests on 9182. Prometheus picks up
changes to the file without a reload.

## Air-gapped installs

Both playbooks download from GitHub by default. Set `exporter_download_base` (or
`windows_exporter_url`) to an internal mirror when the guests have no outbound
access; the checksum variables stay the same.
