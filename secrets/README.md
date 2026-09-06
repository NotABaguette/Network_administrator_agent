# secrets/

Only `*.enc.yaml` files (encrypted with SOPS + age) belong here. The age
private key lives outside the repo (`~/.config/sops/age/keys.txt` by default)
and is created by `infra onboard init`.

Files written by the onboarding harness:

| File | Contents |
|---|---|
| `platform.enc.yaml` | Anthropic API key, Telegram bot token, owner Telegram user id, dead-man heartbeat URL |
| `devices.enc.yaml` | One entry per device credential reference: username/password or API token |

Nothing in this directory is ever passed to the language model.
