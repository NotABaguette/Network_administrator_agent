"""Encrypting the copy of the bundle that leaves the building.

A DR bundle is credential-equivalent. `configs.bundle` carries the raw
running-configs the config store keeps - SNMP communities in cleartext,
reversible Cisco type-7 keys, FortiOS `ENC` blobs - and `postgres/netbox.dump`
carries the NetBox API tokens and Django password hashes. The manifest already
refuses to carry `deploy/.env` for exactly this reason; the rest of the archive
deserves the same answer.

So the local copy is written 0600 and the copy that travels is encrypted to an
age recipient (`INFRA_DR_AGE_RECIPIENT`) whenever one is configured. age is
already on the box: SOPS uses it for `secrets/*.enc.yaml`, and the private half
is already required to be offline for any restore to be possible at all. One
key, one story.

`age` is shelled out to through an injectable runner, so every path here is
exercised offline. When no recipient is configured nothing is encrypted and the
bundle's protection is the file mode plus the standby's `0700` inbox - which
the runbook says out loud rather than implying.
"""

from __future__ import annotations

import logging
import os
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from infra_agent.dr.errors import DRError

log = logging.getLogger(__name__)

#: Suffix appended to an encrypted bundle: `infra-dr-<host>-<stamp>.tar.gz.age`.
AGE_SUFFIX = ".age"
#: Both the binary and the armored age formats start with this header.
AGE_MAGIC = b"age-encryption.org/v1"
AGE_TIMEOUT = 900.0

#: (argv) -> (returncode, combined output). Never raises for a non-zero exit.
Runner = Callable[[Sequence[str]], tuple[int, str]]


def _run(argv: Sequence[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=AGE_TIMEOUT)
    except FileNotFoundError:
        return 127, "age is not installed on this host"
    except subprocess.TimeoutExpired:
        return 124, "age timed out"
    return proc.returncode, (proc.stderr or "") + (proc.stdout or "")


def looks_encrypted(path: Path) -> bool:
    """Is this an age file? By name, or by the header if the name lies."""
    if path.name.endswith(AGE_SUFFIX):
        return True
    try:
        with path.open("rb") as handle:
            return handle.read(len(AGE_MAGIC)) == AGE_MAGIC
    except OSError:
        return False


def encrypt(src: Path, dest: Path, recipient: str, *, runner: Runner | None = None) -> Path:
    """`age -r <recipient> -o dest src`, and the result is 0600."""
    run = runner or _run
    dest.parent.mkdir(parents=True, exist_ok=True)
    code, output = run(["age", "-r", recipient, "-o", str(dest), str(src)])
    if code != 0:
        dest.unlink(missing_ok=True)
        raise DRError(f"age encryption failed: {_tail(output)}")
    if not dest.exists():
        raise DRError("age reported success but wrote no file")
    _chmod(dest, 0o600)
    return dest


def decrypt(src: Path, dest: Path, identity: Path | None, *, runner: Runner | None = None) -> Path:
    """`age -d -i <identity> -o dest src`. The identity is the offline age key."""
    run = runner or _run
    if identity is None:
        raise DRError(
            f"{src.name} is encrypted and no age identity is available. Restore "
            "~/.config/sops/age/keys.txt from the owner's offline copy, or point "
            "INFRA_DR_AGE_IDENTITY at it."
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    code, output = run(["age", "-d", "-i", str(identity), "-o", str(dest), str(src)])
    if code != 0:
        dest.unlink(missing_ok=True)
        raise DRError(f"could not decrypt {src.name}: {_tail(output)}")
    if not dest.exists():
        raise DRError("age reported success but wrote no file")
    _chmod(dest, 0o600)
    return dest


def identity_file(settings: object | None = None) -> Path | None:
    """Where the age private key is, if it is anywhere this process can read.

    The same key SOPS uses, in the same order SOPS looks for it, so an operator
    never has to keep two of them in sync.
    """
    candidates: list[Path] = []
    configured = getattr(settings, "dr_age_identity", None) if settings is not None else None
    if configured:
        candidates.append(Path(configured))
    env = os.environ.get("SOPS_AGE_KEY_FILE")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.home() / ".config" / "sops" / "age" / "keys.txt")
    for path in candidates:
        try:
            if path.is_file():
                return path
        except OSError:  # pragma: no cover - an unreadable HOME is not a DR failure
            continue
    return None


def ensure_plaintext(
    bundle: Path,
    workdir: Path,
    settings: object | None = None,
    *,
    runner: Runner | None = None,
) -> tuple[Path, bool]:
    """The bundle as a plain tarball, decrypting it into `workdir` if it is not.

    Returns `(path, was_encrypted)`. Verify and import both call this, so a
    standby that only ever received encrypted bundles restores with the same
    command as one that received plain ones.
    """
    bundle = Path(bundle)
    if not looks_encrypted(bundle):
        return bundle, False
    workdir.mkdir(parents=True, exist_ok=True)
    plain = workdir / (
        bundle.name[: -len(AGE_SUFFIX)] if bundle.name.endswith(AGE_SUFFIX) else bundle.name
    )
    decrypt(bundle, plain, identity_file(settings), runner=runner)
    return plain, True


def _chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - a filesystem without modes is not a failure
        log.debug("could not set mode %o on %s", mode, path.name)


def _tail(text: str, limit: int = 300) -> str:
    cleaned = " ".join(text.split())
    return cleaned[-limit:] if len(cleaned) > limit else cleaned
