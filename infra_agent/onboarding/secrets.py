"""SOPS + age secrets. Plaintext never touches disk unencrypted and never
enters the language model.

Files: secrets/platform.enc.yaml, secrets/devices.enc.yaml
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

DEFAULT_AGE_KEY = Path.home() / ".config" / "sops" / "age" / "keys.txt"


class SopsError(RuntimeError):
    pass


def sops_available() -> bool:
    return shutil.which("sops") is not None


def age_available() -> bool:
    return shutil.which("age-keygen") is not None


def ensure_age_key(path: Path = DEFAULT_AGE_KEY) -> str:
    """Create an age key if missing and return the public recipient."""
    if not age_available():
        raise SopsError("age-keygen not found; install age (https://age-encryption.org)")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["age-keygen", "-o", str(path)], check=True, capture_output=True)
        path.chmod(0o600)
    out = subprocess.run(
        ["age-keygen", "-y", str(path)], check=True, capture_output=True, text=True
    ).stdout.strip()
    return out


def set_sops_recipient(sops_yaml: Path, recipient: str) -> None:
    text = sops_yaml.read_text() if sops_yaml.exists() else ""
    if "REPLACE_WITH_AGE_PUBLIC_KEY" in text:
        text = text.replace("REPLACE_WITH_AGE_PUBLIC_KEY", recipient)
    elif not re.search(r"age:\s*\"?age1", text):
        text = (
            f'creation_rules:\n  - path_regex: secrets/.*\\.enc\\.yaml$\n    age: "{recipient}"\n'
        )
    sops_yaml.write_text(text)


class SecretsStore:
    def __init__(self, secrets_dir: Path, age_key_file: Path | None = None):
        self.dir = secrets_dir
        self.age_key_file = age_key_file or Path(
            os.environ.get("SOPS_AGE_KEY_FILE", str(DEFAULT_AGE_KEY))
        )

    def available(self) -> bool:
        return sops_available() and self.age_key_file.exists()

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.enc.yaml"

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["SOPS_AGE_KEY_FILE"] = str(self.age_key_file)
        return env

    def read(self, name: str) -> dict[str, Any]:
        path = self._path(name)
        if not path.exists():
            return {}
        proc = subprocess.run(
            ["sops", "--decrypt", "--output-type", "json", str(path)],
            capture_output=True,
            text=True,
            env=self._env(),
        )
        if proc.returncode != 0:
            raise SopsError(proc.stderr.strip())
        return json.loads(proc.stdout or "{}")

    def write(self, name: str, data: dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self._path(name)
        plaintext = yaml.safe_dump(data, sort_keys=True)
        proc = subprocess.run(
            [
                "sops",
                "--encrypt",
                "--input-type",
                "yaml",
                "--output-type",
                "yaml",
                "--filename-override",
                str(path),
                "/dev/stdin",
            ],
            input=plaintext,
            capture_output=True,
            text=True,
            env=self._env(),
            cwd=self._repo_root(),
        )
        if proc.returncode != 0:
            raise SopsError(proc.stderr.strip())
        path.write_text(proc.stdout)

    def _repo_root(self) -> Path:
        # .sops.yaml is resolved relative to the working directory; the repo root
        # is the parent of the secrets dir.
        return self.dir.resolve().parent

    def update(self, name: str, key: str, value: Any) -> None:
        data = self.read(name)
        data[key] = value
        self.write(name, data)

    def keys(self, name: str) -> list[str]:
        return list(self.read(name).keys())

    def has(self, name: str, key: str) -> bool:
        return key in self.read(name)

    def get(self, name: str, key: str) -> Any:
        return self.read(name).get(key)
