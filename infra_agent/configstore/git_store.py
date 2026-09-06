"""Local git repository holding raw device configurations.

Raw configs live here and only here. They are never handed to the language
model; the correlation layer works from parsed structures. A commit that does
not correspond to an approved ChangePlan is an `UnapprovedConfigChange`.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class ConfigGitStore:
    def __init__(self, path: Path):
        self.path = path

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.path), *args],
            check=check,
            capture_output=True,
            text=True,
        )

    def ensure(self) -> None:
        if (self.path / ".git").exists():
            return
        self.path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q", str(self.path)], check=True)
        self._git("config", "user.name", "infra-agent")
        self._git("config", "user.email", "infra-agent@localhost")
        (self.path / "README.md").write_text(
            "# Device configuration backups\n\n"
            "Written by infra_agent collectors. Never edit by hand.\n"
        )
        self._git("add", "README.md")
        self._git("commit", "-q", "-m", "init config store")

    def write(self, device: str, filename: str, content: str) -> str | None:
        """Write a config file and commit it. Returns the commit sha, or None if unchanged."""
        self.ensure()
        target = self.path / device / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_text() == content:
            return None
        target.write_text(content)
        rel = f"{device}/{filename}"
        self._git("add", rel)
        status = self._git("status", "--porcelain", "--", rel)
        if not status.stdout.strip():
            return None
        self._git("commit", "-q", "-m", f"{device}: {filename} changed")
        return self._git("rev-parse", "HEAD").stdout.strip()

    def latest(self, device: str, filename: str) -> str | None:
        target = self.path / device / filename
        return target.read_text() if target.exists() else None

    def history(self, device: str, limit: int = 20) -> list[dict[str, str]]:
        if not (self.path / ".git").exists():
            return []
        out = self._git(
            "log", f"-n{limit}", "--format=%H%x09%aI%x09%s", "--", device, check=False
        ).stdout
        entries = []
        for line in out.splitlines():
            sha, when, subject = line.split("\t", 2)
            entries.append({"sha": sha, "at": when, "subject": subject})
        return entries

    def diff(self, device: str, filename: str, old_sha: str, new_sha: str = "HEAD") -> str:
        """Raw unified diff. For operators only: never passes the redaction gateway."""
        return self._git("diff", old_sha, new_sha, "--", f"{device}/{filename}").stdout
