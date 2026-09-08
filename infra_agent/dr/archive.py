"""Making and opening the tarball, safely.

A DR bundle is written by this platform and read back by this platform, but it
travels over SSH to a machine whose whole purpose is to be trusted less than
the primary. So extraction refuses absolute paths, `..`, symlinks, hard links
and devices: a bundle must never be able to write outside the directory it is
being extracted into. Python 3.12 has `filter="data"` for exactly this; on
3.11 the members are checked by hand to the same rules.
"""

from __future__ import annotations

import tarfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from infra_agent.dr.errors import DRError


def create(source: Path, dest: Path) -> Path:
    """Tar+gzip the contents of `source` with the members at the archive root."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as tar:
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            tar.add(path, arcname=path.relative_to(source).as_posix())
    return dest


def member_names(bundle: Path) -> list[str]:
    with tarfile.open(bundle, "r:gz") as tar:
        return [name for name in tar.getnames()]


def _check(member: tarfile.TarInfo) -> None:
    name = member.name
    if not member.isfile():
        raise DRError(f"bundle member {name!r} is not a regular file")
    posix = PurePosixPath(name)
    if posix.is_absolute() or ".." in posix.parts or name.startswith("/"):
        raise DRError(f"bundle member {name!r} escapes the extraction directory")


def extract(bundle: Path, dest: Path, *, members: Iterable[str] | None = None) -> Path:
    """Extract `bundle` into `dest`, rejecting anything that is not a plain file."""
    dest.mkdir(parents=True, exist_ok=True)
    wanted = set(members) if members is not None else None
    try:
        with tarfile.open(bundle, "r:gz") as tar:
            selected = []
            for member in tar.getmembers():
                if wanted is not None and member.name not in wanted:
                    continue
                _check(member)
                selected.append(member)
            if hasattr(tarfile, "data_filter"):
                tar.extractall(dest, members=selected, filter="data")
            else:  # pragma: no cover - 3.11 without the backport
                tar.extractall(dest, members=selected)  # noqa: S202 - members checked above
    except tarfile.TarError as exc:
        raise DRError(f"could not read the bundle: {exc}") from exc
    return dest


def read_member(bundle: Path, name: str) -> bytes:
    try:
        with tarfile.open(bundle, "r:gz") as tar:
            handle = tar.extractfile(name)
            if handle is None:
                raise DRError(f"bundle has no member {name!r}")
            return handle.read()
    except KeyError as exc:
        raise DRError(f"bundle has no member {name!r}") from exc
    except tarfile.TarError as exc:
        raise DRError(f"could not read the bundle: {exc}") from exc
