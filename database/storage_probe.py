"""Probe local evidence storage primitives without retaining test evidence."""

from __future__ import annotations

import argparse
import errno
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class StorageProbeError(ValueError):
    """Raised when required evidence-publication primitives are unavailable."""


@dataclass(frozen=True, slots=True)
class StorageProbeResult:
    directory: str
    exclusive_create: bool
    file_sync: bool
    hard_link_publish: bool
    no_replace_collision: bool
    directory_sync: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "directory": self.directory,
            "exclusive_create": self.exclusive_create,
            "file_sync": self.file_sync,
            "hard_link_publish": self.hard_link_publish,
            "no_replace_collision": self.no_replace_collision,
            "directory_sync": self.directory_sync,
            "status": "supported",
        }


def probe_storage_directory(directory: Path) -> StorageProbeResult:
    """Exercise the primitives used to publish complete detached manifests."""
    try:
        target = directory.resolve(strict=True)
    except OSError as exc:
        raise StorageProbeError("storage directory does not exist") from exc
    if not target.is_dir() or directory.is_symlink():
        raise StorageProbeError("storage target must be a non-symlink directory")

    token = secrets.token_hex(16)
    temporary = target / f".zero-shadow-probe-{token}.tmp"
    competitor = target / f".zero-shadow-probe-{token}.competitor"
    published = target / f".zero-shadow-probe-{token}.published"
    descriptor: int | None = None
    directory_descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.write(descriptor, b"zero-shadow-storage-probe\n")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        os.link(temporary, published)

        competitor_descriptor = os.open(
            competitor,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(competitor_descriptor, b"replacement-must-not-publish\n")
            os.fsync(competitor_descriptor)
        finally:
            os.close(competitor_descriptor)
        try:
            os.link(competitor, published)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
        else:
            raise StorageProbeError("storage publication replaced an existing artifact")
        if published.read_bytes() != b"zero-shadow-storage-probe\n":
            raise StorageProbeError("storage publication changed during collision testing")

        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(target, flags)
        os.fsync(directory_descriptor)

        published.unlink()
        competitor.unlink()
        temporary.unlink()
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise StorageProbeError(
            "storage directory lacks a required publication primitive"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        for path in (published, competitor, temporary):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass

    return StorageProbeResult(str(target), True, True, True, True, True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        result = probe_storage_directory(args.directory)
    except StorageProbeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
