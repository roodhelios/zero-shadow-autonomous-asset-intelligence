"""Create or verify a local snapshot authentication manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .evidence_auth import EvidenceAuthError, create_manifest, verify_manifest
from .evidence_diff import load_snapshot


def _local(path: Path, label: str, *, exists: bool) -> Path:
    if "://" in str(path):
        raise EvidenceAuthError(f"{label} must be a local path")
    return path.resolve(strict=exists)


def _key(path: Path) -> bytes:
    resolved = _local(path, "key file", exists=True)
    if not resolved.is_file():
        raise EvidenceAuthError("key file must be a regular local file")
    if os.name == "posix" and stat.S_IMODE(resolved.stat().st_mode) & 0o077:
        raise EvidenceAuthError("key file permissions must exclude group and other users")
    key = resolved.read_bytes()
    if len(key) < 32:
        raise EvidenceAuthError("key file must contain at least 32 bytes")
    return key


def _keyring(path: Path | None) -> dict | None:
    if path is None:
        return None
    resolved = _local(path, "keyring file", exists=True)
    if not resolved.is_file() or resolved.stat().st_size > 1_048_576:
        raise EvidenceAuthError("keyring must be a local file no larger than 1 MiB")
    if os.name == "posix" and stat.S_IMODE(resolved.stat().st_mode) & 0o022:
        raise EvidenceAuthError("keyring permissions must exclude group and other write access")
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise EvidenceAuthError("keyring contains duplicate JSON fields")
            result[key] = item
        return result

    value = json.loads(resolved.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise EvidenceAuthError("keyring must be a JSON object")
    return value


def _write_new_json(path: Path, value: dict) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _fsync_directory(directory: Path) -> None:
    """Synchronize the directory entry that publishes a completed manifest."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authenticate a local evidence snapshot")
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("create", help="create a detached HMAC manifest")
    seal.add_argument("snapshot", type=Path)
    seal.add_argument("--key-file", required=True, type=Path)
    seal.add_argument("--key-id", required=True)
    seal.add_argument("--keyring", type=Path, help="optional non-secret lifecycle metadata")
    seal.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="verify a snapshot and its manifest")
    verify.add_argument("snapshot", type=Path)
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--key-file", required=True, type=Path)
    verify.add_argument("--key-id", required=True)
    verify.add_argument("--keyring", type=Path, help="optional non-secret lifecycle metadata")
    args = parser.parse_args(argv)
    try:
        snapshot_path = _local(args.snapshot, "snapshot", exists=True)
        key_path = _local(args.key_file, "key file", exists=True)
        snapshot = load_snapshot(snapshot_path)
        key = _key(key_path)
        keyring = _keyring(args.keyring)
        operation_time = (datetime.now(timezone.utc).replace(microsecond=0)
                          .isoformat().replace("+00:00", "Z")) if keyring is not None else None
        if args.command == "create":
            output = _local(args.output, "output", exists=False)
            if output in {snapshot_path, key_path}:
                raise EvidenceAuthError("output must differ from snapshot and key file")
            if output.exists():
                raise EvidenceAuthError("output already exists")
            manifest = create_manifest(
                snapshot, key, key_id=args.key_id, keyring=keyring, at=operation_time
            )
            _write_new_json(output, manifest)
            print(f"manifest created for {manifest['asset_id']}")
        else:
            manifest_path = _local(args.manifest, "manifest", exists=True)
            if manifest_path in {snapshot_path, key_path}:
                raise EvidenceAuthError("manifest must differ from snapshot and key file")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            verify_manifest(
                snapshot, manifest, key, expected_key_id=args.key_id,
                keyring=keyring, at=operation_time,
            )
            print(f"verified {manifest['asset_id']} {manifest['snapshot_sha256']}")
    except (EvidenceAuthError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
