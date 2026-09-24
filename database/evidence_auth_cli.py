"""Create or verify a local snapshot authentication manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authenticate a local evidence snapshot")
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("create", help="create a detached HMAC manifest")
    seal.add_argument("snapshot", type=Path)
    seal.add_argument("--key-file", required=True, type=Path)
    seal.add_argument("--output", required=True, type=Path)
    verify = commands.add_parser("verify", help="verify a snapshot and its manifest")
    verify.add_argument("snapshot", type=Path)
    verify.add_argument("manifest", type=Path)
    verify.add_argument("--key-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        snapshot_path = _local(args.snapshot, "snapshot", exists=True)
        key_path = _local(args.key_file, "key file", exists=True)
        snapshot = load_snapshot(snapshot_path)
        key = _key(key_path)
        if args.command == "create":
            output = _local(args.output, "output", exists=False)
            if output in {snapshot_path, key_path}:
                raise EvidenceAuthError("output must differ from snapshot and key file")
            if output.exists():
                raise EvidenceAuthError("output already exists")
            manifest = create_manifest(snapshot, key)
            output.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"manifest created for {manifest['asset_id']}")
        else:
            manifest_path = _local(args.manifest, "manifest", exists=True)
            if manifest_path in {snapshot_path, key_path}:
                raise EvidenceAuthError("manifest must differ from snapshot and key file")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            verify_manifest(snapshot, manifest, key)
            print(f"verified {manifest['asset_id']} {manifest['snapshot_sha256']}")
    except (EvidenceAuthError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
