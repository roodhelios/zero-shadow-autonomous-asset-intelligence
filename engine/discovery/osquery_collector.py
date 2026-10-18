"""Import saved osquery system_info rows. Never execute queries or contact hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from pathlib import Path

from engine.discovery.fixture_discovery import ALLOWED_SCOPES
from engine.models import AssetObservation, AssetValidationError

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ROWS = 10_000
SOURCE = "osquery-system-info"
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AssetValidationError("duplicate JSON field")
        result[key] = value
    return result


def convert_system_info(data: bytes, *, scope: str) -> dict:
    """Convert only hostname and UUID claims into the existing fixture contract."""
    if scope not in ALLOWED_SCOPES:
        raise AssetValidationError("explicit synthetic, owned, or authorized scope is required")
    if len(data) > MAX_INPUT_BYTES:
        raise AssetValidationError("input exceeds 4 MiB")
    rows = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)
    if not isinstance(rows, list) or not rows or len(rows) > MAX_ROWS:
        raise AssetValidationError("input must contain 1 to 10000 system_info rows")
    assets = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"hostname", "uuid"}:
            raise AssetValidationError("each row must contain exactly hostname and uuid")
        if not isinstance(row["hostname"], str) or not isinstance(row["uuid"], str):
            raise AssetValidationError("hostname and uuid must be strings")
        hostname = row["hostname"].strip().rstrip(".").lower()
        if len(hostname) > 253 or not all(LABEL.fullmatch(label) for label in hostname.split(".")):
            raise AssetValidationError("hostname must use ASCII DNS-style labels")
        identifier = uuid.UUID(row["uuid"].strip())
        if identifier.int in {0, (1 << 128) - 1} or identifier in seen:
            raise AssetValidationError("UUID must be non-placeholder and unique within the export")
        seen.add(identifier)
        asset = {"source_record_id": str(identifier), "kind": "host", "hostname": hostname,
                 "tags": {}, "ip_addresses": []}
        AssetObservation.from_dict(SOURCE, asset)
        assets.append(asset)
    return {"schema_version": 1, "source": SOURCE, "scope": scope,
            "assets": sorted(assets, key=lambda item: item["source_record_id"]),
            "import_metadata": {"table": "system_info", "input_sha256": hashlib.sha256(data).hexdigest()}}


def _read(path):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise AssetValidationError("input must be a regular local file")
        return source.read(MAX_INPUT_BYTES + 1)


def _publish(path, rendered):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".osquery-import-", delete=False) as output:
            temporary = output.name
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="saved JSON array from SELECT hostname, uuid FROM system_info")
    parser.add_argument("--scope", choices=sorted(ALLOWED_SCOPES), required=True)
    parser.add_argument("--output", type=Path, help="new private fixture file, never overwrite")
    args = parser.parse_args(argv)
    try:
        result = convert_system_info(_read(args.export), scope=args.scope)
        rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            _publish(args.output, rendered)
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("error: osquery import failed; check the saved rows, explicit scope, and new output path",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
