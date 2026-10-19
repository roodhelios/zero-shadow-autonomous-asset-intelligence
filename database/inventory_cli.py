"""Store a saved osquery export in a new private SQLite evidence database."""

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from database.repository import EvidenceRepository, ALLOWED_SCOPES, _timestamp
from database.inventory_receipt import store_receipt
from engine.correlation import correlate_assets
from engine.discovery.osquery_collector import _read, convert_system_info
from engine.models import AssetObservation


def store_export(source: Path, output: Path, *, scope: str, observed_at: datetime) -> dict:
    """Publish a complete one-batch database exclusively, never update an old run."""
    if os.name != "posix":
        raise ValueError("private inventory storage requires POSIX")
    fixture = convert_system_info(_read(source), scope=scope)
    assets = correlate_assets(AssetObservation.from_dict(fixture["source"], item)
                              for item in fixture["assets"])
    descriptor, temporary = tempfile.mkstemp(prefix=".inventory-", dir=output.parent)
    os.close(descriptor)
    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.executescript(Path(__file__).with_name("schema.sql").read_text())
            EvidenceRepository(connection).store_inventory(assets, scope=scope, observed_at=observed_at)
            receipt_digest = store_receipt(connection, {
                "schema_version": 1, "report_type": "inventory-import",
                "source": fixture["source"], "scope": scope,
                "observed_at": _timestamp(observed_at, "observed_at"),
                "asset_ids": [asset.asset_id for asset in assets],
                "observation_count": len(fixture["assets"]),
                "input_sha256": fixture["import_metadata"]["input_sha256"],
            })
        finally:
            connection.close()
        with open(temporary, "rb") as handle:
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"schema_version": 1, "status": "stored", "scope": scope,
            "receipt_sha256": receipt_digest,
            "asset_ids": [asset.asset_id for asset in assets],
            "observation_count": len(fixture["assets"]),
            "input_sha256": fixture["import_metadata"]["input_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scope", required=True, choices=sorted(ALLOWED_SCOPES))
    parser.add_argument("--observed-at", required=True, help="timezone-aware ISO observation time")
    args = parser.parse_args(argv)
    try:
        result = store_export(args.export, args.output, scope=args.scope,
                              observed_at=datetime.fromisoformat(args.observed_at.replace("Z", "+00:00")))
    except (OSError, ValueError, sqlite3.DatabaseError, UnicodeError, RecursionError):
        print("error: inventory was not stored; check export, scope, time, and new output path", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
