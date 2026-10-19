"""Retain and reconcile the receipt of a discovery-only inventory import."""

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path
from contextlib import closing

from database.evidence_reader import EvidenceReader
from engine.discovery.osquery_collector import _read, convert_inventory

FIELDS = {"schema_version", "report_type", "source", "scope", "observed_at",
          "input_sha256", "asset_ids", "observation_count"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def store_receipt(connection, receipt):
    payload = _canonical(receipt)
    digest = hashlib.sha256(payload.encode()).hexdigest()
    connection.executescript("""
        CREATE TABLE inventory_import_receipt (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            payload_json TEXT NOT NULL, receipt_sha256 TEXT NOT NULL);
        CREATE TRIGGER inventory_receipt_no_update BEFORE UPDATE ON inventory_import_receipt
        BEGIN SELECT RAISE(ABORT, 'import receipt is append-only'); END;
        CREATE TRIGGER inventory_receipt_no_delete BEFORE DELETE ON inventory_import_receipt
        BEGIN SELECT RAISE(ABORT, 'import receipt is append-only'); END;
    """)
    with connection:
        connection.execute("INSERT INTO inventory_import_receipt VALUES (1, ?, ?)", (payload, digest))
    return digest


def read_receipt(connection, *, export_data=None):
    """Check receipt integrity and its relationship to retained observations."""
    row = connection.execute("SELECT payload_json, receipt_sha256 FROM inventory_import_receipt WHERE singleton=1").fetchone()
    if row is None:
        raise ValueError("inventory import receipt is missing")
    receipt = json.loads(row[0])
    if not isinstance(receipt, dict) or set(receipt) != FIELDS:
        raise ValueError("unsupported import receipt")
    if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or receipt["report_type"] != "inventory-import"
            or receipt["source"] != "osquery-system-info"
            or receipt["scope"] not in ("synthetic", "owned", "authorized")
            or not isinstance(receipt["input_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", receipt["input_sha256"])
            or type(receipt["observation_count"]) is not int or receipt["observation_count"] < 1):
        raise ValueError("invalid import receipt fields")
    if hashlib.sha256(_canonical(receipt).encode()).hexdigest() != row[1]:
        raise ValueError("import receipt digest mismatch")
    ids = [item[0] for item in connection.execute("SELECT asset_id FROM assets ORDER BY asset_id")]
    if not ids or receipt["asset_ids"] != ids:
        raise ValueError("receipt does not match stored assets")
    observations = []
    for asset_id in ids:
        observations.extend(EvidenceReader(connection).read_inventory(asset_id).observations)
    if len(observations) != receipt["observation_count"]:
        raise ValueError("receipt does not match observation count")
    if any(item["scope"] != receipt["scope"] or item["observed_at"] != receipt["observed_at"]
           or item["source"] != receipt["source"] for item in observations):
        raise ValueError("receipt does not match observation metadata")
    if export_data is not None:
        inventory = convert_inventory(export_data, scope=receipt["scope"])
        payloads = sorted(_canonical(item["payload"]) for item in observations)
        expected = sorted(_canonical(item) for asset in inventory["assets"] for item in asset["observations"])
        if (inventory["input_sha256"] != receipt["input_sha256"]
                or [asset["asset_id"] for asset in inventory["assets"]] != ids or payloads != expected):
            raise ValueError("retained export does not match import receipt")
    return {"schema_version": 1, "status": "consistent", "receipt": receipt,
            "receipt_sha256": row[1], "original_export_checked": export_data is not None}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--export", type=Path, help="optionally reproduce from the original saved export")
    args = parser.parse_args(argv)
    try:
        path = args.database.resolve(strict=True)
        if not path.is_file() or args.database.is_symlink():
            raise ValueError("expected a local inventory database")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            result = read_receipt(connection, export_data=_read(args.export) if args.export else None)
    except (OSError, ValueError, sqlite3.DatabaseError, UnicodeError, RecursionError, TypeError):
        print("error: inventory receipt could not be reconciled", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
