"""Retain and reproduce one saved EC2 discovery batch in private SQLite."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime
from pathlib import Path

from database.evidence_reader import EvidenceReader
from database.inventory_assessment_verify import MAX_DATABASE_BYTES, _snapshot
from database.repository import EvidenceRepository, _timestamp
from engine.correlation import correlate_assets
from engine.discovery.aws_discovery import convert_export
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _read, _unique_fields
from engine.models import AssetObservation


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def _prepare(data, *, scope, account, region, observed_at):
    fixture = convert_export(data, scope=scope, account=account, region=region)
    assets = correlate_assets(AssetObservation.from_dict(fixture["source"], item) for item in fixture["assets"])
    if not assets:
        raise ValueError("retention requires at least one supplied instance")
    context = {"schema_version": 1, "scope": scope, "account": account, "region": region,
               "observed_at": _timestamp(observed_at, "observed_at"),
               "input_sha256": hashlib.sha256(data).hexdigest(),
               "projection_sha256": hashlib.sha256(_canonical(fixture).encode()).hexdigest(),
               "source_records": fixture["import_metadata"]["source_records"]}
    return assets, context


def _write_discovery(path, assets, context):
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(Path(__file__).with_name("schema.sql").read_text())
        EvidenceRepository(connection).store_inventory(assets, scope=context["scope"],
            observed_at=datetime.fromisoformat(context["observed_at"].replace("Z", "+00:00")))


def _snapshots(connection):
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise ValueError("invalid discovery references")
    ids = [row[0] for row in connection.execute("SELECT asset_id FROM assets ORDER BY asset_id")]
    reader = EvidenceReader(connection)
    return [reader.read_inventory(identifier).to_dict() for identifier in ids]


def _reproduce_ec2(database, export_data):
    with tempfile.TemporaryDirectory(prefix="ec2-verify-") as directory:
        root = Path(directory); retained = root/"retained.sqlite"
        _snapshot(database, retained)
        with closing(sqlite3.connect(retained.as_uri()+"?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON"); connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            objects = connection.execute("SELECT name, type, sql FROM sqlite_schema WHERE type IN ('table','view')").fetchall()
            expected_tables = {"assets", "asset_observations", "findings", "ownership_decisions",
                               "remediation_plans", "ec2_import_context"}
            if ({name for name, _, _ in objects} != expected_tables or
                any(kind == "view" or not isinstance(sql, str) or
                    not re.match(r"\s*CREATE\s+TABLE\b", sql, re.IGNORECASE) for _, kind, sql in objects)):
                raise ValueError("only ordinary evidence tables are supported")
            rows = connection.execute("SELECT singleton, context_json, context_sha256 FROM ec2_import_context").fetchall()
            if len(rows) != 1 or rows[0][0] != 1:
                raise ValueError("expected one EC2 context")
            _, payload, digest = rows[0]
            if not isinstance(payload, str) or len(payload.encode()) > MAX_INPUT_BYTES:
                raise ValueError("invalid EC2 context size")
            context = json.loads(payload, object_pairs_hook=_unique_fields)
            if (not isinstance(context, dict) or type(context.get("schema_version")) is not int or
                    context["schema_version"] != 1 or hashlib.sha256(payload.encode()).hexdigest() != digest):
                raise ValueError("invalid EC2 context")
            assets, expected = _prepare(export_data, scope=context["scope"], account=context["account"],
                region=context["region"], observed_at=datetime.fromisoformat(context["observed_at"].replace("Z", "+00:00")))
            if payload != _canonical(expected):
                raise ValueError("source bytes or context did not reproduce")
            actual = _snapshots(connection)
        rebuilt = root/"rebuilt.sqlite"
        _write_discovery(rebuilt, assets, expected)
        with closing(sqlite3.connect(rebuilt.as_uri()+"?mode=ro", uri=True)) as connection:
            reproduced = _snapshots(connection)
        if actual != reproduced:
            raise ValueError("retained discovery did not reproduce")
    result = {"schema_version": 1, "status": "ec2_inventory_reproduced", "asset_count": len(assets),
            "observation_count": len(expected["source_records"]), "input_sha256": expected["input_sha256"],
            "context_sha256": digest, "original_export_checked": True,
            "interpretation": "Discovery-only records reproduce from a separately supplied saved export. "
            "Context, row references and projected observations are checked, not collector authenticity, "
            "complete coverage, historical observation time, accepted ownership or remediation."}
    return result, expected, actual


def verify_ec2(database, export_data):
    return _reproduce_ec2(database, export_data)[0]


def read_ec2(database, export_data):
    """Return only snapshots from the closed-file copy that passed reproduction."""
    result, context, snapshots = _reproduce_ec2(database, export_data)
    return {"schema_version": 1, "report_type": "retained-ec2-inventory",
            "source_reconciliation": result, "import_context": context, "assets": snapshots}


def export_ec2(database, export_data, output):
    """Publish snapshots from the same closed-file copy that passed reproduction."""
    document = read_ec2(database, export_data)
    _publish(output, json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n")
    # Only the private file contains identities, addresses, tags and source-row references.
    return dict(document["source_reconciliation"], status="ec2_inventory_exported")


def store_ec2(source, output, *, scope, account, region, observed_at):
    if os.name != "posix":
        raise ValueError("private evidence requires POSIX")
    data = _read(source)
    assets, context = _prepare(data, scope=scope, account=account, region=region, observed_at=observed_at)
    payload = _canonical(context)
    if len(payload.encode()) > MAX_INPUT_BYTES:
        raise ValueError("EC2 context exceeds 4 MiB")
    descriptor, name = tempfile.mkstemp(prefix=".ec2-inventory-", dir=output.parent)
    os.close(descriptor); temporary = Path(name)
    try:
        _write_discovery(temporary, assets, context)
        with closing(sqlite3.connect(temporary)) as connection:
            connection.executescript("""
                CREATE TABLE ec2_import_context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    context_json TEXT NOT NULL, context_sha256 TEXT NOT NULL);
                CREATE TRIGGER ec2_context_no_update BEFORE UPDATE ON ec2_import_context
                BEGIN SELECT RAISE(ABORT, 'EC2 context is append-only'); END;
                CREATE TRIGGER ec2_context_no_delete BEFORE DELETE ON ec2_import_context
                BEGIN SELECT RAISE(ABORT, 'EC2 context is append-only'); END;
            """)
            with connection:
                connection.execute("INSERT INTO ec2_import_context VALUES(1,?,?)",
                    (payload, hashlib.sha256(payload.encode()).hexdigest()))
        if temporary.stat().st_size > MAX_DATABASE_BYTES:
            raise ValueError("EC2 database exceeds 16 MiB")
        result = verify_ec2(temporary, data)
        with temporary.open("rb") as handle: os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return dict(result, status="ec2_inventory_stored")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    store = commands.add_parser("store")
    store.add_argument("export", type=Path); store.add_argument("--output", required=True, type=Path)
    store.add_argument("--scope", required=True, choices=("synthetic", "owned", "authorized"))
    store.add_argument("--account", required=True); store.add_argument("--region", required=True)
    store.add_argument("--observed-at", required=True)
    verify = commands.add_parser("verify"); verify.add_argument("database", type=Path)
    verify.add_argument("--export", required=True, type=Path)
    export = commands.add_parser("export", help="reproduce and privately export complete discovery snapshots")
    export.add_argument("database", type=Path)
    export.add_argument("--export", required=True, type=Path)
    export.add_argument("--output", required=True, type=Path, help="new private JSON file; never stdout")
    args = parser.parse_args(argv)
    try:
        if args.command == "export":
            result = export_ec2(args.database, _read(args.export), args.output)
        elif args.command == "verify":
            result = verify_ec2(args.database, _read(args.export))
        else:
            result = store_ec2(args.export, args.output, scope=args.scope, account=args.account, region=args.region,
                observed_at=datetime.fromisoformat(args.observed_at.replace("Z", "+00:00")))
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError, RecursionError, OverflowError):
        print("error: EC2 evidence workflow failed; check closed database, original export and new output path",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
