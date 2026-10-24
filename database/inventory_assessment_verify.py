"""Reproduce a retained first assessment from its inputs and original osquery export."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from datetime import date, datetime
from pathlib import Path

from database.inventory_assessment_cli import retain_assessment
from database.assessment_model import read_model
from database.inventory_cli import store_export
from database.inventory_export_cli import export_inventory
from database.repository import _timestamp
from engine.discovery.osquery_collector import _read
from engine.inventory_queue_cli import MAX_BYTES, _json

MAX_DATABASE_BYTES = 16 * 1024 * 1024


def _snapshot(source, destination):
    if os.name != "posix":
        raise ValueError("private evidence snapshots require POSIX")
    if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-journal")):
        raise ValueError("close and checkpoint the source database first")
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DATABASE_BYTES:
            raise ValueError("expected a bounded regular database")
        data = handle.read(MAX_DATABASE_BYTES + 1)
    if len(data) > MAX_DATABASE_BYTES:
        raise ValueError("database exceeds 16 MiB")
    destination.write_bytes(data)
    destination.chmod(0o600)


def verify_assessment(database, export_data, *, require_model_binding=False):
    """Use one private closed-file snapshot, then compare every reconstructed decision."""
    with tempfile.TemporaryDirectory(prefix="assessment-check-") as directory:
        root = Path(directory)
        snapshot = root / "retained.sqlite"
        _snapshot(database, snapshot)
        with closing(sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            objects = connection.execute("SELECT type, sql FROM sqlite_schema WHERE type IN ('table', 'view')").fetchall()
            if any(kind == "view" or not isinstance(sql, str) or
                   not re.match(r"\s*CREATE\s+TABLE\b", sql, re.IGNORECASE) for kind, sql in objects):
                raise ValueError("only ordinary stored evidence tables are supported")
            model_binding = read_model(connection, required=require_model_binding)
            rows = connection.execute("SELECT singleton, findings_jsonl, ownership_directory_json, "
                "as_of, assessed_at, inventory_binding_json, input_sha256_json "
                "FROM inventory_assessment_input").fetchall()
            if len(rows) != 1 or rows[0][0] != 1:
                raise ValueError("expected one first-assessment input record")
            _, findings, ownership, as_of, assessed_at, binding_text, digest_text = rows[0]
            if any(not isinstance(value, str) or len(value.encode("utf-8")) > MAX_BYTES
                   for value in rows[0][1:]):
                raise ValueError("assessment input fields exceed their contract")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("invalid evidence references")
            stored_counts = {table: connection.execute("SELECT count(*) FROM " + table).fetchone()[0]
                             for table in ("findings", "ownership_decisions", "remediation_plans")}
        binding, digests = _json(binding_text.encode()), _json(digest_text.encode())
        if not isinstance(binding, dict) or type(binding.get("original_export_checked")) is not bool:
            raise ValueError("invalid original inventory binding")
        expected_digests = {"findings": hashlib.sha256(findings.encode()).hexdigest(),
                            "ownership_directory": hashlib.sha256(ownership.encode()).hexdigest()}
        if digests != expected_digests:
            raise ValueError("retained input digest mismatch")
        review_date = date.fromisoformat(as_of)
        assessment_time = datetime.fromisoformat(assessed_at.replace("Z", "+00:00"))
        if review_date.isoformat() != as_of or _timestamp(assessment_time, "assessed_at") != assessed_at:
            raise ValueError("noncanonical assessment dates")
        retained = export_inventory(snapshot, export_data=export_data)
        receipt = retained["import_reconciliation"]["receipt"]
        source = root / "source.json"
        source.write_bytes(export_data)
        source.chmod(0o600)
        discovery = root / "discovery.sqlite"
        store_export(source, discovery, scope=receipt["scope"],
                     observed_at=datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00")))
        initial = export_inventory(discovery, export_data=export_data)
        # Reproduce the recorded binding flag, without treating it as historical proof.
        initial["import_reconciliation"]["original_export_checked"] = binding["original_export_checked"]
        canonical = json.dumps(initial, sort_keys=True, ensure_ascii=True, allow_nan=False,
                               separators=(",", ":")).encode("ascii")
        rebuilt = root / "rebuilt.sqlite"
        result = retain_assessment(discovery, findings.encode(), ownership.encode(), rebuilt,
            as_of=review_date, assessed_at=assessment_time, export_data=export_data)
        expected_binding = {"batch_sha256": hashlib.sha256(canonical).hexdigest(),
            "asset_count": result["inventory_asset_count"],
            "assets_with_supplied_findings": result["assessed_asset_count"],
            "assets_without_supplied_findings": result["inventory_asset_count"]-result["assessed_asset_count"],
            "original_export_checked": binding["original_export_checked"]}
        if binding != expected_binding:
            raise ValueError("inventory binding did not reproduce")
        reproduced = export_inventory(rebuilt, export_data=export_data)
        if retained != reproduced:
            raise ValueError("retained finding, ownership or plan did not reproduce")
        if any(count != result["finding_count"] for count in stored_counts.values()):
            raise ValueError("unexpected decision record count")
    return {"schema_version": 1, "status": "assessment_reproduced",
            "model_binding": model_binding,
            "asset_count": result["inventory_asset_count"], "finding_count": result["finding_count"],
            "original_export_checked": True, "input_sha256": expected_digests,
            "interpretation": "Stored findings, ownership decisions and plans reproduce from retained "
            "inputs and the separately supplied osquery export using the current model. This does not "
            "authenticate a reviewer, source claims, historical validation time or accepted ownership, "
            "and does not establish remediation."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--require-model-binding", action="store_true",
                        help="reject legacy assessments without an explicit retained model")
    args = parser.parse_args(argv)
    try:
        result = verify_assessment(args.database, _read(args.export),
                                   require_model_binding=args.require_model_binding)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: retained assessment did not reproduce; check closed database and original export",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
