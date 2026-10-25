"""Retain and reproduce one EC2 assessment receipt without changing discovery evidence."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import date, datetime
from pathlib import Path

from database.assessment_model import SOURCE_FILES
from database.ec2_inventory import read_ec2, store_ec2
from database.inventory_assessment_verify import MAX_DATABASE_BYTES, _snapshot
from database.repository import _timestamp
from engine.discovery.osquery_collector import _publish, _read, _unique_fields
from engine.discovery_queue_cli import plan_discovery

MAX_RECEIPT_BYTES = 12 * 1024 * 1024
MODEL_FILES = tuple(sorted(set(SOURCE_FILES) | {
    "database/assessment_model.py", "database/ec2_assessment.py", "database/ec2_inventory.py",
    "database/evidence_reader.py", "database/repository.py", "database/schema.sql",
    "database/inventory_assessment_verify.py", "engine/discovery/aws_discovery.py",
    "engine/discovery/fixture_discovery.py", "engine/discovery_queue_cli.py"}))


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))


def current_model():
    root = Path(__file__).resolve().parents[1]
    return {"schema_version": 1, "model_id": "zero-shadow-ec2-assessment", "model_version": 1,
            "implementation_sha256": {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                                      for name in MODEL_FILES}}


def _build(database, finding_data, directory_data, *, export_data, as_of, assessed_at):
    inventory = read_ec2(database, export_data)
    timestamp = _timestamp(assessed_at, "assessed_at")
    observed = datetime.fromisoformat(inventory["import_context"]["observed_at"].replace("Z", "+00:00"))
    assessed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    if type(as_of) is not date or assessed < observed or not observed.date() <= as_of <= assessed.date():
        raise ValueError("review date and assessment time must follow discovery")
    queues = plan_discovery(database, finding_data, directory_data, source="ec2",
                            export_data=export_data, as_of=as_of)
    count = queues["queues"]["assigned_item_count"] + queues["queues"]["unassigned_item_count"]
    if count == 0:
        raise ValueError("assessment retention requires explicitly supplied findings")
    return {"schema_version": 1, "receipt_type": "ec2-first-assessment", "source_kind": "ec2",
            "model": current_model(), "as_of": as_of.isoformat(), "assessed_at": timestamp,
            "discovery": inventory, "findings_jsonl": finding_data.decode("utf-8"),
            "ownership_directory_json": directory_data.decode("utf-8"), "queue_report": queues}


def _reproduce(record, export_data):
    fields = {"schema_version", "receipt_type", "source_kind", "model", "as_of", "assessed_at",
              "discovery", "findings_jsonl", "ownership_directory_json", "queue_report"}
    if (not isinstance(record, dict) or set(record) != fields or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["receipt_type"] != "ec2-first-assessment" or record["source_kind"] != "ec2" or
            _canonical(record["model"]) != _canonical(current_model())):
        raise ValueError("unsupported assessment receipt or current model mismatch")
    as_of = date.fromisoformat(record["as_of"])
    assessed_at = datetime.fromisoformat(record["assessed_at"].replace("Z", "+00:00"))
    if as_of.isoformat() != record["as_of"] or _timestamp(assessed_at, "assessed_at") != record["assessed_at"]:
        raise ValueError("noncanonical assessment date")
    context = record["discovery"]["import_context"]
    with tempfile.TemporaryDirectory(prefix="ec2-assessment-replay-") as directory:
        root = Path(directory); source = root/"export.json"; database = root/"discovery.sqlite"
        source.write_bytes(export_data); source.chmod(0o600)
        store_ec2(source, database, scope=context["scope"], account=context["account"],
            region=context["region"], observed_at=datetime.fromisoformat(context["observed_at"].replace("Z", "+00:00")))
        rebuilt = _build(database, record["findings_jsonl"].encode("utf-8"),
            record["ownership_directory_json"].encode("utf-8"), export_data=export_data,
            as_of=as_of, assessed_at=assessed_at)
    if _canonical(record) != _canonical(rebuilt):
        raise ValueError("retained discovery, inputs or decisions did not reproduce")


def _verified(database, export_data):
    with tempfile.TemporaryDirectory(prefix="ec2-assessment-check-") as directory:
        snapshot = Path(directory)/"receipt.sqlite"; _snapshot(database, snapshot)
        with closing(sqlite3.connect(snapshot.as_uri()+"?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON"); connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            objects = connection.execute("SELECT name,type,sql FROM sqlite_schema WHERE type IN ('table','view')").fetchall()
            if (len(objects) != 1 or objects[0][0] != "ec2_assessment_record" or objects[0][1] != "table" or
                    not isinstance(objects[0][2], str) or not re.match(r"\s*CREATE\s+TABLE\b", objects[0][2], re.I)):
                raise ValueError("expected only the ordinary EC2 assessment receipt table")
            rows = connection.execute("SELECT singleton,payload_json,payload_sha256 FROM ec2_assessment_record").fetchmany(2)
            if len(rows) != 1 or rows[0][0] != 1:
                raise ValueError("expected one assessment receipt")
            _, payload, digest = rows[0]
            if (not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_RECEIPT_BYTES or
                    hashlib.sha256(payload.encode("utf-8")).hexdigest() != digest):
                raise ValueError("invalid assessment receipt payload")
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("invalid assessment database")
        record = json.loads(payload, object_pairs_hook=_unique_fields)
        if payload != _canonical(record):
            raise ValueError("noncanonical assessment receipt")
        _reproduce(record, export_data)
    binding = record["queue_report"]["inventory_binding"]
    summary = {"schema_version": 1, "status": "ec2_assessment_reproduced", "asset_count": binding["asset_count"],
        "assessed_asset_count": binding["assets_with_supplied_findings"],
        "finding_count": record["queue_report"]["queues"]["assigned_item_count"] +
                         record["queue_report"]["queues"]["unassigned_item_count"],
        "payload_sha256": digest, "model_sha256": hashlib.sha256(_canonical(record["model"]).encode()).hexdigest(),
        "original_export_checked": True,
        "interpretation": "Retained EC2 discovery, reviewed inputs and queue decisions reproduce under the "
            "exact current model-source binding. This receipt does not authenticate source/reviewer claims, "
            "freeze historical code, establish accepted ownership or perform remediation."}
    return record, summary


def verify_assessment(database, export_data):
    return _verified(database, export_data)[1]


def retain_assessment(database, finding_data, directory_data, output, *, export_data, as_of, assessed_at):
    if os.name != "posix":
        raise ValueError("private receipt storage requires POSIX")
    with tempfile.TemporaryDirectory(prefix="ec2-assessment-source-") as directory:
        snapshot = Path(directory)/"discovery.sqlite"; _snapshot(database, snapshot)
        record = _build(snapshot, finding_data, directory_data, export_data=export_data,
                        as_of=as_of, assessed_at=assessed_at)
    payload = _canonical(record)
    if len(payload.encode()) > MAX_RECEIPT_BYTES:
        raise ValueError("assessment receipt exceeds 12 MiB")
    descriptor, name = tempfile.mkstemp(prefix=".ec2-assessment-", dir=output.parent)
    os.close(descriptor); temporary = Path(name)
    try:
        with closing(sqlite3.connect(temporary)) as connection:
            connection.executescript("""
                CREATE TABLE ec2_assessment_record(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL);
                CREATE TRIGGER assessment_no_update BEFORE UPDATE ON ec2_assessment_record
                BEGIN SELECT RAISE(ABORT, 'EC2 assessment is append-only'); END;
                CREATE TRIGGER assessment_no_delete BEFORE DELETE ON ec2_assessment_record
                BEGIN SELECT RAISE(ABORT, 'EC2 assessment is append-only'); END;
            """)
            with connection:
                connection.execute("INSERT INTO ec2_assessment_record VALUES(1,?,?)",
                                   (payload, hashlib.sha256(payload.encode()).hexdigest()))
        if temporary.stat().st_size > MAX_DATABASE_BYTES:
            raise ValueError("assessment database exceeds 16 MiB")
        result = verify_assessment(temporary, export_data)
        with temporary.open("rb") as handle: os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return dict(result, status="ec2_assessment_stored")


def export_review(database, export_data, output):
    record, result = _verified(database, export_data)
    report = {"schema_version": 1, "report_type": "retained-ec2-assessment-review",
              "verification": result, "as_of": record["as_of"], "assessed_at": record["assessed_at"],
              "queue_report": record["queue_report"]}
    _publish(output, json.dumps(report, sort_keys=True, indent=2, allow_nan=False)+"\n")
    return dict(result, status="ec2_assessment_exported")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    retain = commands.add_parser("retain"); retain.add_argument("database", type=Path)
    retain.add_argument("findings", type=Path); retain.add_argument("--directory", required=True, type=Path)
    retain.add_argument("--as-of", required=True); retain.add_argument("--assessed-at", required=True)
    retain.add_argument("--export", required=True, type=Path); retain.add_argument("--output", required=True, type=Path)
    for command in ("verify", "review"):
        sub = commands.add_parser(command); sub.add_argument("database", type=Path)
        sub.add_argument("--export", required=True, type=Path)
        if command == "review": sub.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        data = _read(args.export)
        if args.command == "retain":
            result = retain_assessment(args.database, _read(args.findings), _read(args.directory), args.output,
                export_data=data, as_of=date.fromisoformat(args.as_of),
                assessed_at=datetime.fromisoformat(args.assessed_at.replace("Z", "+00:00")))
        elif args.command == "verify": result = verify_assessment(args.database, data)
        else: result = export_review(args.database, data, args.output)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: EC2 assessment workflow failed; check source, current model, reviewed inputs and new output path",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
