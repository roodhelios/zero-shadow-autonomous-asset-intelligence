"""Retain a bounded same-model EC2 review history in new private SQLite files."""

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
from datetime import datetime
from pathlib import Path

from database.ec2_assessment import _canonical, _reproduce, _verified, MAX_RECEIPT_BYTES
from database.ec2_assessment_compare import _items
from database.inventory_assessment_verify import _snapshot, MAX_DATABASE_BYTES
from engine.discovery.osquery_collector import _read, _unique_fields

MAX_REVIEWS = 32
MAX_DECISIONS = 20000
MAX_TOTAL_RECEIPT_BYTES = 12 * 1024 * 1024


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _head(sequence, previous, receipt_digest):
    return _sha(_canonical({"schema_version": 1, "sequence": sequence,
                            "previous_sha256": previous, "receipt_sha256": receipt_digest}))


def _check_digest(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("expected a lowercase SHA-256 head")


def _validate(records, export_data):
    if not 1 <= len(records) <= MAX_REVIEWS:
        raise ValueError("history requires 1 to 32 reviews")
    total = sum(len(_canonical(record).encode("utf-8")) for record in records)
    if total > MAX_TOTAL_RECEIPT_BYTES:
        raise ValueError("combined review payload exceeds 12 MiB")
    seen_receipts, identities, decisions = set(), {}, []
    previous = None
    for sequence, record in enumerate(records, 1):
        payload = _canonical(record)
        if len(payload.encode("utf-8")) > MAX_RECEIPT_BYTES or _sha(payload) in seen_receipts:
            raise ValueError("oversized or duplicate review")
        _reproduce(record, export_data)
        if previous is not None:
            if (_canonical(record["discovery"]) != _canonical(previous["discovery"]) or
                    _canonical(record["model"]) != _canonical(previous["model"])):
                raise ValueError("history requires the same discovery batch and model")
            if (record["as_of"] < previous["as_of"] or
                    datetime.fromisoformat(record["assessed_at"]) < datetime.fromisoformat(previous["assessed_at"])):
                raise ValueError("review must not precede its predecessor")
        for finding_id, item in sorted(_items(record).items()):
            asset_id = item["asset_id"]
            if finding_id in identities and identities[finding_id] != asset_id:
                raise ValueError("finding identity moved between assets")
            identities[finding_id] = asset_id
            decisions.append((sequence, finding_id, asset_id, _canonical(item)))
            if len(decisions) > MAX_DECISIONS:
                raise ValueError("history exceeds 20000 decision rows")
        seen_receipts.add(_sha(payload))
        previous = record
    return decisions


def _private(path, *, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    mode = 0o700 if directory else 0o600
    if os.name != "posix" or not kind(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
        raise ValueError("expected owned private history storage")


def _load(database, export_data, *, expected_head=None):
    database = Path(database)
    _private(database)
    with tempfile.TemporaryDirectory(prefix="ec2-history-check-") as directory:
        snapshot = Path(directory)/"history.sqlite"
        _snapshot(database, snapshot)
        with closing(sqlite3.connect(snapshot.as_uri()+"?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN")
            if connection.execute("PRAGMA user_version").fetchone() != (1,):
                raise ValueError("unsupported history version")
            objects = connection.execute("SELECT name,type,sql FROM sqlite_schema WHERE type IN ('table','view')").fetchall()
            if ({name for name, _, _ in objects} != {"reviews", "decisions"} or len(objects) != 2 or
                    any(kind != "table" or not re.match(r"\s*CREATE\s+TABLE\b", sql or "", re.I)
                        for _, kind, sql in objects)):
                raise ValueError("expected ordinary history tables")
            rows = connection.execute("SELECT sequence,previous_sha256,receipt_json,receipt_sha256,node_sha256 "
                                      "FROM reviews ORDER BY sequence").fetchmany(MAX_REVIEWS+1)
            normalized = connection.execute("SELECT sequence,finding_id,asset_id,decision_json FROM decisions "
                                            "ORDER BY sequence,finding_id").fetchmany(MAX_DECISIONS+1)
            if (connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)] or
                    connection.execute("PRAGMA foreign_key_check").fetchall()):
                raise ValueError("invalid history database")
    if not 1 <= len(rows) <= MAX_REVIEWS or len(normalized) > MAX_DECISIONS:
        raise ValueError("history row limit exceeded")
    records, previous, total = [], None, 0
    for sequence, (index, predecessor, payload, digest, node) in enumerate(rows, 1):
        if not isinstance(payload, str):
            raise ValueError("invalid review payload")
        total += len(payload.encode("utf-8"))
        if total > MAX_TOTAL_RECEIPT_BYTES or len(payload.encode("utf-8")) > MAX_RECEIPT_BYTES:
            raise ValueError("review payload limit exceeded")
        if (type(index) is not int or index != sequence or predecessor != previous or
                digest != _sha(payload) or node != _head(index, predecessor, digest)):
            raise ValueError("invalid review predecessor or digest")
        record = json.loads(payload, object_pairs_hook=_unique_fields)
        if payload != _canonical(record):
            raise ValueError("noncanonical review payload")
        records.append(record)
        previous = node
    if expected_head is not None:
        _check_digest(expected_head)
        if previous != expected_head:
            raise ValueError("history head does not match the expected predecessor")
    decisions = _validate(records, export_data)
    if _canonical(normalized) != _canonical(decisions):
        raise ValueError("normalized decisions did not reproduce")
    return records, {"schema_version": 1, "status": "ec2_review_history_reproduced",
                     "review_count": len(records), "decision_count": len(decisions), "head_sha256": previous,
                     "original_export_checked": True, "expected_head_checked": expected_head is not None}


def verify_history(database, *, export_data, expected_head=None):
    return _load(database, export_data, expected_head=expected_head)[1]


def retain_history(receipt, output, *, export_data, history=None, expected_head=None):
    """Start or extend an immutable history artifact, never update a supplied database."""
    output = Path(output)
    _private(output.parent, directory=True)
    if history is None:
        if expected_head is not None:
            raise ValueError("a new history has no predecessor")
        records = []
    else:
        _check_digest(expected_head)
        records, _ = _load(history, export_data, expected_head=expected_head)
    record, _ = _verified(receipt, export_data)
    records.append(record)
    decisions = _validate(records, export_data)
    descriptor, name = tempfile.mkstemp(prefix=".ec2-history-", dir=output.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        with closing(sqlite3.connect(temporary)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.executescript("""
                PRAGMA user_version=1;
                CREATE TABLE reviews(sequence INTEGER PRIMARY KEY, previous_sha256 TEXT,
                    receipt_json TEXT NOT NULL, receipt_sha256 TEXT NOT NULL UNIQUE, node_sha256 TEXT NOT NULL UNIQUE);
                CREATE TABLE decisions(sequence INTEGER NOT NULL REFERENCES reviews(sequence), finding_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL, decision_json TEXT NOT NULL, PRIMARY KEY(sequence,finding_id));
                CREATE TRIGGER reviews_no_update BEFORE UPDATE ON reviews BEGIN SELECT RAISE(ABORT,'immutable history'); END;
                CREATE TRIGGER reviews_no_delete BEFORE DELETE ON reviews BEGIN SELECT RAISE(ABORT,'immutable history'); END;
                CREATE TRIGGER decisions_no_update BEFORE UPDATE ON decisions BEGIN SELECT RAISE(ABORT,'immutable history'); END;
                CREATE TRIGGER decisions_no_delete BEFORE DELETE ON decisions BEGIN SELECT RAISE(ABORT,'immutable history'); END;
            """)
            previous = None
            with connection:
                for sequence, item in enumerate(records, 1):
                    payload = _canonical(item); digest = _sha(payload); node = _head(sequence, previous, digest)
                    connection.execute("INSERT INTO reviews VALUES(?,?,?,?,?)", (sequence, previous, payload, digest, node))
                    previous = node
                connection.executemany("INSERT INTO decisions VALUES(?,?,?,?)", decisions)
        if temporary.stat().st_size > MAX_DATABASE_BYTES:
            raise ValueError("history database exceeds 16 MiB")
        result = verify_history(temporary, export_data=export_data, expected_head=previous)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return dict(result, status="ec2_review_history_stored", expected_head_checked=history is not None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("start", "append", "verify"):
        sub = commands.add_parser(command)
        if command in ("append", "verify"):
            sub.add_argument("history", type=Path)
        if command in ("start", "append"):
            sub.add_argument("receipt", type=Path)
            sub.add_argument("--output", required=True, type=Path, help="new SQLite file in an owned 0700 directory")
        sub.add_argument("--export", required=True, type=Path)
        if command in ("append", "verify"):
            sub.add_argument("--expected-head", required=command == "append")
    args = parser.parse_args(argv)
    try:
        export = _read(args.export)
        if args.command == "verify":
            result = verify_history(args.history, export_data=export, expected_head=args.expected_head)
        else:
            result = retain_history(args.receipt, args.output, export_data=export,
                history=getattr(args, "history", None), expected_head=getattr(args, "expected_head", None))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: EC2 history operation failed; check private files, original export, head and current model",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
