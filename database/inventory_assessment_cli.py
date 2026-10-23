"""Retain a first reviewed assessment in a new private inventory database."""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from datetime import date, datetime
from pathlib import Path

from database.evidence_reader import EvidenceReader
from database.inventory_export_cli import export_inventory
from database.inventory_receipt import store_receipt
from database.repository import EvidenceBundle, EvidenceRepository, _timestamp
from engine.correlation import correlate_assets
from engine.discovery.osquery_collector import _read
from engine.inventory_queue_cli import _json, plan_inventory
from engine.models import AssetObservation
from engine.ownership import OwnershipDirectory
from engine.risk import FindingEvidence
from engine.work_queue_cli import queue_item


def retain_assessment(database, finding_data, directory_data, output, *, as_of,
                      assessed_at, export_data=None):
    """Reconstruct discovery, validate all inputs, append all decisions, then publish."""
    if os.name != "posix":
        raise ValueError("private evidence storage requires POSIX")
    assessment_time = _timestamp(assessed_at, "assessed_at")
    original = export_inventory(database, export_data=export_data)
    if any(item[field] for item in original["assets"]
           for field in ("findings", "ownership_decisions", "remediation_plans")):
        raise ValueError("only a first assessment of discovery-only inventory is supported")
    receipt = original["import_reconciliation"]["receipt"]
    observed_at = datetime.fromisoformat(receipt["observed_at"].replace("Z", "+00:00"))
    if assessed_at < observed_at:
        raise ValueError("assessment cannot precede inventory observation")
    assets = correlate_assets(AssetObservation.from_dict(observation["source"], observation["payload"])
        for item in original["assets"] for observation in item["observations"])
    by_id = {asset.asset_id: asset for asset in assets}
    descriptor, temporary = tempfile.mkstemp(prefix=".assessment-", dir=output.parent)
    os.close(descriptor)
    temporary = Path(temporary)
    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.executescript(Path(__file__).with_name("schema.sql").read_text())
            repository = EvidenceRepository(connection)
            repository.store_inventory(assets, scope=receipt["scope"], observed_at=observed_at)
            store_receipt(connection, receipt)
            # Reject any reconstruction that would change the retained discovery batch.
            reconstructed = export_inventory(temporary, export_data=export_data)
            if reconstructed != original:
                raise ValueError("inventory could not be reconstructed exactly")
            report = plan_inventory(temporary, finding_data, directory_data,
                                    as_of=as_of, export_data=export_data)
            directory = OwnershipDirectory.from_dict(_json(directory_data))
            bundles = []
            for line in finding_data.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                record = _json(line.encode("utf-8"))
                finding = FindingEvidence.from_dict(record["finding"])
                item = queue_item(record, directory=directory, as_of=as_of)
                identity = hashlib.sha256(finding.finding_id.encode("utf-8")).hexdigest()
                bundles.append(EvidenceBundle(asset=by_id[finding.asset_id], finding=finding,
                    ownership=item.ownership, plan=item.plan, scope=receipt["scope"],
                    observed_at=observed_at, decision_id="assessment-owner-" + identity,
                    decided_at=assessed_at, plan_id="assessment-plan-" + identity,
                    plan_version=1, created_at=assessed_at))
            if not bundles:
                raise ValueError("retention requires at least one explicitly supplied finding")
            connection.executescript("""
                CREATE TABLE inventory_assessment_input (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    findings_jsonl TEXT NOT NULL, ownership_directory_json TEXT NOT NULL,
                    as_of TEXT NOT NULL, assessed_at TEXT NOT NULL,
                    inventory_binding_json TEXT NOT NULL, input_sha256_json TEXT NOT NULL);
                CREATE TRIGGER assessment_input_no_update BEFORE UPDATE ON inventory_assessment_input
                BEGIN SELECT RAISE(ABORT, 'assessment input is append-only'); END;
                CREATE TRIGGER assessment_input_no_delete BEFORE DELETE ON inventory_assessment_input
                BEGIN SELECT RAISE(ABORT, 'assessment input is append-only'); END;
            """)
            repository.store_assessments(tuple(bundles))
            with connection:
                connection.execute("INSERT INTO inventory_assessment_input VALUES (1, ?, ?, ?, ?, ?, ?)",
                    (finding_data.decode("utf-8"), directory_data.decode("utf-8"), as_of.isoformat(),
                     assessment_time, json.dumps(report["inventory_binding"], sort_keys=True),
                     json.dumps(report["input_sha256"], sort_keys=True)))
            for asset_id in {bundle.asset.asset_id for bundle in bundles}:
                EvidenceReader(connection).read_asset(asset_id)
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("retained decisions have invalid references")
        finally:
            connection.close()
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"schema_version": 1, "status": "assessment_stored", "finding_count": len(bundles),
            "assessed_asset_count": len({bundle.asset.asset_id for bundle in bundles}),
            "inventory_asset_count": len(assets), "input_sha256": report["input_sha256"],
            "interpretation": "A new database retains supplied assessment inputs and linked decisions. "
            "The original inventory was not changed. Tags, finding facts and times remain caller claims. "
            "No accepted ownership, live exploitability, source authenticity or remediation is established."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("findings", type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--assessed-at", required=True)
    parser.add_argument("--export", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = retain_assessment(args.database, _read(args.findings), _read(args.directory), args.output,
            as_of=date.fromisoformat(args.as_of),
            assessed_at=datetime.fromisoformat(args.assessed_at.replace("Z", "+00:00")),
            export_data=_read(args.export) if args.export else None)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: assessment was not retained; check inventory, supplied findings, dates and new output path",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
