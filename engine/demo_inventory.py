"""Exercise saved inventory import, assessment retention and strict replay locally."""

import json
import hashlib
import sqlite3
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from database.inventory_cli import store_export
from database.inventory_assessment_cli import retain_assessment
from database.inventory_assessment_verify import verify_assessment
from database.inventory_assessment_queue import build_queues
from database.inventory_assessment_queue_verify import verify_queues

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def exercise():
    export = EXAMPLES / "osquery-system-info-expanded.json"
    with tempfile.TemporaryDirectory(prefix="inventory-demo-") as directory:
        root = Path(directory)
        discovery, assessed = root / "discovery.sqlite", root / "assessed.sqlite"
        store_export(export, discovery, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        original = discovery.read_bytes()
        retained = retain_assessment(discovery,
            (EXAMPLES / "inventory-findings.jsonl").read_bytes(),
            (EXAMPLES / "ownership-directory.json").read_bytes(), assessed,
            as_of=date(2026, 10, 23),
            assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc),
            export_data=export.read_bytes())
        if discovery.read_bytes() != original:
            raise ValueError("discovery changed during assessment")
        discovery.unlink()
        before = assessed.read_bytes()
        verified = verify_assessment(assessed, export.read_bytes(), require_model_binding=True)
        if assessed.read_bytes() != before or verified["status"] != "assessment_reproduced":
            raise ValueError("assessment did not reproduce without mutation")
        if verified["model_binding"] != retained["model_binding"]:
            raise ValueError("model binding changed")
        queued = build_queues(assessed, export.read_bytes(),
            expected_database_sha256=hashlib.sha256(before).hexdigest(), as_of=date(2026, 11, 15))
        comparison = queued['queue_document']['priority_comparison']
        if comparison['changed_item_count'] != 1 or not comparison['changes'][0]['current_overdue']:
            raise ValueError('retained finding did not become overdue in the later review')
        if assessed.read_bytes() != before:
            raise ValueError('dated queue planning changed the retained assessment')
        queue_data = json.dumps(queued, sort_keys=True).encode()
        received = verify_queues(queue_data, assessed, export.read_bytes(),
            expected_report_sha256=hashlib.sha256(queue_data).hexdigest(),
            expected_database_sha256=hashlib.sha256(before).hexdigest(), as_of=date(2026, 11, 15))
        try:
            verify_assessment(assessed, export.read_bytes() + b"\n", require_model_binding=True)
        except ValueError:
            pass
        else:
            raise ValueError("changed original export was accepted")
    return {"status": "inventory_exercise_passed", "scope": "synthetic",
            "asset_count": verified["asset_count"], "finding_count": verified["finding_count"],
            "model_status": verified["model_binding"]["status"],
            "assessment_status": verified["status"], "changed_export": "rejected",
            "dated_queue_assigned_items": queued['queue_document']['queues']['assigned_item_count'],
            "dated_queue_changed_items": comparison['changed_item_count'],
            "recipient_queue_status": received['status'],
            "interpretation": "Fixed fixture dates and supplied finding/ownership claims. "
            "Local replay does not establish live discovery, accepted ownership or remediation."}


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print("error: local inventory exercise did not complete", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
