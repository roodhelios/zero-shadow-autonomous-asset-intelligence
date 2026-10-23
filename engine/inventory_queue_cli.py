"""Plan review queues only for explicit findings linked to a retained inventory."""

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

from database.inventory_export_cli import export_inventory
from engine.discovery.osquery_collector import _read, _publish, _unique_fields
from engine.ownership import OwnershipDirectory
from engine.work_queue import build_work_queue_document
from engine.work_queue_cli import queue_item

MAX_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 10000
MAX_LINE_BYTES = 64 * 1024


def _json(data):
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds 4 MiB")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)
    json.dumps(value, allow_nan=False)
    return value


def plan_inventory(database, finding_data, directory_data, *, as_of, export_data=None):
    """Reconcile inventory, then validate every finding reference before returning queues."""
    if len(finding_data) > MAX_BYTES:
        raise ValueError("finding input exceeds 4 MiB")
    directory = OwnershipDirectory.from_dict(_json(directory_data))
    inventory = export_inventory(database, export_data=export_data)
    asset_ids = {item["asset"]["asset_id"] for item in inventory["assets"]}
    items, assessed = [], set()
    for line in finding_data.decode("utf-8").splitlines():
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ValueError("finding line exceeds 64 KiB")
        if not line.strip():
            continue
        if len(items) >= MAX_RECORDS:
            raise ValueError("finding input exceeds 10000 records")
        record = _json(line.encode("utf-8"))
        if not isinstance(record, dict) or not {"finding", "asset_tags", "opened_on"} <= record.keys():
            raise ValueError("expected a finding, reviewed tags, and opened_on")
        if set(record) - {"finding", "asset_tags", "opened_on", "requested_due_date"}:
            raise ValueError("unknown finding record field")
        finding = record["finding"]
        if not isinstance(finding, dict) or finding.get("asset_id") not in asset_ids:
            raise ValueError("finding asset is absent from retained inventory")
        item = queue_item(record, directory=directory, as_of=as_of)
        # Finding normalization must not silently retarget an inventory reference.
        if item.plan.asset_id != finding["asset_id"]:
            raise ValueError("finding asset identity changed during validation")
        items.append(item)
        assessed.add(finding["asset_id"])
    queues = build_work_queue_document(items, directory=directory, as_of=as_of)
    canonical = json.dumps(inventory, sort_keys=True, ensure_ascii=True,
                           allow_nan=False, separators=(",", ":")).encode("ascii")
    return {
        "schema_version": 1,
        "report_type": "inventory-remediation-queues",
        "inventory_binding": {
            "batch_sha256": hashlib.sha256(canonical).hexdigest(),
            "asset_count": len(asset_ids),
            "assets_with_supplied_findings": len(assessed),
            "assets_without_supplied_findings": len(asset_ids - assessed),
            "original_export_checked": inventory["import_reconciliation"]["original_export_checked"],
        },
        "input_sha256": {
            "findings": hashlib.sha256(finding_data).hexdigest(),
            "ownership_directory": hashlib.sha256(directory_data).hexdigest(),
        },
        "queues": queues,
        "interpretation": (
            "Plans use explicitly supplied findings and reviewed tags for retained asset IDs. "
            "Tags, severity, exposure, and other assessment inputs remain caller claims. "
            "Assets without supplied findings are unassessed, not clean. "
            "No database decisions were written, tickets sent, or remediation performed. "
            "Digests establish consistency, not source or reviewer authenticity."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("findings", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--export", type=Path, help="check inventory against original osquery export")
    parser.add_argument("--output", type=Path, help="new private JSON file; otherwise stdout")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("private inventory files require POSIX")
        result = plan_inventory(args.database, _read(args.findings), _read(args.directory),
            as_of=date.fromisoformat(args.as_of),
            export_data=_read(args.export) if args.export else None)
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: inventory queues were not produced; check inventory, finding references, and review inputs",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
