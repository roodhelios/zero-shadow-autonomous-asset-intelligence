"""Plan explicit findings against one source-selected, reproduced discovery batch."""

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import date
from pathlib import Path

from database.ec2_inventory import read_ec2
from engine.discovery.osquery_collector import _publish, _read
from engine.inventory_queue_cli import MAX_BYTES, MAX_LINE_BYTES, MAX_RECORDS, _json, plan_inventory
from engine.ownership import OwnershipDirectory
from engine.work_queue import build_work_queue_document
from engine.work_queue_cli import queue_item


def plan_discovery(database, finding_data, directory_data, *, source, export_data, as_of):
    """Select the source explicitly; never guess a receipt type or infer findings."""
    if not isinstance(export_data, bytes) or type(as_of) is not date:
        raise ValueError("original export bytes and explicit review date required")
    if source == "osquery":
        result = plan_inventory(database, finding_data, directory_data, as_of=as_of,
                                export_data=export_data)
        return dict(result, source_kind=source, report_type="source-inventory-remediation-queues")
    if source != "ec2":
        raise ValueError("unsupported discovery source")
    if len(finding_data) > MAX_BYTES:
        raise ValueError("finding input exceeds 4 MiB")
    directory = OwnershipDirectory.from_dict(_json(directory_data))
    inventory = read_ec2(database, export_data)
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
        required = {"finding", "asset_tags", "opened_on"}
        if (not isinstance(record, dict) or not required <= record.keys() or
                set(record) - required - {"requested_due_date"}):
            raise ValueError("expected explicit finding, reviewed tags and dates")
        finding = record["finding"]
        if not isinstance(finding, dict) or finding.get("asset_id") not in asset_ids:
            raise ValueError("finding asset is absent from the selected inventory")
        item = queue_item(record, directory=directory, as_of=as_of)
        if item.plan.asset_id != finding["asset_id"]:
            raise ValueError("finding identity changed during validation")
        items.append(item)
        assessed.add(item.plan.asset_id)
    queues = build_work_queue_document(items, directory=directory, as_of=as_of)
    canonical = json.dumps(inventory, sort_keys=True, ensure_ascii=True, allow_nan=False,
                           separators=(",", ":")).encode("ascii")
    return {"schema_version": 1, "report_type": "source-inventory-remediation-queues",
            "source_kind": source,
            "inventory_binding": {"batch_sha256": hashlib.sha256(canonical).hexdigest(),
                "asset_count": len(asset_ids), "assets_with_supplied_findings": len(assessed),
                "assets_without_supplied_findings": len(asset_ids-assessed),
                "original_export_checked": True},
            "input_sha256": {"findings": hashlib.sha256(finding_data).hexdigest(),
                "ownership_directory": hashlib.sha256(directory_data).hexdigest()},
            "queues": queues,
            "interpretation": "The selected EC2 discovery batch reproduced against the original export. "
                "Only explicit findings and separately reviewed tags drive risk, ownership routing and plans. "
                "Imported tags and addresses do not establish accepted ownership or exposure. Assets without "
                "supplied findings are unassessed. No database decisions, tickets or remediation were written. "
                "Digests establish current-importer consistency, not source authenticity or historical replay."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("findings", type=Path)
    parser.add_argument("--source", required=True, choices=("osquery", "ec2"))
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--output", required=True, type=Path, help="new private JSON file")
    args = parser.parse_args(argv)
    try:
        result = plan_discovery(args.database, _read(args.findings), _read(args.directory),
            source=args.source, export_data=_read(args.export), as_of=date.fromisoformat(args.as_of))
        _publish(args.output, json.dumps(result, sort_keys=True, indent=2, allow_nan=False)+"\n")
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError,
            RecursionError, OverflowError):
        print("error: source-selected queues were not produced; check source, export and reviewed inputs",
              file=sys.stderr)
        return 2
    print(json.dumps({"status": "queues_created", "source_kind": result["source_kind"],
                      **result["inventory_binding"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
