"""Compare a saved review checkpoint with freshly reconstructed inventory coverage."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from database.inventory_export_cli import export_inventory, review_record
from engine.discovery.osquery_collector import _read, _unique_fields

MAX_REVIEW_BYTES = 16 * 1024


def verify_review(database: Path, record_data: bytes, *, export_data: bytes | None = None) -> dict:
    """Recompute the complete checkpoint, including its digest and coverage values."""
    if len(record_data) > MAX_REVIEW_BYTES:
        raise ValueError("review record exceeds 16 KiB")
    record = json.loads(record_data.decode("utf-8"), object_pairs_hook=_unique_fields)
    if not isinstance(record, dict):
        raise ValueError("review record must be an object")
    inventory = export_inventory(database, export_data=export_data)
    expected = review_record(inventory, reviewed_at=record.get("reviewed_at"),
                             reviewer_note=record.get("reviewer_note"))

    def canonical(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          allow_nan=False, separators=(",", ":"))

    if canonical(record) != canonical(expected):
        raise ValueError("review record does not match current coverage")
    return {
        "schema_version": 1,
        "report_type": "inventory-review-verification",
        "status": "consistent",
        "review_sha256": expected["review_sha256"],
        "asset_count": inventory["asset_count"],
        "original_export_checked": expected["coverage_summary"]["original_export_checked"],
        "interpretation": (
            "Current aggregate coverage matches the saved review record. This does not "
            "authenticate the reviewer, identify the batch, or verify source claims."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("review", type=Path, help="saved inventory review JSON")
    parser.add_argument("--export", type=Path, help="original osquery export, when used for the review")
    args = parser.parse_args(argv)
    try:
        result = verify_review(args.database, _read(args.review),
                               export_data=_read(args.export) if args.export else None)
    except (OSError, ValueError, TypeError, OverflowError, sqlite3.DatabaseError,
            UnicodeError, RecursionError):
        print("error: review record did not verify against current inventory coverage", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
