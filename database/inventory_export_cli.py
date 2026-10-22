"""Export every retained asset and its reconciled import receipt from local SQLite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from database.evidence_reader import EvidenceReader
from database.inventory_receipt import read_receipt
from engine.discovery.osquery_collector import _publish, _read


def export_inventory(database: Path, *, export_data: bytes | None = None) -> dict:
    """Use one read-only transaction so receipt and snapshots see the same state."""
    if database.is_symlink():
        raise ValueError("expected a local inventory database")
    path = database.resolve(strict=True)
    if not path.is_file():
        raise ValueError("expected a local inventory database")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        reconciliation = read_receipt(connection, export_data=export_data)
        reader = EvidenceReader(connection)
        assets = [reader.read_inventory(asset_id).to_dict()
                  for asset_id in reconciliation["receipt"]["asset_ids"]]
        return {
            "schema_version": 1,
            "report_type": "retained-inventory",
            "asset_count": len(assets),
            "observation_count": sum(len(asset["observations"]) for asset in assets),
            "import_reconciliation": reconciliation,
            "assets": assets,
        }


def review_summary(result: dict) -> str:
    """Summarize an export already reconstructed and reconciled by this module."""
    reconciliation = result["import_reconciliation"]
    receipt = reconciliation["receipt"]
    # Quote all supplied strings so newlines and terminal controls stay visible.
    def quote(value):
        return json.dumps(value, ensure_ascii=True)
    lines = [
        f"Retained inventory: {result['asset_count']} assets, {result['observation_count']} observations",
        f"Claimed scope: {quote(receipt['scope'])}",
        f"Observed at: {quote(receipt['observed_at'])}",
        f"Receipt: {quote(reconciliation['status'])}",
        "Original export: " + ("checked" if reconciliation["original_export_checked"] else "not checked"),
    ]
    for item in result["assets"]:
        asset = item["asset"]
        findings = len(item["findings"])
        ownership = len(item["ownership_decisions"])
        plans = len(item["remediation_plans"])
        lines.extend((
            f"Asset: {quote(asset['asset_id'])}, hostname {quote(asset['primary_hostname'])}",
            f"  Observations: {len(item['observations'])}",
            f"  Findings: {findings}" + (" (not assessed by this import)" if not findings else " (retained records)"),
            f"  Ownership decisions: {ownership}; remediation plans: {plans}",
        ))
    lines.append("Inventory review only. Missing decisions do not mean safe, assigned, or remediated.")
    lines.append("Use JSON for linked records and digests. No collector authentication or complete coverage is established.")
    return "\n".join(lines) + "\n"


def coverage_summary(result: dict) -> dict:
    """Return aggregate record coverage without asset or evidence identifiers."""
    assets = result["assets"]

    def count_with(field):
        return sum(bool(item[field]) for item in assets)

    findings = count_with("findings")
    ownership = count_with("ownership_decisions")
    remediation = count_with("remediation_plans")
    reconciliation = result["import_reconciliation"]
    return {
        "schema_version": 1,
        "report_type": "inventory-coverage-summary",
        "asset_count": result["asset_count"],
        "observation_count": result["observation_count"],
        "receipt_status": reconciliation["status"],
        "original_export_checked": reconciliation["original_export_checked"],
        "record_coverage": {
            "assets_with_findings": findings,
            "assets_without_findings": len(assets) - findings,
            "assets_with_ownership_decisions": ownership,
            "assets_without_ownership_decisions": len(assets) - ownership,
            "assets_with_remediation_plans": remediation,
            "assets_without_remediation_plans": len(assets) - remediation,
        },
        "identifiers_included": False,
        "evidence_included": False,
        "interpretation": (
            "Counts describe retained records only. Missing records do not mean an asset "
            "is safe, assigned, or remediated."
        ),
    }


def review_record(result: dict, *, reviewed_at: str, reviewer_note: str) -> dict:
    """Bind a caller-supplied review checkpoint to an exact coverage summary."""
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("reviewed-at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("reviewed-at must include a UTC offset")
    if not isinstance(reviewer_note, str) or reviewer_note != reviewer_note.strip():
        raise ValueError("reviewer-note must not have surrounding whitespace")
    if not 1 <= len(reviewer_note) <= 500 or not reviewer_note.isprintable():
        raise ValueError("reviewer-note must be 1 to 500 printable characters")

    summary = coverage_summary(result)
    normalized_time = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    review_payload = {
        "reviewed_at": normalized_time,
        "reviewer_note": reviewer_note,
        "coverage_summary": summary,
    }
    canonical = json.dumps(
        review_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return {
        "schema_version": 1,
        "report_type": "inventory-review-record",
        "reviewed_at": normalized_time,
        "reviewer_note": reviewer_note,
        "review_sha256": hashlib.sha256(canonical).hexdigest(),
        "coverage_summary": summary,
        "interpretation": (
            "The review time and note are caller-supplied metadata. The digest binds them "
            "to the included coverage summary but does not authenticate the reviewer."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--export", type=Path,
                        help="optionally verify against the original saved osquery export")
    parser.add_argument("--output", type=Path,
                        help="publish a new private file instead of printing to stdout")
    parser.add_argument("--format", choices=("json", "text", "coverage", "review"),
                        default="json",
                        help="complete JSON, analyst text, coverage, or review record")
    parser.add_argument("--reviewed-at",
                        help="caller-supplied ISO 8601 review time for review format")
    parser.add_argument("--reviewer-note",
                        help="caller-supplied bounded note for review format")
    args = parser.parse_args(argv)
    try:
        if args.output and os.name != "posix":
            raise ValueError("private inventory publication requires POSIX")
        result = export_inventory(args.database,
                                  export_data=_read(args.export) if args.export else None)
        review_fields = (args.reviewed_at, args.reviewer_note)
        if args.format == "review" and not all(review_fields):
            raise ValueError("review format requires reviewed-at and reviewer-note")
        if args.format != "review" and any(review_fields):
            raise ValueError("review metadata requires review format")
        if args.format == "text":
            rendered = review_summary(result)
        else:
            if args.format == "coverage":
                document = coverage_summary(result)
            elif args.format == "review":
                document = review_record(
                    result,
                    reviewed_at=args.reviewed_at,
                    reviewer_note=args.reviewer_note,
                )
            else:
                document = result
            rendered = json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, sqlite3.DatabaseError, UnicodeError, RecursionError, TypeError):
        print("error: inventory was not exported; check database, receipt, and new output path",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
