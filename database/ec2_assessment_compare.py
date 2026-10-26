"""Compare two reproduced EC2 review receipts for the same discovery batch."""

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from database.ec2_assessment import _canonical, _verified
from engine.discovery.osquery_collector import _publish, _read

MAX_REPORT_BYTES = 24 * 1024 * 1024


def _items(record):
    queues = record["queue_report"]["queues"]
    items = list(queues["unassigned"])
    for queue in queues["queues"]:
        items.extend(queue["items"])
    return {item["finding_id"]: item for item in items}


def compare_assessments(previous, current, *, export_data):
    """Verify both snapshots before comparing derived decisions, never raw DB rows."""
    old, old_check = _verified(previous, export_data)
    new, new_check = _verified(current, export_data)
    if (_canonical(old["discovery"]) != _canonical(new["discovery"]) or
            _canonical(old["model"]) != _canonical(new["model"])):
        raise ValueError("comparison requires the same discovery batch and model")
    if (new["as_of"] < old["as_of"] or
            datetime.fromisoformat(new["assessed_at"]) < datetime.fromisoformat(old["assessed_at"])):
        raise ValueError("current review must not precede the previous review")
    before, after = _items(old), _items(new)
    common = before.keys() & after.keys()
    if any(before[key]["asset_id"] != after[key]["asset_id"] for key in common):
        raise ValueError("finding identity moved between assets")
    changed = []
    for key in sorted(common):
        left, right = before[key], after[key]
        fields = sorted(name for name in left.keys() | right.keys() if left.get(name) != right.get(name))
        if fields:
            changed.append({"finding_id": key, "changed_fields": fields, "previous": left, "current": right})
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    omitted = [before[key] for key in sorted(before.keys() - after.keys())]
    return {"schema_version": 1, "report_type": "ec2-assessment-comparison", "source_kind": "ec2",
            "previous": {"as_of": old["as_of"], "assessed_at": old["assessed_at"], "verification": old_check},
            "current": {"as_of": new["as_of"], "assessed_at": new["assessed_at"], "verification": new_check},
            "review_inputs_changed": old["queue_report"]["input_sha256"] != new["queue_report"]["input_sha256"],
            "counts": {"added": len(added), "omitted": len(omitted), "changed": len(changed),
                       "unchanged": len(common) - len(changed)},
            "added": added, "omitted": omitted, "changes": changed,
            "interpretation": "Both independent receipts reproduce against the same original export, discovery "
                "context and exact current model. Changes describe derived decisions; changed review inputs may "
                "also leave decisions unchanged. An omitted finding is not proof of resolution. This comparison "
                "does not append reassessment history, authenticate reviewers, establish accepted ownership, "
                "prove remediation or replay historical code. Keep the detailed report private."}


def export_comparison(previous, current, output, *, export_data):
    report = compare_assessments(previous, current, export_data=export_data)
    rendered = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
    if len(rendered.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("comparison exceeds 24 MiB")
    _publish(output, rendered)
    return {"schema_version": 1, "status": "ec2_assessments_compared", **report["counts"],
            "review_inputs_changed": report["review_inputs_changed"], "original_export_checked": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private comparison JSON file")
    args = parser.parse_args(argv)
    try:
        result = export_comparison(args.previous, args.current, args.output, export_data=_read(args.export))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: EC2 reviews were not compared; check receipts, export, dates, batch and current model",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
