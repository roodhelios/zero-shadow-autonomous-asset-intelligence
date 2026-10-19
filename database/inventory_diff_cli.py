"""Compare source-claimed identities in two retained inventory imports."""

import argparse
import json
import sqlite3
import sys
from contextlib import ExitStack, closing
from datetime import datetime
from pathlib import Path

from database.evidence_reader import EvidenceReader
from database.inventory_receipt import read_receipt
from engine.discovery.osquery_collector import _publish


def _claims(connection, asset_id):
    snapshot = EvidenceReader(connection).read_inventory(asset_id)
    return {"kinds": snapshot.asset["kinds"],
            "primary_hostname": snapshot.asset["primary_hostname"],
            "observations": sorted(json.dumps(item["payload"], sort_keys=True, allow_nan=False)
                                   for item in snapshot.observations)}


def compare_inventories(base, current):
    before, after = read_receipt(base), read_receipt(current)
    left, right = before["receipt"], after["receipt"]
    if left["scope"] != right["scope"] or left["source"] != right["source"]:
        raise ValueError("inventories must have the same source and claimed scope")
    start = datetime.fromisoformat(left["observed_at"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(right["observed_at"].replace("Z", "+00:00"))
    if start.tzinfo is None or end.tzinfo is None or end < start:
        raise ValueError("current observation time must not precede the base")
    old, new = set(left["asset_ids"]), set(right["asset_ids"])
    shared = sorted(old & new)
    changed = [asset_id for asset_id in shared if _claims(base, asset_id) != _claims(current, asset_id)]
    return {"schema_version": 1, "report_type": "inventory-diff", "scope": left["scope"],
            "source": left["source"], "base_observed_at": left["observed_at"],
            "current_observed_at": right["observed_at"],
            "base_receipt_sha256": before["receipt_sha256"],
            "current_receipt_sha256": after["receipt_sha256"],
            "base_input_sha256": left["input_sha256"], "current_input_sha256": right["input_sha256"],
            "source_bytes_changed": left["input_sha256"] != right["input_sha256"],
            "added_asset_ids": sorted(new - old), "not_observed_asset_ids": sorted(old - new),
            "shared_asset_ids": shared, "changed_shared_asset_ids": changed,
            "counts": {"base_assets": len(old), "current_assets": len(new),
                       "added": len(new - old), "not_observed": len(old - new),
                       "shared": len(shared), "changed_shared": len(changed)}}


def _open(stack, path):
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or path.is_symlink():
        raise ValueError("expected a trusted local inventory database")
    connection = stack.enter_context(closing(sqlite3.connect(resolved.as_uri() + "?mode=ro", uri=True)))
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    return connection


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--output", type=Path, help="new private JSON file, never overwrite")
    args = parser.parse_args(argv)
    try:
        with ExitStack() as stack:
            result = compare_inventories(_open(stack, args.base), _open(stack, args.current))
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, TypeError, sqlite3.DatabaseError, UnicodeError, RecursionError):
        print("error: retained inventories could not be compared", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
