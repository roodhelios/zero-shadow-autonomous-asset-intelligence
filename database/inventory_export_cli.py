"""Export every retained asset and its reconciled import receipt from local SQLite."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import closing
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--export", type=Path,
                        help="optionally verify against the original saved osquery export")
    parser.add_argument("--output", type=Path,
                        help="publish a new private file instead of printing to stdout")
    args = parser.parse_args(argv)
    try:
        if args.output and os.name != "posix":
            raise ValueError("private inventory publication requires POSIX")
        result = export_inventory(args.database,
                                  export_data=_read(args.export) if args.export else None)
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
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
