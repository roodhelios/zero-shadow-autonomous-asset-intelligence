"""Export one verified local asset evidence snapshot."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence
from urllib.parse import quote

from .evidence_reader import EvidenceReadError, EvidenceReader
from engine.discovery.osquery_collector import _publish


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct one asset from a local evidence database"
    )
    parser.add_argument("database", type=Path)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory", action="store_true",
                        help="allow discovery-only assets with no findings or decisions")
    args = parser.parse_args(argv)

    connection = None
    try:
        if "://" in str(args.database):
            raise EvidenceReadError("database must be a local path")
        database = args.database.resolve(strict=True)
        if not database.is_file():
            raise EvidenceReadError("database must be a local file")
        if args.output:
            output = args.output.resolve()
            if output == database:
                raise EvidenceReadError("output must differ from the database")
            if output.exists():
                raise EvidenceReadError("output already exists")
        uri = f"file:{quote(str(database), safe='/')}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        reader = EvidenceReader(connection)
        snapshot = (reader.read_inventory if args.inventory else reader.read_asset)(args.asset_id)
        rendered = json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n"
        if args.output:
            _publish(output, rendered)
        else:
            print(rendered, end="")
    except (EvidenceReadError, OSError, sqlite3.DatabaseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if connection is not None:
            connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
