"""Load the local SQLite schema and report its reviewable objects."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Sequence


class SchemaCheckError(ValueError):
    """Raised when the schema cannot be loaded or is missing required objects."""


REQUIRED_TABLES = {
    "assets",
    "asset_observations",
    "findings",
    "ownership_decisions",
    "remediation_plans",
}


def inspect_schema(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(source.read_text(encoding="utf-8"))
        tables = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        missing = sorted(REQUIRED_TABLES - set(tables))
        if missing:
            raise SchemaCheckError(f"schema is missing tables: {', '.join(missing)}")
        indexes = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        triggers = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'trigger' ORDER BY name"
            )
        )
        foreign_keys = sum(
            len(connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall())
            for table in tables
        )
        foreign_keys_enabled = bool(
            connection.execute("PRAGMA foreign_keys").fetchone()[0]
        )
    except (OSError, sqlite3.Error) as exc:
        raise SchemaCheckError(f"{source}: {exc}") from exc
    finally:
        connection.close()

    if not foreign_keys_enabled:
        raise SchemaCheckError("schema must enable foreign key enforcement")
    return {
        "schema_version": 1,
        "dialect": "sqlite",
        "tables": list(tables),
        "indexes": list(indexes),
        "triggers": list(triggers),
        "foreign_key_count": foreign_keys,
        "foreign_keys_enabled": foreign_keys_enabled,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the local evidence schema")
    parser.add_argument("schema", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        summary = inspect_schema(args.schema)
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, SchemaCheckError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
