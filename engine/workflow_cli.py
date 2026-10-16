"""Run and safely retry the local fixture evidence workflow without Airflow."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from engine.evidence_workflow import EvidenceWorkflowError
from engine.workflow_runs import run_workflow_once


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--schema", type=Path,
                        default=Path(__file__).resolve().parents[1] / "database/schema.sql")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--allowed-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = run_workflow_once(
            run_id=args.run_id, spec_path=args.spec, schema_path=args.schema,
            output_root=args.output_root, allowed_root=args.allowed_root,
        )
    except (EvidenceWorkflowError, OSError, ValueError, sqlite3.DatabaseError):
        print("error: local evidence workflow failed; review inputs, scope, and saved artifacts",
              file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
