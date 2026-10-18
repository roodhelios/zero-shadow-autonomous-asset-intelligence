"""Run and safely retry the local fixture evidence workflow without Airflow."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from database.evidence_reader import EvidenceReader
from engine.evidence_workflow import EvidenceWorkflowError
from engine.workflow_runs import run_workflow_once


def review_summary(result, output_root: Path) -> str:
    """Render selected evidence without changing the stored report or manifest."""
    report = result.report
    try:
        stages = {entry["checkpoint"]: entry["evidence"] for entry in report["checkpoints"]}
        risk = stages["risk_scored"]
        ownership = stages["ownership_resolved"]
        plan = stages["remediation_planned"]
        # JSON-quote supplied strings so terminal control characters stay escaped.
        def quote(value):
            return json.dumps(value, ensure_ascii=True)
        return "\n".join((
            f"Run: {quote(result.run_id)} ({'verified retry' if result.reused else 'created'})",
            f"Asset: {quote(report['asset_id'])}",
            f"Risk: {quote(risk['score'])}/100, band {quote(risk['band'])}",
            f"Ownership: {quote(ownership['status'])}, team {quote(ownership['team_id'])}",
            f"Remediation: {quote(plan['priority'])}, due {quote(plan['due_date'])}",
            f"Evidence directory: {quote(str(output_root.resolve() / result.run_key))}",
            "Review workflow-report.json for checkpoints and evidence.sqlite for linked records.",
            "Fixture assessment only. Risk is not verified exploitability; no action was sent.",
        ))
    except (KeyError, TypeError) as exc:
        raise EvidenceWorkflowError("workflow report cannot be summarized") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("--schema", type=Path,
                        default=Path(__file__).resolve().parents[1] / "database/schema.sql")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--allowed-root", required=True, type=Path)
    parser.add_argument("--format", choices=("json", "text", "snapshot"), default="json",
                        help="run JSON (default), concise review text, or linked SQLite evidence snapshot")
    args = parser.parse_args(argv)
    try:
        result = run_workflow_once(
            run_id=args.run_id, spec_path=args.spec, schema_path=args.schema,
            output_root=args.output_root, allowed_root=args.allowed_root,
        )
        if args.format == "snapshot":
            database = args.output_root.resolve() / result.run_key / "evidence.sqlite"
            connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
            try:
                snapshot = EvidenceReader(connection).read_asset(result.report["asset_id"])
                output = json.dumps(snapshot.to_dict(), sort_keys=True)
            finally:
                connection.close()
        else:
            output = (review_summary(result, args.output_root) if args.format == "text"
                      else json.dumps(result.to_dict(), sort_keys=True))
    except (EvidenceWorkflowError, OSError, ValueError, sqlite3.DatabaseError):
        print("error: local evidence workflow failed; review inputs, scope, and saved artifacts",
              file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

