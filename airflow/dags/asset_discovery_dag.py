"""Manual, fixture-only Airflow workflow for local evidence persistence."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from engine.evidence_workflow import load_workflow_spec
from engine.workflow_runs import run_workflow_once


DEFAULT_ROOT = Path(__file__).resolve().parents[2]
ROOT = Path(os.getenv("ZERO_SHADOW_ROOT", DEFAULT_ROOT)).resolve()
SPEC_PATH = Path(os.getenv("ZERO_SHADOW_SPEC", ROOT / "examples/workflow-spec.json"))
SCHEMA_PATH = Path(os.getenv("ZERO_SHADOW_SCHEMA", ROOT / "database/schema.sql"))
OUTPUT_ROOT = Path(os.getenv("ZERO_SHADOW_OUTPUT_ROOT", ROOT / "output/runs"))


def preflight() -> dict[str, str]:
    spec = load_workflow_spec(SPEC_PATH, allowed_root=ROOT)
    return {
        "asset_fixture": str(spec.asset_fixture),
        "ownership_directory": str(spec.ownership_directory),
        "output_root": str(OUTPUT_ROOT.resolve()),
        "scope_boundary": "local-files-only",
    }


def persist_evidence(run_id: str | None = None) -> dict:
    selected_run_id = run_id or os.getenv("ZERO_SHADOW_RUN_ID", "manual-local")
    return run_workflow_once(
        run_id=selected_run_id,
        spec_path=SPEC_PATH,
        schema_path=SCHEMA_PATH,
        output_root=OUTPUT_ROOT,
        allowed_root=ROOT,
    ).to_dict()


try:
    from airflow import DAG
    from airflow.operators.python import PythonOperator
except (ImportError, ModuleNotFoundError):
    dag = None
else:
    with DAG(
        dag_id="zero_shadow_fixture_evidence",
        description="Persist one reviewed local fixture without external discovery",
        start_date=datetime(2026, 9, 19, tzinfo=timezone.utc),
        schedule=None,
        catchup=False,
        default_args={"retries": 1},
        tags=["zero-shadow", "fixture-only"],
    ) as dag:
        validate_task = PythonOperator(
            task_id="validate_local_scope",
            python_callable=preflight,
        )
        persist_task = PythonOperator(
            task_id="persist_evidence_bundle",
            python_callable=persist_evidence,
            op_kwargs={"run_id": "{{ run_id }}"},
        )
        validate_task >> persist_task
