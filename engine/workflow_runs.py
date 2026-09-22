"""Deterministic run directories and safe retry checks for fixture workflows."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from engine.evidence_workflow import (
    EvidenceWorkflowError,
    load_workflow_spec,
    run_workflow_to_sqlite,
)


HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FIELDS = {
    "schema_version",
    "run_id",
    "run_key",
    "status",
    "inputs",
    "artifacts",
}
INPUT_FIELDS = {
    "spec_sha256",
    "schema_sha256",
    "asset_fixture_sha256",
    "ownership_directory_sha256",
}
ARTIFACT_FIELDS = {"database_sha256", "report_sha256"}


@dataclass(frozen=True, slots=True)
class WorkflowRunResult:
    run_id: str
    run_key: str
    reused: bool
    report: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "run_key": self.run_key,
            "reused": self.reused,
            "report": dict(self.report),
        }


def _text(value: Any, field_name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceWorkflowError(f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise EvidenceWorkflowError(f"{field_name} exceeds {maximum} characters")
    return normalized


def _exact_fields(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise EvidenceWorkflowError(f"{name} is missing fields: {', '.join(missing)}")
    if extra:
        raise EvidenceWorkflowError(f"{name} has unknown fields: {', '.join(extra)}")


def _inside(path: str | Path, *, root: Path, field_name: str) -> Path:
    candidate = Path(path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise EvidenceWorkflowError(f"{field_name} must stay inside allowed_root") from exc
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(65_536), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceWorkflowError(f"cannot hash local file {path}") from exc
    return digest.hexdigest()


def _run_key(run_id: str) -> str:
    return f"run-{hashlib.sha256(run_id.encode('utf-8')).hexdigest()[:24]}"


def _input_hashes(
    *,
    spec_path: Path,
    schema_path: Path,
    allowed_root: Path,
) -> dict[str, str]:
    spec = load_workflow_spec(spec_path, allowed_root=allowed_root)
    return {
        "spec_sha256": _sha256(spec_path),
        "schema_sha256": _sha256(schema_path),
        "asset_fixture_sha256": _sha256(spec.asset_fixture),
        "ownership_directory_sha256": _sha256(spec.ownership_directory),
    }


def _json_object(path: Path, field_name: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceWorkflowError(f"cannot read {field_name}") from exc
    if not isinstance(value, Mapping):
        raise EvidenceWorkflowError(f"{field_name} must be an object")
    return value


def _validate_report(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != 1 or value.get("status") != "completed":
        raise EvidenceWorkflowError("saved workflow report is not completed version 1")
    checkpoints = value.get("checkpoints")
    if not isinstance(checkpoints, list) or len(checkpoints) != 6:
        raise EvidenceWorkflowError("saved workflow report has invalid checkpoints")


def _load_retry(
    *,
    run_id: str,
    run_key: str,
    run_directory: Path,
    inputs: Mapping[str, str],
) -> WorkflowRunResult:
    database = run_directory / "evidence.sqlite"
    report_path = run_directory / "workflow-report.json"
    manifest_path = run_directory / "run-manifest.json"
    if not all(path.is_file() for path in (database, report_path, manifest_path)):
        raise EvidenceWorkflowError("existing run directory is incomplete")

    manifest = _json_object(manifest_path, "run manifest")
    _exact_fields(manifest, MANIFEST_FIELDS, "run manifest")
    if (
        manifest["schema_version"] != 1
        or manifest["status"] != "completed"
        or manifest["run_id"] != run_id
        or manifest["run_key"] != run_key
    ):
        raise EvidenceWorkflowError("run manifest identity does not match this retry")
    saved_inputs = manifest["inputs"]
    saved_artifacts = manifest["artifacts"]
    if not isinstance(saved_inputs, Mapping) or not isinstance(saved_artifacts, Mapping):
        raise EvidenceWorkflowError("run manifest hashes must be objects")
    _exact_fields(saved_inputs, INPUT_FIELDS, "run manifest inputs")
    _exact_fields(saved_artifacts, ARTIFACT_FIELDS, "run manifest artifacts")
    if any(not HASH_PATTERN.fullmatch(value) for value in saved_inputs.values()):
        raise EvidenceWorkflowError("run manifest contains an invalid input hash")
    if any(not HASH_PATTERN.fullmatch(value) for value in saved_artifacts.values()):
        raise EvidenceWorkflowError("run manifest contains an invalid artifact hash")
    if dict(saved_inputs) != dict(inputs):
        raise EvidenceWorkflowError("retry input evidence changed for this run_id")
    if saved_artifacts["database_sha256"] != _sha256(database):
        raise EvidenceWorkflowError("saved workflow database hash does not match")
    if saved_artifacts["report_sha256"] != _sha256(report_path):
        raise EvidenceWorkflowError("saved workflow report hash does not match")

    report = _json_object(report_path, "workflow report")
    _validate_report(report)
    return WorkflowRunResult(run_id, run_key, True, report)


def run_workflow_once(
    *,
    run_id: str,
    spec_path: str | Path,
    schema_path: str | Path,
    output_root: str | Path,
    allowed_root: str | Path,
) -> WorkflowRunResult:
    """Create one run directory or verify and reuse its completed artifacts."""

    normalized_id = _text(run_id, "run_id")
    root = Path(allowed_root).resolve()
    spec = _inside(spec_path, root=root, field_name="spec_path")
    schema = _inside(schema_path, root=root, field_name="schema_path")
    outputs = _inside(output_root, root=root, field_name="output_root")
    inputs = _input_hashes(
        spec_path=spec,
        schema_path=schema,
        allowed_root=root,
    )
    key = _run_key(normalized_id)
    run_directory = outputs / key
    if run_directory.exists():
        run_directory = _inside(
            run_directory,
            root=root,
            field_name="run_directory",
        )
        return _load_retry(
            run_id=normalized_id,
            run_key=key,
            run_directory=run_directory,
            inputs=inputs,
        )

    outputs.mkdir(parents=True, exist_ok=True)
    try:
        run_directory.mkdir()
    except FileExistsError:
        run_directory = _inside(
            run_directory,
            root=root,
            field_name="run_directory",
        )
        return _load_retry(
            run_id=normalized_id,
            run_key=key,
            run_directory=run_directory,
            inputs=inputs,
        )

    database = run_directory / "evidence.sqlite"
    report_path = run_directory / "workflow-report.json"
    manifest_path = run_directory / "run-manifest.json"
    try:
        report = run_workflow_to_sqlite(
            spec_path=spec,
            schema_path=schema,
            database_path=database,
            report_path=report_path,
            allowed_root=root,
        ).to_dict()
        manifest = {
            "schema_version": 1,
            "run_id": normalized_id,
            "run_key": key,
            "status": "completed",
            "inputs": inputs,
            "artifacts": {
                "database_sha256": _sha256(database),
                "report_sha256": _sha256(report_path),
            },
        }
        temporary = run_directory / "run-manifest.json.tmp"
        temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(manifest_path)
    except Exception:
        shutil.rmtree(run_directory, ignore_errors=True)
        raise
    return WorkflowRunResult(normalized_id, key, False, report)
