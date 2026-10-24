"""Bind retained assessments to an explicit current source-checkout model."""

import hashlib
import json
from pathlib import Path

MODEL_ID = "zero-shadow-first-assessment"
MODEL_VERSION = 1
SOURCE_FILES = (
    "engine/risk.py", "engine/remediation.py", "engine/ownership.py",
    "engine/work_queue.py", "engine/work_queue_cli.py", "engine/inventory_queue_cli.py",
    "engine/models.py", "engine/correlation/asset_graph.py",
    "engine/discovery/osquery_collector.py",
)
MAX_BINDING_BYTES = 64 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"))


def current_contract():
    root = Path(__file__).resolve().parents[1]
    return {"schema_version": 1, "model_id": MODEL_ID, "model_version": MODEL_VERSION,
            "implementation_sha256": {name: hashlib.sha256((root/name).read_bytes()).hexdigest()
                                      for name in SOURCE_FILES}}


def store_model(connection):
    contract = _canonical(current_contract())
    digest = hashlib.sha256(contract.encode("ascii")).hexdigest()
    connection.executescript("""
        CREATE TABLE inventory_assessment_model (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            contract_json TEXT NOT NULL, binding_sha256 TEXT NOT NULL);
        CREATE TRIGGER assessment_model_no_update BEFORE UPDATE ON inventory_assessment_model
        BEGIN SELECT RAISE(ABORT, 'assessment model is append-only'); END;
        CREATE TRIGGER assessment_model_no_delete BEFORE DELETE ON inventory_assessment_model
        BEGIN SELECT RAISE(ABORT, 'assessment model is append-only'); END;
    """)
    with connection:
        connection.execute("INSERT INTO inventory_assessment_model VALUES (1, ?, ?)", (contract, digest))
    return {"status": "bound_current_model", "model_id": MODEL_ID,
            "model_version": MODEL_VERSION, "binding_sha256": digest}


def read_model(connection, *, required=False):
    present = connection.execute("SELECT 1 FROM sqlite_schema WHERE type='table' "
                                 "AND name='inventory_assessment_model'").fetchone()
    if present is None:
        if required:
            raise ValueError("a retained model binding is required")
        return {"status": "legacy_unversioned", "model_id": None, "model_version": None,
                "interpretation": "Current-model replay only. No historical model binding was retained."}
    rows = connection.execute("SELECT singleton, contract_json, binding_sha256 "
                              "FROM inventory_assessment_model").fetchall()
    if len(rows) != 1 or rows[0][0] != 1:
        raise ValueError("expected one retained model binding")
    _, payload, digest = rows[0]
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_BINDING_BYTES:
        raise ValueError("invalid retained model size")
    # Canonical bytes also distinguish booleans/floats from integer schema fields.
    if payload != _canonical(current_contract()) or hashlib.sha256(payload.encode("ascii")).hexdigest() != digest:
        raise ValueError("retained model is unsupported or differs from the current implementation")
    return {"status": "bound_current_model", "model_id": MODEL_ID,
            "model_version": MODEL_VERSION, "binding_sha256": digest}
