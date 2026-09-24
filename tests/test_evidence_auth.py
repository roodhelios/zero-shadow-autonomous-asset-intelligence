from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from database.evidence_auth import EvidenceAuthError, create_manifest, verify_manifest
from database.evidence_auth_cli import main
from database.evidence_reader import EvidenceReader
from engine.evidence_workflow import load_workflow_spec, run_fixture_workflow


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "database" / "schema.sql"
SPEC = ROOT / "examples" / "workflow-spec.json"
KEY = b"synthetic-test-key-material-32-bytes-minimum"


def snapshot() -> dict:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SCHEMA.read_text(encoding="utf-8"))
        report = run_fixture_workflow(
            load_workflow_spec(SPEC, allowed_root=ROOT), connection=connection
        )
        return EvidenceReader(connection).read_asset(report.asset_id).to_dict()
    finally:
        connection.close()


class EvidenceAuthTests(unittest.TestCase):
    def test_manifest_authenticates_snapshot_and_is_deterministic(self) -> None:
        value = snapshot()
        manifest = create_manifest(value, KEY)
        self.assertEqual(manifest, create_manifest(value, KEY))
        self.assertEqual(manifest["algorithm"], "HMAC-SHA256")
        self.assertNotIn(KEY.decode("ascii"), json.dumps(manifest))
        verify_manifest(value, manifest, KEY)

    def test_changed_snapshot_fails_even_if_its_digest_is_recomputed(self) -> None:
        value = snapshot()
        manifest = create_manifest(value, KEY)
        changed = json.loads(json.dumps(value))
        changed["asset"]["primary_hostname"] = "changed.example.test"
        body = {key: item for key, item in changed.items() if key != "snapshot_sha256"}
        changed["snapshot_sha256"] = hashlib.sha256(
            json.dumps(body, allow_nan=False, ensure_ascii=False,
                       separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(EvidenceAuthError, "authentication failed"):
            verify_manifest(changed, manifest, KEY)

    def test_wrong_key_and_short_key_fail(self) -> None:
        manifest = create_manifest(snapshot(), KEY)
        with self.assertRaisesRegex(EvidenceAuthError, "authentication failed"):
            verify_manifest(snapshot(), manifest, b"different-test-key-material-32-bytes")
        with self.assertRaisesRegex(EvidenceAuthError, "at least 32 bytes"):
            create_manifest(snapshot(), b"short")

    def test_unknown_manifest_field_is_rejected(self) -> None:
        manifest = create_manifest(snapshot(), KEY)
        manifest["key"] = "must-not-be-stored"
        with self.assertRaisesRegex(EvidenceAuthError, "unknown fields"):
            verify_manifest(snapshot(), manifest, KEY)

    def test_cli_creates_and_verifies_a_detached_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            manifest_path = root / "snapshot.auth.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            created = StringIO()
            with redirect_stdout(created):
                create_status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--output", str(manifest_path),
                ])
            verified = StringIO()
            with redirect_stdout(verified):
                verify_status = main([
                    "verify", str(snapshot_path), str(manifest_path),
                    "--key-file", str(key_path),
                ])
            errors = StringIO()
            with redirect_stderr(errors):
                overwrite_status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--output", str(manifest_path),
                ])
            manifest_text = manifest_path.read_text(encoding="utf-8")
        self.assertEqual((create_status, verify_status, overwrite_status), (0, 0, 2))
        self.assertNotIn(KEY.decode("ascii"), manifest_text)
        self.assertIn("output already exists", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
