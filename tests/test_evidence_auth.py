from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
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
    def test_keyring_allows_active_create_and_retired_verify_only(self) -> None:
        value = snapshot()
        active = {
            "schema_version": 1,
            "keys": [{"key_id": "snapshot-key-2026-09", "state": "active",
                      "activate_at": "2026-09-01T00:00:00Z",
                      "verify_until": "2026-10-01T00:00:00Z"}],
        }
        manifest = create_manifest(
            value, KEY, key_id="snapshot-key-2026-09", keyring=active,
            at="2026-09-29T12:00:00Z",
        )
        retired = json.loads(json.dumps(active))
        retired["keys"][0]["state"] = "retired"
        verify_manifest(
            value, manifest, KEY, expected_key_id="snapshot-key-2026-09",
            keyring=retired, at="2026-09-29T12:00:00Z",
        )
        with self.assertRaisesRegex(EvidenceAuthError, "only an active key"):
            create_manifest(
                value, KEY, key_id="snapshot-key-2026-09", keyring=retired,
                at="2026-09-29T12:00:00Z",
            )

    def test_keyring_expiry_unknown_key_and_missing_time_fail_closed(self) -> None:
        value = snapshot()
        ring = {"schema_version": 1, "keys": [{
            "key_id": "snapshot-key-2026-09", "state": "retired",
            "activate_at": "2026-09-01T00:00:00Z",
            "verify_until": "2026-09-15T00:00:00Z",
        }]}
        for key_id, at, message in (
            ("snapshot-key-2026-09", "2026-09-16T00:00:00Z", "outside its validity"),
            ("snapshot-key-2026-10", "2026-09-10T00:00:00Z", "not in the keyring"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(EvidenceAuthError, message):
                verify_manifest(
                    value, {"schema_version": 2, "algorithm": "HMAC-SHA256",
                            "key_id": key_id, "asset_id": "asset", "snapshot_sha256": "0" * 64,
                            "hmac_sha256": "0" * 64}, KEY, expected_key_id=key_id,
                    keyring=ring, at=at,
                )
        with self.assertRaisesRegex(EvidenceAuthError, "requires an operation and timestamp"):
            create_manifest(value, KEY, key_id="snapshot-key-2026-09", keyring=ring)

    def test_manifest_authenticates_snapshot_and_is_deterministic(self) -> None:
        value = snapshot()
        manifest = create_manifest(value, KEY, key_id="snapshot-key-2026-09")
        self.assertEqual(manifest, create_manifest(value, KEY, key_id="snapshot-key-2026-09"))
        self.assertEqual(manifest["algorithm"], "HMAC-SHA256")
        self.assertNotIn(KEY.decode("ascii"), json.dumps(manifest))
        verify_manifest(value, manifest, KEY, expected_key_id="snapshot-key-2026-09")

    def test_changed_snapshot_fails_even_if_its_digest_is_recomputed(self) -> None:
        value = snapshot()
        manifest = create_manifest(value, KEY, key_id="snapshot-key-2026-09")
        changed = json.loads(json.dumps(value))
        changed["asset"]["primary_hostname"] = "changed.example.test"
        body = {key: item for key, item in changed.items() if key != "snapshot_sha256"}
        changed["snapshot_sha256"] = hashlib.sha256(
            json.dumps(body, allow_nan=False, ensure_ascii=False,
                       separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(EvidenceAuthError, "authentication failed"):
            verify_manifest(changed, manifest, KEY, expected_key_id="snapshot-key-2026-09")

    def test_wrong_key_and_short_key_fail(self) -> None:
        manifest = create_manifest(snapshot(), KEY, key_id="snapshot-key-2026-09")
        with self.assertRaisesRegex(EvidenceAuthError, "authentication failed"):
            verify_manifest(snapshot(), manifest, b"different-test-key-material-32-bytes", expected_key_id="snapshot-key-2026-09")
        with self.assertRaisesRegex(EvidenceAuthError, "at least 32 bytes"):
            create_manifest(snapshot(), b"short", key_id="snapshot-key-2026-09")
        with self.assertRaisesRegex(EvidenceAuthError, "selected key"):
            verify_manifest(snapshot(), manifest, KEY, expected_key_id="snapshot-key-2026-10")
        with self.assertRaisesRegex(EvidenceAuthError, "lowercase identifier"):
            create_manifest(snapshot(), KEY, key_id="INVALID KEY")

    def test_unknown_manifest_field_is_rejected(self) -> None:
        manifest = create_manifest(snapshot(), KEY, key_id="snapshot-key-2026-09")
        manifest["key"] = "must-not-be-stored"
        with self.assertRaisesRegex(EvidenceAuthError, "unknown fields"):
            verify_manifest(snapshot(), manifest, KEY, expected_key_id="snapshot-key-2026-09")

    def test_cli_creates_and_verifies_a_detached_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            manifest_path = root / "snapshot.auth.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)
            created = StringIO()
            with redirect_stdout(created):
                create_status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                    "--output", str(manifest_path),
                ])
            verified = StringIO()
            with redirect_stdout(verified):
                verify_status = main([
                    "verify", str(snapshot_path), str(manifest_path),
                    "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                ])
            errors = StringIO()
            with redirect_stderr(errors):
                overwrite_status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                    "--output", str(manifest_path),
                ])
            manifest_text = manifest_path.read_text(encoding="utf-8")
        self.assertEqual((create_status, verify_status, overwrite_status), (0, 0, 2))
        self.assertNotIn(KEY.decode("ascii"), manifest_text)
        self.assertIn("output already exists", errors.getvalue())

    def test_cli_removes_its_partial_manifest_after_flush_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            manifest_path = root / "snapshot.auth.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)
            errors = StringIO()
            with patch(
                "database.evidence_auth_cli.os.fsync",
                side_effect=OSError("synthetic sync failure"),
            ), redirect_stderr(errors):
                status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--key-id", "snapshot-key-2026-09", "--output", str(manifest_path),
                ])
            manifest_exists = manifest_path.exists()

        self.assertEqual(status, 2)
        self.assertFalse(manifest_exists)
        self.assertIn("synthetic sync failure", errors.getvalue())

    def test_cli_enforces_keyring_and_allows_retired_key_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            ring_path = root / "keyring.json"
            manifest_path = root / "snapshot.auth.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)
            ring = {"schema_version": 1, "keys": [{
                "key_id": "snapshot-key-2026-09", "state": "active",
                "activate_at": "2026-09-01T00:00:00Z",
                "verify_until": "2030-01-01T00:00:00Z",
            }]}
            ring_path.write_text(json.dumps(ring), encoding="utf-8")
            with redirect_stdout(StringIO()):
                created = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--key-id", "snapshot-key-2026-09", "--keyring", str(ring_path),
                    "--output", str(manifest_path),
                ])
            ring["keys"][0]["state"] = "retired"
            ring_path.write_text(json.dumps(ring), encoding="utf-8")
            with redirect_stdout(StringIO()):
                verified = main([
                    "verify", str(snapshot_path), str(manifest_path),
                    "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                    "--keyring", str(ring_path),
                ])
            with redirect_stderr(StringIO()):
                rejected = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--key-id", "snapshot-key-2026-09", "--keyring", str(ring_path),
                    "--output", str(root / "second-manifest.json"),
                ])
        self.assertEqual((created, verified, rejected), (0, 0, 2))

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_cli_rejects_group_or_world_readable_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            key_path.chmod(0o640)
            errors = StringIO()
            with redirect_stderr(errors):
                status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                    "--output", str(root / "manifest.json"),
                ])
        self.assertEqual(status, 2)
        self.assertIn("permissions must exclude group and other", errors.getvalue())

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_cli_rejects_group_or_world_writable_keyring(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            key_path = root / "key.bin"
            ring_path = root / "keyring.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)
            ring_path.write_text(json.dumps({"schema_version": 1, "keys": []}), encoding="utf-8")
            ring_path.chmod(0o666)
            errors = StringIO()
            with redirect_stderr(errors):
                status = main([
                    "create", str(snapshot_path), "--key-file", str(key_path),
                    "--key-id", "snapshot-key-2026-09", "--keyring", str(ring_path),
                    "--output", str(root / "manifest.json"),
                ])
        self.assertEqual(status, 2)
        self.assertIn("keyring permissions must exclude group and other write access", errors.getvalue())

    def test_cli_rejects_duplicate_keyring_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ring_path = root / "keyring.json"
            ring_path.write_text('{"schema_version":1,"schema_version":1,"keys":[]}', encoding="utf-8")
            if os.name == "posix":
                ring_path.chmod(0o600)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path = root / "key.bin"
            key_path.write_bytes(b"x" * 32)
            if os.name == "posix":
                key_path.chmod(0o600)
            errors = StringIO()
            with redirect_stderr(errors):
                status = main([
                    "verify", str(snapshot_path), str(root / "manifest.json"),
                    "--key-file", str(key_path), "--key-id", "snapshot-key-2026-09",
                    "--keyring", str(ring_path),
                ])
        self.assertEqual(status, 2)
        self.assertIn("keyring contains duplicate JSON fields", errors.getvalue())

    def test_cli_does_not_replace_concurrently_created_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot_path = root / "snapshot.json"
            snapshot_path.write_text(json.dumps(snapshot()), encoding="utf-8")
            key_path = root / "key.bin"
            key_path.write_bytes(KEY)
            key_path.chmod(0o600)
            output = root / "manifest.json"
            def competing_writer(*args, **kwargs):
                output.write_text("retained evidence", encoding="utf-8")
                return {"asset_id": "synthetic"}
            with patch("database.evidence_auth_cli.create_manifest", side_effect=competing_writer):
                with redirect_stderr(StringIO()):
                    result = main(["create", str(snapshot_path), "--key-file", str(key_path),
                                   "--key-id", "test-key", "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertEqual(output.read_text(), "retained evidence")


if __name__ == "__main__":
    unittest.main()
