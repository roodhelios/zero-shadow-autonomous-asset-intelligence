"""Restore native retained assessments without the original database."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import patch

from database.assessment_backup import _closed_bytes, backup_assessment, restore_assessment
from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


@unittest.skipUnless(os.name == "posix", "private POSIX evidence storage")
class AssessmentBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("source", "backup", "restore"):
            (self.root / name).mkdir(mode=0o700)
        self.source = self.root / "source/assessment.sqlite"
        self.backup = self.root / "backup/assessment.sqlite"
        self.restored = self.root / "restore/assessment.sqlite"
        self.export_path = EXAMPLES / "osquery-system-info-expanded.json"
        self.export = self.export_path.read_bytes()
        discovery = self.root / "source/discovery.sqlite"
        store_export(self.export_path, discovery, scope="synthetic",
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        retain_assessment(discovery, (EXAMPLES / "inventory-findings.jsonl").read_bytes(),
                          (EXAMPLES / "ownership-directory.json").read_bytes(), self.source,
                          as_of=date(2026, 10, 23),
                          assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc),
                          export_data=self.export)
        discovery.unlink()
        self.before = self.source.read_bytes()
        self.digest = hashlib.sha256(self.before).hexdigest()

    def save(self):
        return backup_assessment(self.source, self.backup, export_data=self.export)

    def restore(self, **options):
        args = {"export_data": self.export, "expected_sha256": self.digest}
        args.update(options)
        return restore_assessment(self.backup, self.restored, **args)

    def cli(self, *arguments):
        return subprocess.run([sys.executable, "-m", "database.assessment_backup", *map(str, arguments)],
                              cwd=ROOT, capture_output=True, text=True, timeout=30)

    def test_exact_private_restore_after_original_removed(self):
        receipt = self.save()
        self.assertEqual(receipt["database_sha256"], self.digest)
        self.assertEqual(self.source.read_bytes(), self.before)
        self.assertEqual(self.backup.read_bytes(), self.before)
        self.source.unlink()
        restored = self.restore()
        self.assertEqual(restored["status"], "assessment_restored")
        self.assertEqual(restored["assessment_status"], "assessment_reproduced")
        self.assertEqual(restored["model_status"], "bound_current_model")
        self.assertEqual((restored["asset_count"], restored["finding_count"]), (2, 1))
        self.assertEqual(self.restored.read_bytes(), self.before)
        self.assertEqual(self.backup.read_bytes(), self.before)
        for path in (self.restored, self.backup):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_fresh_cli_backup_and_restore_emit_only_summary(self):
        saved = self.cli("backup", self.source, "--export", self.export_path, "--output", self.backup)
        self.assertEqual(saved.returncode, 0, saved.stderr)
        receipt = json.loads(saved.stdout)
        self.source.unlink()
        restored = self.cli("restore", self.backup, "--export", self.export_path,
                            "--expected-sha256", receipt["database_sha256"], "--output", self.restored)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(json.loads(restored.stdout)["status"], "assessment_restored")
        self.assertEqual(self.restored.read_bytes(), self.before)
        for output in (saved.stdout, restored.stdout):
            for sensitive in (str(self.root), "checkout.example.test", "cloud-platform", "asset-"):
                self.assertNotIn(sensitive, output)
        self.assertEqual(saved.stderr + restored.stderr, "")

    def test_missing_malformed_or_wrong_digest_cannot_restore(self):
        self.save()
        for digest in ("0" * 64, "a" * 63, "A" * 64, None, True):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.restore(expected_sha256=digest)
            self.assertFalse(self.restored.exists())
        result = self.cli("restore", self.backup, "--export", self.export_path, "--output", self.restored)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertFalse(self.restored.exists())

    def test_changed_source_export_rejects_both_operations_without_output(self):
        self.save()
        with self.assertRaises(ValueError):
            backup_assessment(self.source, self.root / "backup/other.sqlite", export_data=self.export + b"\n")
        with self.assertRaises(ValueError):
            self.restore(export_data=self.export + b"\n")
        self.assertEqual(list(self.backup.parent.iterdir()), [self.backup])
        self.assertEqual(list(self.restored.parent.iterdir()), [])

    def test_tampered_decision_is_not_blessed_by_a_matching_file_digest(self):
        with sqlite3.connect(self.source) as connection:
            connection.execute("DROP TRIGGER remediation_plans_no_update")
            connection.execute("UPDATE remediation_plans SET risk_score=0")
        altered_digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        for operation in (
                lambda: backup_assessment(self.source, self.backup, export_data=self.export),
                lambda: restore_assessment(self.source, self.restored, export_data=self.export,
                                           expected_sha256=altered_digest)):
            with self.assertRaises(ValueError):
                operation()
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.restored.exists())

    def test_missing_model_binding_and_discovery_only_database_rejected(self):
        with sqlite3.connect(self.source) as connection:
            connection.execute("DROP TABLE inventory_assessment_model")
        with self.assertRaises(ValueError):
            self.save()
        empty = self.root / "source/empty.sqlite"
        with sqlite3.connect(empty) as connection:
            connection.executescript((ROOT / "database/schema.sql").read_text())
        empty.chmod(0o600)
        with self.assertRaises((ValueError, sqlite3.DatabaseError)):
            backup_assessment(empty, self.backup, export_data=self.export)
        self.assertFalse(self.backup.exists())

    def test_changed_backup_bytes_rejected_even_when_sqlite_can_read_them(self):
        self.save()
        with self.backup.open("ab") as output:
            output.write(b"trailing bytes")
        with self.assertRaises(ValueError):
            self.restore()
        self.assertFalse(self.restored.exists())

    def test_output_collision_same_path_and_symlink_never_replace(self):
        self.save()
        with self.assertRaises(ValueError):
            self.save()
        with self.assertRaises(ValueError):
            backup_assessment(self.source, self.source, export_data=self.export)
        self.restored.symlink_to(self.root / "missing")
        with self.assertRaises(ValueError):
            self.restore()
        self.assertTrue(self.restored.is_symlink())
        self.assertEqual(self.source.read_bytes(), self.before)
        self.assertEqual(self.backup.read_bytes(), self.before)

    def test_unsafe_source_kinds_modes_links_and_sidecars_rejected(self):
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.source) + suffix)
            sidecar.symlink_to(self.root / "absent")
            with self.assertRaises(ValueError):
                self.save()
            sidecar.unlink()
        self.source.chmod(0o640)
        with self.assertRaises(ValueError):
            self.save()
        self.source.chmod(0o600)
        other = self.source.parent / "hardlink"
        os.link(self.source, other)
        with self.assertRaises(ValueError):
            self.save()
        other.unlink()
        link = self.source.parent / "symlink"
        link.symlink_to(self.source)
        fifo = self.source.parent / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path.name), self.assertRaises((ValueError, OSError)):
                _closed_bytes(path)
        self.assertFalse(self.backup.exists())

    def test_source_and_destination_parent_must_be_private_owned_directories(self):
        for parent in (self.source.parent, self.backup.parent):
            parent.chmod(0o750)
            with self.assertRaises(ValueError):
                self.save()
            parent.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.backup.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            backup_assessment(self.source, alias / "new.sqlite", export_data=self.export)
        with patch("database.assessment_backup.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(ValueError):
                self.save()
        self.assertFalse(self.backup.exists())

    def test_oversized_or_malformed_database_does_not_publish(self):
        with self.source.open("r+b") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.save()
        self.source.write_bytes(b"not SQLite")
        with self.assertRaises(sqlite3.DatabaseError):
            self.save()
        self.assertFalse(self.backup.exists())

    def test_publication_collision_race_preserves_competitor_and_cleans_stage(self):
        real_link = os.link

        def competitor(source, target):
            if Path(target) == self.backup:
                self.backup.write_bytes(b"competitor preserved")
            return real_link(source, target)

        with patch("database.assessment_backup.os.link", side_effect=competitor):
            with self.assertRaises(FileExistsError):
                self.save()
        self.assertEqual(self.backup.read_bytes(), b"competitor preserved")
        self.assertEqual(list(self.backup.parent.iterdir()), [self.backup])
        self.assertEqual(self.source.read_bytes(), self.before)

    def test_cli_failure_is_fixed_and_does_not_publish(self):
        self.save()
        result = self.cli("restore", self.backup, "--export", self.export_path,
                          "--expected-sha256", "0" * 64, "--output", self.restored)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(str(self.root), result.stderr)
        self.assertNotIn(self.digest, result.stderr)
        self.assertFalse(self.restored.exists())

    def test_standalone_walkthrough(self):
        result = subprocess.run([sys.executable, "-m", "engine.demo_assessment_backup"],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["status"], "assessment_backup_exercise_passed")
        self.assertTrue(summary["original_databases_removed"])
        self.assertTrue(summary["exact_bytes_restored"])
        self.assertEqual(summary["negative_cases_rejected"], 3)


if __name__ == "__main__":
    unittest.main()
