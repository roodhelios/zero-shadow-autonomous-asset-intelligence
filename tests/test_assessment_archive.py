"""Archive portability and full replay without the original database or export file."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from unittest.mock import patch

from database.assessment_archive import (RUNTIME_FILES, _archive_bytes, _entry, create_archive,
                                          restore_archive, verify_archive)
from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'private POSIX archives')
class AssessmentArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        for name in ('original', 'archives', 'restored'):
            (self.root/name).mkdir(mode=0o700)
        self.source = self.root/'original/assessment.sqlite'
        self.archive = self.root/'archives/assessment.json'
        self.output = self.root/'restored/assessment.sqlite'
        self.export_path = self.root/'original/export.json'
        self.export = (ROOT/'examples/osquery-system-info-expanded.json').read_bytes()
        self.export_path.write_bytes(self.export); self.export_path.chmod(0o600)
        discovery = self.root/'original/discovery.sqlite'
        store_export(self.export_path, discovery, scope='synthetic', observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        retain_assessment(discovery, (ROOT/'examples/inventory-findings.jsonl').read_bytes(),
            (ROOT/'examples/ownership-directory.json').read_bytes(), self.source, as_of=date(2026, 10, 23),
            assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc), export_data=self.export)
        discovery.unlink(); self.before = self.source.read_bytes()

    def create(self):
        return create_archive(self.source, self.archive, export_data=self.export)

    def pin(self): return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def altered(self, mutate):
        document = json.loads(self.archive.read_bytes()); mutate(document)
        self.archive.write_text(json.dumps(document)); self.archive.chmod(0o600)
        return self.pin()

    def test_restore_after_original_database_and_export_removed(self):
        with patch('socket.socket.connect', side_effect=AssertionError('network forbidden')):
            receipt = self.create()
            original_archive = self.archive.read_bytes()
            self.source.unlink(); self.export_path.unlink()
            verified = verify_archive(self.archive, expected_sha256=receipt['archive_sha256'])
            restored = restore_archive(self.archive, self.output, expected_sha256=receipt['archive_sha256'])
        self.assertEqual(verified['status'], 'assessment_archive_verified')
        self.assertEqual(restored['status'], 'assessment_archive_restored')
        self.assertEqual((restored['asset_count'], restored['finding_count']), (2, 1))
        self.assertEqual(restored['model_status'], 'bound_current_model')
        self.assertEqual(self.output.read_bytes(), self.before)
        self.assertEqual(self.archive.read_bytes(), original_archive)
        for p in (self.output, self.archive): self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        for value in (str(self.root), 'checkout.example.test', 'cloud-platform', 'asset-'):
            self.assertNotIn(value, json.dumps(restored))

    def test_trusted_source_snapshot_is_sufficient_in_fresh_standard_library_process(self):
        receipt = self.create(); self.source.unlink(); self.export_path.unlink()
        checkout = self.root/'trusted-checkout'; checkout.mkdir(mode=0o700)
        # Copy from the trusted checkout, never extract or execute code from the archive.
        for name in RUNTIME_FILES:
            target = checkout/name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name, target)
        result = subprocess.run([sys.executable, '-S', '-m', 'database.assessment_archive', 'restore',
            str(self.archive), '--expected-sha256', receipt['archive_sha256'], '--output', str(self.output)],
            cwd=checkout, env=dict(os.environ, PYTHONPATH=''), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'assessment_archive_restored')
        self.assertEqual(self.output.read_bytes(), self.before)

    def test_wrong_pin_and_self_rehashed_changed_export_do_not_restore(self):
        self.create()
        with self.assertRaises(ValueError): restore_archive(self.archive, self.output, expected_sha256='0'*64)
        pin = self.altered(lambda d: d['entries'].update({'export.json': _entry(self.export+b'\n')}))
        with self.assertRaises(ValueError): restore_archive(self.archive, self.output, expected_sha256=pin)
        self.assertFalse(self.output.exists())

    def test_source_tampering_extra_entry_and_model_type_changes_fail_even_with_new_pin(self):
        self.create(); original = self.archive.read_bytes()
        source = 'source/'+RUNTIME_FILES[0]
        mutations = [lambda d: d['entries'].update({source: _entry(b'changed code')}),
            lambda d: d['entries'].update({'../../outside.py': _entry(b'inert')}),
            lambda d: d['entries'].pop(source), lambda d: d['model'].update(model_version=True),
            lambda d: d.update(schema_version=1.0), lambda d: d.update(extra='invalid')]
        for index, mutate in enumerate(mutations):
            self.archive.write_bytes(original); pin = self.altered(mutate)
            with self.subTest(case=index), self.assertRaises(ValueError):
                restore_archive(self.archive, self.output, expected_sha256=pin)
            self.assertFalse(self.output.exists())

    def test_malformed_entry_json_and_pins_reject(self):
        self.create(); original = self.archive.read_bytes()
        for entry in ({'bytes_b64': '!!!!', 'byte_count': 4, 'sha256': '0'*64},
                      dict(_entry(self.export), byte_count=True), dict(_entry(self.export), sha256='0'*64)):
            self.archive.write_bytes(original)
            pin = self.altered(lambda d: d['entries'].update({'export.json': entry}))
            with self.assertRaises(ValueError): verify_archive(self.archive, expected_sha256=pin)
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'[]', b'\xff'):
            self.archive.write_bytes(raw)
            with self.assertRaises((ValueError, UnicodeError)): verify_archive(self.archive, expected_sha256=self.pin())
        for pin in (None, True, 'A'*64, 'a'*63):
            with self.assertRaises(ValueError): verify_archive(self.archive, expected_sha256=pin)

    def test_tampered_decision_cannot_be_archived_or_blessed_by_rehashed_entries(self):
        self.create()
        with sqlite3.connect(self.source) as connection:
            connection.execute('DROP TRIGGER remediation_plans_no_update')
            connection.execute('UPDATE remediation_plans SET risk_score=0')
        with self.assertRaises(ValueError):
            create_archive(self.source, self.root/'archives/invalid.json', export_data=self.export)
        data = self.source.read_bytes()
        pin = self.altered(lambda d: d['entries'].update({'assessment.sqlite': _entry(data)}))
        with self.assertRaises(ValueError): restore_archive(self.archive, self.output, expected_sha256=pin)
        self.assertFalse(self.output.exists())

    def test_private_storage_modes_links_symlink_and_fifo_checks(self):
        self.create()
        self.archive.chmod(0o644)
        with self.assertRaises(ValueError): _archive_bytes(self.archive)
        self.archive.chmod(0o600)
        alias = self.archive.parent/'hardlink'; os.link(self.archive, alias)
        with self.assertRaises(ValueError): _archive_bytes(self.archive)
        alias.unlink(); alias.symlink_to(self.archive)
        with self.assertRaises(OSError): _archive_bytes(alias)
        alias.unlink(); os.mkfifo(alias)
        with self.assertRaises(ValueError): _archive_bytes(alias)
        self.archive.parent.chmod(0o750)
        with self.assertRaises(ValueError): _archive_bytes(self.archive)

    def test_changed_export_sidecar_and_output_collisions_publish_nothing(self):
        with self.assertRaises(ValueError): create_archive(self.source, self.archive, export_data=self.export+b'\n')
        self.assertFalse(self.archive.exists())
        sidecar = Path(str(self.source)+'-wal'); sidecar.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError): self.create()
        sidecar.unlink(); self.create(); saved = self.archive.read_bytes()
        with self.assertRaises(ValueError): self.create()
        self.assertEqual(self.archive.read_bytes(), saved)
        self.output.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError): restore_archive(self.archive, self.output, expected_sha256=self.pin())
        self.assertTrue(self.output.is_symlink())

    def test_bounds_and_publication_failure_clean_staging(self):
        with patch('database.assessment_archive.MAX_ARCHIVE_BYTES', 1):
            with self.assertRaises(ValueError): self.create()
        with patch('database.assessment_backup.os.link', side_effect=OSError('private detail')):
            with self.assertRaises(OSError): self.create()
        self.assertEqual(list(self.archive.parent.iterdir()), [])
        self.create()
        with patch('database.assessment_archive.MAX_ARCHIVE_BYTES', 1):
            with self.assertRaises(ValueError): _archive_bytes(self.archive)
        with patch('database.assessment_archive.MAX_SOURCE_BYTES', 1):
            with self.assertRaises(ValueError): verify_archive(self.archive, expected_sha256=self.pin())

    def test_fresh_cli_create_and_verify_with_original_export_removed(self):
        command = [sys.executable, '-m', 'database.assessment_archive']
        created = subprocess.run(command + ['create', str(self.source), '--export', str(self.export_path),
            '--output', str(self.archive)], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(created.returncode, 0, created.stderr)
        pin = json.loads(created.stdout)['archive_sha256']
        self.source.unlink(); self.export_path.unlink()
        verified = subprocess.run(command + ['verify', str(self.archive), '--expected-sha256', pin],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout)['status'], 'assessment_archive_verified')
        self.assertNotIn(str(self.root), created.stdout + verified.stdout)

    def test_cli_error_is_fixed_without_paths_or_success_output(self):
        self.create()
        result = subprocess.run([sys.executable, '-m', 'database.assessment_archive', 'restore',
            str(self.archive), '--expected-sha256', '0'*64, '--output', str(self.output)], cwd=ROOT,
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2); self.assertEqual(result.stdout, '')
        self.assertNotIn(str(self.root), result.stderr); self.assertFalse(self.output.exists())

class ArchiveWalkthroughTests(unittest.TestCase):
    def test_standalone_walkthrough(self):
        result = subprocess.run([sys.executable, '-m', 'engine.demo_assessment_archive'], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary['status'], 'assessment_archive_exercise_passed')
        self.assertTrue(summary['original_database_and_export_removed'])
        self.assertTrue(summary['exact_database_bytes_restored'])
        self.assertFalse(summary['archived_code_executed'])
        self.assertEqual(summary['negative_cases_rejected'], 2)


if __name__ == '__main__': unittest.main()
