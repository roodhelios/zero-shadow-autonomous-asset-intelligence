"""Closed native SQLite history copies retain exact bytes and require full replay."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database.ec2_history_backup import backup_history, main, restore_history
from database.ec2_review_history import verify_history
from engine.demo_ec2_history_backup import exercise, prepare_history


@unittest.skipUnless(os.name == 'posix', 'private copies require POSIX')
class EC2HistoryBackupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.history, self.export, self.head = prepare_history(self.root)
        self.original = self.history.read_bytes()
        self.backup, self.restored = self.root/'backup.sqlite', self.root/'restored.sqlite'

    def backup_options(self):
        return dict(export_data=self.export, expected_head=self.head)

    def store(self):
        return backup_history(self.history, self.backup, **self.backup_options())

    def restore_options(self, **overrides):
        return dict(export_data=self.export, expected_head=self.head,
                    expected_sha256=hashlib.sha256(self.original).hexdigest()) | overrides

    def test_exact_bytes_restore_both_reviews_without_original_history(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            stored = self.store(); self.history.unlink()
            result = restore_history(self.backup, self.restored, **self.restore_options())
        self.assertEqual((result['review_count'], result['decision_count']), (2, 2))
        self.assertTrue(result['expected_head_checked'])
        self.assertEqual(stored['database_sha256'], result['database_sha256'])
        self.assertEqual(self.restored.read_bytes(), self.original)
        self.assertEqual(self.backup.read_bytes(), self.original)
        self.assertEqual(self.restored.stat().st_mode & 0o777, 0o600)

    def test_wrong_head_export_or_database_pin_publishes_nothing(self):
        self.store()
        for override in ({'expected_head': '0'*64}, {'export_data': self.export+b'\n'},
                         {'expected_sha256': '0'*64}):
            with self.assertRaises(ValueError):
                restore_history(self.backup, self.restored, **self.restore_options(**override))
            self.assertFalse(self.restored.exists())

    def test_bad_or_missing_pins_fail_before_reading_database(self):
        for override in ({'expected_head': None}, {'expected_head': 'bad'},
                         {'expected_sha256': None}, {'expected_sha256': 'A'*64}):
            with patch('database.ec2_history_backup._closed_bytes', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError):
                    restore_history(self.history, self.restored, **self.restore_options(**override))

    def test_changed_model_blocks_backup_and_restore(self):
        self.store()
        with patch('database.ec2_assessment.current_model', return_value={}):
            with self.assertRaises(ValueError):
                backup_history(self.history, self.root/'other.sqlite', **self.backup_options())
            with self.assertRaises(ValueError):
                restore_history(self.backup, self.restored, **self.restore_options())
        self.assertFalse(self.restored.exists())

    def test_corrupt_decisions_do_not_pass_with_a_matching_raw_file_pin(self):
        self.store()
        with sqlite3.connect(self.backup) as connection:
            connection.execute('DROP TRIGGER decisions_no_update')
            connection.execute("UPDATE decisions SET decision_json='{}' WHERE sequence=1")
        pin = hashlib.sha256(self.backup.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            restore_history(self.backup, self.restored, **self.restore_options(expected_sha256=pin))
        self.assertFalse(self.restored.exists())

    def test_existing_destination_and_source_are_preserved(self):
        self.store()
        with self.assertRaises(ValueError): self.store()
        with self.assertRaises(ValueError):
            restore_history(self.backup, self.history, **self.restore_options())
        self.assertEqual(self.history.read_bytes(), self.original)
        self.assertEqual(self.backup.read_bytes(), self.original)

    def test_symlinks_hardlinks_modes_and_sidecars_are_rejected(self):
        alias = self.root/'alias.sqlite'; alias.symlink_to(self.history)
        with self.assertRaises(OSError): backup_history(alias, self.backup, **self.backup_options())
        alias.unlink(); os.link(self.history, alias)
        with self.assertRaises(ValueError): self.store()
        alias.unlink()
        self.history.chmod(0o644)
        with self.assertRaises(ValueError): self.store()
        self.history.chmod(0o600)
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(self.history)+suffix); sidecar.touch()
            with self.assertRaises(ValueError): self.store()
            sidecar.unlink()
        self.root.chmod(0o755)
        try:
            with self.assertRaises(ValueError): self.store()
        finally: self.root.chmod(0o700)
        self.assertFalse(self.backup.exists())

    def test_capture_is_verified_and_published_even_if_source_changes_later(self):
        def verify_and_change(captured, **options):
            result = verify_history(captured, **options)
            self.history.write_bytes(b'changed after capture')
            return result
        with patch('database.ec2_history_backup.verify_history', side_effect=verify_and_change): self.store()
        self.assertEqual(self.backup.read_bytes(), self.original)

    def test_failed_publication_removes_staging_file(self):
        with patch('database.assessment_backup.os.link', side_effect=OSError('synthetic publication failure')):
            with self.assertRaises(OSError): self.store()
        self.assertFalse(self.backup.exists())
        self.assertFalse(list(self.root.glob('.assessment-backup-*')))
        self.assertEqual(self.history.read_bytes(), self.original)

    def test_cli_success_and_fixed_failure_are_minimized(self):
        export = self.root/'export.json'; export.write_bytes(self.export)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(['backup', str(self.history), '--output', str(self.backup),
                                   '--export', str(export), '--expected-head', self.head]), 0)
        result = json.loads(out.getvalue()); self.assertEqual(result['review_count'], 2)
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(main(['restore', str(self.backup), '--output', str(self.restored),
                '--export', str(export), '--expected-head', self.head, '--expected-sha256', '0'*64]), 2)
        self.assertNotIn(str(self.root), out.getvalue()+err.getvalue())
        self.assertNotIn('asset_id', out.getvalue())
        self.assertFalse(self.restored.exists())

    def test_native_temporary_walkthrough(self):
        result = exercise()
        self.assertTrue(result['original_history_removed'])
        self.assertTrue(result['exact_bytes_restored'])
        self.assertEqual(result['negative_cases_rejected'], 3)


if __name__ == '__main__': unittest.main()
