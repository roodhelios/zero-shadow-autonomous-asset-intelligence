"""Native closed SQLite histories, retained dependencies and independently selected pins."""

import ast
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database import ec2_history_archive as archive
from database.assessment_archive import _canonical, _entry
from database.ec2_review_history import verify_history
from engine.demo_ec2_history_backup import prepare_history


@unittest.skipUnless(os.name == 'posix', 'private archive requires POSIX')
class EC2HistoryArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.history, self.export, self.head = prepare_history(self.root)
        self.original = self.history.read_bytes()
        self.path, self.output = self.root/'archive.json', self.root/'restored'

    def store(self):
        return archive.create_archive(self.history, self.path, export_data=self.export, expected_head=self.head)

    def options(self, **overrides):
        return dict(expected_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
                    expected_head=self.head) | overrides

    def revise(self, change):
        doc = json.loads(self.path.read_bytes())
        change(doc)
        self.path.write_text(_canonical(doc)+'\n', encoding='ascii')

    def refused(self, **overrides):
        with self.assertRaises((ValueError, OSError, sqlite3.DatabaseError)):
            archive.restore_archive(self.path, self.output, **self.options(**overrides))
        self.assertFalse(self.output.exists())

    def test_retains_exact_history_export_and_sources_after_original_removal(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            saved = self.store()
            self.history.unlink()
            checked = archive.verify_archive(self.path, **self.options())
            result = archive.restore_archive(self.path, self.output, **self.options())
        self.assertEqual((result['review_count'], result['decision_count']), (2, 2))
        self.assertEqual(saved['archive_sha256'], checked['archive_sha256'])
        self.assertEqual((self.output/'history.sqlite').read_bytes(), self.original)
        self.assertEqual((self.output/'export.json').read_bytes(), self.export)
        self.assertEqual(set(p.name for p in self.output.iterdir()), {'history.sqlite', 'export.json', 'RESTORE.json'})
        verify_history(self.output/'history.sqlite', export_data=(self.output/'export.json').read_bytes(),
                       expected_head=self.head)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.output.iterdir()))

    def test_wrong_independent_archive_or_head_pin_cannot_restore(self):
        self.store()
        self.refused(expected_sha256='0'*64)
        self.refused(expected_head='0'*64)

    def test_archive_supplies_export_dependency_missing_from_raw_backup(self):
        from database.ec2_history_backup import backup_history, restore_history

        copied = self.root/'raw-backup.sqlite'
        saved = backup_history(self.history, copied, export_data=self.export, expected_head=self.head)
        self.store()
        self.history.unlink()
        with self.assertRaises(ValueError):
            restore_history(copied, self.root/'without-export.sqlite', export_data=b'',
                            expected_head=self.head, expected_sha256=saved['database_sha256'])
        self.assertFalse((self.root/'without-export.sqlite').exists())
        archive.restore_archive(self.path, self.output, **self.options())
        self.assertEqual((self.output/'export.json').read_bytes(), self.export)

    def test_invalid_pin_syntax_precedes_archive_or_history_access(self):
        for override in ({'expected_sha256': None}, {'expected_head': 'bad'}, {'expected_sha256': 'A'*64}):
            with patch.object(archive, '_archive_bytes', side_effect=AssertionError('must not read')):
                with self.assertRaises(ValueError):
                    archive.verify_archive(self.path, **(dict(expected_sha256='0'*64, expected_head=self.head) | override))
        with patch.object(archive, '_closed_bytes', side_effect=AssertionError('must not read')):
            with self.assertRaises(ValueError):
                archive.create_archive(self.history, self.path, export_data=self.export, expected_head=None)

    def test_modified_original_export_rejects_create_and_repacked_archive(self):
        with self.assertRaises(ValueError):
            archive.create_archive(self.history, self.path, export_data=self.export+b'\n', expected_head=self.head)
        self.assertFalse(self.path.exists())
        self.store()
        self.revise(lambda d: d.update(export=_entry(self.export+b'\n')))
        self.refused()

    def test_source_snapshot_is_data_and_must_match_trusted_checkout(self):
        self.store()
        self.revise(lambda d: d['sources'].update({archive.SOURCE_FILES[0]: _entry(b'raise AssertionError("inert changed source")\n')}))
        self.refused()
        self.assertFalse(list(self.root.glob('*.py')))

    def test_model_change_and_repacked_model_claim_rejected(self):
        self.store()
        with patch.object(archive, 'current_model', return_value={}):
            self.refused()
        self.revise(lambda d: d.update(model={}))
        self.refused()

    def test_corrupt_normalized_decisions_fail_even_with_matching_outer_pin(self):
        self.store()
        with sqlite3.connect(self.history) as connection:
            connection.execute('DROP TRIGGER decisions_no_update')
            connection.execute("UPDATE decisions SET decision_json='{}' WHERE sequence=1")
        self.revise(lambda d: d.update(history=_entry(self.history.read_bytes())))
        self.refused()

    def test_noncanonical_duplicate_and_unknown_entries_rejected(self):
        self.store()
        valid = self.path.read_bytes()
        self.path.write_bytes(b' '+valid)
        self.refused()
        self.path.write_bytes(b'{"schema_version":1,'+valid[1:])
        self.refused()
        self.path.write_bytes(valid)
        self.revise(lambda d: d['sources'].update({'../unexpected.py': _entry(b'inert')}))
        self.refused()

    def test_bad_entry_size_digest_and_base64_do_not_restore(self):
        self.store()
        valid = self.path.read_bytes()
        for override in ({'byte_count': True}, {'sha256': '0'*64}, {'bytes_b64': '!invalid!'}):
            self.path.write_bytes(valid)
            self.revise(lambda d: d['history'].update(override))
            self.refused()

    def test_existing_destinations_and_archive_are_preserved(self):
        self.store()
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            self.store()
        self.output.mkdir()
        (self.output/'sentinel').write_bytes(b'original')
        with self.assertRaises(FileExistsError):
            archive.restore_archive(self.path, self.output, **self.options())
        self.assertEqual((self.output/'sentinel').read_bytes(), b'original')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.history.read_bytes(), self.original)

    def test_closed_private_history_and_archive_file_contracts(self):
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(self.history)+suffix)
            sidecar.touch()
            with self.assertRaises(ValueError):
                self.store()
            sidecar.unlink()
        self.store()
        self.path.chmod(0o644)
        self.refused()
        self.path.chmod(0o600)
        alias = self.root/'alias.json'
        os.link(self.path, alias)
        self.refused()
        alias.unlink()
        alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            archive.verify_archive(alias, **self.options())

    def test_create_bounds_and_archive_read_bound(self):
        with patch.object(archive, 'MAX_INPUT_BYTES', 1):
            with self.assertRaises(ValueError): self.store()
        with patch.object(archive, 'MAX_SOURCE_BYTES', 1):
            with self.assertRaises(ValueError): self.store()
        with patch.object(archive, 'MAX_ARCHIVE_BYTES', 1):
            with self.assertRaises(ValueError): self.store()
        self.assertFalse(self.path.exists())
        self.store()
        with patch('database.assessment_archive.MAX_ARCHIVE_BYTES', 1):
            self.refused()

    def test_verified_captured_bytes_used_after_original_changes(self):
        original_replay = archive._replay

        def checked_then_changed(*args):
            report = original_replay(*args)
            self.history.write_bytes(b'changed after capture')
            return report

        with patch.object(archive, '_replay', side_effect=checked_then_changed):
            self.store()
        archive.restore_archive(self.path, self.output, **self.options())
        self.assertEqual((self.output/'history.sqlite').read_bytes(), self.original)

    def test_restore_failure_cleans_owned_partial_directory(self):
        self.store()
        publish = archive._publish

        def fail_completion(path, data):
            if path.name == 'RESTORE.json':
                raise OSError('synthetic completion failure')
            return publish(path, data)

        with patch.object(archive, '_publish', side_effect=fail_completion):
            with self.assertRaises(OSError):
                archive.restore_archive(self.path, self.output, **self.options())
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.assessment-backup-*')))

    def test_cli_roundtrip_and_fixed_error_without_private_values(self):
        export = self.root/'export.json'
        export.write_bytes(self.export)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out):
            self.assertEqual(archive.main(['create', str(self.history), '--export', str(export),
                '--output', str(self.path), '--expected-head', self.head]), 0)
        saved = json.loads(out.getvalue())
        export.unlink()
        self.history.unlink()
        with redirect_stdout(StringIO()):
            self.assertEqual(archive.main(['restore', str(self.path), '--output', str(self.output),
                '--expected-sha256', saved['archive_sha256'], '--expected-head', self.head]), 0)
        with redirect_stdout(StringIO()), redirect_stderr(err):
            self.assertEqual(archive.main(['verify', str(self.path), '--expected-head', self.head,
                '--expected-sha256', '0'*64]), 2)
        self.assertNotIn(str(self.root), out.getvalue()+err.getvalue())
        self.assertNotIn('asset_id', out.getvalue())

    def test_declared_sources_cover_existing_local_imports(self):
        # Check retention coverage without executing any archived code.
        root = Path(__file__).resolve().parents[1]
        for name in archive.SOURCE_FILES:
            if not name.endswith('.py'): continue
            for node in ast.walk(ast.parse((root/name).read_text())):
                modules = ([node.module] if isinstance(node, ast.ImportFrom) and node.module else
                           [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
                for module in modules:
                    if module.split('.')[0] not in ('database', 'engine'): continue
                    path = module.replace('.', '/')
                    target = path+'.py' if (root/(path+'.py')).exists() else path+'/__init__.py'
                    if (root/target).exists(): self.assertIn(target, archive.SOURCE_FILES)

    def test_fresh_process_standard_library_walkthrough(self):
        result = subprocess.run([sys.executable, '-S', '-m', 'engine.demo_ec2_history_archive'],
                                check=True, capture_output=True, text=True, timeout=30)
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 'ec2_history_archive_exercise_passed')
        self.assertTrue(value['original_export_removed'] and value['original_history_removed'])
        self.assertTrue(value['exact_bytes_restored'])
        self.assertEqual(value['negative_cases_rejected'], 3)
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
