"""Native closed SQLite histories and independently pinned local selection records."""

from contextlib import redirect_stderr, redirect_stdout
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

from database import ec2_history_enrollment as enrollment
from database.ec2_review_history import retain_history
from engine.demo_ec2_enrollment import prepare_histories


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.histories, self.heads, self.receipts, self.export = prepare_histories(self.root)
        self.initial, self.advanced = self.root/'initial.json', self.root/'advanced.json'
        enrollment.enroll_history(self.histories[0], self.initial, export_data=self.export, expected_head=self.heads[0])
        self.data = self.initial.read_bytes()
        self.pin = enrollment._digest(self.data)

    def advance(self, index=1, **changes):
        options = dict(enrollment_data=self.data, expected_enrollment_sha256=self.pin,
                       export_data=self.export, expected_head=self.heads[index]) | changes
        return enrollment.advance_enrollment(self.histories[index], self.advanced, **options)

    def verify(self, history=None, **changes):
        return enrollment.verify_enrollment(history or self.histories[0], **(dict(enrollment_data=self.data,
            expected_enrollment_sha256=self.pin, export_data=self.export) | changes))

    def test_initial_selection_binds_exact_bytes_and_replays(self):
        result = self.verify()
        document = json.loads(self.data)
        self.assertEqual(document['database_sha256'], enrollment._digest(self.histories[0].read_bytes()))
        self.assertEqual(result['review_count'], 1)
        self.assertFalse(result['latest_head_established'])
        self.assertEqual(self.initial.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('arn:', json.dumps(result))

    def test_advance_retains_label_and_prior_pin_then_verifies(self):
        saved = self.advance()
        data = self.advanced.read_bytes()
        document = json.loads(data)
        self.assertEqual(document['enrollment_id'], json.loads(self.data)['enrollment_id'])
        self.assertEqual(document['previous_enrollment_sha256'], self.pin)
        self.assertEqual((saved['revision'], saved['review_count']), (2, 2))
        self.verify(self.histories[1], enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))
        self.assertEqual(self.initial.read_bytes(), self.data)

    def test_skip_to_later_strict_extension_is_supported(self):
        result = self.advance(2)
        self.assertEqual((result['revision'], result['review_count']), (2, 3))

    def test_old_history_rejected_under_latest_selection_but_old_pin_still_matches(self):
        self.advance(); data = self.advanced.read_bytes()
        with self.assertRaises(ValueError):
            self.verify(enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))
        self.assertEqual(self.verify()['review_count'], 1)

    def test_same_or_shorter_history_cannot_advance(self):
        with self.assertRaises(ValueError): self.advance(0)
        self.advance(); data = self.advanced.read_bytes()
        self.advanced.unlink()
        with self.assertRaises(ValueError):
            self.advance(0, enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))
        self.assertFalse(self.advanced.exists())

    def test_valid_divergent_history_is_not_selected_lineage(self):
        first, second = self.root/'fork1.sqlite', self.root/'fork2.sqlite'
        start = retain_history(self.receipts[1], first, export_data=self.export)
        branch = retain_history(self.receipts[2], second, export_data=self.export, history=first,
                                expected_head=start['head_sha256'])
        with self.assertRaises(ValueError):
            enrollment.advance_enrollment(second, self.advanced, enrollment_data=self.data,
                expected_enrollment_sha256=self.pin, export_data=self.export, expected_head=branch['head_sha256'])
        self.assertFalse(self.advanced.exists())

    def test_same_head_with_different_database_bytes_requires_new_selection(self):
        copy = self.root/'copy.sqlite'
        copy.write_bytes(self.histories[0].read_bytes()); copy.chmod(0o600)
        with sqlite3.connect(copy) as connection:
            connection.execute('CREATE INDEX additional_index ON reviews(sequence)')
        with self.assertRaises(ValueError): self.verify(copy)

    def test_changed_export_or_head_rejects_without_output(self):
        for changes in ({'export_data': self.export+b'\n'}, {'expected_head': '0'*64}):
            with self.assertRaises(ValueError): self.advance(**changes)
        self.assertFalse(self.advanced.exists())

    def test_wrong_enrollment_pin_precedes_history_access(self):
        with patch.object(enrollment, '_capture', side_effect=AssertionError('must not read history')):
            for value in ('bad', '0'*64, None, 'A'*64):
                with self.assertRaises(ValueError): self.advance(expected_enrollment_sha256=value)

    def test_malformed_or_noncanonical_enrollment_rejects(self):
        original = json.loads(self.data)
        for change in ({'schema_version': True}, {'purpose': 'wrong'}, {'revision': True},
                       {'review_count': 0}, {'decision_count': -1}, {'enrollment_id': 'bad'},
                       {'previous_enrollment_sha256': '0'*64}, {'extra': True}):
            data = enrollment._bytes(original | change)
            with self.assertRaises(ValueError):
                self.advance(enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))
        for data in (self.data+b' ', self.data[:-2]+b',"schema_version":1}\n'):
            with self.assertRaises(ValueError):
                self.advance(enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))

    def test_repacked_previous_decision_or_context_claim_rejected(self):
        for change in ({'decision_count': 2}, {'discovery_sha256': '0'*64},
                       {'model_sha256': '0'*64}, {'export_sha256': '0'*64}, {'head_sha256': '0'*64}):
            data = enrollment._bytes(json.loads(self.data) | change)
            with self.assertRaises(ValueError):
                self.advance(enrollment_data=data, expected_enrollment_sha256=enrollment._digest(data))

    def test_collision_and_publication_failure_preserve_prior_selection(self):
        self.advance(); original = self.advanced.read_bytes()
        with self.assertRaises(FileExistsError): self.advance()
        self.assertEqual(self.advanced.read_bytes(), original)
        self.advanced.unlink()
        with patch('database.assessment_backup.os.link', side_effect=OSError('synthetic publication failure')):
            with self.assertRaises(OSError): self.advance()
        self.assertFalse(self.advanced.exists())
        self.assertFalse(list(self.root.glob('.assessment-backup-*')))
        self.assertEqual(self.initial.read_bytes(), self.data)

    def test_checkpoint_size_and_private_regular_file_contract(self):
        with patch.object(enrollment, 'MAX_ENROLLMENT_BYTES', 1):
            with self.assertRaises(ValueError): self.verify()
        link = self.root/'alias'; link.symlink_to(self.initial)
        with self.assertRaises(OSError): enrollment.read_enrollment(link)
        hard = self.root/'hard'; os.link(self.initial, hard)
        with self.assertRaises(ValueError): enrollment.read_enrollment(self.initial)
        hard.unlink(); self.initial.chmod(0o644)
        with self.assertRaises(ValueError): enrollment.read_enrollment(self.initial)
        self.initial.chmod(0o600)
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): enrollment.read_enrollment(fifo)

    def test_sidecar_or_changed_normalized_history_rejected(self):
        sidecar = Path(str(self.histories[0])+'-wal'); sidecar.write_bytes(b'synthetic')
        with self.assertRaises(ValueError): self.verify()
        sidecar.unlink()
        with sqlite3.connect(self.histories[0]) as connection:
            connection.execute('DROP TRIGGER decisions_no_update')
            connection.execute("UPDATE decisions SET decision_json='{}'")
        with self.assertRaises(ValueError): self.verify()

    def test_cli_bad_pin_before_any_read_has_fixed_error(self):
        out, err = StringIO(), StringIO()
        with patch.object(enrollment, 'read_enrollment', side_effect=AssertionError('must not read')):
            with redirect_stdout(out), redirect_stderr(err):
                self.assertEqual(enrollment.main(['verify', 'private-history', '--export', 'private-export',
                    '--enrollment', 'private-record', '--expected-enrollment-sha256', 'bad']), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn('private-history', err.getvalue())

    def test_cli_verify_and_advance_in_standard_library_subprocesses(self):
        export = self.root/'export-copy.json'; export.write_bytes(self.export)
        common = ['--export', str(export), '--enrollment', str(self.initial), '--expected-enrollment-sha256', self.pin]
        for command in (['verify', str(self.histories[0]), *common],
                        ['advance', str(self.histories[1]), *common, '--expected-head', self.heads[1],
                         '--output', str(self.advanced)]):
            result = subprocess.run([sys.executable, '-S', '-m', 'database.ec2_history_enrollment', *command],
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['latest_head_established'])
            self.assertNotIn(str(self.root), result.stdout)

    def test_input_histories_and_export_unchanged_after_review(self):
        saved = {p: p.read_bytes() for p in self.histories}
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.verify(); self.advance()
        self.assertEqual(saved, {p: p.read_bytes() for p in self.histories})

    def test_native_fresh_process_enrollment_walkthrough(self):
        result = subprocess.run([sys.executable, '-S', '-m', 'engine.demo_ec2_enrollment'],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['negative_cases_rejected'], 4)
        self.assertTrue(value['old_selection_still_verifies'])
        self.assertTrue(value['original_history_removed'])


if __name__ == '__main__': unittest.main()
