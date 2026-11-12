"""Native signature, SQLite, filesystem failure and competing recipient tests."""

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database import ec2_recipient_checkpoint as recipient
from engine.demo_ec2_recipient import prepare_handoffs

try:
    import nacl.signing
except ImportError:
    nacl = None


@unittest.skipUnless(os.name == 'posix' and nacl is not None, 'requires POSIX and requirements-review.txt')
class RecipientTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.first, self.second = prepare_handoffs(self.root)
        self.checkpoint = self.root/'accepted.json'
        self.pin = self.first[2]['expected_enrollment_sha256']

    def accept(self, handoff, **mode):
        return recipient.accept_checkpoint(self.checkpoint, handoff[0], handoff[1], **handoff[2], **mode)

    def bootstrap(self):
        return self.accept(self.first, bootstrap=True)

    def test_bootstrap_advance_stale_and_rollback(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.bootstrap()
            result = self.accept(self.second, expected_accepted_sha256=self.pin)
        self.assertTrue(result['previous_checkpoint_verified'])
        self.assertEqual(result['revision'], 2)
        self.assertFalse(result['latest_head_established'])
        for handoff, mode in ((self.first, {'bootstrap': True}),
                (self.second, {'expected_accepted_sha256': self.pin}),
                (self.first, {'expected_accepted_sha256': result['checkpoint_sha256']})):
            with self.assertRaises(ValueError):
                self.accept(handoff, **mode)
            self.assertEqual(self.checkpoint.read_bytes(), self.second[2]['enrollment_data'])
        self.assertEqual(self.checkpoint.stat().st_mode & 0o777, 0o600)

    def test_bootstrap_requires_initial_revision_and_explicit_mode(self):
        for handoff, mode in ((self.second, {'bootstrap': True}), (self.first, {}),
                (self.first, {'bootstrap': True, 'expected_accepted_sha256': self.pin})):
            with self.assertRaises(ValueError): self.accept(handoff, **mode)
            self.assertFalse(self.checkpoint.exists())

    def test_failed_signature_policy_export_and_clock_preserve_checkpoint(self):
        self.bootstrap()
        for field, value in (('policy_data', b'{}'), ('export_data', b'{}'),
                             ('audience', 'other-recipient'), ('at', '2026-10-28T02:00:00Z')):
            options = dict(self.second[2], **{field: value})
            with self.assertRaises(ValueError):
                recipient.accept_checkpoint(self.checkpoint, self.second[0], self.second[1],
                    **options, expected_accepted_sha256=self.pin)
            self.assertEqual(self.checkpoint.read_bytes(), self.first[2]['enrollment_data'])
        damaged = json.loads(self.second[1])
        damaged['signature_b64'] = base64.b64encode(bytes(64)).decode('ascii')
        with self.assertRaises(ValueError):
            recipient.accept_checkpoint(self.checkpoint, self.second[0], json.dumps(damaged).encode(),
                **self.second[2], expected_accepted_sha256=self.pin)
        self.assertEqual(self.checkpoint.read_bytes(), self.first[2]['enrollment_data'])

    def test_file_sync_and_rename_failure_preserve_old_complete_state(self):
        self.bootstrap()
        commit = recipient._commit
        for target in ('os.fsync', 'os.replace'):
            def fail_commit(*args):
                with patch('database.ec2_recipient_checkpoint.'+target, side_effect=OSError('synthetic private failure')):
                    return commit(*args)
            with patch.object(recipient, '_commit', side_effect=fail_commit):
                with self.assertRaises(OSError):
                    self.accept(self.second, expected_accepted_sha256=self.pin)
            self.assertEqual(self.checkpoint.read_bytes(), self.first[2]['enrollment_data'])
            self.assertEqual(list(self.root.glob('.ec2-checkpoint-*')), [])

    def test_directory_sync_failure_can_leave_new_complete_state(self):
        self.bootstrap()
        commit = recipient._commit
        def fail_directory_sync(*args):
            with patch('database.ec2_recipient_checkpoint.os.fsync', side_effect=[None, OSError('sync failed')]):
                return commit(*args)
        with patch.object(recipient, '_commit', side_effect=fail_directory_sync):
            with self.assertRaises(OSError): self.accept(self.second, expected_accepted_sha256=self.pin)
        self.assertEqual(self.checkpoint.read_bytes(), self.second[2]['enrollment_data'])
        self.assertEqual(list(self.root.glob('.ec2-checkpoint-*')), [])
        with self.assertRaises(ValueError): self.accept(self.second, expected_accepted_sha256=self.pin)

    def test_native_process_lock_blocks_second_writer_before_verification(self):
        self.bootstrap()
        worker = 'import fcntl,sys; f=open(sys.argv[1], "r+"); fcntl.flock(f, fcntl.LOCK_EX); print("locked", flush=True); sys.stdin.read()'
        process = subprocess.Popen([sys.executable, '-c', worker, str(self.root/'.accepted.json.lock')],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline(), 'locked\n')
            with patch('database.ec2_recipient_checkpoint.verify_approval', side_effect=AssertionError('must not verify')):
                with self.assertRaises(BlockingIOError): self.accept(self.second, expected_accepted_sha256=self.pin)
            self.assertEqual(self.checkpoint.read_bytes(), self.first[2]['enrollment_data'])
        finally:
            process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0)
        self.accept(self.second, expected_accepted_sha256=self.pin)

    def test_unsafe_lock_and_checkpoint_storage_reject(self):
        lock = self.root/'.accepted.json.lock'
        lock.symlink_to(self.root/'uncreated')
        with self.assertRaises(OSError): self.bootstrap()
        lock.unlink()
        lock.write_text('not a lock'); lock.chmod(0o600)
        with self.assertRaises(ValueError): self.bootstrap()
        lock.unlink()
        self.bootstrap()
        data = self.checkpoint.read_bytes()
        self.checkpoint.unlink()
        original = self.root/'original.json'; original.write_bytes(data); original.chmod(0o600)
        self.checkpoint.symlink_to(original)
        with self.assertRaises(OSError): self.accept(self.second, expected_accepted_sha256=self.pin)
        self.assertEqual(original.read_bytes(), data)
        self.checkpoint.unlink(); self.checkpoint.write_bytes(data); self.checkpoint.chmod(0o644)
        with self.assertRaises(ValueError): self.accept(self.second, expected_accepted_sha256=self.pin)

    def test_cli_accepts_and_redacts_failure(self):
        history, approval, options = self.first
        for name, data in (('approval.json', approval), ('selection.json', options['enrollment_data']),
                           ('policy.json', options['policy_data'])):
            path = self.root/name; path.write_bytes(data); path.chmod(0o600)
        args = [str(self.checkpoint), str(history), str(self.root/'approval.json'), '--bootstrap',
            '--enrollment', str(self.root/'selection.json'), '--expected-enrollment-sha256', self.pin,
            '--export', str(self.root/'export.json'), '--policy', str(self.root/'policy.json'),
            '--expected-policy-sha256', options['expected_policy_sha256'],
            '--audience', options['audience'], '--at', options['at']]
        output = StringIO()
        with redirect_stdout(output): self.assertEqual(recipient.main(args), 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'ec2_recipient_checkpoint_accepted')
        errors, output = StringIO(), StringIO()
        with redirect_stderr(errors), redirect_stdout(output): self.assertEqual(recipient.main(args), 2)
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn(str(self.root), errors.getvalue())


if __name__ == '__main__':
    unittest.main()
