"""Real signatures bind recipient consent to one exact checkpoint transition."""

import base64
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from database import ec2_operator_acceptance as operator
from database.ec2_history_enrollment import _digest
from engine.demo_ec2_operator import consent_for, operator_policy
from engine.demo_ec2_recipient import prepare_handoffs

try:
    from nacl.signing import SigningKey
except ImportError:
    SigningKey = None


@unittest.skipUnless(os.name == 'posix' and SigningKey is not None, 'requires POSIX and requirements-review.txt')
class OperatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.first, self.second = prepare_handoffs(self.root)
        self.signer = SigningKey.generate()
        self.policy = operator_policy(self.signer)
        self.shared = dict(operator_policy_data=self.policy, expected_operator_policy_sha256=_digest(self.policy))
        self.checkpoint = self.root/'accepted.json'
        self.pin = self.first[2]['expected_enrollment_sha256']
        self.initial = consent_for(self.first, self.policy, self.signer, None)
        self.successor = consent_for(self.second, self.policy, self.signer, self.pin)

    def accept(self, handoff, consent, **changes):
        options = dict(handoff[2], **self.shared, operator_approval_data=consent)
        return operator.accept_authorized(self.checkpoint, handoff[0], handoff[1], **dict(options, **changes))

    def test_native_separate_key_consent_bootstrap_advance_and_replay_rejection(self):
        del self.signer
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.accept(self.first, self.initial, bootstrap=True)
            result = self.accept(self.second, self.successor, expected_accepted_sha256=self.pin)
        self.assertTrue(result['operator_approval_verified'])
        self.assertTrue(result['previous_checkpoint_verified'])
        self.assertEqual(result['revision'], 2)
        self.assertFalse(result['latest_head_established'])
        with self.assertRaises(ValueError):
            self.accept(self.second, self.successor, expected_accepted_sha256=self.pin)
        self.assertEqual(self.checkpoint.read_bytes(), self.second[2]['enrollment_data'])

    def test_wrong_context_rejects_before_history_verification_or_checkpoint_write(self):
        for change in ({'expected_enrollment_sha256': '0'*64}, {'expected_policy_sha256': '0'*64},
                       {'expected_operator_policy_sha256': '0'*64}, {'audience': 'other-recipient'},
                       {'expected_accepted_sha256': self.pin}, {'at': '2026-10-28T02:00:00Z'}):
            with self.subTest(fields=list(change)), patch.object(operator, 'accept_checkpoint', side_effect=AssertionError('must not accept')):
                with self.assertRaises(ValueError): self.accept(self.first, self.initial, bootstrap=True, **change)
            self.assertFalse(self.checkpoint.exists())

    def test_invalid_signature_and_history_signature_cannot_authorize_acceptance(self):
        document = json.loads(self.initial)
        document['signature_b64'] = base64.b64encode(bytes(64)).decode('ascii')
        for data in (json.dumps(document).encode(), self.first[1], b'{}', b'x'*4097):
            with self.assertRaises(ValueError): self.accept(self.first, data, bootstrap=True)
            self.assertFalse(self.checkpoint.exists())

    def test_changed_export_or_history_approval_still_fails_after_valid_operator_consent(self):
        with self.assertRaises(ValueError):
            self.accept(self.first, self.initial, bootstrap=True, export_data=b'{}')
        with self.assertRaises(ValueError):
            operator.accept_authorized(self.checkpoint, self.first[0], b'{}', **self.first[2], **self.shared,
                operator_approval_data=self.initial, bootstrap=True)
        self.assertFalse(self.checkpoint.exists())

    def test_issuance_rejects_wrong_predecessor_seed_policy_purpose_and_window(self):
        options = dict(expected_enrollment_sha256=self.pin, expected_accepted_sha256=None,
            authority_policy_sha256=self.first[2]['expected_policy_sha256'], **self.shared,
            audience='fixture-recipient', at='2026-10-28T01:00:00Z', key_id='fixture-operator',
            seed=self.signer.encode(), issued_at='2026-10-28T01:00:00Z', expires_at='2026-10-28T02:00:00Z')
        for change in ({'expected_accepted_sha256': '0'*64}, {'seed': bytes(32)},
                       {'expires_at': '2026-10-28T02:00:01Z'}, {'issued_at': '2026-10-28T01:00:01Z'},
                       {'operator_policy_data': self.first[2]['policy_data'],
                        'expected_operator_policy_sha256': self.first[2]['expected_policy_sha256']}):
            with self.subTest(fields=list(change)), self.assertRaises(ValueError):
                operator.approve_acceptance(self.first[2]['enrollment_data'], **dict(options, **change))

    def test_policy_change_cannot_reuse_old_consent_even_with_same_public_key(self):
        changed = json.loads(self.policy); changed['max_validity_seconds'] = 1800
        data = json.dumps(changed).encode()
        with self.assertRaises(ValueError):
            self.accept(self.first, self.initial, bootstrap=True, operator_policy_data=data,
                        expected_operator_policy_sha256=_digest(data))
        self.assertFalse(self.checkpoint.exists())

    def test_staging_failure_keeps_previous_checkpoint(self):
        self.accept(self.first, self.initial, bootstrap=True)
        with patch('database.ec2_recipient_checkpoint._commit', side_effect=OSError('private staging failure')):
            with self.assertRaises(OSError):
                self.accept(self.second, self.successor, expected_accepted_sha256=self.pin)
        self.assertEqual(self.checkpoint.read_bytes(), self.first[2]['enrollment_data'])

    def test_cli_sign_accept_without_retaining_operator_seed_and_collision_redaction(self):
        for name, data in (('operator.json', self.policy), ('history-policy.json', self.first[2]['policy_data']),
                           ('history-approval.json', self.first[1]), ('seed', self.signer.encode())):
            path = self.root/name; path.write_bytes(data); path.chmod(0o600)
        consent = self.root/'consent.json'
        common = ['--enrollment', str(self.root/'selection-1.json'), '--expected-enrollment-sha256', self.pin,
            '--bootstrap', '--expected-policy-sha256', self.first[2]['expected_policy_sha256'],
            '--operator-policy', str(self.root/'operator.json'), '--expected-operator-policy-sha256', _digest(self.policy),
            '--audience', 'fixture-recipient', '--at', '2026-10-28T01:00:00Z']
        sign = ['sign', *common, '--seed-file', str(self.root/'seed'), '--key-id', 'fixture-operator',
                '--issued-at', '2026-10-28T01:00:00Z', '--expires-at', '2026-10-28T02:00:00Z', '--output', str(consent)]
        with redirect_stdout(StringIO()): self.assertEqual(operator.main(sign), 0)
        saved = consent.read_bytes()
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()): self.assertEqual(operator.main(sign), 2)
        self.assertEqual(consent.read_bytes(), saved)
        self.assertEqual(consent.stat().st_mode & 0o777, 0o600)
        (self.root/'seed').unlink(); del self.signer
        accept = ['accept', str(self.checkpoint), str(self.first[0]), str(self.root/'history-approval.json'),
                  *common, '--operator-approval', str(consent), '--export', str(self.root/'export.json'),
                  '--policy', str(self.root/'history-policy.json')]
        out = StringIO()
        with redirect_stdout(out): self.assertEqual(operator.main(accept), 0)
        self.assertTrue(json.loads(out.getvalue())['operator_approval_verified'])
        out, errors = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(errors): self.assertEqual(operator.main(accept), 2)
        self.assertEqual(out.getvalue(), '')
        self.assertNotIn(str(self.root), errors.getvalue())


if __name__ == '__main__':
    unittest.main()
