import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.ec2_assessment import retain_assessment
from database.ec2_history_approval import PURPOSE, DOMAIN, _canonical, _file, approve_history, verify_approval, main
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history

try:
    from nacl.signing import SigningKey
except ImportError:
    SigningKey = None

ROOT = Path(__file__).resolve().parents[1]
EXPORT = (ROOT/'examples/ec2-describe-instances.json').read_bytes()


@unittest.skipUnless(os.name == 'posix' and SigningKey is not None, 'requires POSIX and requirements-review.txt')
class HistoryApprovalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root/'export.json'; self.source.write_bytes(EXPORT)
        discovery = self.root/'discovery.sqlite'
        store_ec2(self.source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.histories = []
        previous, head = None, None
        for i in (1, 2):
            receipt = self.root/('receipt-'+str(i)+'.sqlite')
            retain_assessment(discovery, (ROOT/'examples/ec2-findings.jsonl').read_bytes(),
                              (ROOT/'examples/ownership-directory.json').read_bytes(), receipt, export_data=EXPORT,
                              as_of=date(2026, 10, 24+i),
                              assessed_at=datetime(2026, 10, 24+i, 1, tzinfo=timezone.utc))
            history = self.root/('history-'+str(i)+'.sqlite')
            report = retain_history(receipt, history, export_data=EXPORT, history=previous, expected_head=head)
            previous, head = history, report['head_sha256']; self.histories.append(history)
        self.history = self.histories[-1]
        self.signer = SigningKey.generate()
        self.policy = dict(schema_version=1, purpose=PURPOSE, audience='fixture-recipient', max_validity_seconds=3600,
            keys=[dict(key_id='fixture-reviewer', state='active',
                       public_key_b64=base64.b64encode(self.signer.verify_key.encode()).decode('ascii'),
                       not_before='2026-10-28T00:00:00Z', not_after='2026-10-29T00:00:00Z')])

    def shared(self, policy=None, **changes):
        data = json.dumps(self.policy if policy is None else policy).encode()
        return dict(dict(export_data=EXPORT, policy_data=data, expected_policy_sha256=hashlib.sha256(data).hexdigest(),
                         audience='fixture-recipient', at='2026-10-28T01:00:00Z'), **changes)

    def sign(self, **changes):
        options = dict(seed=self.signer.encode(), key_id='fixture-reviewer', issued_at='2026-10-28T01:00:00Z',
                       expires_at='2026-10-28T02:00:00Z')
        return approve_history(self.history, **self.shared(), **dict(options, **changes))

    def encoded(self, value=None):
        return json.dumps(self.sign() if value is None else value).encode()

    def test_native_signature_then_full_reproduction_without_private_seed(self):
        data = self.encoded(); del self.signer
        before = self.history.read_bytes()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = verify_approval(self.history, data, **self.shared())
        self.assertEqual((result['review_count'], result['decision_count']), (2, 2))
        self.assertEqual(result['status'], 'ec2_history_approval_verified')
        self.assertEqual(self.history.read_bytes(), before)

    def test_pin_recipient_purpose_and_signature_fail_before_database_read(self):
        approval = self.sign()
        for changes in ({'expected_policy_sha256': '0'*64}, {'audience': 'other-recipient'}):
            with patch('database.ec2_history_approval.verify_history', side_effect=AssertionError('database read')):
                with self.assertRaises(ValueError): verify_approval(self.history, self.encoded(approval), **self.shared(**changes))
        for field, value in (('purpose', 'other-purpose'), ('signature_b64', base64.b64encode(bytes(64)).decode())):
            changed = dict(approval, **{field: value})
            with patch('database.ec2_history_approval.verify_history', side_effect=AssertionError('database read')):
                with self.assertRaises(ValueError): verify_approval(self.history, self.encoded(changed), **self.shared())

    def test_export_bytes_older_prefix_and_decision_tampering_are_rejected(self):
        data = self.encoded()
        with self.assertRaises(ValueError): verify_approval(self.history, data, **self.shared(export_data=EXPORT+b'\n'))
        with self.assertRaises(ValueError): verify_approval(self.histories[0], data, **self.shared())
        with sqlite3.connect(self.history) as connection:
            connection.execute('DROP TRIGGER decisions_no_update')
            connection.execute("UPDATE decisions SET asset_id='changed-fixture'")
        with self.assertRaises(ValueError): verify_approval(self.history, data, **self.shared())

    def test_key_lifecycle_and_expiry(self):
        data = self.encoded()
        self.policy['keys'][0]['state'] = 'retired'
        self.assertEqual(verify_approval(self.history, data, **self.shared())['review_count'], 2)
        with self.assertRaises(ValueError): self.sign()
        self.policy['keys'][0]['state'] = 'revoked'
        with self.assertRaises(ValueError): verify_approval(self.history, data, **self.shared())
        self.policy['keys'][0]['state'] = 'active'
        for at in ('2026-10-28T00:59:59Z', '2026-10-28T02:00:00Z', '2026-10-29T00:00:00Z'):
            with self.subTest(at=at), self.assertRaises(ValueError):
                verify_approval(self.history, data, **self.shared(at=at))

    def test_issuance_must_fit_policy_and_key_window(self):
        for changes in ({'expires_at': '2026-10-28T02:00:01Z'}, {'issued_at': '2026-10-28T02:00:00Z'},
                        {'issued_at': '2026-10-28T01:00:00+00:00'}, {'expires_at': '2026-10-28T01:00:00Z'},
                        {'seed': bytes(32)}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError): self.sign(**changes)
        self.policy['keys'][0]['not_before'] = '2026-10-28T01:00:01Z'
        with self.assertRaises(ValueError): self.sign()

    def test_signed_wrong_counts_still_fail_reproduction(self):
        approval = self.sign(); approval['review_count'] = 1
        unsigned = {k: v for k, v in approval.items() if k != 'signature_b64'}
        approval['signature_b64'] = base64.b64encode(self.signer.sign(DOMAIN+_canonical(unsigned).encode()).signature).decode()
        with self.assertRaises(ValueError): verify_approval(self.history, self.encoded(approval), **self.shared())

    def test_policy_validates_all_keys_and_exact_shapes(self):
        data = self.encoded()
        for change in ('duplicate', 'state', 'version', 'extra', 'maximum', 'purpose'):
            policy = json.loads(json.dumps(self.policy))
            if change == 'duplicate': policy['keys'].append(dict(policy['keys'][0], key_id='other-key'))
            elif change == 'state': policy['keys'][0]['state'] = 'unknown'
            elif change == 'version': policy['schema_version'] = True
            elif change == 'extra': policy['keys'][0]['seed'] = 'not-a-real-seed'
            elif change == 'maximum': policy['max_validity_seconds'] = True
            else: policy['purpose'] = 'other-purpose'
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_approval(self.history, data, **self.shared(policy))

    def test_strict_json_and_bounds(self):
        approval = self.sign()
        for data in (b'{}', b'[]', b'{"x":NaN}', b'{"x":1,"x":2}', b'x'*4097,
                     self.encoded(dict(approval, schema_version=True)), self.encoded(dict(approval, review_count=True)),
                     self.encoded(dict(approval, signature_b64='bad'))):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                verify_approval(self.history, data, **self.shared())
        for data in (b'x'*65537, b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                verify_approval(self.history, self.encoded(approval),
                    **self.shared(policy_data=data, expected_policy_sha256=hashlib.sha256(data).hexdigest()))

    def test_private_seed_files_symlinks_hardlinks_fifo_and_bounds(self):
        seed = self.root/'seed'; seed.write_bytes(self.signer.encode()); seed.chmod(0o600)
        self.assertEqual(_file(seed, 32, private=True), self.signer.encode())
        seed.chmod(0o644)
        with self.assertRaises(ValueError): _file(seed, 32, private=True)
        seed.chmod(0o600); link = self.root/'link'; link.symlink_to(seed)
        with self.assertRaises(OSError): _file(link, 32, private=True)
        hard = self.root/'hard'; os.link(seed, hard)
        with self.assertRaises(ValueError): _file(seed, 32, private=True)
        hard.unlink(); seed.write_bytes(bytes(33))
        with self.assertRaises(ValueError): _file(seed, 32, private=True)
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): _file(fifo, 32)

    def test_cli_sign_verify_and_no_overwrite_or_secret_output(self):
        policy = self.root/'policy.json'; policy.write_bytes(self.shared()['policy_data'])
        seed = self.root/'seed'; seed.write_bytes(self.signer.encode()); seed.chmod(0o600)
        output = self.root/'approval.json'
        common = ['--export', str(self.source), '--policy', str(policy), '--expected-policy-sha256',
                  self.shared()['expected_policy_sha256'], '--audience', 'fixture-recipient', '--at', '2026-10-28T01:00:00Z']
        args = ['sign', str(self.history), *common, '--seed-file', str(seed), '--key-id', 'fixture-reviewer',
                '--issued-at', '2026-10-28T01:00:00Z', '--expires-at', '2026-10-28T02:00:00Z', '--output', str(output)]
        stdout = StringIO()
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes(); stderr = StringIO()
        with redirect_stderr(stderr): self.assertEqual(main(args), 2)
        self.assertEqual(output.read_bytes(), before); seed.unlink(); del self.signer
        with redirect_stdout(stdout): self.assertEqual(main(['verify', str(self.history), str(output), *common]), 0)
        for hidden in ('111122223333', str(self.root), 'signature_b64', 'private_key'):
            self.assertNotIn(hidden, stdout.getvalue()+stderr.getvalue())

    def test_demo(self):
        from engine.demo_ec2_approval import exercise
        result = exercise()
        self.assertEqual(result['status'], 'ec2_approval_exercise_passed')
        self.assertEqual(result['negative_cases_rejected'], 4)
        self.assertTrue(result['inputs_unchanged'])


if __name__ == '__main__':
    unittest.main()
