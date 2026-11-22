import base64
import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from engine.discovery import ec2_collector_attestation as attestation


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CollectorAttestationTests(unittest.TestCase):
    def setUp(self):
        try:
            from nacl.signing import SigningKey
        except ImportError:
            self.skipTest('optional requirements-review.txt required')
        self.signer = SigningKey.generate()
        root = Path(__file__).resolve().parents[1]
        self.export = (root / 'examples/ec2-interface-addresses.json').read_bytes()
        self.roster = (root / 'examples/ec2-network-expectations.json').read_bytes()
        self.policy = {'schema_version': 1, 'scope': 'synthetic', 'account': '111122223333', 'region': 'us-east-1',
            'authority': {'schema_version': 1, 'purpose': attestation.PURPOSE, 'audience': 'fixture-review',
                'max_validity_seconds': 3600, 'keys': [{'key_id': 'fixture-collector',
                    'public_key_b64': base64.b64encode(self.signer.verify_key.encode()).decode(),
                    'state': 'active', 'not_before': '2026-11-22T00:00:00Z', 'not_after': '2026-11-23T00:00:00Z'}]}}
        self.policy_data = encoded(self.policy)
        self.options = dict(expected_policy_sha256=digest(self.policy_data), scope='synthetic',
            account='111122223333', region='us-east-1', audience='fixture-review', at='2026-11-22T12:01:00Z')
        self.claim = attestation.create_attestation(self.export, self.roster, self.policy_data,
            **self.options, key_id='fixture-collector', seed=self.signer.encode(),
            captured_at='2026-11-22T12:00:00Z', expires_at='2026-11-22T12:30:00Z')
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def verify(self, *, claim=None, export=None, roster=None, policy=None, **changes):
        data = encoded(self.claim if claim is None else claim)
        policy_data = self.policy_data if policy is None else encoded(policy)
        options = self.options | {'expected_policy_sha256': digest(policy_data)} | changes
        return attestation.verify_attestation(self.export if export is None else export,
            self.roster if roster is None else roster, data, policy_data,
            expected_claim_sha256=digest(data), **options)

    def test_real_signature_then_complete_network_review_preserves_differences(self):
        result = self.verify()
        self.assertEqual(result, self.verify())
        self.assertTrue(result['collector_signature_verified'])
        self.assertFalse(result['aws_source_verified'])
        self.assertTrue(result['capture_time_is_claim'])
        self.assertFalse(result['collection_completeness_established'])
        self.assertFalse(result['network_review']['selected_roster_matches'])
        self.assertEqual(result['network_review']['differs_instance_count'], 1)
        self.assertEqual(result['network_review']['original_sha256'], digest(self.export))

    def test_changed_export_and_roster_reject_before_network_projection(self):
        for source, roster in [(self.export+b' ', self.roster), (self.export, self.roster+b' ')]:
            with patch.object(attestation, '_review', side_effect=AssertionError('must not project')):
                with self.assertRaises(ValueError): self.verify(export=source, roster=roster)

    def test_modified_signed_fields_and_signature_reject(self):
        for field, value in [('captured_at', '2026-11-22T11:59:00Z'),
                             ('expires_at', '2026-11-22T12:29:00Z'),
                             ('export_sha256', '0'*64), ('expectations_sha256', '0'*64),
                             ('signature_b64', base64.b64encode(bytes(64)).decode())]:
            claim = self.claim | {field: value}
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(claim=claim)

    def test_wrong_scope_account_region_audience_and_purpose_reject(self):
        for field, value in [('scope', 'owned'), ('account', '000000000000'),
                             ('region', 'eu-west-1'), ('audience', 'other-review')]:
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify(**{field:value})
        with self.assertRaises(ValueError): self.verify(claim=self.claim | {'purpose':'history-approval'})

    def test_revoked_key_and_wrong_enrolled_public_key_reject(self):
        policy = copy.deepcopy(self.policy); policy['authority']['keys'][0]['state'] = 'revoked'
        with self.assertRaises(ValueError): self.verify(policy=policy)
        policy = copy.deepcopy(self.policy)
        policy['authority']['keys'][0]['public_key_b64'] = base64.b64encode(bytes(32)).decode()
        with self.assertRaises(ValueError): self.verify(policy=policy)

    def test_retired_key_verifies_existing_claim_but_cannot_create(self):
        policy = copy.deepcopy(self.policy); policy['authority']['keys'][0]['state'] = 'retired'
        self.assertTrue(self.verify(policy=policy)['collector_signature_verified'])
        data = encoded(policy)
        with self.assertRaises(ValueError):
            attestation.create_attestation(self.export,self.roster,data,
                **(self.options | {'expected_policy_sha256':digest(data)}), key_id='fixture-collector',
                seed=self.signer.encode(), captured_at=self.claim['captured_at'], expires_at=self.claim['expires_at'])

    def test_future_expiry_and_policy_maximum_windows_reject(self):
        for instant in ('2026-11-22T11:59:59Z','2026-11-22T12:30:00Z','2026-11-23T00:00:00Z'):
            with self.subTest(at=instant), self.assertRaises(ValueError): self.verify(at=instant)
        self.assertTrue(self.verify(at=self.claim['captured_at'])['collector_signature_verified'])
        policy = copy.deepcopy(self.policy); policy['authority']['max_validity_seconds'] = 10
        with self.assertRaises(ValueError): self.verify(policy=policy)

    def test_create_requires_enrolled_seed_and_valid_source(self):
        for seed, source in [(bytes(32), self.export), (self.signer.encode(), b'{}')]:
            with self.assertRaises(ValueError):
                attestation.create_attestation(source,self.roster,self.policy_data,
                    **self.options, key_id='fixture-collector', seed=seed,
                    captured_at=self.claim['captured_at'], expires_at=self.claim['expires_at'])

    def test_independent_policy_and_claim_pins_precede_parsing(self):
        data=encoded(self.claim)
        for claim_pin,policy_pin in [('0'*64,digest(self.policy_data)),(digest(data),'0'*64)]:
            with patch.object(attestation,'_json',side_effect=AssertionError('must not parse')):
                with self.assertRaises(ValueError):
                    attestation.verify_attestation(self.export,self.roster,data,self.policy_data,
                        expected_claim_sha256=claim_pin,**(self.options|{'expected_policy_sha256':policy_pin}))

    def test_strict_shapes_duplicates_and_bounds_reject(self):
        for claim in [self.claim|{'schema_version':True},self.claim|{'extra':'untrusted'},
                      self.claim|{'signature_b64':'invalid'}]:
            with self.assertRaises(ValueError):self.verify(claim=claim)
        for data in [b'{"schema_version":1,"schema_version":1}',b' '*4097]:
            with self.assertRaises(ValueError):
                attestation.verify_attestation(self.export,self.roster,data,self.policy_data,
                    expected_claim_sha256=digest(data),**self.options)
        policy=copy.deepcopy(self.policy);policy['authority']['keys']*=2
        with self.assertRaises(ValueError): self.verify(policy=policy)

    def test_real_cli_private_read_only_no_overwrite_and_minimized(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); inputs=[]
            for name,data in [('export',self.export),('roster',self.roster),('claim',encoded(self.claim)),('policy',self.policy_data)]:
                path=root/(name+'.json');path.write_bytes(data);inputs.append((path,data))
            target=root/'review.json'
            args=['verify',*(str(p) for p,_ in inputs),'--expected-claim-sha256',digest(inputs[2][1]),
                '--expected-policy-sha256',digest(self.policy_data),'--scope','synthetic',
                '--account','111122223333','--region','us-east-1','--audience','fixture-review',
                '--at',self.options['at'],'--output',str(target)]
            with redirect_stdout(StringIO()) as out:self.assertEqual(attestation.main(args),0)
            self.assertTrue(json.loads(out.getvalue())['collector_signature_verified'])
            for private in ('111122223333','fixture-collector',str(root)):
                self.assertNotIn(private,out.getvalue())
            saved=target.read_bytes();self.assertEqual(target.stat().st_mode&0o777,0o600)
            with redirect_stdout(StringIO()) as out,redirect_stderr(StringIO()) as err:
                self.assertEqual(attestation.main(args),2)
            self.assertEqual(out.getvalue(),'');self.assertNotIn(str(root),err.getvalue())
            self.assertEqual(target.read_bytes(),saved)
            for path,data in inputs:self.assertEqual(path.read_bytes(),data)
            target.unlink();inputs[0][0].unlink();inputs[0][0].symlink_to(inputs[1][0])
            with redirect_stderr(StringIO()):self.assertEqual(attestation.main(args),2)
            self.assertFalse(target.exists())

    def test_demo(self):
        self.assertTrue(attestation.exercise()['changed_export_rejected'])


if __name__=='__main__':unittest.main()
