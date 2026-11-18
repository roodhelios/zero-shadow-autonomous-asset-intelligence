import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from engine.discovery import ec2_network_expectations as review

ROOT = Path(__file__).resolve().parents[1]


class NetworkExpectationTests(unittest.TestCase):
    def setUp(self):
        self.source = json.loads((ROOT / 'examples/ec2-interface-addresses.json').read_bytes())
        self.expected = json.loads((ROOT / 'examples/ec2-network-expectations.json').read_bytes())
        self.host = self.source['Reservations'][0]['Instances'][0]
        self.host.update(VpcId='vpc-00000001', SubnetId='subnet-00000001')
        self.interface = self.host['NetworkInterfaces'][0]
        self.interface.update(NetworkInterfaceId='eni-00000001', VpcId='vpc-00000001', SubnetId='subnet-00000001')
        self.network = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        self.network.start()
        self.addCleanup(self.network.stop)

    def compare(self, source=None, expected=None):
        data = json.dumps(self.source if source is None else source).encode()
        manifest = json.dumps(self.expected if expected is None else expected).encode()
        return review.review(data, manifest, original_sha256=hashlib.sha256(data).hexdigest(),
            expectations_sha256=hashlib.sha256(manifest).hexdigest(), scope='synthetic',
            account='111122223333', region='us-east-1')

    def test_matches_retains_exact_pins_and_original_paths_without_mutation(self):
        before = copy.deepcopy(self.source)
        result = self.compare()
        self.assertEqual(result, self.compare())
        self.assertEqual(self.source, before)
        self.assertTrue(result['selected_roster_matches'])
        self.assertFalse(result['collection_completeness_established'])
        self.assertFalse(result['collision_established'])
        row = result['instances'][0]
        self.assertEqual(row['source_path'], '/Reservations/0/Instances/0')
        self.assertEqual(row['interfaces'][0]['source_path'], '/Reservations/0/Instances/0/NetworkInterfaces/0')
        self.assertEqual(row['interfaces'][0]['observed']['interface_vpc_id'], self.interface['VpcId'])

    def test_interface_metadata_is_never_inherited_from_instance(self):
        self.interface.pop('VpcId')
        result = self.compare()
        self.assertFalse(result['selected_roster_matches'])
        row = result['instances'][0]
        self.assertEqual(row['instance_context']['status'], 'matches')
        self.assertEqual(row['interfaces'][0]['status'], 'differs')
        self.assertIsNone(row['interfaces'][0]['observed']['interface_vpc_id'])

    def test_null_requires_absent_metadata_and_is_not_a_wildcard(self):
        self.expected['instances'][0]['instance_vpc_id'] = None
        self.assertEqual(self.compare()['differs_instance_count'], 1)
        self.host.pop('VpcId')
        self.assertTrue(self.compare()['selected_roster_matches'])
        self.host['VpcId'] = None
        with self.assertRaises(ValueError): self.compare()

    def test_missing_and_unexpected_instances_are_both_retained(self):
        self.host['InstanceId'] = 'i-0123456789abcdef1'
        result = self.compare()
        self.assertEqual(result['missing_instance_count'], 1)
        self.assertEqual(result['unexpected_instance_count'], 1)
        self.assertEqual(result['matches_instance_count'], 0)
        self.assertEqual(result['instances'][0]['status'], 'missing')
        self.assertIsNone(result['instances'][0]['source_path'])
        self.assertFalse(result['selected_roster_matches'])

    def test_empty_export_is_missing_collection_not_remediation(self):
        result = self.compare(source={'Reservations': []})
        self.assertEqual(result['missing_instance_count'], 1)
        self.assertEqual(result['observed_instance_count'], 0)
        self.expected['instances'] = []
        empty = self.compare(source={'Reservations': []})
        self.assertTrue(empty['selected_roster_matches'])
        self.assertFalse(empty['collection_completeness_established'])

    def test_interfaces_match_by_identity_not_position(self):
        other = copy.deepcopy(self.interface)
        other['NetworkInterfaceId'] = 'eni-00000002'
        expected = copy.deepcopy(self.expected['instances'][0]['interfaces'][0])
        expected['network_interface_id'] = other['NetworkInterfaceId']
        self.expected['instances'][0]['interfaces'].append(expected)
        self.host['NetworkInterfaces'].insert(0, other)
        result = self.compare()
        self.assertTrue(result['selected_roster_matches'])
        self.assertTrue(result['instances'][0]['interfaces'][0]['source_path'].endswith('/1'))

    def test_missing_unexpected_and_unidentified_interfaces_do_not_pass(self):
        self.interface['NetworkInterfaceId'] = 'eni-00000002'
        row = self.compare()['instances'][0]
        self.assertEqual([i['status'] for i in row['interfaces']], ['missing', 'unexpected'])
        self.interface.pop('NetworkInterfaceId')
        row = self.compare()['instances'][0]
        self.assertEqual(len(row['unidentified_interfaces']), 1)
        self.assertEqual(row['interfaces'][0]['status'], 'missing')
        self.assertEqual(row['status'], 'differs')

    def test_unshared_instance_and_addressless_interface_are_still_reviewed(self):
        self.host['NetworkInterfaces'] = [{'NetworkInterfaceId': 'eni-00000001',
            'VpcId': 'vpc-00000002', 'SubnetId': 'subnet-00000001'}]
        self.assertEqual(self.compare()['differs_instance_count'], 1)

    def test_duplicate_expected_or_observed_identities_reject(self):
        self.expected['instances'].append(copy.deepcopy(self.expected['instances'][0]))
        with self.assertRaises(ValueError): self.compare()
        self.expected['instances'].pop()
        self.expected['instances'][0]['interfaces'] *= 2
        with self.assertRaises(ValueError): self.compare()
        self.expected['instances'][0]['interfaces'].pop()
        self.host['NetworkInterfaces'].append(copy.deepcopy(self.interface))
        with self.assertRaises(ValueError): self.compare()

    def test_strict_manifest_schema_scope_ids_and_bounds(self):
        for key, value in [('schema_version', True), ('scope', 'owned'), ('account', '000000000000'),
                           ('region', 'eu-west-1'), ('unexpected', 1), ('instances', {})]:
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.expected); manifest[key] = value
                with self.assertRaises(ValueError): self.compare(expected=manifest)
        for target, key, value in [(self.expected['instances'][0], 'instance_vpc_id', 'vpc-invalid'),
                                   (self.expected['instances'][0]['interfaces'][0], 'network_interface_id', None)]:
            previous = target[key]; target[key] = value
            with self.assertRaises(ValueError): self.compare()
            target[key] = previous
        with patch.object(review, 'MAX_EXPECTATIONS_BYTES', 1), self.assertRaises(ValueError): self.compare()
        with patch('engine.discovery.ec2_address_review.MAX_REPORT_BYTES', 1), self.assertRaises(ValueError):
            review._render(self.compare())

    def test_pins_reject_before_json_parsing(self):
        with patch.object(review, '_expectations', side_effect=AssertionError('must not parse')):
            with self.assertRaises(ValueError):
                review.review(b'invalid', b'invalid', original_sha256='0' * 64,
                    expectations_sha256='0' * 64, scope='synthetic', account='111122223333', region='us-east-1')
            with self.assertRaises(ValueError):
                review.review(b'invalid', b'invalid', original_sha256=hashlib.sha256(b'invalid').hexdigest(),
                    expectations_sha256='0' * 64, scope='synthetic', account='111122223333', region='us-east-1')

    def test_duplicate_json_fields_and_unfinished_source_reject(self):
        data = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaises(ValueError):
            review._expectations(data, scope='synthetic', account='111122223333', region='us-east-1')
        self.source['NextToken'] = 'synthetic-incomplete'
        with self.assertRaises(ValueError): self.compare()

    @unittest.skipUnless(os.name == 'posix', 'private file handling requires POSIX')
    def test_real_cli_keeps_inputs_unchanged_output_private_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, manifest, target = root / 'export.json', root / 'expected.json', root / 'report.json'
            data, expected = json.dumps(self.source).encode(), json.dumps(self.expected).encode()
            source.write_bytes(data); manifest.write_bytes(expected)
            args = ['review', str(source), str(manifest), '--original-sha256', hashlib.sha256(data).hexdigest(),
                '--expectations-sha256', hashlib.sha256(expected).hexdigest(), '--scope', 'synthetic',
                '--account', '111122223333', '--region', 'us-east-1', '--output', str(target)]
            with redirect_stdout(StringIO()) as stdout:
                self.assertEqual(review.main(args), 0)
            self.assertTrue(json.loads(stdout.getvalue())['selected_roster_matches'])
            for sensitive in ('111122223333', 'eni-00000001', '192.0.2.', str(root)):
                self.assertNotIn(sensitive, stdout.getvalue())
            saved = target.read_bytes()
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with redirect_stderr(StringIO()) as errors, redirect_stdout(StringIO()) as stdout:
                self.assertEqual(review.main(args), 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn(str(root), errors.getvalue())
            self.assertEqual(target.read_bytes(), saved)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(manifest.read_bytes(), expected)
            target.unlink(); source.write_bytes(data + b' ')
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                self.assertEqual(review.main(args), 2)
            self.assertFalse(target.exists())
            source.unlink(); source.symlink_to(manifest)
            with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                self.assertEqual(review.main(args), 2)
            self.assertFalse(target.exists())

    def test_demo(self):
        self.assertEqual(review.exercise()['status'], 'ec2_network_expectation_exercise_passed')


if __name__ == '__main__':
    unittest.main()
