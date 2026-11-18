import copy
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from engine.discovery.ec2_address_context import exercise, review_address_context
from engine.discovery.ec2_address_review import main, review_addresses

ROOT = Path(__file__).resolve().parents[1]
OPTIONS = {'scope': 'synthetic', 'account': '111122223333', 'region': 'us-east-1'}


class AddressContextTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / 'examples/ec2-interface-addresses.json').read_bytes())
        self.first = self.document['Reservations'][0]['Instances'][0]
        self.second = copy.deepcopy(self.first)
        self.second['InstanceId'] = 'i-0123456789abcdef1'
        self.document['Reservations'][0]['Instances'].append(self.second)

    def review(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            return review_address_context(json.dumps(self.document).encode(), **OPTIONS)

    def test_every_context_resolves_to_exact_original_leaf_and_preserves_role(self):
        result = self.review()
        self.assertEqual(result, self.review())
        self.assertEqual(result['schema_version'], 2)
        self.assertEqual(result['context_record_count'], 20)
        self.assertEqual(result['asset_count'], 2)
        for claim in result['shared_claims']:
            self.assertEqual(claim['identity_count'], 2)
            for observation in claim['observations']:
                for context in observation['address_contexts']:
                    value = self.document
                    for part in context['source_path'].strip('/').split('/'):
                        value = value[int(part)] if isinstance(value, list) else value[part]
                    self.assertEqual(str(ipaddress.ip_address(value)), claim['address'])
                    self.assertIsNone(context['instance_vpc_id'])
                    self.assertIsNone(context['interface_vpc_id'])
                    self.assertIsNone(context['network_interface_id'])
        public = next(item for item in result['shared_claims'] if item['address'] == '198.51.100.41')
        context = public['observations'][0]['address_contexts'][0]
        self.assertEqual(context['role'], 'private_record_associated_public_ipv4')
        self.assertEqual(context['associated_private_ipv4'], '192.0.2.41')
        self.assertIs(context['primary'], False)

    def test_distinct_vpc_claims_and_missing_interface_vpc_are_not_inherited(self):
        self.first['VpcId'] = 'vpc-00000001'
        self.first['NetworkInterfaces'][0].update(VpcId='vpc-00000002',
            NetworkInterfaceId='eni-00000001', SubnetId='subnet-00000001')
        self.second['VpcId'] = 'vpc-00000003'
        result = self.review()
        claim = next(item for item in result['shared_claims'] if item['address'] == '192.0.2.40')
        first = claim['observations'][0]['address_contexts']
        self.assertEqual({x['instance_vpc_id'] for x in first}, {'vpc-00000001'})
        self.assertEqual({x['interface_vpc_id'] for x in first}, {None, 'vpc-00000002'})
        self.assertEqual({x['interface_vpc_id'] for x in claim['observations'][1]['address_contexts']}, {None})
        self.assertNotIn('collision', {key for key in result if key != 'interpretation'})

    def test_false_true_and_absent_primary_are_distinct_without_exposure_inference(self):
        result = self.review()
        contexts = [context for item in result['shared_claims'] for obs in item['observations']
                    for context in obs['address_contexts']]
        self.assertTrue(any(x['primary'] is True for x in contexts))
        self.assertTrue(any(x['primary'] is False for x in contexts))
        self.assertTrue(any(x['primary'] is None for x in contexts))
        before = json.dumps(result, sort_keys=True)
        self.first['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Primary'] = False
        after = self.review()
        self.assertNotEqual(json.dumps(after, sort_keys=True), before)
        self.assertEqual(after['shared_address_count'], result['shared_address_count'])

    def test_optional_context_validation_is_strict_but_legacy_review_is_unchanged(self):
        for key, value in [('NetworkInterfaceId', 'eni-wrong'), ('VpcId', None),
                           ('SubnetId', True), ('VpcId', 'vpc-0000000A')]:
            with self.subTest(key=key, value=value):
                document = copy.deepcopy(self.document)
                document['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0][key] = value
                data = json.dumps(document).encode()
                self.assertEqual(review_addresses(data, **OPTIONS)['schema_version'], 1)
                with self.assertRaises(ValueError): review_address_context(data, **OPTIONS)
        for key, value, rows in [('Primary', 1, 'PrivateIpAddresses'),
                                 ('IsPrimaryIpv6', 'false', 'Ipv6Addresses')]:
            document = copy.deepcopy(self.document)
            document['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0][rows][0][key] = value
            with self.assertRaises(ValueError): review_address_context(json.dumps(document).encode(), **OPTIONS)

    def test_missing_metadata_and_zero_result_remain_explicitly_unknown(self):
        self.document['Reservations'][0]['Instances'] = [self.first]
        result = self.review()
        self.assertEqual(result['shared_claims'], [])
        self.assertEqual(result['context_record_count'], 0)
        self.document['Reservations'] = []
        self.assertEqual(self.review()['asset_count'], 0)

    @unittest.skipUnless(os.name == 'posix', 'private CLI requires POSIX')
    def test_cli_publishes_selected_private_context_without_echo_or_overwrite(self):
        self.first['VpcId'] = 'vpc-00000001'
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'input.json', Path(directory) / 'context.json'
            original = json.dumps(self.document).encode(); source.write_bytes(original)
            args = ['review-context', str(source), '--scope', 'synthetic', '--account', OPTIONS['account'],
                    '--region', OPTIONS['region'], '--output', str(target)]
            with redirect_stdout(StringIO()) as out:
                self.assertEqual(main(args), 0)
            result = json.loads(out.getvalue())
            self.assertEqual(result['status'], 'ec2_address_context_review_created')
            self.assertEqual(result['context_record_count'], 20)
            self.assertNotIn('vpc-', out.getvalue())
            self.assertNotIn('111122223333', out.getvalue())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            saved = target.read_bytes()
            self.assertNotIn('checkout.example.test', saved.decode())
            self.assertNotIn('unselected-note', saved.decode())
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as errors:
                self.assertEqual(main(args), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(target), errors.getvalue())
            self.assertEqual(target.read_bytes(), saved)
            self.assertEqual(source.read_bytes(), original)

    def test_demo(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(exercise()['distinct_supplied_interface_vpcs'], 2)


if __name__ == '__main__':
    unittest.main()
