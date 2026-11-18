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

from engine.discovery import ec2_address_review as review

ROOT = Path(__file__).resolve().parents[1]


class AddressReviewTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / 'examples/ec2-interface-addresses.json').read_bytes())

    def run_review(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            return review.review_addresses(json.dumps(self.document).encode(), scope='synthetic',
                                           account='111122223333', region='us-east-1')

    def add_copy(self):
        other = copy.deepcopy(self.document['Reservations'][0]['Instances'][0])
        other['InstanceId'] = 'i-0123456789abcdef1'
        self.document['Reservations'][0]['Instances'].append(other)
        return other

    def test_duplicate_paths_within_one_identity_do_not_count_as_shared(self):
        result = self.run_review()
        self.assertEqual(result['asset_count'], 1)
        self.assertEqual(result['shared_claims'], [])
        self.assertEqual(result['shared_identity_count'], 0)

    def test_shared_claims_preserve_distinct_identities_and_exact_row_references(self):
        self.add_copy()
        result = self.run_review()
        self.assertEqual(result, self.run_review())
        self.assertEqual((result['asset_count'], result['shared_address_count'], result['shared_identity_count']), (2, 6, 2))
        self.assertEqual(result['original_sha256'], hashlib.sha256(json.dumps(self.document).encode()).hexdigest())
        for item in result['shared_claims']:
            self.assertEqual(item['identity_count'], 2)
            self.assertEqual(len({r['cloud_resource_id'] for r in item['observations']}), 2)
            self.assertEqual([r['source_reference']['instance_record'] for r in item['observations']], [1, 2])
            self.assertTrue(all(r['source_reference']['reservation_record'] == 1 for r in item['observations']))
        self.assertEqual({item['address_family'] for item in result['shared_claims']}, {4, 6})

    def test_ipv6_equivalent_spelling_counts_once_per_identity(self):
        other = self.add_copy()
        other['NetworkInterfaces'][0]['Ipv6Addresses'][0]['Ipv6Address'] = '2001:0DB8:0:0:0:0:0:40'
        result = self.run_review()
        claim = next(item for item in result['shared_claims'] if item['address'] == '2001:db8::40')
        self.assertEqual(claim['identity_count'], 2)

    def test_empty_export_and_no_common_addresses_are_valid(self):
        other = self.add_copy()
        other.pop('NetworkInterfaces')
        other.pop('PublicIpAddress', None)
        other.pop('Ipv6Address', None)
        other['PrivateIpAddress'] = '192.0.2.99'
        self.assertEqual(self.run_review()['shared_claims'], [])
        self.document['Reservations'][0]['Instances'] = []
        self.assertEqual(self.run_review()['asset_count'], 0)
        self.assertEqual(self.run_review()['shared_claims'], [])

    def test_ambiguous_export_context_and_unfinished_pagination_reject(self):
        document = copy.deepcopy(self.document)
        document['NextToken'] = 'synthetic-incomplete'
        with self.assertRaises(ValueError):
            review.review_addresses(json.dumps(document).encode(), scope='synthetic', account='111122223333', region='us-east-1')
        for options in ({'scope': 'public'}, {'account': '000000000000'}, {'region': 'invalid'}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                review.review_addresses(json.dumps(self.document).encode(),
                    **({'scope': 'synthetic', 'account': '111122223333', 'region': 'us-east-1'} | options))
        self.add_copy()['InstanceId'] = self.document['Reservations'][0]['Instances'][0]['InstanceId']
        with self.assertRaises(ValueError): self.run_review()

    @unittest.skipUnless(os.name == 'posix', 'private CLI requires POSIX')
    def test_retained_cli_is_private_read_only_exclusive_and_minimized(self):
        self.add_copy()
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'source.json', Path(directory) / 'review.json'
            data = json.dumps(self.document).encode(); source.write_bytes(data)
            args = ['review', str(source), '--scope', 'synthetic', '--account', '111122223333',
                    '--region', 'us-east-1', '--output', str(target)]
            with redirect_stdout(StringIO()) as stdout:
                self.assertEqual(review.main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())['shared_address_count'], 6)
            self.assertNotIn('111122223333', stdout.getvalue())
            self.assertNotIn('192.0.2.', stdout.getvalue())
            saved = target.read_bytes()
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as errors:
                self.assertEqual(review.main(args), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(target), errors.getvalue())
            self.assertEqual(target.read_bytes(), saved)
            self.assertEqual(source.read_bytes(), data)

    def test_render_bound_rejects(self):
        with patch.object(review, 'MAX_REPORT_BYTES', 1), self.assertRaises(ValueError):
            review._render(self.run_review())

    def test_demo(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            self.assertEqual(review.exercise()['shared_address_count'], 6)


if __name__ == '__main__':
    unittest.main()
