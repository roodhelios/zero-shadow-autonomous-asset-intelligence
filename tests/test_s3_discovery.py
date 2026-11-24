"""Saved bucket claims must remain scoped, bounded and traceable to original rows."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from engine.correlation import correlate_assets
from engine.discovery import s3_discovery as s3
from engine.discovery.fixture_discovery import load_fixture
from engine.models import AssetObservation

ACCOUNT = '123456789012'
ROOT = Path(__file__).resolve().parents[1]


def encoded(rows, **extra):
    return json.dumps(dict(Buckets=rows, **extra)).encode()


class S3DiscoveryTests(unittest.TestCase):
    def convert(self, data, account=ACCOUNT):
        return s3.convert_export(data, scope='synthetic', account=account)

    def test_example_correlates_without_network_and_retains_original_rows(self):
        data = (ROOT / 'examples/s3-list-buckets.json').read_bytes()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            document = self.convert(data)
            result = s3.inventory(document)
        self.assertEqual(result['asset_count'], 2)
        self.assertEqual(result['observation_count'], 2)
        self.assertEqual(document['import_metadata']['input_sha256'], hashlib.sha256(data).hexdigest())
        refs = document['import_metadata']['source_records']
        self.assertEqual([r['bucket_record'] for r in refs], [1, 2])
        self.assertTrue(refs[0]['source_record_id'].endswith('fixture-research-archive'))
        self.assertEqual(result['import_metadata']['coverage'], 'not_established')
        self.assertTrue(all(not a['ip_addresses'] and not a['hostnames'] for a in result['assets']))

    def test_account_scope_prevents_false_merge_via_source_key(self):
        data = encoded([{'Name': 'fixture-archive'}])
        documents = [self.convert(data, account=a) for a in (ACCOUNT, '210987654321')]
        observations = [AssetObservation.from_dict(s3.SOURCE, a) for d in documents for a in d['assets']]
        self.assertEqual(len(correlate_assets(observations)), 2)
        self.assertEqual(len(correlate_assets(observations[:1] * 2)), 1)

    def test_projection_omits_owner_and_unverified_security_fields(self):
        data = encoded([{'Name': 'fixture-archive', 'BucketRegion': 'us-east-1',
                         'PublicAccess': False, 'CreationDate': 'private marker'}],
                       Owner={'DisplayName': 'private owner', 'ID': 'private identifier'}, Prefix='fixture-')
        result = json.dumps(self.convert(data))
        for forbidden in ('private marker', 'private owner', 'private identifier', 'us-east-1', 'PublicAccess'):
            self.assertNotIn(forbidden, result)

    def test_empty_listing_has_zero_observations_and_unknown_coverage(self):
        result = s3.inventory(self.convert(encoded([])))
        self.assertEqual(result['asset_count'], 0)
        self.assertEqual(result['import_metadata']['coverage'], 'not_established')

    def test_unsupported_names(self):
        for name in ('ab', 'a' * 64, 'Uppercase', 'bucket_name', 'x..y', '192.168.1.2',
                     'xn--archive', 'sthree-archive', 'amzn-s3-demo-archive',
                     'fixture--x-s3', 'fixture--table-s3', 'fixture-s3alias', 'fixture--ol-s3',
                     'fixture.mrap', 'fixture-an', 'x\nprivate marker', None, 123):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.convert(encoded([{'Name': name}]))

    def test_bad_shapes_and_duplicate_names(self):
        for data in (b'[]', b'{}', b'{"Buckets":{}}', b'{"Buckets":[null]}',
                     b'{"Buckets":[{}]}', b'{"Buckets":[],"Buckets":[]}',
                     b'{"Buckets":[],"ignored":NaN}',
                     encoded([{'Name': 'fixture-archive'}] * 2),
                     encoded([{'Name': 'fixture-archive', 'BucketArn': 'arn:aws-cn:s3:::fixture-archive'}])):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.convert(data)

    def test_incomplete_pages_fail_and_empty_tokens_are_allowed(self):
        for key in ('NextToken', 'ContinuationToken'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.convert(encoded([], **{key: 'synthetic continuation'}))
            self.assertEqual(self.convert(encoded([], **{key: ''}))['assets'], [])

    def test_explicit_account_scope_and_bounds(self):
        for account in ('', '123', '12345678901x', 123456789012):
            with self.subTest(account=account), self.assertRaises(ValueError):
                self.convert(encoded([]), account=account)
        with self.assertRaises(ValueError):
            s3.convert_export(encoded([]), scope='public', account=ACCOUNT)
        with patch.object(s3, 'MAX_BUCKETS', 1), self.assertRaises(ValueError):
            self.convert(encoded([{'Name': 'fixture-one'}, {'Name': 'fixture-two'}]))
        with patch.object(s3, 'MAX_INPUT_BYTES', 1), self.assertRaises(ValueError):
            self.convert(encoded([]))

    @unittest.skipUnless(os.name == 'posix', 'private file handling requires POSIX')
    def test_cli_private_output_no_clobber_and_fixed_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'source.json', Path(directory)/'inventory.json'
            source.write_bytes(encoded([{'Name': 'fixture-archive'}]))
            argv = [str(source), '--scope', 'synthetic', '--account', ACCOUNT, '--output', str(output)]
            with patch('socket.socket', side_effect=AssertionError('network forbidden')):
                self.assertEqual(s3.main(argv), 0)
            before = output.read_bytes()
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                self.assertEqual(s3.main(argv), 2)
            self.assertEqual(output.read_bytes(), before)
            self.assertNotIn(directory, error.getvalue())
            source.write_bytes(b'{"Buckets":[{"Name":"private marker"}]}')
            output.unlink()
            with contextlib.redirect_stderr(error):
                self.assertEqual(s3.main(argv), 2)
            self.assertFalse(output.exists())
            self.assertNotIn('private marker', error.getvalue())
            link = Path(directory)/'link'; link.symlink_to(source)
            with contextlib.redirect_stderr(error):
                self.assertEqual(s3.main([str(link), *argv[1:]]), 2)

    def test_root_entry_point_runs_bundled_example(self):
        result = subprocess.run([sys.executable, '-m', 'engine', 'discover-s3',
            'examples/s3-list-buckets.json', '--scope', 'synthetic', '--account', ACCOUNT],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['asset_count'], 2)
        self.assertEqual(result.stderr, '')

    def test_fixture_output_loads_through_existing_asset_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'assets.json'
            args = [str(ROOT/'examples/s3-list-buckets.json'), '--scope', 'synthetic',
                    '--account', ACCOUNT, '--format', 'fixture', '--output', str(path)]
            self.assertEqual(s3.main(args), 0)
            batch = load_fixture(path)
            self.assertEqual(batch.source, s3.SOURCE)
            self.assertEqual(len(correlate_assets(batch.observations)), 2)

    def test_late_invalid_row_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'source.json', Path(directory)/'inventory.json'
            source.write_bytes(encoded([{'Name': 'fixture-archive'}, {'Name': 'invalid_name'}]))
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(s3.main([str(source), '--scope', 'synthetic', '--account', ACCOUNT,
                                          '--output', str(output)]), 2)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [source])


if __name__ == '__main__':
    unittest.main()
