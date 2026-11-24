"""Native S3 inventory retention replays the exact export and supplied account."""

from contextlib import redirect_stderr
from datetime import datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from database.inventory_cli import store_export, main
from database.inventory_export_cli import export_inventory

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'examples/s3-list-buckets.json'
ACCOUNT = '123456789012'
TIME = datetime(2026, 11, 24, tzinfo=timezone.utc)


@unittest.skipUnless(os.name == 'posix', 'private evidence requires POSIX')
class S3InventoryRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root/'inventory.sqlite'

    def retain(self, source=SOURCE, **options):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            return store_export(source, self.database, scope='synthetic', observed_at=TIME,
                                source_format='s3', account=options.get('account', ACCOUNT))

    def test_native_retention_replays_all_observations_and_original_rows(self):
        result = self.retain()
        self.assertEqual(result['observation_count'], 2)
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        report = export_inventory(self.database, export_data=SOURCE.read_bytes())
        receipt = report['import_reconciliation']['receipt']
        self.assertEqual(receipt['schema_version'], 2)
        self.assertEqual(receipt['source'], 'aws-s3-export')
        self.assertEqual(receipt['source_parameters'], {'account': ACCOUNT})
        self.assertEqual([r['bucket_record'] for r in receipt['source_records']], [1, 2])
        self.assertTrue(receipt['source_records'][0]['source_record_id'].endswith('fixture-research-archive'))
        self.assertTrue(report['import_reconciliation']['original_export_checked'])
        self.assertTrue(all(not a['findings'] for a in report['assets']))

    def test_changed_bytes_even_unselected_fields_fail_original_replay(self):
        self.retain()
        data = json.loads(SOURCE.read_bytes()); data['Owner'] = {'ID': 'synthetic change'}
        with self.assertRaises(ValueError):
            export_inventory(self.database, export_data=json.dumps(data).encode())

    def test_reordered_original_rows_are_not_silently_relabelled(self):
        self.retain()
        data = json.loads(SOURCE.read_bytes()); data['Buckets'].reverse()
        with self.assertRaises(ValueError):
            export_inventory(self.database, export_data=json.dumps(data).encode())

    def test_account_tamper_fails_even_with_recomputed_receipt_digest(self):
        self.retain()
        with sqlite3.connect(self.database) as connection:
            connection.execute('DROP TRIGGER inventory_receipt_no_update')
            receipt = json.loads(connection.execute('SELECT payload_json FROM inventory_import_receipt').fetchone()[0])
            receipt['source_parameters']['account'] = '210987654321'
            payload = json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
            connection.execute('UPDATE inventory_import_receipt SET payload_json=?, receipt_sha256=?',
                               (payload, hashlib.sha256(payload.encode()).hexdigest()))
        with self.assertRaises(ValueError):
            export_inventory(self.database)

    def test_bad_source_context_empty_export_and_existing_output_leave_no_new_files(self):
        empty = self.root/'empty.json'; empty.write_text('{"Buckets":[]}')
        for source, account in ((SOURCE, None), (SOURCE, 'bad'), (empty, ACCOUNT)):
            with self.subTest(account=account), self.assertRaises(ValueError):
                self.retain(source, account=account)
            self.assertFalse(self.database.exists())
            self.assertEqual(list(self.root.iterdir()), [empty])
        self.retain()
        before = self.database.read_bytes()
        with self.assertRaises(OSError):
            self.retain()
        self.assertEqual(self.database.read_bytes(), before)

    def test_cli_missing_account_has_fixed_failure_and_no_output(self):
        errors = StringIO()
        with redirect_stderr(errors):
            result = main([str(SOURCE), '--output', str(self.database), '--scope', 'synthetic',
                           '--observed-at', '2026-11-24T00:00:00Z', '--source-format', 's3'])
        self.assertEqual(result, 2)
        self.assertFalse(self.database.exists())
        self.assertNotIn(str(self.root), errors.getvalue())


if __name__ == '__main__':
    unittest.main()
