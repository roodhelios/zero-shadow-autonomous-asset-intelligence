"""An S3 assessment must replay its original listing and source-specific model."""

from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database.assessment_archive import create_archive
from database.assessment_model import current_contract
from database.inventory_assessment_cli import retain_assessment
from database.inventory_assessment_verify import verify_assessment
from database.inventory_assessment_queue import build_queues
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/'examples/s3-list-buckets.json'


@unittest.skipUnless(os.name == 'posix', 'private evidence requires POSIX')
class S3AssessmentWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.discovery, self.assessment = self.root/'discovery.sqlite', self.root/'assessment.sqlite'
        self.data = EXPORT.read_bytes()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            store_export(EXPORT, self.discovery, scope='synthetic', source_format='s3',
                account='123456789012', observed_at=datetime(2026, 11, 24, tzinfo=timezone.utc))
            self.stored = retain_assessment(self.discovery,
                (ROOT/'examples/s3-inventory-findings.jsonl').read_bytes(),
                (ROOT/'examples/ownership-directory.json').read_bytes(), self.assessment,
                as_of=date(2026, 11, 24), assessed_at=datetime(2026, 11, 24, 1, tzinfo=timezone.utc),
                export_data=self.data)

    def test_replay_needs_only_retained_assessment_and_original_export(self):
        self.discovery.unlink()
        before = self.assessment.read_bytes()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = verify_assessment(self.assessment, self.data, require_model_binding=True)
        self.assertEqual(result['status'], 'assessment_reproduced')
        self.assertEqual(result['asset_count'], 2)
        self.assertEqual(result['finding_count'], 1)
        self.assertEqual(result['model_binding']['source'], 'aws-s3-export')
        self.assertEqual(result['model_binding']['model_version'], 2)
        self.assertEqual(self.assessment.read_bytes(), before)

    def test_queue_preserves_unassessed_asset_and_requires_exact_database_pin(self):
        pin = hashlib.sha256(self.assessment.read_bytes()).hexdigest()
        result = build_queues(self.assessment, self.data, expected_database_sha256=pin,
                              as_of=date(2026, 12, 10))
        binding = result['queue_document']['inventory_binding']
        self.assertEqual(binding['asset_count'], 2)
        self.assertEqual(binding['assets_with_supplied_findings'], 1)
        self.assertEqual(binding['assets_without_supplied_findings'], 1)
        self.assertEqual(result['assessment_verification']['model_binding']['model_version'], 2)
        with self.assertRaises(ValueError):
            build_queues(self.assessment, self.data, expected_database_sha256='0'*64,
                         as_of=date(2026, 12, 10))

    def test_changed_original_and_stored_plan_are_rejected(self):
        with self.assertRaises(ValueError):
            verify_assessment(self.assessment, self.data+b'\n', require_model_binding=True)
        with sqlite3.connect(self.assessment) as connection:
            connection.execute('DROP TRIGGER remediation_plans_no_update')
            connection.execute("UPDATE remediation_plans SET priority='P3'")
        with self.assertRaises(ValueError):
            verify_assessment(self.assessment, self.data, require_model_binding=True)

    def test_valid_osquery_model_cannot_label_an_s3_assessment(self):
        with sqlite3.connect(self.assessment) as connection:
            connection.execute('DROP TRIGGER assessment_model_no_update')
            payload = json.dumps(current_contract(), sort_keys=True, ensure_ascii=True, separators=(',', ':'))
            connection.execute('UPDATE inventory_assessment_model SET contract_json=?, binding_sha256=?',
                               (payload, hashlib.sha256(payload.encode()).hexdigest()))
        with self.assertRaises(ValueError):
            verify_assessment(self.assessment, self.data, require_model_binding=True)

    def test_s3_model_binds_importer_and_receipt_code_without_changing_legacy_contract(self):
        legacy, s3 = current_contract(), current_contract(source='aws-s3-export')
        self.assertEqual(legacy['model_version'], 1)
        self.assertNotIn('source', legacy)
        self.assertEqual(s3['model_version'], 2)
        self.assertTrue({'engine/discovery/s3_discovery.py', 'database/inventory_receipt.py',
                         'database/inventory_cli.py'} <= set(s3['implementation_sha256']))
        changed = current_contract(source='aws-s3-export')
        changed['implementation_sha256']['engine/discovery/s3_discovery.py'] = '0'*64
        with patch('database.assessment_model.current_contract', return_value=changed), self.assertRaises(ValueError):
            verify_assessment(self.assessment, self.data, require_model_binding=True)

    def test_osquery_archive_format_cannot_mislabel_s3_source(self):
        output = self.root/'archive.json'
        with self.assertRaisesRegex(ValueError, 'osquery model version 1'):
            create_archive(self.assessment, output, export_data=self.data)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
