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

from database.ec2_assessment import retain_assessment, current_model
from database.ec2_assessment_compare import compare_assessments, export_comparison, main
from database.ec2_inventory import store_ec2

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT/'examples/ec2-describe-instances.json'
DIRECTORY = ROOT/'examples/ownership-directory.json'
FINDINGS = ROOT/'examples/ec2-findings.jsonl'


@unittest.skipUnless(os.name == 'posix', 'private receipts require POSIX')
class EC2ComparisonTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.discovery = self.root/'discovery.sqlite'
        store_ec2(EXPORT, self.discovery, scope='synthetic', account='111122223333',
                  region='us-east-1', observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.old = self.receipt('old', '2026-10-25')

    def receipt(self, name, day, data=None, directory=None, discovery=None):
        path = self.root/(name+'.sqlite')
        retain_assessment(discovery or self.discovery, FINDINGS.read_bytes() if data is None else data,
                          DIRECTORY.read_bytes() if directory is None else directory, path,
                          export_data=EXPORT.read_bytes(), as_of=date.fromisoformat(day),
                          assessed_at=datetime.fromisoformat(day+'T01:00:00+00:00'))
        return path

    def compare(self, new):
        return compare_assessments(self.old, new, export_data=EXPORT.read_bytes())

    def test_later_date_explains_overdue_without_changing_risk_or_inputs(self):
        new = self.receipt('new', '2027-01-01')
        saved = {p: p.read_bytes() for p in (self.old, new, EXPORT)}
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            report = self.compare(new)
        self.assertEqual(report['counts'], dict(added=0, omitted=0, changed=1, unchanged=0))
        change = report['changes'][0]
        self.assertIn('overdue', change['changed_fields'])
        self.assertFalse(change['previous']['overdue']); self.assertTrue(change['current']['overdue'])
        self.assertEqual(change['previous']['risk_assessment'], change['current']['risk_assessment'])
        self.assertFalse(report['review_inputs_changed'])
        self.assertEqual(saved, {p: p.read_bytes() for p in saved})

    def test_equal_receipts_are_unchanged(self):
        report = self.compare(self.old)
        self.assertEqual(report['counts'], dict(added=0, omitted=0, changed=0, unchanged=1))
        self.assertEqual(report['changes'], [])

    def test_changed_risk_and_unassigned_routing_are_visible(self):
        item = json.loads(FINDINGS.read_bytes()); item['finding']['severity'] = 'critical'; item['asset_tags'] = {}
        report = self.compare(self.receipt('new', '2026-10-26', json.dumps(item).encode()))
        self.assertTrue(report['review_inputs_changed'])
        change = report['changes'][0]
        self.assertIn('risk_assessment', change['changed_fields'])
        self.assertIn('ownership_resolution', change['changed_fields'])
        self.assertIsNone(change['current']['owner'])

    def test_changed_input_bytes_can_leave_decisions_unchanged(self):
        report = self.compare(self.receipt('new', '2026-10-25', FINDINGS.read_bytes()+b'\n'))
        self.assertTrue(report['review_inputs_changed'])
        self.assertEqual(report['counts']['unchanged'], 1)

    def test_added_and_omitted_do_not_mean_resolution(self):
        item = json.loads(FINDINGS.read_bytes()); item['finding']['finding_id'] = 'synthetic-replacement'
        report = self.compare(self.receipt('new', '2026-10-26', json.dumps(item).encode()))
        self.assertEqual(report['counts'], dict(added=1, omitted=1, changed=0, unchanged=0))
        self.assertEqual(report['omitted'][0]['finding_id'], 'synthetic-ec2-review')
        self.assertIn('not proof of resolution', report['interpretation'])

    def test_different_discovery_context_and_reversed_dates_fail(self):
        other = self.root/'other-discovery.sqlite'
        store_ec2(EXPORT, other, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, 1, tzinfo=timezone.utc))
        with self.assertRaisesRegex(ValueError, 'same discovery'):
            self.compare(self.receipt('other', '2026-10-26', discovery=other))
        with self.assertRaisesRegex(ValueError, 'precede'):
            compare_assessments(self.receipt('later', '2026-10-26'), self.old, export_data=EXPORT.read_bytes())

    def test_reused_finding_id_cannot_move_to_another_asset(self):
        from copy import deepcopy
        from database.ec2_inventory import read_ec2
        document = json.loads(EXPORT.read_bytes())
        second = deepcopy(document['Reservations'][0]['Instances'][0])
        second['InstanceId'] = 'i-0123456789abcdef1'
        second['PrivateIpAddress'] = '192.0.2.41'; second['PublicIpAddress'] = '198.51.100.41'
        document['Reservations'][0]['Instances'].append(second)
        data = json.dumps(document).encode(); source = self.root/'two.json'; source.write_bytes(data)
        discovery = self.root/'two.sqlite'
        store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        asset_ids = sorted(item['asset']['asset_id'] for item in read_ec2(discovery, data)['assets'])
        self.assertEqual(len(asset_ids), 2)
        receipts = []
        for index, asset_id in enumerate(asset_ids):
            item = json.loads(FINDINGS.read_bytes()); item['finding']['asset_id'] = asset_id
            output = self.root/('moved-'+str(index)+'.sqlite')
            retain_assessment(discovery, json.dumps(item).encode(), DIRECTORY.read_bytes(), output,
                export_data=data, as_of=date(2026, 10, 25),
                assessed_at=datetime(2026, 10, 25, index+1, tzinfo=timezone.utc))
            receipts.append(output)
        with self.assertRaisesRegex(ValueError, 'moved between assets'):
            compare_assessments(*receipts, export_data=data)

    def test_equal_review_date_still_rejects_reversed_assessment_instants(self):
        late = self.root/'late.sqlite'
        retain_assessment(self.discovery, FINDINGS.read_bytes(), DIRECTORY.read_bytes(), late,
            export_data=EXPORT.read_bytes(), as_of=date(2026, 10, 25),
            assessed_at=datetime(2026, 10, 25, 2, tzinfo=timezone.utc))
        with self.assertRaisesRegex(ValueError, 'precede'):
            compare_assessments(late, self.old, export_data=EXPORT.read_bytes())

    def test_recomputed_checksum_does_not_hide_tampered_decisions(self):
        new = self.receipt('new', '2026-10-26')
        with sqlite3.connect(new) as connection:
            connection.execute('DROP TRIGGER assessment_no_update')
            record = json.loads(connection.execute('SELECT payload_json FROM ec2_assessment_record').fetchone()[0])
            record['queue_report']['queues']['queues'][0]['items'][0]['priority'] = 'P0'
            payload = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
            connection.execute('UPDATE ec2_assessment_record SET payload_json=?,payload_sha256=?',
                               (payload, hashlib.sha256(payload.encode()).hexdigest()))
        output = self.root/'bad.json'
        with self.assertRaises(ValueError): export_comparison(self.old, new, output, export_data=EXPORT.read_bytes())
        self.assertFalse(output.exists())

    def test_both_receipts_and_original_export_are_required(self):
        new = self.receipt('new', '2026-10-26')
        with self.assertRaises(ValueError): compare_assessments(self.old, new, export_data=EXPORT.read_bytes()+b'\n')
        altered = current_model(); altered['model_version'] = 2
        with patch('database.ec2_assessment.current_model', return_value=altered), self.assertRaises(ValueError):
            self.compare(new)
        with self.assertRaises(OSError): compare_assessments(self.root/'missing', new, export_data=EXPORT.read_bytes())

    def test_private_publication_no_overwrite_and_aggregate_only_cli(self):
        new = self.receipt('new', '2027-01-01'); output = self.root/'comparison.json'
        args = [str(self.old), str(new), '--export', str(EXPORT), '--output', str(output)]
        stdout = StringIO()
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        self.assertEqual(json.loads(stdout.getvalue())['changed'], 1)
        for private in ('synthetic-ec2-review', 'cloud-platform', '111122223333', '192.0.2.40'):
            self.assertNotIn(private, stdout.getvalue())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        saved = output.read_bytes()
        with redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
        self.assertEqual(saved, output.read_bytes())

    def test_output_bound_and_invalid_current_publish_nothing(self):
        output = self.root/'limited.json'
        with patch('database.ec2_assessment_compare.MAX_REPORT_BYTES', 1), self.assertRaises(ValueError):
            export_comparison(self.old, self.old, output, export_data=EXPORT.read_bytes())
        self.assertFalse(output.exists())
        with redirect_stderr(StringIO()):
            self.assertEqual(main([str(self.old), str(self.root/'missing'), '--export', str(EXPORT),
                                   '--output', str(output)]), 2)
        self.assertFalse(output.exists())


if __name__ == '__main__': unittest.main()
