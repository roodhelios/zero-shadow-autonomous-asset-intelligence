"""Retained inputs produce dated queues only after complete pinned assessment replay."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from database.inventory_assessment_cli import retain_assessment
from database.inventory_assessment_queue import build_queues, main
from database.inventory_cli import store_export

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT/'examples'


@unittest.skipUnless(os.name == 'posix', 'private evidence requires POSIX')
class AssessmentQueueTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        discovery = self.root/'discovery.sqlite'
        self.database = self.root/'assessed.sqlite'
        self.original = EXAMPLES/'osquery-system-info-expanded.json'
        store_export(self.original, discovery, scope='synthetic',
                     observed_at=datetime(2026, 10, 23, tzinfo=timezone.utc))
        retain_assessment(discovery, (EXAMPLES/'inventory-findings.jsonl').read_bytes(),
            (EXAMPLES/'ownership-directory.json').read_bytes(), self.database, as_of=date(2026, 10, 23),
            assessed_at=datetime(2026, 10, 23, 1, tzinfo=timezone.utc), export_data=self.original.read_bytes())
        discovery.unlink()
        self.before = self.database.read_bytes()
        self.pin = hashlib.sha256(self.before).hexdigest()

    def build(self, **overrides):
        return build_queues(self.database, self.original.read_bytes(),
            **(dict(expected_database_sha256=self.pin, as_of=date(2026, 11, 15)) | overrides))

    def test_replans_from_retained_inputs_without_discovery_or_separate_assessment_files(self):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.build()
        self.assertEqual(result['assessment_verification']['status'], 'assessment_reproduced')
        self.assertEqual(result['assessment_verification']['model_binding']['status'], 'bound_current_model')
        queues = result['queue_document']
        self.assertEqual(queues['inventory_binding']['assets_without_supplied_findings'], 1)
        self.assertEqual(queues['queues']['assigned_item_count'], 1)
        change = queues['priority_comparison']['changes'][0]
        self.assertEqual((change['previous_priority'], change['current_priority']), ('P0', 'P0'))
        self.assertFalse(change['previous_overdue']); self.assertTrue(change['current_overdue'])
        self.assertEqual(self.database.read_bytes(), self.before)
        self.assertEqual(result, self.build())
        same = self.build(as_of=date(2026, 10, 23))
        self.assertEqual(same['queue_document']['priority_comparison']['changed_item_count'], 0)

    def test_bad_pin_rejects_before_database_sql_and_earlier_date_rejects(self):
        with patch('database.inventory_assessment_queue.verify_assessment', side_effect=AssertionError('must not replay')):
            for pin in ('not-a-pin', '0'*64):
                with self.assertRaises(ValueError): self.build(expected_database_sha256=pin)
        with self.assertRaises(ValueError): self.build(as_of=date(2026, 10, 22))
        with self.assertRaises(ValueError): self.build(as_of='2026-11-15')

    def test_changed_original_and_materially_changed_decisions_reject_even_with_new_database_pin(self):
        with self.assertRaises(ValueError):
            build_queues(self.database, self.original.read_bytes()+b'\n', expected_database_sha256=self.pin,
                         as_of=date(2026, 11, 15))
        with sqlite3.connect(self.database) as connection:
            connection.execute('DROP TRIGGER remediation_plans_no_update')
            connection.execute("UPDATE remediation_plans SET priority='P3'")
        new_pin = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with self.assertRaises(ValueError): self.build(expected_database_sha256=new_pin)

    def test_model_binding_and_closed_regular_database_required(self):
        sidecar = Path(str(self.database)+'-wal'); sidecar.write_bytes(b'synthetic')
        with self.assertRaises(ValueError): self.build()
        sidecar.unlink()
        link = self.root/'link.sqlite'; link.symlink_to(self.database)
        with self.assertRaises(OSError):
            build_queues(link, self.original.read_bytes(), expected_database_sha256=self.pin, as_of=date(2026, 11, 15))
        with sqlite3.connect(self.database) as connection:
            connection.execute('DROP TABLE inventory_assessment_model')
        with self.assertRaises(ValueError):
            self.build(expected_database_sha256=hashlib.sha256(self.database.read_bytes()).hexdigest())

    def test_single_original_database_capture_and_private_cli_publication(self):
        from database.inventory_assessment_queue import _snapshot
        snapshots = []
        def capture(source, destination):
            _snapshot(source, destination); snapshots.append(source)
            self.database.write_bytes(b'changed original after capture')
        with patch('database.inventory_assessment_queue._snapshot', side_effect=capture):
            result = self.build()
        self.assertEqual(snapshots, [self.database])
        self.assertEqual(result['database_sha256'], self.pin)
        self.database.write_bytes(self.before)
        output = self.root/'queue.json'
        args = [str(self.database), '--export', str(self.original), '--expected-database-sha256', self.pin,
                '--as-of', '2026-11-15', '--output', str(output)]
        with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
            self.assertEqual(main(args), 0)
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary['status'], 'assessment_queue_exported')
        self.assertEqual(summary['changed_item_count'], 1)
        self.assertEqual(summary['output_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertNotIn('synthetic-checkout-review', stdout.getvalue())
        self.assertNotIn(str(self.root), stdout.getvalue()+stderr.getvalue())
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        before = output.read_bytes()
        with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
            self.assertEqual(main(args), 2)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn(str(self.root), stderr.getvalue())
        self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__': unittest.main()
