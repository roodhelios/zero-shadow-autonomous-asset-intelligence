"""Ordered EC2 claims must reproduce before a timeline can be retained or verified."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import _canonical, store_ec2
from database.ec2_observation_timeline import build_timeline, export_timeline, main, verify_timeline
from database.inventory_assessment_verify import _snapshot
from engine.demo_ec2_timeline import timeline_exports

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'private closed evidence requires POSIX')
class EC2ObservationTimelineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.batches = []
        for day, data in enumerate(timeline_exports(), 24):
            self.batches.append((self.store(str(day), data, day), data))
        self.output = self.root/'timeline.json'

    def store(self, name, data, day, **options):
        source, database = self.root/(name+'.json'), self.root/(name+'.sqlite')
        source.write_bytes(data)
        store_ec2(source, database, scope=options.get('scope', 'synthetic'), account=options.get('account', '111122223333'),
                  region=options.get('region', 'us-east-1'), observed_at=datetime(2026, 10, day, tzinfo=timezone.utc))
        return database

    def test_omission_repeated_absence_and_observed_again_have_distinct_meanings(self):
        before = [p.read_bytes() for p, _ in self.batches]
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            report = build_timeline(self.batches)
        self.assertEqual(report['event_totals'], dict(first_observed=3, changed=1, unchanged=3, observed_again=1, not_observed=2))
        self.assertEqual(report['unique_asset_count'], 3)
        self.assertEqual(report['batches'][2]['counts']['not_observed'], 0)
        returned = next(e for e in report['batches'][3]['events'] if e['status'] == 'observed_again')
        self.assertEqual(returned['previous_observation']['batch_sequence'], 1)
        self.assertEqual(returned['previous_observation']['record']['source_reference']['instance_record'], 2)
        self.assertEqual(returned['current']['source_reference']['instance_record'], 2)
        self.assertEqual(returned['changed_fields_since_last_observation'], ['tags'])
        self.assertTrue(all(b['collection_completeness'] == 'not_established' for b in report['batches']))
        self.assertEqual(before, [p.read_bytes() for p, _ in self.batches])
        self.assertNotIn('deleted', report['event_totals'])

    def test_reordered_rows_format_and_time_alone_are_unchanged(self):
        data = json.loads(self.batches[0][1]); data['Reservations'][0]['Instances'].reverse()
        rendered = json.dumps(data, indent=4).encode()
        batches = [self.batches[0], (self.store('reordered', rendered, 25), rendered)]
        report = build_timeline(batches)
        self.assertEqual(report['batches'][1]['counts']['unchanged'], 2)
        self.assertEqual(report['batches'][1]['counts']['changed'], 0)
        self.assertNotEqual(report['batches'][0]['snapshot_sha256'], report['batches'][1]['snapshot_sha256'])

    def test_each_database_is_reproduced_once_and_only_copied_snapshots_are_used(self):
        def copy_remove(source, destination):
            _snapshot(source, destination); source.unlink()
        with patch('database.ec2_inventory._snapshot', side_effect=copy_remove) as copied:
            report = build_timeline(self.batches)
        self.assertEqual(copied.call_count, 4); self.assertEqual(report['batch_count'], 4)

    def test_context_and_chronology_fail_before_publication(self):
        data = self.batches[1][1]
        for name, day, options in [('scope', 25, {'scope':'owned'}), ('region', 25, {'region':'us-west-2'}),
                                   ('equal',24,{}), ('older',23,{})]:
            candidate = (self.store(name, data, day, **options), data)
            with self.assertRaises(ValueError): export_timeline([self.batches[0], candidate], self.output)
            self.assertFalse(self.output.exists())
        data = json.loads(data); data['Reservations'][0]['OwnerId'] = '444455556666'; data = json.dumps(data).encode()
        candidate = (self.store('account', data, 25, account='444455556666'), data)
        with self.assertRaises(ValueError): build_timeline([self.batches[0], candidate])

    def test_every_exact_original_export_is_required(self):
        for i in range(4):
            batches = list(self.batches); database, data = batches[i]; batches[i] = (database, data+b'\n')
            with self.assertRaises(ValueError): export_timeline(batches, self.output)
            self.assertFalse(self.output.exists())

    def test_tampered_database_is_not_a_legitimate_transition(self):
        with sqlite3.connect(self.batches[-1][0]) as connection:
            connection.execute("UPDATE assets SET primary_hostname='changed.example.test'")
        with self.assertRaises(ValueError): export_timeline(self.batches, self.output)
        self.assertFalse(self.output.exists())

    def test_complete_report_and_independent_pin_are_both_required(self):
        result = export_timeline(self.batches, self.output)
        original = self.output.read_bytes()
        verified = verify_timeline(self.output, self.batches, expected_sha256=result['report_sha256'])
        self.assertEqual(verified['status'], 'ec2_observation_timeline_reproduced')
        for pin in ('0'*64, 'ABC', None):
            with self.assertRaises(ValueError): verify_timeline(self.output, self.batches, expected_sha256=pin)
        for change in ('counts', 'events', 'context', 'digest', 'coverage'):
            document = json.loads(original)
            if change == 'counts': document['event_totals']['observed_again'] = 0
            elif change == 'events': document['batches'][3]['events'][0]['status'] = 'recreated'
            elif change == 'context': document['batches'][0]['import_context']['scope'] = 'owned'
            elif change == 'digest': document['batches'][0]['snapshot_sha256'] = '0'*64
            else: document['batches'][0]['collection_completeness'] = 'complete'
            altered = (_canonical(document)+'\n').encode('ascii'); self.output.write_bytes(altered)
            with self.assertRaises(ValueError):
                verify_timeline(self.output, self.batches, expected_sha256=hashlib.sha256(altered).hexdigest())
        self.output.write_bytes(original)
        with self.assertRaises(ValueError): verify_timeline(self.output, self.batches[:-1], expected_sha256=result['report_sha256'])

    def test_older_consistent_prefix_is_rejected_by_current_pin(self):
        result = export_timeline(self.batches, self.output)
        prefix = self.root/'prefix.json'; old = export_timeline(self.batches[:2], prefix)
        self.assertEqual(verify_timeline(prefix, self.batches[:2], expected_sha256=old['report_sha256'])['batch_count'], 2)
        with self.assertRaises(ValueError): verify_timeline(prefix, self.batches[:2], expected_sha256=result['report_sha256'])

    def test_count_byte_and_output_bounds_fail_without_output(self):
        for batches in ([], self.batches[:1], self.batches*5):
            with self.assertRaises(ValueError): export_timeline(batches, self.output)
        with patch('database.ec2_observation_timeline.MAX_TOTAL_EXPORT_BYTES', 1):
            with self.assertRaises(ValueError): export_timeline(self.batches, self.output)
        with patch('database.ec2_observation_timeline.MAX_REPORT_BYTES', 1):
            with self.assertRaises(ValueError): export_timeline(self.batches, self.output)
        self.assertFalse(self.output.exists())

    def test_symlink_wal_and_report_symlink_are_rejected(self):
        database, data = self.batches[0]; link = self.root/'linked.sqlite'; link.symlink_to(database)
        with self.assertRaises((OSError, ValueError)): build_timeline([(link,data),self.batches[1]])
        wal = Path(str(database)+'-wal'); wal.touch()
        with self.assertRaises(ValueError): build_timeline(self.batches)
        wal.unlink(); result = export_timeline(self.batches, self.output)
        link = self.root/'linked.json'; link.symlink_to(self.output)
        with self.assertRaises((OSError, ValueError)):
            verify_timeline(link, self.batches, expected_sha256=result['report_sha256'])

    def test_cli_metadata_only_output_private_exclusive_and_failure(self):
        batches = [arg for day,(p,_) in enumerate(self.batches,24) for arg in ('--batch',str(p),str(self.root/f'{day}.json'))]
        stdout = StringIO()
        with redirect_stdout(stdout): self.assertEqual(main(['create',*batches,'--output',str(self.output)]),0)
        result = json.loads(stdout.getvalue()); original = self.output.read_bytes()
        self.assertEqual(self.output.stat().st_mode&0o777,0o600)
        for private in ('111122223333','192.0.2.40','i-0123456789abcdef0',str(self.root)):
            self.assertNotIn(private,stdout.getvalue())
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['verify',str(self.output),*batches,'--expected-sha256',result['report_sha256']]),0)
        with redirect_stderr(StringIO()): self.assertEqual(main(['create',*batches,'--output',str(self.output)]),2)
        self.assertEqual(self.output.read_bytes(),original)
        stdout = StringIO()
        with redirect_stdout(stdout),redirect_stderr(StringIO()):
            self.assertEqual(main(['verify',str(self.output),*batches,'--expected-sha256','0'*64]),2)
        self.assertEqual(stdout.getvalue(),'')

    def test_fresh_standard_library_walkthrough(self):
        run = subprocess.run([sys.executable,'-S','-m','engine.demo_ec2_timeline'],cwd=ROOT,
                             capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result['status'],'ec2_timeline_exercise_passed')
        self.assertEqual(result['event_totals']['observed_again'],1)
        self.assertEqual(result['negative_cases_rejected'],3)


if __name__ == '__main__':
    unittest.main()
