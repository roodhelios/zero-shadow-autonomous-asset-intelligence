"""Recipient expectations stay independent of a source-reproduced candidate sequence."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database.ec2_inventory import _canonical, store_ec2
from database.ec2_timeline_checkpoint import (assess_sequence, export_checkpoint_review, main,
                                            read_checkpoint, verify_checkpoint_review)
from database.inventory_assessment_verify import _snapshot
from engine.demo_ec2_timeline import timeline_exports


@unittest.skipUnless(os.name == 'posix','private SQLite reproduction requires POSIX')
class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batches = []
        self.slots = []
        for day, data in enumerate(timeline_exports()[:3],24):
            at = datetime(2026,10,day,tzinfo=timezone.utc)
            self.batches.append((self.store(str(day),data,at),data))
            self.slots.append(dict(observed_at=at.isoformat().replace('+00:00','Z'),export_sha256=hashlib.sha256(data).hexdigest()))
        self.checkpoint = self.render()
        self.pin = hashlib.sha256(self.checkpoint).hexdigest()
        self.output = self.root/'review.json'

    def store(self, name, data, at):
        source, database = self.root/(name+'.json'), self.root/(name+'.sqlite')
        source.write_bytes(data)
        store_ec2(source,database,scope='synthetic',account='111122223333',region='us-east-1',observed_at=at)
        return database

    def render(self, **changes):
        document = dict(schema_version=1,checkpoint_type='ec2-observation-sequence',scope='synthetic',
                        account='111122223333',region='us-east-1',expected_batches=self.slots)
        document.update(changes)
        return (_canonical(document)+'\n').encode()

    def assess(self, batches=None, data=None):
        data = self.checkpoint if data is None else data
        return assess_sequence(self.batches if batches is None else batches,data,
                               expected_checkpoint_sha256=hashlib.sha256(data).hexdigest())

    def test_complete_checkpoint_and_missing_middle_have_different_outcomes(self):
        complete = self.assess()
        self.assertTrue(complete['requirements_satisfied'])
        report = self.assess([self.batches[0],self.batches[2]])
        self.assertFalse(report['requirements_satisfied'])
        self.assertEqual(report['counts'],dict(matched=2,missing_batch=1,export_mismatch=0,unexpected_batch=0))
        self.assertIsNone(report['expected_batches'][1]['supplied_sequence'])
        self.assertEqual(report['expected_batches'][2]['supplied_sequence'],2)
        self.assertEqual(report['collection_completeness'],'not_established')

    def test_reproduced_but_unexpected_time_remains_a_gap(self):
        data = self.batches[-1][1]
        extra = (self.store('extra',data,datetime(2026,10,27,tzinfo=timezone.utc)),data)
        report = self.assess(self.batches+[extra])
        self.assertEqual(report['counts']['unexpected_batch'],1)
        self.assertEqual(report['unexpected_batches'][0]['supplied_sequence'],4)
        self.assertFalse(report['requirements_satisfied'])

    def test_changed_export_with_valid_new_database_is_not_the_expected_checkpoint(self):
        data = self.batches[1][1]+b'\n'
        changed = (self.store('different',data,datetime(2026,10,25,tzinfo=timezone.utc)),data)
        report = self.assess([self.batches[0],changed,self.batches[2]])
        self.assertEqual(report['counts']['export_mismatch'],1)
        self.assertEqual(report['expected_batches'][1]['status'],'export_mismatch')

    def test_invalid_pin_fails_before_candidate_reproduction(self):
        with patch('database.ec2_timeline_checkpoint.build_timeline',side_effect=AssertionError('must not reproduce')):
            with self.assertRaises(ValueError):
                assess_sequence(self.batches,self.checkpoint,expected_checkpoint_sha256='0'*64)

    def test_context_is_independent_of_the_candidate(self):
        for changes in ({'scope':'owned'},{'account':'444455556666'},{'region':'us-west-2'}):
            with self.assertRaises(ValueError):
                self.assess(data=self.render(**changes))

    def test_checkpoint_contract_rejects_unknown_duplicate_boolean_nonfinite_and_bad_slots(self):
        cases = [self.render(schema_version=True), self.render(extra=True), b'{"schema_version":1,"schema_version":1}',
                 self.render(expected_batches=[]), self.render(expected_batches=self.slots[::-1]),
                 self.render(expected_batches=[self.slots[0],self.slots[0]]),
                 self.render(expected_batches=[dict(self.slots[0],extra=True),self.slots[1]]),
                 self.render(expected_batches=[dict(self.slots[0],export_sha256='A'*64),self.slots[1]]),
                 self.render(expected_batches=[dict(self.slots[0],observed_at='2026-10-24T00:00:00+00:00'),self.slots[1]]),
                 self.checkpoint.replace(b'"schema_version":1',b'"schema_version":NaN')]
        for data in cases:
            with self.subTest(data_length=len(data)),self.assertRaises(ValueError):
                read_checkpoint(data,expected_sha256=hashlib.sha256(data).hexdigest())

    def test_each_database_reproduced_once_and_verified_copies_are_used(self):
        def capture(source,destination):
            _snapshot(source,destination)
            source.unlink()
        with patch('database.ec2_inventory._snapshot',side_effect=capture) as copied:
            self.assertTrue(self.assess()['requirements_satisfied'])
        self.assertEqual(copied.call_count,3)

    def test_bad_database_or_original_never_publishes_a_gap_report(self):
        batches = list(self.batches)
        batches[1] = (batches[1][0],batches[1][1]+b'\n')
        with self.assertRaises(ValueError):
            export_checkpoint_review(batches,self.checkpoint,self.output,expected_checkpoint_sha256=self.pin)
        self.assertFalse(self.output.exists())

    def test_private_exclusive_report_full_reproduction_and_unchanged_inputs(self):
        before = [p.read_bytes() for p,_ in self.batches]
        result = export_checkpoint_review(self.batches,self.checkpoint,self.output,expected_checkpoint_sha256=self.pin)
        verified = verify_checkpoint_review(self.output,self.batches,self.checkpoint,
            expected_checkpoint_sha256=self.pin,expected_report_sha256=result['report_sha256'])
        self.assertTrue(verified['report_reproduced'])
        self.assertEqual(self.output.stat().st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError):
            export_checkpoint_review(self.batches,self.checkpoint,self.output,expected_checkpoint_sha256=self.pin)
        self.assertEqual(before,[p.read_bytes() for p,_ in self.batches])

    def test_recalculated_report_digest_does_not_hide_changed_coverage(self):
        export_checkpoint_review(self.batches,self.checkpoint,self.output,expected_checkpoint_sha256=self.pin)
        report = json.loads(self.output.read_bytes())
        report['expected_batches'][0]['supplied_sequence'] = 2
        data = (_canonical(report)+'\n').encode()
        self.output.write_bytes(data)
        with self.assertRaises(ValueError):
            verify_checkpoint_review(self.output,self.batches,self.checkpoint,expected_checkpoint_sha256=self.pin,
                                     expected_report_sha256=hashlib.sha256(data).hexdigest())

    def test_stale_consistent_prefix_fails_current_checkpoint_and_report_pin(self):
        previous = self.render(expected_batches=self.slots[:2])
        result = export_checkpoint_review(self.batches[:2],previous,self.output,
            expected_checkpoint_sha256=hashlib.sha256(previous).hexdigest())
        with self.assertRaises(ValueError):
            verify_checkpoint_review(self.output,self.batches[:2],self.checkpoint,
                expected_checkpoint_sha256=self.pin,expected_report_sha256=result['report_sha256'])
        self.assertEqual(self.assess(self.batches[:2])['counts']['missing_batch'],1)

    def test_bounds_symlinks_and_sidecars(self):
        with patch('database.ec2_timeline_checkpoint.MAX_CHECKPOINT_BYTES',1):
            with self.assertRaises(ValueError):
                self.assess()
        with patch('database.ec2_timeline_checkpoint.MAX_COVERAGE_BYTES',1):
            with self.assertRaises(ValueError):
                export_checkpoint_review(self.batches,self.checkpoint,self.output,expected_checkpoint_sha256=self.pin)
        self.assertFalse(self.output.exists())
        sidecar = Path(str(self.batches[0][0])+'-wal')
        sidecar.touch()
        with self.assertRaises(ValueError):
            self.assess()
        sidecar.unlink()
        alias = self.root/'alias.sqlite'
        alias.symlink_to(self.batches[0][0])
        with self.assertRaises((ValueError,OSError)):
            self.assess([(alias,self.batches[0][1]),*self.batches[1:]])

    def test_cli_reports_gaps_as_exit_one_without_private_times_or_context(self):
        checkpoint = self.root/'checkpoint.json'
        checkpoint.write_bytes(self.checkpoint)
        args = ['create','--checkpoint',str(checkpoint),'--expected-checkpoint-sha256',self.pin,
                '--output',str(self.output)]
        for database,_ in (self.batches[0],self.batches[2]):
            args += ['--batch',str(database),str(database.with_suffix('.json'))]
        out,err = StringIO(),StringIO()
        with redirect_stdout(out),redirect_stderr(err):
            self.assertEqual(main(args),1)
        result = json.loads(out.getvalue())
        self.assertEqual(result['counts']['missing_batch'],1)
        for private in ('111122223333','us-east-1','2026-10-',str(self.root)):
            self.assertNotIn(private,out.getvalue())
        self.assertEqual(err.getvalue(),'')
        with redirect_stdout(StringIO()),redirect_stderr(StringIO()):
            self.assertEqual(main(args),2)  # Existing output is preserved.

    def test_fresh_standard_library_walkthrough(self):
        result = subprocess.run([sys.executable,'-S','-m','engine.demo_ec2_checkpoint'],check=True,
                                capture_output=True,text=True)
        value = json.loads(result.stdout)
        self.assertEqual(value['missing_expected_batches'],1)
        self.assertTrue(value['gap_report_reproduced'])
        self.assertTrue(value['complete_sequence_satisfied'])
        self.assertTrue(value['inputs_unchanged'])
        self.assertEqual(result.stderr,'')


if __name__ == '__main__':
    unittest.main()
