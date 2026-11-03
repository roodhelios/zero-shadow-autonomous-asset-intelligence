"""Portable EC2 evidence remains bound to independent expectations and original bytes."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database.ec2_inventory import _canonical, store_ec2
from database.ec2_sequence_archive import SOURCE_FILES, create_archive, verify_archive, restore_archive, main
from database.assessment_archive import _entry
from engine.demo_ec2_timeline import timeline_exports
from engine.demo_ec2_archive import exercise


@unittest.skipUnless(os.name == 'posix','private closed-file retention requires POSIX')
class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.archive = self.root/'archive.json'
        self.batches, slots = [], []
        for day, export in enumerate(timeline_exports()[:3],24):
            source, database = self.root/f'{day}.json', self.root/f'{day}.sqlite'
            source.write_bytes(export); at = datetime(2026,10,day,tzinfo=timezone.utc)
            store_ec2(source, database, scope='synthetic', account='111122223333', region='us-east-1', observed_at=at)
            self.batches.append((database,export))
            slots.append(dict(observed_at=at.isoformat().replace('+00:00','Z'),export_sha256=hashlib.sha256(export).hexdigest()))
        self.checkpoint = (_canonical(dict(schema_version=1,checkpoint_type='ec2-observation-sequence',
            scope='synthetic',account='111122223333',region='us-east-1',expected_batches=slots))+'\n').encode()
        self.cp = hashlib.sha256(self.checkpoint).hexdigest()

    def create(self, batches=None):
        result = create_archive(self.batches if batches is None else batches, self.archive,
            checkpoint_data=self.checkpoint, expected_checkpoint_sha256=self.cp)
        return dict(expected_sha256=result['archive_sha256'], expected_checkpoint_sha256=self.cp)

    def mutate(self, change):
        document = json.loads(self.archive.read_bytes()); change(document)
        self.archive.write_text(_canonical(document)+'\n')
        return dict(expected_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(), expected_checkpoint_sha256=self.cp)

    def test_roundtrip_preserves_exact_inputs_and_permissions_after_originals_removed(self):
        original = [(p.read_bytes(),b) for p,b in self.batches]; options = self.create()
        self.assertEqual(original,[(p.read_bytes(),b) for p,b in self.batches])
        for p,_ in self.batches: p.unlink()
        destination = self.root/'restore'; result = restore_archive(self.archive,destination,**options)
        self.assertTrue(result['requirements_satisfied'])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode),0o700)
        for i,(database,export) in enumerate(original,1):
            self.assertEqual((destination/f'{i:02d}.sqlite').read_bytes(),database)
            self.assertEqual((destination/f'{i:02d}.json').read_bytes(),export)
        self.assertTrue((destination/'RESTORE.json').is_file())
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in destination.iterdir()))
        self.assertEqual(verify_archive(self.archive,**options)['counts']['matched'],3)

    def test_partial_sequence_stays_partial_after_archive_and_restore(self):
        options = self.create([self.batches[0],self.batches[2]])
        result = restore_archive(self.archive,self.root/'restore',**options)
        self.assertFalse(result['requirements_satisfied']); self.assertEqual(result['counts']['missing_batch'],1)

    def test_trusted_allowlist_runs_in_fresh_standard_library_checkout(self):
        options = self.create(); checkout = self.root/'trusted'; checkout.mkdir(mode=0o700)
        root = Path(__file__).resolve().parents[1]
        for name in SOURCE_FILES:
            target = checkout/name; target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(root/name,target)
        result = subprocess.run([sys.executable,'-S','-m','database.ec2_sequence_archive','verify',str(self.archive),
            '--expected-sha256',options['expected_sha256'],'--expected-checkpoint-sha256',self.cp],
            cwd=checkout,env=dict(os.environ,PYTHONPATH=''),capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['supplied_batch_count'],3)

    def test_source_change_after_capture_does_not_change_archived_copies(self):
        from database.assessment_backup import _closed_bytes
        originals = [p.read_bytes() for p,_ in self.batches]
        def capture(path):
            data = _closed_bytes(path); path.write_bytes(b'changed after capture'); return data
        with patch('database.ec2_sequence_archive._closed_bytes',side_effect=capture): options = self.create()
        destination = self.root/'restored'; restore_archive(self.archive,destination,**options)
        self.assertEqual(originals,[(destination/f'{i:02d}.sqlite').read_bytes() for i in (1,2,3)])

    def test_both_pins_are_independent_and_checked_before_replay(self):
        options = self.create()
        with patch('database.ec2_sequence_archive._reproduce',side_effect=AssertionError('no replay')):
            for changes in ({'expected_sha256':'0'*64},{'expected_checkpoint_sha256':'0'*64}):
                with self.assertRaises(ValueError): verify_archive(self.archive,**dict(options,**changes))

    def test_rebound_coverage_entry_still_must_reproduce(self):
        self.create()
        def change(d):
            import base64
            report = json.loads(base64.b64decode(d['coverage']['bytes_b64'])); report['requirements_satisfied']=False
            d['coverage'] = _entry((_canonical(report)+'\n').encode())
        options = self.mutate(change)
        with self.assertRaisesRegex(ValueError,'did not reproduce'): verify_archive(self.archive,**options)

    def test_changed_original_export_rejected_even_with_new_archive_pin(self):
        self.create(); options = self.mutate(lambda d:d['batches'][0].update(export=_entry(self.batches[0][1]+b'\n')))
        with self.assertRaises(ValueError): verify_archive(self.archive,**options)

    def test_archived_code_is_compared_not_executed(self):
        self.create(); options = self.mutate(lambda d:d['sources'].update({'database/ec2_sequence_archive.py':_entry(b'raise AssertionError("never execute")')}))
        with patch('database.ec2_sequence_archive._reproduce',side_effect=AssertionError('no database replay')):
            with self.assertRaisesRegex(ValueError,'trusted checkout'): verify_archive(self.archive,**options)

    def test_extra_fields_and_unsafe_source_names_rejected(self):
        self.create(); options = self.mutate(lambda d:d.update(extra=True))
        with self.assertRaises(ValueError): verify_archive(self.archive,**options)
        options = self.mutate(lambda d:(d.pop('extra'),d['sources'].update({'../escape':_entry(b'private')})))
        with self.assertRaises(ValueError): verify_archive(self.archive,**options)

    def test_existing_outputs_preserved_including_empty_restore_directory(self):
        options = self.create(); original = self.archive.read_bytes()
        with self.assertRaises(ValueError): self.create()
        self.assertEqual(self.archive.read_bytes(),original)
        destination = self.root/'restore'; destination.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError): restore_archive(self.archive,destination,**options)
        self.assertEqual(list(destination.iterdir()),[])

    def test_sidecars_symlinks_and_unclosed_inputs_rejected(self):
        database,_ = self.batches[0]; sidecar = Path(str(database)+'-wal'); sidecar.write_bytes(b'fixture')
        with self.assertRaises(ValueError): self.create()
        sidecar.unlink(); alias = self.root/'alias.sqlite'; alias.symlink_to(database)
        with self.assertRaises(OSError): self.create([(alias,self.batches[0][1]),self.batches[1]])
        self.assertFalse(self.archive.exists())

    def test_creation_failure_does_not_publish_archive(self):
        with patch('database.ec2_sequence_archive._reproduce',side_effect=ValueError('fixture')):
            with self.assertRaises(ValueError): self.create()
        self.assertFalse(self.archive.exists())

    def test_restore_failure_cleans_only_new_directory(self):
        options = self.create(); destination = self.root/'restore'
        from database.assessment_backup import _publish
        def failing(path,data):
            if path.name=='02.json': raise OSError('synthetic disk failure')
            return _publish(path,data)
        with patch('database.ec2_sequence_archive._publish',side_effect=failing):
            with self.assertRaises(OSError): restore_archive(self.archive,destination,**options)
        self.assertFalse(destination.exists()); self.assertTrue(self.archive.exists())

    def test_bounds_and_invalid_batch_count_fail_before_publication(self):
        for batches in ([],self.batches[:1],self.batches*6):
            with self.assertRaises(ValueError): self.create(batches)
        with patch('database.ec2_sequence_archive.MAX_ARCHIVE_BYTES',100):
            with self.assertRaises(ValueError): self.create()
        self.assertFalse(self.archive.exists())

    def test_cli_gap_exit_and_private_error(self):
        options = self.create([self.batches[0],self.batches[2]])
        stdout,stderr = StringIO(),StringIO()
        args = ['verify',str(self.archive),'--expected-sha256',options['expected_sha256'],'--expected-checkpoint-sha256',self.cp]
        with redirect_stdout(stdout),redirect_stderr(stderr): self.assertEqual(main(args),1)
        self.assertEqual(json.loads(stdout.getvalue())['counts']['missing_batch'],1)
        self.assertNotIn(str(self.root),stdout.getvalue())
        args[3]='0'*64
        with redirect_stderr(stderr): self.assertEqual(main(args),2)
        self.assertNotIn(str(self.root),stderr.getvalue())

    def test_complete_temporary_walkthrough(self):
        result = exercise(); self.assertTrue(result['exact_bytes_restored'])
        self.assertEqual(result['negative_cases_rejected'],3)


if __name__ == '__main__': unittest.main()
