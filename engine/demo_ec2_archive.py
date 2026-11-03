"""Restore a synthetic EC2 sequence after removing its original databases and exports."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from database.ec2_inventory import _canonical, store_ec2
from database.ec2_sequence_archive import create_archive, verify_archive, restore_archive
from database.ec2_timeline_checkpoint import verify_checkpoint_review
from engine.demo_ec2_timeline import timeline_exports


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-sequence-archive-') as name:
        root = Path(name); batches, slots, originals = [], [], []
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            for day, export in enumerate(timeline_exports()[:3], 24):
                source, database = root/f'{day}.json', root/f'{day}.sqlite'
                source.write_bytes(export)
                at = datetime(2026,10,day,tzinfo=timezone.utc)
                store_ec2(source, database, scope='synthetic', account='111122223333', region='us-east-1', observed_at=at)
                batches.append((database, export)); originals.append((database.read_bytes(),export))
                slots.append(dict(observed_at=at.isoformat().replace('+00:00','Z'), export_sha256=hashlib.sha256(export).hexdigest()))
            checkpoint = (_canonical(dict(schema_version=1, checkpoint_type='ec2-observation-sequence',
                scope='synthetic', account='111122223333', region='us-east-1', expected_batches=slots))+'\n').encode()
            checkpoint_pin = hashlib.sha256(checkpoint).hexdigest()
            archive = root/'sequence.archive.json'
            stored = create_archive([batches[0],batches[2]], archive,
                checkpoint_data=checkpoint, expected_checkpoint_sha256=checkpoint_pin)
            for database, _ in batches: database.unlink()
            for source in root.glob('[0-9]*.json'): source.unlink()
            options = dict(expected_sha256=stored['archive_sha256'], expected_checkpoint_sha256=checkpoint_pin)
            verified = verify_archive(archive, **options)
            destination = root/'restored'; restored = restore_archive(archive, destination, **options)
            for sequence, original in enumerate((originals[0], originals[2]),1):
                if ((destination/f'{sequence:02d}.sqlite').read_bytes(),
                    (destination/f'{sequence:02d}.json').read_bytes()) != original:
                    raise ValueError('restored bytes differ')
            recovered = [(destination/f'{i:02d}.sqlite',(destination/f'{i:02d}.json').read_bytes()) for i in (1,2)]
            coverage = destination/'coverage.json'
            checked = verify_checkpoint_review(coverage, recovered, (destination/'checkpoint.json').read_bytes(),
                expected_checkpoint_sha256=checkpoint_pin, expected_report_sha256=hashlib.sha256(coverage.read_bytes()).hexdigest())
            if verified['counts']['missing_batch'] != 1 or restored['requirements_satisfied'] or not checked['report_reproduced']:
                raise ValueError('missing expected batch was hidden')
            negatives = 0
            for changes in ({'expected_sha256':'0'*64},{'expected_checkpoint_sha256':'0'*64}):
                try: verify_archive(archive, **dict(options, **changes))
                except ValueError: negatives += 1
                else: raise ValueError('incorrect independent pin accepted')
            try: restore_archive(archive, destination, **options)
            except FileExistsError: negatives += 1
            else: raise ValueError('existing restore overwritten')
    return dict(status='ec2_sequence_archive_exercise_passed', supplied_batches=2, expected_batches=3,
        missing_expected_batches=1, originals_removed=True, exact_bytes_restored=True,
        restored_coverage_reproduced=True, negative_cases_rejected=negatives,
        interpretation='Native temporary SQLite and original synthetic exports only. Archived sources remain data. '
        'Retain archive/checkpoint pins independently. No AWS call, credential, live collection or historical dispatch.')


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: EC2 archive exercise failed; inspect fixtures, checkout and temporary storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
