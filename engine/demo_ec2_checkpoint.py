"""Review an omitted expected EC2 batch against a temporary recipient checkpoint."""

import hashlib
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import _canonical, store_ec2
from database.ec2_timeline_checkpoint import export_checkpoint_review, verify_checkpoint_review
from engine.demo_ec2_timeline import timeline_exports


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-sequence-checkpoint-') as name:
        root = Path(name)
        batches, slots = [], []
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            for day, data in enumerate(timeline_exports()[:3], 24):
                source, database = root/f'export-{day}.json', root/f'batch-{day}.sqlite'
                source.write_bytes(data)
                at = datetime(2026,10,day,tzinfo=timezone.utc)
                store_ec2(source, database, scope='synthetic', account='111122223333', region='us-east-1', observed_at=at)
                batches.append((database,data))
                slots.append(dict(observed_at=at.isoformat().replace('+00:00','Z'), export_sha256=hashlib.sha256(data).hexdigest()))
            original = [database.read_bytes() for database, _ in batches]
            # Synthetic recipient expectations are explicit, not inferred from the incomplete candidate.
            checkpoint = (_canonical(dict(schema_version=1, checkpoint_type='ec2-observation-sequence',
                scope='synthetic', account='111122223333', region='us-east-1', expected_batches=slots))+'\n').encode()
            checkpoint_pin = hashlib.sha256(checkpoint).hexdigest()
            partial = [batches[0],batches[2]]
            gaps = export_checkpoint_review(partial, checkpoint, root/'gaps.json', expected_checkpoint_sha256=checkpoint_pin)
            if gaps['counts'] != dict(matched=2,missing_batch=1,export_mismatch=0,unexpected_batch=0):
                raise ValueError('omitted batch did not remain visible')
            retained = verify_checkpoint_review(root/'gaps.json', partial, checkpoint,
                expected_checkpoint_sha256=checkpoint_pin, expected_report_sha256=gaps['report_sha256'])
            complete = export_checkpoint_review(batches, checkpoint, root/'complete.json', expected_checkpoint_sha256=checkpoint_pin)
            if not complete['requirements_satisfied'] or retained['requirements_satisfied']:
                raise ValueError('checkpoint outcome did not reproduce')
            negatives = 0
            for change in ({'expected_checkpoint_sha256':'0'*64,'expected_report_sha256':gaps['report_sha256']},
                           {'expected_checkpoint_sha256':checkpoint_pin,'expected_report_sha256':'0'*64}):
                try:
                    verify_checkpoint_review(root/'gaps.json', partial, checkpoint, **change)
                except ValueError:
                    negatives += 1
                else:
                    raise ValueError('invalid independent pin accepted')
            if original != [database.read_bytes() for database, _ in batches]:
                raise ValueError('input database changed')
    return dict(status='ec2_sequence_checkpoint_exercise_passed', expected_batches=3, supplied_partial_batches=2,
        missing_expected_batches=1, gap_report_reproduced=True, complete_sequence_satisfied=True,
        negative_cases_rejected=negatives, inputs_unchanged=True,
        interpretation='Synthetic recipient checkpoint, original exports and native temporary SQLite. '
        'Missing means not supplied, not proof of failed live collection. Trusted checkpoint distribution/freshness, '
        'source authenticity and authoritative lifecycle are not established. No AWS calls.')


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: local EC2 checkpoint exercise failed; inspect fixtures and temporary storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
