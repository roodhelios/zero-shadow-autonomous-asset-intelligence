"""Build and reproduce a four-batch observation timeline using temporary synthetic evidence."""

import copy
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import store_ec2
from database.ec2_observation_timeline import export_timeline, verify_timeline
from engine.demo_ec2_discovery_compare import exports


def timeline_exports():
    before, after = exports()
    first, last = json.loads(before), json.loads(after)
    returning = copy.deepcopy(first['Reservations'][0]['Instances'][1])
    returning['Tags'][1]['Value'] = 'application-security'
    last['Reservations'][0]['Instances'] = [last['Reservations'][0]['Instances'][1], returning]
    return [before, after, after, json.dumps(last).encode()]


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-timeline-') as name:
        root = Path(name); batches = []
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            for day, data in enumerate(timeline_exports(), 24):
                source, database = root/f'export-{day}.json', root/f'inventory-{day}.sqlite'
                source.write_bytes(data)
                store_ec2(source, database, scope='synthetic', account='111122223333', region='us-east-1',
                          observed_at=datetime(2026, 10, day, tzinfo=timezone.utc))
                batches.append((database, data))
            original = [p.read_bytes() for p, _ in batches]
            output = root/'timeline.json'
            result = export_timeline(batches, output)
            verified = verify_timeline(output, batches, expected_sha256=result['report_sha256'])
            expected = dict(first_observed=3, changed=1, unchanged=3, observed_again=1, not_observed=2)
            if result['event_totals'] != expected or verified['report_sha256'] != result['report_sha256']:
                raise ValueError('timeline outcome differed')
            changed_export = list(batches); changed_export[-1] = (batches[-1][0], batches[-1][1]+b'\n')
            for evidence, pin in ((changed_export, result['report_sha256']),
                                  (batches[:-1], result['report_sha256']), (batches, '0'*64)):
                try: verify_timeline(output, evidence, expected_sha256=pin)
                except ValueError: pass
                else: raise ValueError('invalid timeline passed')
            if original != [p.read_bytes() for p, _ in batches]:
                raise ValueError('input database changed')
    return {'status': 'ec2_timeline_exercise_passed', 'batch_count': 4, 'unique_asset_count': 3,
            'event_totals': expected, 'negative_cases_rejected': 3, 'inputs_unchanged': True,
            'interpretation': 'Temporary native SQLite and original synthetic exports. Observed again is not '
            'recreation or recovery; omitted rows do not establish deletion or complete collection. No AWS calls.'}


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: local EC2 timeline exercise failed; check fixtures and temporary storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
