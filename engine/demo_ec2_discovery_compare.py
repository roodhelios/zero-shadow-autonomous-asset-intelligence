"""Compare later synthetic EC2 discoveries using native SQLite and original exports."""

import copy
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import store_ec2
from database.ec2_inventory_compare import compare_inventories, export_comparison

ROOT = Path(__file__).resolve().parents[1]


def exports():
    original = json.loads((ROOT/'examples/ec2-describe-instances.json').read_bytes())
    instance = original['Reservations'][0]['Instances'][0]
    extra = copy.deepcopy(instance); extra['InstanceId'] = 'i-0123456789abcdef1'
    extra['PrivateIpAddress'] = '192.0.2.41'
    original['Reservations'][0]['Instances'].append(extra)
    current = copy.deepcopy(original)
    changed = current['Reservations'][0]['Instances'][0]
    changed.pop('PublicIpAddress'); changed['Tags'][1]['Value'] = 'application-security'
    added = copy.deepcopy(extra); added['InstanceId'] = 'i-0123456789abcdef2'
    added['PrivateIpAddress'] = '192.0.2.42'
    current['Reservations'][0]['Instances'] = [added, changed]
    return json.dumps(original).encode(), json.dumps(current).encode()


def exercise():
    before, after = exports()
    with tempfile.TemporaryDirectory(prefix='ec2-discovery-comparison-') as name:
        root = Path(name); sources = [root/'before.json', root/'after.json']
        databases = [root/'before.sqlite', root/'after.sqlite']
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            for day, data, source, database in zip((24, 25), (before, after), sources, databases):
                source.write_bytes(data)
                store_ec2(source, database, scope='synthetic', account='111122223333', region='us-east-1',
                          observed_at=datetime(2026, 10, day, tzinfo=timezone.utc))
            retained = [p.read_bytes() for p in databases]
            result = export_comparison(*databases, root/'comparison.json', previous_export=before, current_export=after)
            document = json.loads((root/'comparison.json').read_bytes())
            if (result['added'], result['not_observed'], result['changed'], result['unchanged']) != (1, 1, 1, 0):
                raise ValueError('comparison differed')
            if document['changes'][0]['changed_fields'] != ['ip_addresses', 'tags']:
                raise ValueError('projected field changes differed')
            for paths, exports_pair in ((databases, (before, after+b'\n')),
                                         (list(reversed(databases)), (after, before))):
                try: compare_inventories(*paths, previous_export=exports_pair[0], current_export=exports_pair[1])
                except ValueError: pass
                else: raise ValueError('invalid comparison passed')
            if retained != [p.read_bytes() for p in databases] or [p.read_bytes() for p in sources] != [before, after]:
                raise ValueError('input evidence changed')
    return {'status': 'ec2_discovery_comparison_exercise_passed', 'added': 1, 'not_observed': 1, 'changed': 1,
            'original_exports_checked': True, 'negative_cases_rejected': 2, 'inputs_unchanged': True,
            'interpretation': 'Synthetic selected discovery claims only. No AWS calls, deletion, resolution, '
            'accepted ownership, risk assessment or remediation is established.'}


def main():
    try: result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: local EC2 discovery comparison failed; check bundled fixtures and private storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
