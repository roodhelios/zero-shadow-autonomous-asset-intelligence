"""Review interface address claims across two saved synthetic EC2 inventories."""

import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

from database.ec2_inventory import store_ec2
from database.ec2_inventory_compare import export_comparison

ROOT = Path(__file__).resolve().parents[1]


def exports():
    previous = json.loads((ROOT/'examples/ec2-interface-addresses.json').read_bytes())
    current = copy.deepcopy(previous)
    instance = current['Reservations'][0]['Instances'][0]
    interface = instance['NetworkInterfaces'][0]
    interface['PrivateIpAddresses'][1]['PrivateIpAddress'] = '192.0.2.42'
    interface['PrivateIpAddresses'][1]['Association']['PublicIp'] = '198.51.100.42'
    interface['Ipv6Addresses'][1]['Ipv6Address'] = '2001:db8::42'
    # A new identity shares an address. It must not join the existing identity.
    current['Reservations'][0]['Instances'].append({
        'InstanceId': 'i-0123456789abcdef1', 'PrivateIpAddress': '192.0.2.40'})
    return json.dumps(previous).encode(), json.dumps(current).encode()


def exercise():
    previous, current = exports()
    with tempfile.TemporaryDirectory(prefix='ec2-address-review-') as name:
        root = Path(name)
        inputs = [root/'before.json', root/'after.json']
        databases = [root/'before.sqlite', root/'after.sqlite']
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            for day, data, source, database in zip((16, 17), (previous, current), inputs, databases):
                source.write_bytes(data)
                store_ec2(source, database, scope='synthetic', account='111122223333',
                          region='us-east-1', observed_at=datetime(2026, 11, day, tzinfo=timezone.utc))
            originals = [path.read_bytes() for path in inputs+databases]
            summary = export_comparison(*databases, root/'review.json',
                previous_export=previous, current_export=current)
            report = json.loads((root/'review.json').read_bytes())
            change = report['changes'][0]
            expected = {'added': ['192.0.2.42', '198.51.100.42', '2001:db8::42'],
                        'not_observed': ['192.0.2.41', '198.51.100.41', '2001:db8::41'],
                        'retained': ['192.0.2.40', '198.51.100.40', '2001:db8::40']}
            if (change['address_claims'] != expected or change['changed_fields'] != ['ip_addresses'] or
                    summary['added'] != 1 or summary['changed'] != 1 or summary['not_observed'] != 0):
                raise ValueError('address review differed')
            if report['added'][0]['asset_id'] == change['asset_id']:
                raise ValueError('shared address merged identities')
            try:
                export_comparison(*databases, root/'invalid.json',
                    previous_export=previous, current_export=current+b'\n')
            except ValueError:
                pass
            else:
                raise ValueError('changed original passed')
            if (root/'invalid.json').exists() or originals != [path.read_bytes() for path in inputs+databases]:
                raise ValueError('original evidence changed or invalid report published')
    return {'status': 'ec2_address_review_exercise_passed', 'shared_identities_with_address_changes': 1,
            'added_address_claims': 3, 'not_observed_address_claims': 3, 'retained_address_claims': 3,
            'separate_added_identities': 1, 'changed_original': 'rejected', 'inputs_unchanged': True,
            'interpretation': 'Synthetic saved claims only. No address reachability, interface attachment, '
            'deletion, source authenticity or exposure change is established. No AWS calls.'}


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: local EC2 address review failed; check fixtures and private storage', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
