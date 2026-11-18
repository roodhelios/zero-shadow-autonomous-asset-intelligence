"""Locate shared saved EC2 address claims without merging identities or contacting AWS."""

import argparse
from collections import defaultdict
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

from engine.discovery.aws_discovery import convert_export
from engine.discovery.osquery_collector import _publish, _read

MAX_REPORT_BYTES = 16 * 1024 * 1024


def review_addresses(data, *, scope, account, region):
    document = convert_export(data, scope=scope, account=account, region=region)
    references = {item['source_record_id']: item for item in document['import_metadata']['source_records']}
    claims = defaultdict(list)
    for asset in document['assets']:
        for address in asset['ip_addresses']:
            claims[address].append({'cloud_resource_id': asset['cloud_resource_id'],
                                    'source_reference': references[asset['source_record_id']]})
    shared = [{'address': address, 'address_family': ipaddress.ip_address(address).version,
               'identity_count': len(records), 'observations': records}
              for address, records in sorted(claims.items()) if len(records) > 1]
    return {'schema_version': 1, 'report_type': 'saved-ec2-shared-address-review', 'scope': scope,
            'account': account, 'region': region, 'original_sha256': hashlib.sha256(data).hexdigest(),
            'asset_count': len(document['assets']), 'shared_address_count': len(shared),
            'shared_identity_count': len({record['cloud_resource_id'] for item in shared
                                         for record in item['observations']}),
            'shared_claims': shared,
            'interpretation': 'Multiple distinct instance identities claim the same selected address '
                'in one supplied export. This does not establish an address collision, common VPC, '
                'reachability, ownership, exposure, compromise or erroneous configuration. NAT and '
                'overlapping address spaces can be legitimate. Address roles/interfaces are not '
                'retained by the existing projection. Collection completeness and source truth are '
                'unverified. No identity is merged, risk scored or AWS request performed.'}


def _render(report):
    data = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n'
    if len(data.encode('utf-8')) > MAX_REPORT_BYTES:
        raise ValueError('shared address report exceeds bound')
    return data


def exercise():
    source = Path(__file__).resolve().parents[2] / 'examples/ec2-interface-addresses.json'
    document = json.loads(source.read_bytes())
    instance = document['Reservations'][0]['Instances'][0]
    other = copy.deepcopy(instance)
    other['InstanceId'] = 'i-0123456789abcdef1'
    document['Reservations'][0]['Instances'].append(other)
    report = review_addresses(json.dumps(document).encode(), scope='synthetic',
                              account='111122223333', region='us-east-1')
    if report['asset_count'] != 2 or report['shared_identity_count'] != 2 or report['shared_address_count'] != 6:
        raise ValueError('shared synthetic claims did not reproduce')
    if any(item['identity_count'] != 2 for item in report['shared_claims']):
        raise ValueError('identity claims were lost')
    _render(report)
    return {'status': 'ec2_shared_address_exercise_passed', 'asset_count': 2,
            'shared_address_count': 6, 'shared_identity_count': 2, 'identities_merged': False,
            'collision_established': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo', help='temporary synthetic shared claims')
    review = commands.add_parser('review', help='retain shared claims from one permitted saved export')
    review.add_argument('export', type=Path)
    review.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    review.add_argument('--account', required=True)
    review.add_argument('--region', required=True)
    review.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            result = exercise()
        else:
            report = review_addresses(_read(args.export), scope=args.scope, account=args.account, region=args.region)
            rendered = _render(report)
            _publish(args.output, rendered)
            result = {'status': 'ec2_shared_address_review_created',
                      'report_sha256': hashlib.sha256(rendered.encode()).hexdigest(),
                      **{key: report[key] for key in ('asset_count', 'shared_address_count', 'shared_identity_count')}}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: saved EC2 address review failed; check private export, context and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
