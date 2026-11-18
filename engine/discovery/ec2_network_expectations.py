"""Compare saved EC2 network claims with a separately pinned reviewed roster."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from engine.discovery.aws_discovery import convert_export
from engine.discovery.ec2_address_context import _identifier
from engine.discovery.ec2_address_review import _render
from engine.discovery.osquery_collector import _publish, _read, _unique_fields

MAX_EXPECTATIONS_BYTES = 256 * 1024
INSTANCE_FIELDS = {'instance_vpc_id': ('VpcId', 'vpc'), 'instance_subnet_id': ('SubnetId', 'subnet')}
INTERFACE_FIELDS = {'interface_vpc_id': ('VpcId', 'vpc'), 'interface_subnet_id': ('SubnetId', 'subnet')}


def _pin(data, expected):
    if not isinstance(expected, str) or re.fullmatch('[0-9a-f]{64}', expected) is None:
        raise ValueError('expected lowercase SHA-256')
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input differs from independent pin')


def _fields(record, fields):
    return {name: _identifier(record, key, prefix) for name, (key, prefix) in fields.items()}


def _expected_fields(record, fields):
    for name, (_, prefix) in fields.items():
        if record[name] is not None:
            _identifier({name: record[name]}, name, prefix)
    return {name: record[name] for name in fields}


def _expectations(data, *, scope, account, region):
    if len(data) > MAX_EXPECTATIONS_BYTES:
        raise ValueError('expectations exceed bound')
    document = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields)
    if not isinstance(document, dict) or set(document) != {'schema_version', 'scope', 'account', 'region', 'instances'}:
        raise ValueError('expected exact roster fields')
    if type(document['schema_version']) is not int or document['schema_version'] != 1:
        raise ValueError('unsupported expectation version')
    if any(document[key] != value for key, value in {'scope': scope, 'account': account, 'region': region}.items()):
        raise ValueError('expectation scope differs from selected context')
    rows = document['instances']
    if not isinstance(rows, list) or len(rows) > 1000:
        raise ValueError('expected at most 1000 instance expectations')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'instance_id', 'interfaces', *INSTANCE_FIELDS}:
            raise ValueError('expected exact instance fields')
        identifier = _identifier({'id': row['instance_id']}, 'id', 'i')
        if identifier in result:
            raise ValueError('duplicate expected instance')
        context = _expected_fields(row, INSTANCE_FIELDS)
        interfaces = row['interfaces']
        if not isinstance(interfaces, list) or len(interfaces) > 100:
            raise ValueError('expected at most 100 interface expectations')
        selected = {}
        for interface in interfaces:
            if not isinstance(interface, dict) or set(interface) != {'network_interface_id', *INTERFACE_FIELDS}:
                raise ValueError('expected exact interface fields')
            eni = _identifier({'id': interface['network_interface_id']}, 'id', 'eni')
            if eni in selected:
                raise ValueError('duplicate expected interface')
            selected[eni] = _expected_fields(interface, INTERFACE_FIELDS)
        result[identifier] = {'context': context, 'interfaces': selected}
    return result


def _comparison(expected, observed):
    return {'expected': expected, 'observed': observed,
            'status': 'matches' if expected == observed else 'differs'}


def review(data, expectations, *, original_sha256, expectations_sha256, scope, account, region):
    # Pins bind the independently selected bytes before either JSON document is parsed.
    _pin(data, original_sha256)
    _pin(expectations, expectations_sha256)
    expected = _expectations(expectations, scope=scope, account=account, region=region)
    convert_export(data, scope=scope, account=account, region=region)
    original = json.loads(data)
    observed = {}
    for r, reservation in enumerate(original['Reservations']):
        for i, instance in enumerate(reservation['Instances']):
            path = f'/Reservations/{r}/Instances/{i}'
            interfaces = {}
            unidentified = []
            for n, interface in enumerate(instance.get('NetworkInterfaces', [])):
                eni = _identifier(interface, 'NetworkInterfaceId', 'eni')
                claim = {'context': _fields(interface, INTERFACE_FIELDS),
                         'source_path': path + '/NetworkInterfaces/' + str(n)}
                if eni is None:
                    unidentified.append(claim)
                elif eni in interfaces:
                    raise ValueError('ambiguous repeated observed interface')
                else:
                    interfaces[eni] = claim
            observed[instance['InstanceId']] = {'context': _fields(instance, INSTANCE_FIELDS),
                'interfaces': interfaces, 'unidentified_interfaces': unidentified, 'source_path': path}
    rows = []
    for identifier in sorted(expected.keys() | observed.keys()):
        wanted, found = expected.get(identifier), observed.get(identifier)
        row = {'instance_id': identifier, 'source_path': found['source_path'] if found else None}
        if wanted is None or found is None:
            row.update(status='unexpected' if wanted is None else 'missing',
                       expected=wanted, observed=found)
        else:
            interfaces = []
            for eni in sorted(wanted['interfaces'].keys() | found['interfaces'].keys()):
                want, have = wanted['interfaces'].get(eni), found['interfaces'].get(eni)
                comparison = _comparison(want, have['context'] if have else None)
                if want is None or have is None:
                    comparison['status'] = 'unexpected' if want is None else 'missing'
                interfaces.append({'network_interface_id': eni,
                    'source_path': have['source_path'] if have else None, **comparison})
            context = _comparison(wanted['context'], found['context'])
            matches = (context['status'] == 'matches' and not found['unidentified_interfaces']
                       and all(item['status'] == 'matches' for item in interfaces))
            row.update(status='matches' if matches else 'differs', instance_context=context,
                       interfaces=interfaces, unidentified_interfaces=found['unidentified_interfaces'])
        rows.append(row)
    counts = {status + '_instance_count': sum(row['status'] == status for row in rows)
              for status in ('matches', 'differs', 'missing', 'unexpected')}
    return {'schema_version': 1, 'report_type': 'saved-ec2-network-expectation-review',
        'scope': scope, 'account': account, 'region': region,
        'original_sha256': original_sha256, 'expectations_sha256': expectations_sha256,
        'expected_instance_count': len(expected), 'observed_instance_count': len(observed),
        **counts, 'instances': rows,
        'selected_roster_matches': all(row['status'] == 'matches' for row in rows),
        'collection_completeness_established': False, 'collision_established': False,
        'interpretation': 'Exact supplied instance and interface claims compared with a separately '
            'selected roster. Null expectations require absent metadata, never a wildcard or default '
            'network. Missing identities are not retired or remediated. Roster equality does not '
            'authenticate either source, prove full collection, current attachment, capture time, '
            'address collision or exposure. No AWS request, risk scoring or identity merge occurs.'}


def exercise():
    root = Path(__file__).resolve().parents[2]
    source = json.loads((root / 'examples/ec2-interface-addresses.json').read_bytes())
    manifest = (root / 'examples/ec2-network-expectations.json').read_bytes()
    host = source['Reservations'][0]['Instances'][0]
    host.update(VpcId='vpc-00000001', SubnetId='subnet-00000001')
    host['NetworkInterfaces'][0].update(NetworkInterfaceId='eni-00000001',
        VpcId='vpc-00000001', SubnetId='subnet-00000001')

    def compare(document):
        data = json.dumps(document).encode()
        return review(data, manifest, original_sha256=hashlib.sha256(data).hexdigest(),
            expectations_sha256=hashlib.sha256(manifest).hexdigest(),
            scope='synthetic', account='111122223333', region='us-east-1')

    matching = compare(source)
    changed = copy.deepcopy(source)
    changed['Reservations'][0]['Instances'][0]['NetworkInterfaces'][0].pop('VpcId')
    mismatch = compare(changed)
    missing = compare({'Reservations': []})
    if not matching['selected_roster_matches'] or mismatch['differs_instance_count'] != 1 or missing['missing_instance_count'] != 1:
        raise ValueError('network expectation exercise failed')
    _render(matching)
    return {'status': 'ec2_network_expectation_exercise_passed', 'matching_instances': 1,
            'changed_context_detected': True, 'missing_instances': 1,
            'collection_completeness_established': False, 'collision_established': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo')
    command = commands.add_parser('review', allow_abbrev=False)
    command.add_argument('export', type=Path)
    command.add_argument('expectations', type=Path)
    command.add_argument('--original-sha256', required=True)
    command.add_argument('--expectations-sha256', required=True)
    command.add_argument('--scope', required=True, choices=('synthetic', 'owned', 'authorized'))
    command.add_argument('--account', required=True)
    command.add_argument('--region', required=True)
    command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix':
            raise ValueError('private local file handling requires POSIX')
        if args.command == 'demo':
            result = exercise()
        else:
            report = review(_read(args.export), _read(args.expectations),
                original_sha256=args.original_sha256, expectations_sha256=args.expectations_sha256,
                scope=args.scope, account=args.account, region=args.region)
            rendered = _render(report)
            _publish(args.output, rendered)
            result = {key: value for key, value in report.items() if key.endswith('_count')}
            result.update(status='ec2_network_expectation_review_created',
                selected_roster_matches=report['selected_roster_matches'],
                report_sha256=hashlib.sha256(rendered.encode()).hexdigest(),
                collection_completeness_established=False, collision_established=False)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: network expectation review failed; check private inputs, independent pins and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
