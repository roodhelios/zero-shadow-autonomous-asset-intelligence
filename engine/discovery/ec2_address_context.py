"""Retain selected saved address roles and interface context without exposure inference."""

import copy
import ipaddress
import json
from pathlib import Path
import re

from engine.discovery.ec2_address_review import review_addresses


def _identifier(record, key, prefix):
    if key not in record:
        return None
    value = record[key]
    if not isinstance(value, str) or re.fullmatch(prefix + r'-(?:[0-9a-f]{8}|[0-9a-f]{17})', value) is None:
        raise ValueError('invalid selected network identifier')
    return value


def _primary(record, key):
    if key not in record:
        return None
    if type(record[key]) is not bool:
        raise ValueError('selected primary flag must be boolean')
    return record[key]


def _contexts(instance, base):
    instance_context = {'instance_vpc_id': _identifier(instance, 'VpcId', 'vpc'),
                        'instance_subnet_id': _identifier(instance, 'SubnetId', 'subnet')}
    result = []

    def add(record, field, role, path, context, *, primary=None, private=None):
        if field in record and record[field] is not None:
            address = str(ipaddress.ip_address(record[field]))
            result.append((address, {**instance_context,
                'network_interface_id': None, 'interface_vpc_id': None, 'interface_subnet_id': None,
                **context, 'role': role, 'source_path': path + '/' + field,
                'primary': primary, 'associated_private_ipv4': private}))

    for field, role in (('PrivateIpAddress', 'instance_private_ipv4'),
                        ('PublicIpAddress', 'instance_public_ipv4'), ('Ipv6Address', 'instance_ipv6')):
        add(instance, field, role, base, {})
    for number, interface in enumerate(instance.get('NetworkInterfaces', [])):
        path = base + '/NetworkInterfaces/' + str(number)
        context = {'network_interface_id': _identifier(interface, 'NetworkInterfaceId', 'eni'),
                   'interface_vpc_id': _identifier(interface, 'VpcId', 'vpc'),
                   'interface_subnet_id': _identifier(interface, 'SubnetId', 'subnet')}
        add(interface, 'PrivateIpAddress', 'interface_private_ipv4', path, context)
        add(interface.get('Association', {}), 'PublicIp', 'interface_associated_public_ipv4',
            path + '/Association', context)
        for row, record in enumerate(interface.get('PrivateIpAddresses', [])):
            record_path = path + '/PrivateIpAddresses/' + str(row)
            primary = _primary(record, 'Primary')
            add(record, 'PrivateIpAddress', 'interface_private_ipv4_record', record_path, context, primary=primary)
            add(record.get('Association', {}), 'PublicIp', 'private_record_associated_public_ipv4',
                record_path + '/Association', context, primary=primary,
                private=str(ipaddress.IPv4Address(record['PrivateIpAddress'])))
        for row, record in enumerate(interface.get('Ipv6Addresses', [])):
            add(record, 'Ipv6Address', 'interface_ipv6_record', path + '/Ipv6Addresses/' + str(row),
                context, primary=_primary(record, 'IsPrimaryIpv6'))
    return result


def review_address_context(data, *, scope, account, region):
    # Reuse full strict import/context validation before projecting any detail.
    report = review_addresses(data, scope=scope, account=account, region=region)
    original = json.loads(data)
    selected = {}
    for reservation_number, reservation in enumerate(original['Reservations']):
        for instance_number, instance in enumerate(reservation['Instances']):
            path = f'/Reservations/{reservation_number}/Instances/{instance_number}'
            selected[(reservation_number + 1, instance_number + 1)] = _contexts(instance, path)
    count = 0
    for claim in report['shared_claims']:
        for observation in claim['observations']:
            reference = observation['source_reference']
            rows = selected[(reference['reservation_record'], reference['instance_record'])]
            contexts = [context for address, context in rows if address == claim['address']]
            if not contexts:
                raise ValueError('selected address has no original context')
            observation['address_contexts'] = contexts
            count += len(contexts)
    report.update(schema_version=2, report_type='saved-ec2-shared-address-context-review',
        context_record_count=count,
        interpretation='Selected address, interface and role claims from the exact saved export. '
            'Null means absent metadata, never a default VPC or a false primary flag. Instance and '
            'interface VPC claims are retained separately without inheritance or reconciliation. '
            'Multiple paths do not count as independent observations. Supplied VPC/role matches '
            'do not establish collision, attachment, reachability, exposure, source authenticity, '
            'complete collection or current state. No identity merge, risk score or AWS call occurs.')
    return report


def exercise():
    root = Path(__file__).resolve().parents[2]
    document = json.loads((root / 'examples/ec2-interface-addresses.json').read_bytes())
    instance = document['Reservations'][0]['Instances'][0]
    other = copy.deepcopy(instance)
    other['InstanceId'] = 'i-0123456789abcdef1'
    document['Reservations'][0]['Instances'].append(other)
    for number, host in enumerate((instance, other), 1):
        host['VpcId'] = 'vpc-' + f'{number:08x}'
        host['NetworkInterfaces'][0].update(VpcId=host['VpcId'],
            NetworkInterfaceId='eni-' + f'{number:08x}', SubnetId='subnet-' + f'{number:08x}')
    report = review_address_context(json.dumps(document).encode(), scope='synthetic',
                                   account='111122223333', region='us-east-1')
    claim = next(item for item in report['shared_claims'] if item['address'] == '192.0.2.40')
    vpcs = {context['interface_vpc_id'] for item in claim['observations']
            for context in item['address_contexts'] if context['interface_vpc_id'] is not None}
    if report['shared_address_count'] != 6 or len(vpcs) != 2 or report['context_record_count'] != 20:
        raise ValueError('synthetic address contexts did not reproduce')
    return {'status': 'ec2_address_context_exercise_passed', 'shared_address_count': 6,
            'shared_identity_count': 2, 'context_record_count': 20,
            'distinct_supplied_interface_vpcs': 2, 'collision_established': False}
