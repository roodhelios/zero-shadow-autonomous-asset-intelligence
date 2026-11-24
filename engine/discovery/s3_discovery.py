"""Convert a saved S3 ListBuckets JSON response without contacting AWS."""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

from engine.correlation import correlate_assets
from engine.discovery.fixture_discovery import ALLOWED_SCOPES
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _read, _unique_fields
from engine.models import AssetObservation

SOURCE = 'aws-s3-export'
MAX_BUCKETS = 10000


def _name(value):
    # Deliberately support global-namespace, modern general purpose names only.
    if (not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value)
            or '..' in value or value.startswith(('xn--', 'sthree-', 'amzn-s3-demo-'))
            or value.endswith(('-s3alias', '--ol-s3', '.mrap', '--x-s3', '--table-s3', '-an'))):
        raise ValueError('unsupported bucket name')
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return value
    raise ValueError('bucket name cannot be an IP address')


def convert_export(data, *, scope, account):
    """Retain selected identity claims and exact original-array row references."""
    if scope not in ALLOWED_SCOPES:
        raise ValueError('explicit permitted scope required')
    if not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account):
        raise ValueError('explicit 12-digit account required')
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ValueError('bounded input bytes required')
    document = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields)
    json.dumps(document, allow_nan=False)
    if not isinstance(document, dict) or not isinstance(document.get('Buckets'), list):
        raise ValueError('ListBuckets object required')
    if any(document.get(key) not in (None, '') for key in ('ContinuationToken', 'NextToken')):
        raise ValueError('unfinished pagination is unsupported')
    if len(document['Buckets']) > MAX_BUCKETS:
        raise ValueError('too many buckets')
    assets, references, seen = [], [], set()
    for position, bucket in enumerate(document['Buckets'], 1):
        if not isinstance(bucket, dict):
            raise ValueError('bucket object required')
        name = _name(bucket.get('Name'))
        if name in seen:
            raise ValueError('duplicate bucket name')
        seen.add(name)
        arn = 'arn:aws:s3:::' + name
        if 'BucketArn' in bucket and bucket['BucketArn'] != arn:
            raise ValueError('conflicting or unsupported bucket ARN')
        # S3 ARNs omit the account. Scope the source key as well as the cloud key
        # so conflicting supplied owner claims cannot merge via the fallback key.
        identifier = account + '/' + arn
        asset = dict(source_record_id=identifier, kind='object-storage', cloud_provider='aws',
                     cloud_account=account, cloud_resource_id=arn, hostname=None,
                     ip_addresses=[], tags={})
        AssetObservation.from_dict(SOURCE, asset)
        assets.append(asset)
        references.append(dict(source_record_id=identifier, bucket_record=position))
    return dict(schema_version=1, source=SOURCE, scope=scope,
                assets=sorted(assets, key=lambda item: item['source_record_id']),
                import_metadata=dict(input_sha256=hashlib.sha256(data).hexdigest(), account=account,
                    source_records=references, coverage='not_established',
                    interpretation='Saved bucket identity claims only. Account and scope are supplied. '
                    'No owner authentication, collection completeness, region, public access, encryption, '
                    'policy, object contents or current state is established. No AWS call occurs.'))


def inventory(document):
    observations = [AssetObservation.from_dict(SOURCE, item) for item in document['assets']]
    assets = correlate_assets(observations)
    return dict(schema_version=1, report_type='saved-s3-inventory', scope=document['scope'],
                observation_count=len(observations), asset_count=len(assets),
                assets=[asset.to_dict() for asset in assets], import_metadata=document['import_metadata'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('export', type=Path)
    parser.add_argument('--scope', required=True, choices=sorted(ALLOWED_SCOPES))
    parser.add_argument('--account', required=True)
    parser.add_argument('--format', choices=('fixture', 'inventory'), default='inventory')
    parser.add_argument('--output', type=Path, help='new private JSON file, never overwrite')
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix':
            raise ValueError('private file handling requires POSIX')
        result = convert_export(_read(args.export), scope=args.scope, account=args.account)
        if args.format == 'inventory':
            result = inventory(result)
        rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n'
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end='')
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print('error: S3 export was not imported; check saved input, scope, account and new output path',
              file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
