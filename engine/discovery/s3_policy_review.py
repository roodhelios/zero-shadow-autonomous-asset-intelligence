"""Bind saved S3 policy-status and reviewed scoring claims to one inventory asset."""

import argparse
from dataclasses import asdict
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

from engine.discovery.fixture_discovery import ALLOWED_SCOPES
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _unique_fields
from engine.discovery.s3_discovery import convert_export, inventory
from engine.risk import FindingEvidence

POLICY_LIMIT = 16 * 1024
REVIEW_LIMIT = 32 * 1024
REPORT_LIMIT = 64 * 1024
CONTEXT_FIELDS = {'schema_version', 'scope', 'account', 'bucket', 'captured_at',
                  'opened_on', 'asset_tags', 'finding'}
FINDING_FIELDS = {'finding_id', 'severity', 'exposure', 'exploit_evidence',
                  'control_state', 'identity_confidence'}
MODEL_FILES = ('engine/discovery/s3_policy_review.py', 'engine/discovery/s3_discovery.py',
               'engine/discovery/osquery_collector.py', 'engine/models.py',
               'engine/correlation/asset_graph.py', 'engine/risk.py')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    result = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields)
    _canonical(result)
    return result


def _pin(data, expected, limit):
    if (type(data) is not bytes or len(data) > limit or type(expected) is not str or
            re.fullmatch(r'[0-9a-f]{64}', expected) is None or _digest(data) != expected):
        raise ValueError('bounded bytes must match independent pin')


def _model():
    root = Path(__file__).resolve().parents[2]
    return _digest(_canonical({name: _digest((root / name).read_bytes()) for name in MODEL_FILES}))


def _read_input(path, limit):
    if os.name != 'posix':
        raise ValueError('private bounded inputs require POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('bounded regular input required')
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds bound')
    return data


def finding_bytes(report):
    record = report['finding_record']
    return b'' if record is None else _canonical(record) + b'\n'


def review_policy(listing_data, policy_data, context_data, *, expected_listing_sha256,
                  expected_policy_sha256, expected_context_sha256, scope):
    for data, pin, limit in ((listing_data, expected_listing_sha256, MAX_INPUT_BYTES),
            (policy_data, expected_policy_sha256, POLICY_LIMIT),
            (context_data, expected_context_sha256, REVIEW_LIMIT)):
        _pin(data, pin, limit)
    context = _json(context_data)
    if (type(context) is not dict or set(context) != CONTEXT_FIELDS or
            type(context['schema_version']) is not int or context['schema_version'] != 1 or
            scope not in ALLOWED_SCOPES or context['scope'] != scope or
            any(type(context[k]) is not str or not 1 <= len(context[k]) <= 64
                for k in ('account', 'bucket', 'captured_at', 'opened_on'))):
        raise ValueError('exact scoped review context required')
    captured = datetime.fromisoformat(context['captured_at'].replace('Z', '+00:00'))
    if captured.tzinfo is None:
        raise ValueError('timezone-aware capture claim required')
    opened = date.fromisoformat(context['opened_on'])
    if opened.isoformat() != context['opened_on']:
        raise ValueError('canonical opening date required')
    tags = context['asset_tags']
    if (type(tags) is not dict or len(tags) > 32 or any(type(k) is not str or
            re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', k) is None or type(v) is not str or
            not 1 <= len(v) <= 128 or v.strip() != v for k, v in tags.items())):
        raise ValueError('bounded explicit routing tags required')
    converted = convert_export(listing_data, scope=scope, account=context['account'])
    identifier = context['account'] + '/arn:aws:s3:::' + context['bucket']
    refs = [row for row in converted['import_metadata']['source_records']
            if row['source_record_id'] == identifier]
    if len(refs) != 1:
        raise ValueError('selected bucket is absent from exact listing')
    selected = [asset for asset in inventory(converted)['assets'] if any(
        row['source_record_id'] == identifier for row in asset['observations'])]
    if len(selected) != 1:
        raise ValueError('selected bucket identity is ambiguous')
    policy = _json(policy_data)
    if (type(policy) is not dict or set(policy) != {'PolicyStatus'} or
            type(policy['PolicyStatus']) is not dict or set(policy['PolicyStatus']) != {'IsPublic'} or
            type(policy['PolicyStatus']['IsPublic']) is not bool):
        raise ValueError('exact saved policy-status CLI response required')
    is_public = policy['PolicyStatus']['IsPublic']
    model = _model()
    binding = {'listing_sha256': expected_listing_sha256, 'policy_sha256': expected_policy_sha256,
               'context_sha256': expected_context_sha256, 'model_sha256': model}
    binding_id = _digest(_canonical(binding))
    record = None
    if is_public:
        supplied = context['finding']
        if (type(supplied) is not dict or set(supplied) != FINDING_FIELDS or
                any(type(v) is not str or not 1 <= len(v) <= 128 or v.strip() != v
                    for v in supplied.values())):
            raise ValueError('explicit reviewed scoring facts required')
        finding = FindingEvidence.from_dict({**supplied, 'asset_id': selected[0]['asset_id'],
            'source': 'saved-s3-policy:' + binding_id,
            'description': 'Saved policy status reports IsPublic true; scoring facts are separately supplied.'})
        record = {'finding': asdict(finding), 'opened_on': context['opened_on'], 'asset_tags': tags}
    elif context['finding'] is not None:
        raise ValueError('nonpublic policy claim cannot justify this public-policy finding')
    result = {'schema_version': 1, 'report_type': 'saved-s3-policy-review', 'scope': scope,
        'binding': binding, 'binding_id': binding_id, 'account': context['account'],
        'bucket_arn': 'arn:aws:s3:::' + context['bucket'], 'source_record': refs[0],
        'asset_id': selected[0]['asset_id'], 'captured_at': context['captured_at'],
        'policy_is_public_claim': is_public, 'finding_record': record,
        'source_truth_verified': False, 'effective_exposure_verified': False,
        'interpretation': 'The independently selected context associates exact saved policy-status bytes '
            'with one account-qualified listing identity. Responses do not contain that identity. '
            'Account, capture time, scoring facts and routing remain supplied claims. IsPublic alone '
            'does not establish effective reachability, object access, compromise or remediation. '
            'False or absent public-policy findings do not establish that the asset is clean.'}
    if len(_canonical(result)) > REPORT_LIMIT:
        raise ValueError('review exceeds report bound')
    return result


def verify_review(report_data, listing_data, policy_data, context_data, *, expected_report_sha256,
                  assessment=None, **options):
    _pin(report_data, expected_report_sha256, REPORT_LIMIT)
    report = review_policy(listing_data, policy_data, context_data, **options)
    if _canonical(_json(report_data)) != _canonical(report):
        raise ValueError('complete policy review did not reproduce')
    matched = False
    if assessment is not None:
        from database.inventory_assessment_verify import verify_assessment
        verified = verify_assessment(assessment, listing_data, require_model_binding=True)
        if verified['input_sha256']['findings'] != _digest(finding_bytes(report)):
            raise ValueError('assessment findings differ from exact policy-derived input')
        matched = True
    return {'status': 's3_policy_review_reproduced', 'finding_count': int(report['finding_record'] is not None),
            'report_sha256': expected_report_sha256, 'assessment_input_verified': matched,
            'effective_exposure_verified': False, 'source_truth_verified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo', help='temporary saved-policy review and native SQLite assessment')
    for command in ('create', 'verify'):
        selected = commands.add_parser(command, allow_abbrev=False)
        for name in ('listing', 'policy', 'context'):
            selected.add_argument(name, type=Path)
            selected.add_argument('--expected-' + name + '-sha256', required=True)
        selected.add_argument('--scope', required=True, choices=sorted(ALLOWED_SCOPES))
        if command == 'create':
            selected.add_argument('--directory', required=True, type=Path)
        else:
            selected.add_argument('--report', required=True, type=Path)
            selected.add_argument('--expected-report-sha256', required=True)
            selected.add_argument('--assessment', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            from engine.demo_s3_policy_review import exercise
            print(json.dumps(exercise(), sort_keys=True))
            return 0
        inputs = (_read_input(args.listing, MAX_INPUT_BYTES), _read_input(args.policy, POLICY_LIMIT),
                  _read_input(args.context, REVIEW_LIMIT))
        options = dict(scope=args.scope, expected_listing_sha256=args.expected_listing_sha256,
            expected_policy_sha256=args.expected_policy_sha256, expected_context_sha256=args.expected_context_sha256)
        if args.command == 'verify':
            result = verify_review(_read_input(args.report, REPORT_LIMIT), *inputs,
                expected_report_sha256=args.expected_report_sha256, assessment=args.assessment, **options)
        else:
            report = review_policy(*inputs, **options)
            data = _canonical(report) + b'\n'
            created = False
            try:
                os.mkdir(args.directory, 0o700); created = True
                _publish(args.directory / 'review.json', data.decode())
                _publish(args.directory / 'findings.jsonl', finding_bytes(report).decode())
            except BaseException:
                if created:
                    for name in ('review.json', 'findings.jsonl'):
                        (args.directory / name).unlink(missing_ok=True)
                    args.directory.rmdir()
                raise
            result = {'status': 's3_policy_review_created', 'report_sha256': _digest(data),
                'finding_count': int(report['finding_record'] is not None), 'effective_exposure_verified': False}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: S3 policy review failed; check private originals, independent pins, review context and output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
