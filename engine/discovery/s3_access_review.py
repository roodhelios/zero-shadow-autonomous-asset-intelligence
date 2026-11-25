"""Review saved S3 Block Public Access claims without inferring live exposure."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import sys

from engine.discovery import s3_policy_review as policy
from engine.discovery.fixture_discovery import ALLOWED_SCOPES

CONTROL_LIMIT = 16 * 1024
REPORT_LIMIT = 96 * 1024
SETTINGS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')
CONTEXT_FIELDS = {'schema_version', 'scope', 'account', 'bucket', 'window_start', 'window_end',
                  'maximum_skew_seconds', 'bucket_captured_at', 'account_captured_at'}
INPUTS = ('listing', 'policy', 'context', 'bucket_controls', 'account_controls', 'control_context')
LIMITS = (policy.MAX_INPUT_BYTES, policy.POLICY_LIMIT, policy.REVIEW_LIMIT,
          CONTROL_LIMIT, CONTROL_LIMIT, CONTROL_LIMIT)
MEANINGS = {
    'BlockPublicAcls': 'Rejects new public ACL operations; does not remove existing ACLs.',
    'IgnorePublicAcls': 'Ignores public ACL grants; does not delete the stored ACLs.',
    'BlockPublicPolicy': 'Rejects new public policy writes; does not neutralize an existing public policy.',
    'RestrictPublicBuckets': 'Restricts public and cross-account policy access when a policy is public; service principals and authorized same-account users remain exceptions.',
}


def _instant(value):
    if type(value) is not str or not 1 <= len(value) <= 64:
        raise ValueError('bounded capture instant required')
    instant = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if instant.tzinfo is None:
        raise ValueError('timezone-aware capture instant required')
    return instant


def _controls(data):
    value = policy._json(data)
    if type(value) is not dict:
        raise ValueError('exact saved control response or unknown record required')
    if set(value) == {'collection_status', 'reason'}:
        if (value['collection_status'] != 'unknown' or
                value['reason'] not in ('not_collected', 'access_denied', 'no_saved_response')):
            raise ValueError('explicit bounded unknown collection reason required')
        return dict(collection_status='unknown', reason=value['reason'],
                    settings={key: None for key in SETTINGS})
    if set(value) != {'PublicAccessBlockConfiguration'}:
        raise ValueError('selected CLI control response required')
    supplied = value['PublicAccessBlockConfiguration']
    if (type(supplied) is not dict or set(supplied) - set(SETTINGS) or
            any(type(v) is not bool for v in supplied.values())):
        raise ValueError('only supplied boolean control settings accepted')
    # Optional API fields that are absent remain unknown, never implicit false.
    return dict(collection_status='supplied', reason=None,
                settings={key: supplied.get(key) for key in SETTINGS})


def review_access(listing_data, policy_data, context_data, bucket_controls_data,
                  account_controls_data, control_context_data, *, scope, **pins):
    data = (listing_data, policy_data, context_data, bucket_controls_data,
            account_controls_data, control_context_data)
    if set(pins) != {'expected_' + name + '_sha256' for name in INPUTS}:
        raise ValueError('all independently selected input pins required')
    for name, original, limit in zip(INPUTS, data, LIMITS):
        policy._pin(original, pins['expected_' + name + '_sha256'], limit)
    selected = policy.review_policy(listing_data, policy_data, context_data, scope=scope,
        **{key: pins[key] for key in ('expected_listing_sha256', 'expected_policy_sha256', 'expected_context_sha256')})
    context = policy._json(control_context_data)
    if (type(context) is not dict or set(context) != CONTEXT_FIELDS or
            type(context['schema_version']) is not int or context['schema_version'] != 1 or
            context['scope'] != scope or context['account'] != selected['account'] or
            type(context['bucket']) is not str or
            'arn:aws:s3:::' + context['bucket'] != selected['bucket_arn'] or
            type(context['maximum_skew_seconds']) is not int or
            not 0 <= context['maximum_skew_seconds'] <= 86400):
        raise ValueError('exact matching control review context required')
    start, end = _instant(context['window_start']), _instant(context['window_end'])
    captures = [_instant(selected['captured_at']), _instant(context['bucket_captured_at']),
                _instant(context['account_captured_at'])]
    if (start > end or any(not start <= instant <= end for instant in captures) or
            (max(captures) - min(captures)).total_seconds() > context['maximum_skew_seconds']):
        raise ValueError('capture claims outside selected window or skew bound')
    sources = dict(bucket=_controls(bucket_controls_data), account=_controls(account_controls_data))
    combined = {}
    for key in SETTINGS:
        values = [sources[level]['settings'][key] for level in ('bucket', 'account')]
        combined[key] = dict(
            combined_claim=True if True in values else None if None in values else False,
            restricting_levels=[level for level in sources if sources[level]['settings'][key] is True],
            unknown_levels=[level for level in sources if sources[level]['settings'][key] is None],
            meaning=MEANINGS[key])
    restriction = combined['RestrictPublicBuckets']['combined_claim']
    if not selected['policy_is_public_claim']:
        state = 'no_public_policy_reported'
    elif restriction is True:
        state = 'restriction_reported'
    elif restriction is False:
        state = 'no_restriction_reported'
    else:
        state = 'restriction_unknown'
    binding = {name + '_sha256': pins['expected_' + name + '_sha256'] for name in INPUTS}
    binding['model_sha256'] = policy._digest(policy._canonical(dict(
        policy_model=policy._model(), access_model=policy._digest(Path(__file__).read_bytes()))))
    result = dict(schema_version=1, report_type='saved-s3-access-control-review', scope=scope,
        binding=binding, binding_id=policy._digest(policy._canonical(binding)),
        policy_review=selected, control_context=context, control_sources=sources,
        combined_settings=combined, public_policy_review_state=state,
        finding_unchanged=True, effective_exposure_verified=False, source_truth_verified=False,
        interpretation='Combines only supplied bucket and account control claims. Missing fields and '
            'unavailable responses stay unknown. A reported restriction is not verified enforcement. '
            'Organization and access-point controls, ACLs, object permissions, policy content, '
            'propagation, capture truth and current state remain outside this review. '
            'False does not prove public access; IsPublic false does not prove a clean asset. '
            'The separately reviewed finding and scoring facts are preserved without suppression.')
    if len(policy._canonical(result)) > REPORT_LIMIT:
        raise ValueError('access review exceeds bound')
    return result


def verify_access(report_data, *inputs, expected_report_sha256, assessment=None, **options):
    policy._pin(report_data, expected_report_sha256, REPORT_LIMIT)
    report = review_access(*inputs, **options)
    if policy._canonical(policy._json(report_data)) != policy._canonical(report):
        raise ValueError('complete access review did not reproduce')
    checked = False
    if assessment is not None:
        original = policy._canonical(report['policy_review'])
        verification = policy.verify_review(original, *inputs[:3],
            expected_report_sha256=policy._digest(original), assessment=assessment,
            scope=options['scope'], **{key: options[key] for key in
                ('expected_listing_sha256', 'expected_policy_sha256', 'expected_context_sha256')})
        checked = verification['assessment_input_verified']
    return dict(status='s3_access_review_reproduced', report_sha256=expected_report_sha256,
        public_policy_review_state=report['public_policy_review_state'], assessment_input_verified=checked,
        effective_exposure_verified=False, source_truth_verified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('demo', help='temporary complete saved-control review and assessment verification')
    for name in ('create', 'verify'):
        command = commands.add_parser(name, allow_abbrev=False)
        for field in INPUTS:
            command.add_argument(field, type=Path)
            command.add_argument('--expected-' + field.replace('_', '-') + '-sha256', required=True,
                                 dest='expected_' + field + '_sha256')
        command.add_argument('--scope', choices=sorted(ALLOWED_SCOPES), required=True)
        if name == 'create':
            command.add_argument('--output', type=Path, required=True)
        else:
            command.add_argument('--report', type=Path, required=True)
            command.add_argument('--expected-report-sha256', required=True)
            command.add_argument('--assessment', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            from engine.demo_s3_access_review import exercise
            result = exercise()
        else:
            originals = [policy._read_input(getattr(args, name), limit) for name, limit in zip(INPUTS, LIMITS)]
            options = dict(scope=args.scope, **{'expected_' + name + '_sha256':
                getattr(args, 'expected_' + name + '_sha256') for name in INPUTS})
            if args.command == 'verify':
                result = verify_access(policy._read_input(args.report, REPORT_LIMIT), *originals,
                    expected_report_sha256=args.expected_report_sha256, assessment=args.assessment, **options)
            else:
                report = review_access(*originals, **options)
                data = policy._canonical(report) + b'\n'
                if len(data) > REPORT_LIMIT: raise ValueError('access review exceeds bound')
                policy._publish(args.output, data.decode())
                result = dict(status='s3_access_review_created', report_sha256=policy._digest(data),
                    public_policy_review_state=report['public_policy_review_state'], effective_exposure_verified=False)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: S3 access review failed; check originals, independent pins, capture context and private output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
