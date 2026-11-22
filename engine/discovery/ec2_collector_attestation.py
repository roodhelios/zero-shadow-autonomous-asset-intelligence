"""Authenticate an enrolled key's saved EC2 collection claim, then reproduce network review."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

from database.ec2_assessment import _canonical
from database.ec2_history_approval import _crypto, _decode, _identifier, _json, _policy, _time
from engine.discovery.ec2_address_review import _render
from engine.discovery.ec2_network_expectations import MAX_EXPECTATIONS_BYTES, _pin, review
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _read

PURPOSE = 'zero-shadow-ec2-collector-attestation-v1'
DOMAIN = PURPOSE.encode('ascii') + b'\x00'
FIELDS = {'schema_version', 'purpose', 'scope', 'account', 'region', 'audience', 'key_id',
          'export_sha256', 'expectations_sha256', 'captured_at', 'expires_at', 'signature_b64'}


def _authority(data, pin, *, scope, account, region, audience, key_id, at, signing=False):
    if type(data) is not bytes or not 0 < len(data) <= 64 * 1024:
        raise ValueError('bounded collector policy required')
    _pin(data, pin)
    policy = _json(data, 64 * 1024)
    if (set(policy) != {'schema_version', 'scope', 'account', 'region', 'authority'} or
            type(policy['schema_version']) is not int or policy['schema_version'] != 1 or
            any(policy[name] != value for name, value in
                {'scope': scope, 'account': account, 'region': region}.items())):
        raise ValueError('collector policy context differs')
    authority = _canonical(policy['authority']).encode('ascii')
    return _policy(authority, hashlib.sha256(authority).hexdigest(), audience, key_id, at,
                   signing=signing, purpose=PURPOSE)


def _window(claim, key, maximum, at):
    captured, expires, now = _time(claim['captured_at']), _time(claim['expires_at']), _time(at)
    if (not captured <= now < expires or not 0 < (expires-captured).total_seconds() <= maximum or
            captured < _time(key['not_before']) or expires > _time(key['not_after'])):
        raise ValueError('capture claim is future, expired or outside policy window')


def _message(claim):
    return DOMAIN + _canonical({k: v for k, v in claim.items() if k != 'signature_b64'}).encode('ascii')


def _review(export, expectations, *, scope, account, region):
    if type(export) is not bytes or not 0 < len(export) <= MAX_INPUT_BYTES:
        raise ValueError('bounded saved export required')
    if type(expectations) is not bytes or not 0 < len(expectations) <= MAX_EXPECTATIONS_BYTES:
        raise ValueError('bounded expected roster required')
    return review(export, expectations, scope=scope, account=account, region=region,
        original_sha256=hashlib.sha256(export).hexdigest(),
        expectations_sha256=hashlib.sha256(expectations).hexdigest())


def create_attestation(export, expectations, policy_data, *, expected_policy_sha256,
                       scope, account, region, audience, key_id, seed, captured_at, expires_at, at):
    key, maximum = _authority(policy_data, expected_policy_sha256, scope=scope, account=account,
        region=region, audience=audience, key_id=key_id, at=at, signing=True)
    SigningKey, _ = _crypto()
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError('private Ed25519 seed required')
    signer = SigningKey(seed)
    if signer.verify_key.encode() != _decode(key['public_key_b64'], 32):
        raise ValueError('signer differs from enrolled collector key')
    report = _review(export, expectations, scope=scope, account=account, region=region)
    claim = {'schema_version': 1, 'purpose': PURPOSE, 'scope': scope, 'account': account,
        'region': region, 'audience': _identifier(audience), 'key_id': _identifier(key_id),
        'export_sha256': report['original_sha256'], 'expectations_sha256': report['expectations_sha256'],
        'captured_at': captured_at, 'expires_at': expires_at, 'signature_b64': ''}
    _window(claim, key, maximum, at)
    claim['signature_b64'] = base64.b64encode(signer.sign(_message(claim)).signature).decode('ascii')
    return claim


def verify_attestation(export, expectations, claim_data, policy_data, *, expected_claim_sha256,
                       expected_policy_sha256, scope, account, region, audience, at):
    if type(claim_data) is not bytes or not 0 < len(claim_data) <= 4096:
        raise ValueError('bounded collector claim required')
    _pin(claim_data, expected_claim_sha256)
    # The independent outer policy pin precedes either policy/claim parsing.
    if type(policy_data) is not bytes or len(policy_data) > 64 * 1024:
        raise ValueError('bounded collector policy required')
    _pin(policy_data, expected_policy_sha256)
    claim = _json(claim_data, 4096)
    if (set(claim) != FIELDS or type(claim['schema_version']) is not int or claim['schema_version'] != 1 or
            claim['purpose'] != PURPOSE or any(claim[name] != value for name, value in
                {'scope': scope, 'account': account, 'region': region, 'audience': audience}.items())):
        raise ValueError('unsupported collector claim or selected context')
    key, maximum = _authority(policy_data, expected_policy_sha256, scope=scope, account=account,
        region=region, audience=audience, key_id=claim['key_id'], at=at)
    _window(claim, key, maximum, at)
    _, VerifyKey = _crypto()
    from nacl.exceptions import BadSignatureError
    try:
        VerifyKey(_decode(key['public_key_b64'], 32)).verify(_message(claim), _decode(claim['signature_b64'], 64))
    except BadSignatureError:
        raise ValueError('collector signature did not verify') from None
    # A valid signature cannot authorize substituted original or roster bytes.
    _pin(export, claim['export_sha256']); _pin(expectations, claim['expectations_sha256'])
    report = _review(export, expectations, scope=scope, account=account, region=region)
    return {'schema_version': 1, 'report_type': 'attested-ec2-network-review',
        'claim_sha256': expected_claim_sha256, 'policy_sha256': expected_policy_sha256,
        'key_id': claim['key_id'], 'audience': audience, 'captured_at': claim['captured_at'],
        'expires_at': claim['expires_at'], 'verified_at': at, 'collector_signature_verified': True,
        'aws_source_verified': False, 'capture_time_is_claim': True,
        'collection_completeness_established': False, 'network_review': report,
        'interpretation': 'An enrolled key signed these exact saved export/roster bytes and capture '
            'claims under the selected pinned policy. This is not AWS response authentication, '
            'host identity proof, truthful collection time, latest policy distribution, one-time '
            'use, complete collection or effective exposure. Repeated verification is allowed.'}


def exercise():
    SigningKey, _ = _crypto(); signer = SigningKey.generate()
    root = Path(__file__).resolve().parents[2]
    export = (root / 'examples/ec2-interface-addresses.json').read_bytes()
    roster = (root / 'examples/ec2-network-expectations.json').read_bytes()
    policy = {'schema_version': 1, 'scope': 'synthetic', 'account': '111122223333', 'region': 'us-east-1',
        'authority': {'schema_version': 1, 'purpose': PURPOSE, 'audience': 'fixture-review',
            'max_validity_seconds': 3600, 'keys': [{'key_id': 'fixture-collector',
            'public_key_b64': base64.b64encode(signer.verify_key.encode()).decode('ascii'),
            'state': 'active', 'not_before': '2026-11-22T00:00:00Z', 'not_after': '2026-11-23T00:00:00Z'}]}}
    policy_data = _canonical(policy).encode('ascii')
    options = dict(expected_policy_sha256=hashlib.sha256(policy_data).hexdigest(), scope='synthetic',
                   account='111122223333', region='us-east-1', audience='fixture-review', at='2026-11-22T12:01:00Z')
    claim = create_attestation(export, roster, policy_data, **options, key_id='fixture-collector',
        seed=signer.encode(), captured_at='2026-11-22T12:00:00Z', expires_at='2026-11-22T12:30:00Z')
    data = _canonical(claim).encode('ascii'); pin = hashlib.sha256(data).hexdigest()
    result = verify_attestation(export, roster, data, policy_data, expected_claim_sha256=pin, **options)
    try:
        verify_attestation(export + b' ', roster, data, policy_data, expected_claim_sha256=pin, **options)
    except ValueError:
        return {'status': 'ec2_collector_attestation_exercise_passed', 'collector_signature_verified': True,
            'changed_export_rejected': True, 'aws_source_verified': False,
            'selected_roster_matches': result['network_review']['selected_roster_matches']}
    raise ValueError('substituted export accepted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True); commands.add_parser('demo')
    verify = commands.add_parser('verify', allow_abbrev=False)
    for name in ('export', 'expectations', 'claim', 'policy'): verify.add_argument(name, type=Path)
    for name in ('claim', 'policy'): verify.add_argument(f'--expected-{name}-sha256', required=True)
    verify.add_argument('--scope', choices=('synthetic', 'owned', 'authorized'), required=True)
    for name in ('account', 'region', 'audience', 'at'): verify.add_argument('--' + name, required=True)
    verify.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo': result = exercise()
        else:
            report = verify_attestation(_read(args.export), _read(args.expectations), _read(args.claim),
                _read(args.policy), expected_claim_sha256=args.expected_claim_sha256,
                expected_policy_sha256=args.expected_policy_sha256, scope=args.scope, account=args.account,
                region=args.region, audience=args.audience, at=args.at)
            rendered = _render(report); _publish(args.output, rendered)
            result = {'status': 'attested_ec2_network_review_created', 'collector_signature_verified': True,
                'aws_source_verified': False, 'capture_time_is_claim': True,
                'selected_roster_matches': report['network_review']['selected_roster_matches'],
                'report_sha256': hashlib.sha256(rendered.encode()).hexdigest()}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print('error: collector attestation failed; check private inputs, independent pins, selected context, time and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
