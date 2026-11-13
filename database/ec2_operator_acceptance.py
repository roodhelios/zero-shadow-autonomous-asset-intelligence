"""Sign explicit recipient consent and verify it before local checkpoint acceptance."""

import argparse
import base64
import json
from pathlib import Path
import sqlite3
import sys

from database.ec2_history_approval import _canonical, _crypto, _decode, _file, _json, _policy, _time
from database.ec2_history_enrollment import _parse, read_enrollment
from database.ec2_recipient_checkpoint import accept_checkpoint
from database.ec2_review_history import _check_digest
from engine.discovery.osquery_collector import _publish, _read

PURPOSE = 'zero-shadow-ec2-operator-acceptance-v1'
FIELDS = {'schema_version', 'purpose', 'key_id', 'audience', 'enrollment_sha256',
          'previous_enrollment_sha256', 'authority_policy_sha256', 'operator_policy_sha256',
          'issued_at', 'expires_at', 'signature_b64'}


def _message(document):
    return PURPOSE.encode('ascii') + b'\x00' + _canonical(
        {k: v for k, v in document.items() if k != 'signature_b64'}).encode('ascii')


def _window(document, key, maximum, at):
    issued, expires = _time(document['issued_at']), _time(document['expires_at'])
    if (not issued <= _time(at) < expires or not 0 < (expires-issued).total_seconds() <= maximum or
            issued < _time(key['not_before']) or expires > _time(key['not_after'])):
        raise ValueError('operator consent is outside its permitted time window')


def approve_acceptance(enrollment_data, *, expected_enrollment_sha256, expected_accepted_sha256,
                       authority_policy_sha256, operator_policy_data, expected_operator_policy_sha256,
                       audience, at, key_id, seed, issued_at, expires_at):
    """Sign reviewed pins only. Full evidence is verified again at acceptance."""
    selected = _parse(enrollment_data, expected_enrollment_sha256)
    _check_digest(authority_policy_sha256)
    if expected_accepted_sha256 is not None:
        _check_digest(expected_accepted_sha256)
    if selected['previous_enrollment_sha256'] != expected_accepted_sha256:
        raise ValueError('consent does not name the selected predecessor')
    key, maximum = _policy(operator_policy_data, expected_operator_policy_sha256,
                          audience, key_id, at, signing=True, purpose=PURPOSE)
    SigningKey, _ = _crypto()
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError('expected a private 32-byte operator seed')
    signer = SigningKey(seed)
    if signer.verify_key.encode() != _decode(key['public_key_b64'], 32):
        raise ValueError('operator seed does not match the enrolled key')
    document = dict(schema_version=1, purpose=PURPOSE, key_id=key_id, audience=audience,
        enrollment_sha256=expected_enrollment_sha256, previous_enrollment_sha256=expected_accepted_sha256,
        authority_policy_sha256=authority_policy_sha256, operator_policy_sha256=expected_operator_policy_sha256,
        issued_at=issued_at, expires_at=expires_at, signature_b64='')
    _window(document, key, maximum, at)
    document['signature_b64'] = base64.b64encode(signer.sign(_message(document)).signature).decode('ascii')
    return document


def verify_acceptance(data, *, expected_enrollment_sha256, expected_accepted_sha256,
                      authority_policy_sha256, operator_policy_data, expected_operator_policy_sha256,
                      audience, at):
    _check_digest(expected_enrollment_sha256)
    _check_digest(authority_policy_sha256)
    if expected_accepted_sha256 is not None:
        _check_digest(expected_accepted_sha256)
    document = _json(data, 4096)
    if (set(document) != FIELDS or type(document['schema_version']) is not int or document['schema_version'] != 1 or
            document['purpose'] != PURPOSE or document['audience'] != audience or
            document['enrollment_sha256'] != expected_enrollment_sha256 or
            document['previous_enrollment_sha256'] != expected_accepted_sha256 or
            document['authority_policy_sha256'] != authority_policy_sha256 or
            document['operator_policy_sha256'] != expected_operator_policy_sha256):
        raise ValueError('operator consent does not bind this acceptance context')
    key, maximum = _policy(operator_policy_data, expected_operator_policy_sha256,
                          audience, document['key_id'], at, purpose=PURPOSE)
    _window(document, key, maximum, at)
    _, VerifyKey = _crypto()
    from nacl.exceptions import BadSignatureError
    try:
        VerifyKey(_decode(key['public_key_b64'], 32)).verify(
            _message(document), _decode(document['signature_b64'], 64))
    except BadSignatureError:
        raise ValueError('operator consent signature did not verify') from None
    return dict(operator_approval_verified=True, operator_key_id=document['key_id'],
                operator_policy_sha256=expected_operator_policy_sha256)


def accept_authorized(checkpoint, history, approval_data, *, operator_approval_data,
                      operator_policy_data, expected_operator_policy_sha256, **options):
    """Require explicit consent, then reuse full replay and the existing writer lock."""
    consent = verify_acceptance(operator_approval_data,
        expected_enrollment_sha256=options['expected_enrollment_sha256'],
        expected_accepted_sha256=options.get('expected_accepted_sha256'),
        authority_policy_sha256=options['expected_policy_sha256'],
        operator_policy_data=operator_policy_data, expected_operator_policy_sha256=expected_operator_policy_sha256,
        audience=options['audience'], at=options['at'])
    result = accept_checkpoint(checkpoint, history, approval_data, **options)
    return dict(result, **consent, status='ec2_operator_acceptance_completed')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    sign = commands.add_parser('sign')
    sign.add_argument('--seed-file', type=Path, required=True)
    sign.add_argument('--key-id', required=True)
    sign.add_argument('--issued-at', required=True)
    sign.add_argument('--expires-at', required=True)
    sign.add_argument('--output', type=Path, required=True)
    accept = commands.add_parser('accept')
    accept.add_argument('checkpoint', type=Path)
    accept.add_argument('history', type=Path)
    accept.add_argument('approval', type=Path)
    accept.add_argument('--operator-approval', type=Path, required=True)
    accept.add_argument('--export', type=Path, required=True)
    accept.add_argument('--policy', type=Path, required=True)
    for sub in (sign, accept):
        sub.add_argument('--enrollment', type=Path, required=True)
        sub.add_argument('--expected-enrollment-sha256', required=True)
        mode = sub.add_mutually_exclusive_group(required=True)
        mode.add_argument('--bootstrap', action='store_true')
        mode.add_argument('--expected-accepted-sha256')
        sub.add_argument('--expected-policy-sha256', required=True)
        sub.add_argument('--operator-policy', type=Path, required=True)
        sub.add_argument('--expected-operator-policy-sha256', required=True)
        sub.add_argument('--audience', required=True)
        sub.add_argument('--at', required=True)
    args = parser.parse_args(argv)
    try:
        policy = _file(args.operator_policy, 64*1024)
        selection = read_enrollment(args.enrollment)
        common = dict(expected_enrollment_sha256=args.expected_enrollment_sha256,
            expected_accepted_sha256=args.expected_accepted_sha256, authority_policy_sha256=args.expected_policy_sha256,
            operator_policy_data=policy, expected_operator_policy_sha256=args.expected_operator_policy_sha256,
            audience=args.audience, at=args.at)
        if args.command == 'sign':
            document = approve_acceptance(selection, **common, seed=_file(args.seed_file, 32, private=True),
                key_id=args.key_id, issued_at=args.issued_at, expires_at=args.expires_at)
            _publish(args.output, _canonical(document)+'\n')
            result = dict(status='ec2_operator_consent_stored')
        else:
            result = accept_authorized(args.checkpoint, args.history, _file(args.approval, 4096),
                operator_approval_data=_file(args.operator_approval, 4096), operator_policy_data=policy,
                expected_operator_policy_sha256=args.expected_operator_policy_sha256,
                enrollment_data=selection, expected_enrollment_sha256=args.expected_enrollment_sha256,
                expected_accepted_sha256=args.expected_accepted_sha256, bootstrap=args.bootstrap,
                export_data=_read(args.export), policy_data=_file(args.policy, 64*1024),
                expected_policy_sha256=args.expected_policy_sha256, audience=args.audience, at=args.at)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError, RecursionError, OverflowError):
        print('error: operator acceptance did not confirm success; inspect private state, consent and trusted policies',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
