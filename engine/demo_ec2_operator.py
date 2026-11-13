"""Exercise separate history and operator keys using temporary original fixtures."""

import base64
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from database.ec2_history_enrollment import _digest
from database.ec2_operator_acceptance import PURPOSE, approve_acceptance, accept_authorized
from engine.demo_ec2_recipient import prepare_handoffs


def operator_policy(signer):
    return json.dumps(dict(schema_version=1, purpose=PURPOSE, audience='fixture-recipient',
        max_validity_seconds=3600, keys=[dict(key_id='fixture-operator', state='active',
        public_key_b64=base64.b64encode(signer.verify_key.encode()).decode('ascii'),
        not_before='2026-10-28T00:00:00Z', not_after='2026-10-29T00:00:00Z')])).encode()


def consent_for(handoff, policy, signer, previous):
    options = handoff[2]
    return json.dumps(approve_acceptance(options['enrollment_data'],
        expected_enrollment_sha256=options['expected_enrollment_sha256'], expected_accepted_sha256=previous,
        authority_policy_sha256=options['expected_policy_sha256'], operator_policy_data=policy,
        expected_operator_policy_sha256=_digest(policy), audience=options['audience'], at=options['at'],
        key_id='fixture-operator', seed=signer.encode(), issued_at='2026-10-28T01:00:00Z',
        expires_at='2026-10-28T02:00:00Z')).encode()


def exercise():
    from nacl.signing import SigningKey
    with tempfile.TemporaryDirectory(prefix='ec2-operator-') as directory:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(directory)
            first, second = prepare_handoffs(root)
            signer = SigningKey.generate()
            policy = operator_policy(signer)
            initial_pin = first[2]['expected_enrollment_sha256']
            initial_consent = consent_for(first, policy, signer, None)
            advance_consent = consent_for(second, policy, signer, initial_pin)
            del signer
            saved = {p: p.read_bytes() for p in root.iterdir() if p.is_file()}
            checkpoint = root/'accepted.json'
            shared = dict(operator_policy_data=policy, expected_operator_policy_sha256=_digest(policy))
            accept_authorized(checkpoint, first[0], first[1], **first[2], **shared,
                              operator_approval_data=initial_consent, bootstrap=True)
            options = dict(second[2], **shared, operator_approval_data=advance_consent,
                           expected_accepted_sha256=initial_pin)
            result = accept_authorized(checkpoint, second[0], second[1], **options)
            rejected = 0
            for change in ({'expected_policy_sha256': '0'*64},
                           {'expected_operator_policy_sha256': '0'*64},
                           {'expected_enrollment_sha256': '0'*64},
                           {'at': '2026-10-28T02:00:00Z'}, {}):
                try: accept_authorized(checkpoint, second[0], second[1], **dict(options, **change))
                except ValueError: rejected += 1
                else: raise ValueError('invalid or stale operator acceptance succeeded')
            if (checkpoint.read_bytes() != second[2]['enrollment_data'] or
                    any(p.read_bytes() != data for p, data in saved.items())):
                raise ValueError('retained evidence or accepted checkpoint changed unexpectedly')
    return dict(status='ec2_operator_exercise_passed', accepted_revision=result['revision'],
        operator_approval_verified=result['operator_approval_verified'], separate_key_roles=2,
        negative_cases_rejected=rejected, inputs_unchanged=True, latest_head_established=False)


def main():
    try: result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: operator exercise failed; install requirements-review.txt and inspect private fixtures', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
