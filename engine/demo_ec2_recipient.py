"""Accept two signed synthetic selections without retaining the private signing key."""

import base64
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

from database.ec2_history_approval import PURPOSE, approve_history
from database.ec2_history_enrollment import _digest, advance_enrollment, enroll_history
from database.ec2_recipient_checkpoint import accept_checkpoint
from engine.demo_ec2_enrollment import prepare_histories


def prepare_handoffs(work):
    """Generate local SQLite evidence and ephemeral Ed25519 approvals for this exercise."""
    from nacl.signing import SigningKey
    histories, heads, _, export = prepare_histories(work)
    first, second = work/'selection-1.json', work/'selection-2.json'
    enroll_history(histories[0], first, export_data=export, expected_head=heads[0])
    advance_enrollment(histories[1], second, enrollment_data=first.read_bytes(),
        expected_enrollment_sha256=_digest(first.read_bytes()), export_data=export, expected_head=heads[1])
    signer = SigningKey.generate()
    policy = json.dumps(dict(schema_version=1, purpose=PURPOSE, audience='fixture-recipient',
        max_validity_seconds=3600, keys=[dict(key_id='fixture-reviewer', state='active',
        public_key_b64=base64.b64encode(signer.verify_key.encode()).decode('ascii'),
        not_before='2026-10-28T00:00:00Z', not_after='2026-10-29T00:00:00Z')])).encode()
    shared = dict(export_data=export, policy_data=policy, expected_policy_sha256=_digest(policy),
                  audience='fixture-recipient', at='2026-10-28T01:00:00Z')
    handoffs = []
    for history, selection in zip(histories, (first, second)):
        options = dict(shared, enrollment_data=selection.read_bytes(),
                       expected_enrollment_sha256=_digest(selection.read_bytes()))
        approval = approve_history(history, **options, seed=signer.encode(), key_id='fixture-reviewer',
            issued_at='2026-10-28T01:00:00Z', expires_at='2026-10-28T02:00:00Z')
        handoffs.append((history, json.dumps(approval).encode(), options))
    # Only public verification context and signed evidence leave this function.
    return handoffs


def exercise():
    with tempfile.TemporaryDirectory(prefix='ec2-recipient-') as name:
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            root = Path(name)
            first, second = prepare_handoffs(root)
            saved = {path: path.read_bytes() for path in root.iterdir() if path.is_file()}
            checkpoint = root/'accepted.json'
            accept_checkpoint(checkpoint, first[0], first[1], **first[2], bootstrap=True)
            pin = first[2]['expected_enrollment_sha256']
            accepted = accept_checkpoint(checkpoint, second[0], second[1], **second[2],
                                         expected_accepted_sha256=pin)
            rejected = 0
            for handoff, expected in ((second, pin), (first, accepted['checkpoint_sha256'])):
                try:
                    accept_checkpoint(checkpoint, handoff[0], handoff[1], **handoff[2],
                                      expected_accepted_sha256=expected)
                except ValueError:
                    rejected += 1
                else:
                    raise ValueError('stale or rollback selection accepted')
            if (checkpoint.read_bytes() != second[2]['enrollment_data'] or
                    any(path.read_bytes() != data for path, data in saved.items())):
                raise ValueError('checkpoint or original evidence changed unexpectedly')
    return dict(status='ec2_recipient_exercise_passed', accepted_revision=accepted['revision'],
        previous_checkpoint_verified=accepted['previous_checkpoint_verified'],
        negative_cases_rejected=rejected, inputs_unchanged=True, latest_head_established=False)


def main():
    try:
        result = exercise()
    except (ImportError, OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
        print('error: recipient exercise failed; install requirements-review.txt and inspect private fixtures',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
