# Accept a signed selection locally

The signed selection verifier checks a successor but does not retain the recipient's
acceptance. This command adds that step. It verifies the signature, original export,
selected SQLite bytes and full history lineage before replacing one recipient-owned
checkpoint. Prepared with assistant support.

## Try it without an account or signing-key file

On POSIX with Python 3.11 or newer, from the repository root:

```bash
python -m pip install -r requirements-review.txt
python -m engine.demo_ec2_recipient
```

The optional PyNaCl dependency supplies native Ed25519. The exercise creates
temporary synthetic exports and SQLite histories, generates a key only in memory,
and passes only signed approvals and public verification context to the recipient.
It bootstraps revision 1, accepts revision 2, rejects a stale update and rollback,
and confirms that the original evidence is unchanged. Expected output:

```json
{
  "status": "ec2_recipient_exercise_passed",
  "accepted_revision": 2,
  "previous_checkpoint_verified": true,
  "negative_cases_rejected": 2,
  "inputs_unchanged": true,
  "latest_head_established": false
}
```

All generated files are removed. Network socket creation is blocked during the
exercise. No AWS calls, cloud resources or production keys are used. Dropping a
Python key reference does not establish secure memory erasure.

## Bootstrap once, then accept a direct successor

Prepare selections and version 2 approvals using the
[enrollment and signing commands](ec2-history-enrollment.md#authenticate-the-selected-enrollment).
Review the policy, recipient, clock and selection pin through a trusted process.
Use a dedicated owned 0700 directory with trusted ancestors for the recipient's
checkpoint. The sender must not control that directory. Uppercase values below
are placeholders for independently supplied lowercase SHA-256 digests.

```bash
python -m database.ec2_recipient_checkpoint /private/recipient/accepted.json \
  /private/handoff/history-1.sqlite /private/handoff/approval-1.json \
  --bootstrap --enrollment /private/handoff/selection-1.json \
  --expected-enrollment-sha256 SELECTION_1_PIN \
  --export /private/handoff/export.json --policy /private/trust/policy.json \
  --expected-policy-sha256 POLICY_PIN --audience fixture-recipient \
  --at 2026-10-28T01:00:00Z
```

Bootstrap requires a nonexistent checkpoint and revision 1. Success returns
`ec2_recipient_checkpoint_accepted` and `checkpoint_sha256`. Retain that digest
separately before considering another handoff. Use the actual trusted evaluation
time for retained data; the October time above belongs only to the synthetic example.

```bash
python -m database.ec2_recipient_checkpoint /private/recipient/accepted.json \
  /private/handoff/history-2.sqlite /private/handoff/approval-2.json \
  --expected-accepted-sha256 SELECTION_1_PIN \
  --enrollment /private/handoff/selection-2.json \
  --expected-enrollment-sha256 SELECTION_2_PIN \
  --export /private/handoff/export.json --policy /private/trust/policy.json \
  --expected-policy-sha256 POLICY_PIN --audience fixture-recipient \
  --at 2026-10-28T01:00:00Z
```

The accepted file must still match `SELECTION_1_PIN` under the writer lock. The
candidate must be its direct selected successor and extend the reproduced logical
history. A competing accepted update makes that pin stale, so this command rejects
instead of replacing the winner. Success stores the exact new enrollment bytes as
mode 0600 and returns its digest. Existing enrollment and approval formats do not change.

## Lock, failure and trust boundaries

All writers must use this command against the same checkpoint path on a local
filesystem with POSIX advisory locks, atomic rename and file/directory fsync support.
A busy writer fails immediately. Keep `.accepted.json.lock` permanently; never
remove, rename or replace it while writers may run. The lock is an owned empty
0600 single-link regular file. Checkpoint symlinks, hardlinks and public permissions
are rejected. This does not defend against another process with the same user's
write access bypassing the lock, changing trusted ancestors or replacing state.

Validation and staging failures leave the accepted checkpoint unchanged. Replacement
publishes a complete file, followed by directory fsync. A failure after replacement
or an interrupted response can leave the new checkpoint present without a success
receipt. Do not blindly retry or bootstrap again. Inspect its exact bytes and compare
their digest with the independently retained old and candidate pins before deciding
which state is accepted. A crash before replacement can leave a private staging file;
only remove it after ensuring no writer is active. Hardware/filesystem crash recovery
has not been certified by these tests.

The command stores an enrollment, not an audit log or the approval. Preserve approvals,
histories, exports and authority policy separately for later reproduction. Policy and
clock remain caller-controlled trusted inputs. This does not authenticate a human's
acceptance decision, arbitrate global forks, synchronize remote recipients or prevent
rollback of both the local file and its separately trusted pin. It cannot discover a
newer selection. Keep `latest_head_established: false` in downstream interpretations.

Next: define authenticated operator acceptance and recovery evidence before using
this checkpoint to authorize actions or synchronize recipients.
