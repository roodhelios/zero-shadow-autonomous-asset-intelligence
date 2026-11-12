# Select and advance an EC2 history revision

History replay checks internal consistency under the current model. This separate
workflow retains which exact revision a local reviewer selected, then permits
advancement only when the new history extends the selected logical prefix. It
does not change existing histories, receipts, archives or their model contract.
Prepared with assistant support.

## Temporary native exercise

From the repository root on POSIX with Python 3.11 or newer:

```bash
python -S -m engine.demo_ec2_enrollment
python -S -m unittest discover -s tests -p test_ec2_history_enrollment.py -v
```

No dependency installation, AWS account, credentials or services are needed. The
exercise builds original synthetic EC2 exports and native SQLite review histories,
selects the first revision and advances to the second. It removes the selected
history, verifies its byte-identical backup and rejects four negative cases:
rollback under the newer selection, a wrong enrollment pin, a changed export and
a non-advancing history. Expected summary:

```json
{
  "status": "ec2_history_enrollment_exercise_passed",
  "revision": 2,
  "review_count": 2,
  "negative_cases_rejected": 4,
  "original_history_removed": true,
  "exact_copy_verified": true,
  "old_selection_still_verifies": true,
  "latest_head_established": false
}
```

The old-selection result is deliberate. An old history still verifies against its
own independently supplied old record. Local enrollment does not distribute the
latest selection or prevent a receiver from choosing a stale record.

## Enroll a selected closed history

First reproduce the history against its original export using the
[history workflow](../README.md#retain-an-ordered-ec2-review-history). Review the
head digest deliberately. Put the files in owned mode-0700 storage with trusted
ancestors, and select a fresh output path. Replace uppercase placeholders with
independently selected lowercase 64-character SHA-256 digests:

```bash
python -S -m database.ec2_history_enrollment enroll /private/history-1.sqlite \
  --export /private/export.json --expected-head TRUSTED_HISTORY_1_HEAD \
  --output /private/enrollment-1.json
```

Success returns `ec2_history_enrolled`, a random enrollment label, selection revision,
counts, selected head and `enrollment_sha256`. Keep that exact record digest through
a separately trusted process. The label belongs to this selection chain; it does
not enroll a real collector, reviewer or unique database installation. Copies retain
the same label.

The canonical record contains its purpose/version, label, revision, previous-record
digest, review/decision counts, logical head, exact database/export digests and
discovery/model digests. There are no individual findings, asset IDs, ownership
details, source paths or raw evidence in the record or success receipt.

## Advance along the selected lineage

```bash
python -S -m database.ec2_history_enrollment advance /private/history-2.sqlite \
  --export /private/export.json --expected-head TRUSTED_HISTORY_2_HEAD \
  --enrollment /private/enrollment-1.json \
  --expected-enrollment-sha256 TRUSTED_ENROLLMENT_1_SHA256 \
  --output /private/enrollment-2.json
```

The supplied prior record must match its independent pin before history or export
access. The candidate history is captured once, fully replayed and checked against
the explicit new head. It must have strictly more reviews. Its prefix at the prior
review count must reproduce the selected prior logical head and decision count,
with unchanged export, discovery and model context. Same-length histories, rollback,
divergent branches and no-op advances reject. A longer valid extension may skip
intermediate selection records. Selection revision counts selections, not reviews.

Success returns `ec2_history_enrollment_advanced`. The new record retains the label,
increments its revision and binds the exact previous record digest. The original
record is never rewritten. Advancement checks the logical prefix, not the physical
bytes of an unavailable prior database; that prior byte digest remains a claim in
the separately trusted previous record. No old database bytes are manufactured.

## Verify a copied or restored selected revision

```bash
python -S -m database.ec2_history_enrollment verify /private/restored-history.sqlite \
  --export /private/export.json --enrollment /private/enrollment-2.json \
  --expected-enrollment-sha256 TRUSTED_ENROLLMENT_2_SHA256
```

Expect `ec2_history_enrollment_verified`. Verification replays the current model,
checks the selected head and compares every selection field, including exact raw
database and export bytes. A logically equivalent SQLite file with different bytes
needs a deliberate new selection; this command does not silently bless it.
The existing backup/archive workflows restore exact bytes and can be verified here.

All success receipts include `latest_head_established: false`. Parse or validation
failure exits 2 with a fixed diagnostic, no private values and no success JSON.
Existing destinations are preserved. Output records are fresh mode-0600 files.
Enrollment JSON is limited to 4 KiB and requires private single-link regular storage;
symlinks, hardlinks, directories and FIFOs reject. Existing closed-history bounds,
private-file and sidecar checks remain in force. Byte capture and publication are
not an atomic filesystem snapshot or a power-loss durability guarantee.

## Interpretation

This is an unsigned local trust selection. It does not authenticate a reviewer,
source, journal identity, accepted ownership or remediation, and it cannot prevent
a trusted local editor from replacing state and selecting different pins. It does
not authenticate the selection chain, retrieve its predecessors or establish that
no other selection branch exists. Keep records and pins privately and independently.
No signing keys, credential rotation, history rewrite, deployed service, live backup
or historical model dispatch is added.

See below for signed successor verification against a separately retained checkpoint.

## Authenticate the selected enrollment

The existing Ed25519 history approval commands accept two additional arguments
on both `sign` and `verify`:

```text
--enrollment /private/selection.json --expected-enrollment-sha256 SELECTION_PIN
```

Use the history, export, policy, audience, clock, and seed setup from the
[history approval workflow](../README.md#independently-verify-an-ec2-history-approval).
Use the selection pin obtained independently from the file being checked.
Signing first verifies the exact enrollment against the retained SQLite bytes
and original export. Verification requires the same enrollment and pin, the
signed approval, and the pinned authority policy; it does not need the seed.

Expect a version 2 approval and verification status
`ec2_history_selection_authenticated`. A history-only version 1 approval is
still valid for its original use but cannot satisfy a request with an enrollment
pin. A different enrollment of the same history also fails. The verifier trusts
the supplied policy, audience, clock and selection pin. It cannot discover a newer
selection, prevent rollback of those trusted inputs, or authenticate AWS export
provenance.


## Verify a successor against a trusted checkpoint

After enrolling a history and accepting its selection, keep that exact private
enrollment and its digest separately from future handoffs. For the next signed
selection, append these arguments to the existing version 2 `verify` command:

```text
--previous-enrollment /private/accepted-selection.json --expected-previous-sha256 ACCEPTED_PIN
```

Pass the new enrollment and its independent pin as usual. The new selection must
have the same enrollment ID, the next selection revision and the exact prior
digest. Its replayed history must extend the accepted history prefix under the
same export, discovery and model. One selection revision can include several
additional review entries. Success returns `previous_checkpoint_verified: true`
alongside `ec2_history_selection_authenticated`. Replaying an already accepted
selection is not an advance.

Keep the prior file and pin under recipient control. The command does not update
that checkpoint, arbitrate between signed successors, or establish global
freshness. If the prior checkpoint and pin are rolled back together, this command
cannot detect that rollback. Choose and retain a new checkpoint only after
verification and your own acceptance decision.

The [recipient checkpoint command](ec2-recipient-checkpoint.md) now performs
verification and local replacement under one advisory writer lock with an explicit
accepted-digest check. Its temporary native exercise demonstrates signed bootstrap,
successor acceptance, stale-writer rejection and rollback rejection. This does not
distribute checkpoints or authenticate the operator's acceptance decision.
