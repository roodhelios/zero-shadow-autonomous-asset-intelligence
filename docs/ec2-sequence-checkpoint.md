# Check a supplied EC2 sequence against recipient expectations

A source-reproduced timeline explains the batches supplied to it. It cannot tell
whether the sender omitted a batch that the recipient expected. This separate
checkpoint review compares a reproduced candidate with exact observation-time and
export-byte expectations controlled by the recipient.

The checkpoint is a bounded JSON document with an independently retained SHA-256
pin. It is not a signature or a service that distributes the latest trusted state.
The recipient must obtain the checkpoint and its current pin through a trusted
process outside the candidate handoff.

## Run the complete local exercise

With Python 3.11 or newer on POSIX, from the repository root:

```bash
python -S -m engine.demo_ec2_checkpoint
```

Expect `ec2_sequence_checkpoint_exercise_passed`, three expected batches, two supplied
partial batches, one missing expected batch, `gap_report_reproduced: true` and
`complete_sequence_satisfied: true`. Two incorrect independent pins are rejected.
Original database bytes remain unchanged.

The example creates three native temporary SQLite inventories from original
synthetic exports and explicitly prepares separate recipient expectations. It
omits the middle batch from the candidate, retains and verifies the gap report,
then checks the complete sequence. All dates are fixed October 24 to 26 fixture
claims. No network, AWS account, credential, model or cloud resource is used.
This demonstrates local separation of inputs, not enrollment of a real recipient
or independent distribution of a production checkpoint.

## Define a recipient checkpoint

The exact object fields are `schema_version: 1`,
`checkpoint_type: ec2-observation-sequence`, `scope`, `account`, `region` and
`expected_batches`. Scope is `synthetic`, `owned` or `authorized`; account is 12
ASCII digits; region is a bounded lowercase/digit/hyphen label matching the supplied
inventory context. Each of 2 to 16 expected batches has exactly `observed_at` and
`export_sha256`. Times must be canonical UTC ISO strings ending in `Z`, including
canonical fractional seconds when present, and strictly increase.

Illustrative checkpoint only. The zero digests below are dummy placeholders:

```json
{
  "schema_version": 1,
  "checkpoint_type": "ec2-observation-sequence",
  "scope": "synthetic",
  "account": "111122223333",
  "region": "us-east-1",
  "expected_batches": [
    {
      "observed_at": "2026-10-24T00:00:00Z",
      "export_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    {
      "observed_at": "2026-10-25T00:00:00Z",
      "export_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

Use separately reviewed exact original-export digests, not the zero placeholders.
Retain the SHA-256 of the entire checkpoint's exact bytes independently. Re-encoding
it changes its pin. Do not generate a checkpoint solely from an untrusted candidate
and call that independent verification. Every slot requires a known export digest;
this is a checkpoint of expected retained artifacts, not a scheduler for future
collections whose bytes are not known yet.

Unknown/duplicate fields, boolean versions, non-finite values, invalid digests,
duplicate/reversed times, empty plans and checkpoints over 64 KiB are rejected.
An incorrect checkpoint pin fails before candidate database reproduction.

## Retain a private review

Prepare closed inventories with the [existing EC2 importer](ec2-import.md) and keep
each original export. Supply the available candidate batches in increasing claimed
time order, plus the independently controlled checkpoint:

```bash
python -m database.ec2_timeline_checkpoint create \
  --batch /private/review/first.sqlite /private/review/first.json \
  --batch /private/review/third.sqlite /private/review/third.json \
  --checkpoint /private/trust/expected-sequence.json \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256 \
  --output /private/review/new-coverage.json
```

Paths and digest text are placeholders for owned or authorized local evidence.
The candidate still requires 2 to 16 supplied nonempty batches, so an entirely
missing sequence or one supplied batch is unsupported by the underlying timeline.
All supplied databases must fully reproduce against their originals and claim the
checkpoint's exact scope/account/region. Invalid evidence fails instead of becoming
an apparent coverage gap. Context mismatch is an input error, not a successful review.

| Status | Meaning |
| --- | --- |
| `matched` | A supplied batch has the expected claimed time and exact original-export bytes |
| `missing_batch` | No supplied batch has that expected claimed time |
| `export_mismatch` | A valid reproduced batch exists at that time, with different original-export bytes |
| `unexpected_batch` | A valid reproduced supplied batch has a time not named by the checkpoint |

The new mode-0600 JSON file retains every expected slot, its supplied sequence
reference when present, actual/expected export digests and all unexpected batches.
It binds the complete source-reproduced timeline through its canonical digest,
without duplicating asset details in the coverage report. Existing files are never
overwritten. Keep output directories private and evidence outside Git: times and
digests remain sensitive operational metadata.

Exit 0 means all expectations match. Exit 1 means a complete gap report was created
or reproduced; gaps are useful results and must not be treated as success. Exit 2
means invalid inputs, pin, evidence or output, with a fixed diagnostic and no success
document. Stdout contains aggregate counts, requirements status and digests only,
not account/region, times, source paths, asset IDs, addresses or tags.

## Reproduce the retained result

Retain the returned `report_sha256` independently too. Supply the same exact
checkpoint and complete ordered candidate evidence:

```bash
python -m database.ec2_timeline_checkpoint verify /private/review/new-coverage.json \
  --batch /private/review/first.sqlite /private/review/first.json \
  --batch /private/review/third.sqlite /private/review/third.json \
  --checkpoint /private/trust/expected-sequence.json \
  --expected-checkpoint-sha256 TRUSTED_CHECKPOINT_SHA256 \
  --expected-report-sha256 TRUSTED_COVERAGE_REPORT_SHA256
```

Verification recreates every report byte from the checkpoint and source-reproduced
candidate, not just its digests or summary. It returns `report_reproduced: true`
even for a faithfully retained gap report, with exit 1 and
`requirements_satisfied: false`. A changed report with a recalculated digest must
still reproduce. A consistent older prefix does not satisfy a current checkpoint
that expects additional batches. The recipient still needs independently current
checkpoint/report pins; a stale but self-consistent checkpoint can approve stale data.

## Boundaries and next work

Each supplied database is reproduced once and the timeline uses its verified copy.
Original database files are unchanged. Existing reader protections reject symlinks,
active SQLite sidecars and invalid retained evidence. Limits remain 4 MiB per export,
16 MiB per database, 16 MiB combined export bytes and a 24 MiB derived timeline.
Checkpoint and coverage documents each have an additional 64 KiB bound.
Reproduction uses the current implementation; retain its trusted source checkout.
Version-specific historical dispatch is not implemented. Files are
not captured atomically across the sequence; only trusted quiescent local evidence
is supported. File fsync does not claim parent-directory crash durability.

Missing means not supplied, not failed collection. A digest mismatch can be simple
re-encoding, not malicious data. Matching all expectations does not prove source
truth, collection completeness, trusted observation time, deletion, recovery, risk,
accepted ownership or remediation. `collection_completeness` stays
`not_established`. No existing database schema, frozen assessment model, review
history, approval protocol or archive runtime allowlist is changed.

Next: enroll checkpoint issuers and distribute fresh recipient checkpoints through
an independently controlled process before treating this as authoritative history.
Future collection scheduling and authenticated collector receipts remain separate.
Implemented with assistant support and synthetic local evidence.
