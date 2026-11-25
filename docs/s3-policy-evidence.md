# Bind saved policy evidence to an S3 finding

The listing establishes bucket identity claims only. This workflow combines its
exact original bytes with a saved `get-bucket-policy-status` JSON response and a
separately pinned review context. It generates the native findings JSONL accepted
by inventory assessment, then can verify that exact input against a reproduced
SQLite assessment. No AWS CLI, SDK, credential or network connection is used.

Run the temporary standard-library-only exercise from the repository root:

```bash
python -m engine s3-policy demo
```

Selected output is `status: s3_policy_assessment_exercise_passed`, `asset_count: 2`,
`finding_count: 1`, `assessment_input_verified: true`, `effective_exposure_verified: false`
and `source_truth_verified: false`. It uses actual local SQLite retention/replay and
removes temporary outputs. The fixture deliberately supplies `exposure: limited`,
not an inferred internet exposure from the policy flag.

## Select three independently reviewed inputs

1. The exact saved ListBuckets JSON and supplied account from the existing inventory.
2. A bounded CLI JSON response with exactly `{"PolicyStatus":{"IsPublic":true}}`
   or its boolean-false counterpart. API metadata, extra fields, string booleans,
   missing results and duplicate keys reject. This is the selected CLI subset,
   not the full SDK response format.
3. A separate context like [the synthetic review](../examples/s3-policy-review.json).
   It has exactly schema_version (integer 1), scope, account, bucket, captured_at, opened_on,
   asset_tags and finding fields. The source response itself has no bucket/account
   identity, so this association remains a reviewed claim. Use a trusted process
   to select the correct file-to-bucket association and distribute its byte pin.

For `IsPublic: true`, the context must explicitly supply finding ID, severity,
exposure, exploit evidence, control state and identity confidence. No default
scoring facts are inferred. Asset ID is computed from the selected listing entry,
and source/description are fixed by the importer; the context cannot retarget them.
Dates are validated claims, not authenticated capture or clock evidence. Routing
tags remain supplied, with at most 32 lowercase keys and bounded string values.

For `IsPublic: false`, `finding` must be JSON null and findings JSONL is empty.
Contradictory public-policy findings reject. Zero findings means this particular
claim did not produce a finding, not that the bucket is clean. The existing native
assessment refuses an empty finding set instead of storing a clean assessment.

## Retain and assess the fixtures

These local pins select bundled fixtures only. Hashing an untrusted download does
not establish operational source truth or reviewer authority.

```bash
s3_review_parent=$(mktemp -d)
s3_listing_pin=$(sha256sum examples/s3-list-buckets.json | cut -d ' ' -f 1)
s3_policy_pin=$(sha256sum examples/s3-policy-status.json | cut -d ' ' -f 1)
s3_context_pin=$(sha256sum examples/s3-policy-review.json | cut -d ' ' -f 1)
python -m engine s3-policy create examples/s3-list-buckets.json \
  examples/s3-policy-status.json examples/s3-policy-review.json --scope synthetic \
  --expected-listing-sha256 "$s3_listing_pin" --expected-policy-sha256 "$s3_policy_pin" \
  --expected-context-sha256 "$s3_context_pin" --directory "$s3_review_parent/review"
python -m engine inventory import examples/s3-list-buckets.json --source-format s3 \
  --account 123456789012 --scope synthetic --observed-at 2026-11-24T00:00:00Z \
  --output "$s3_review_parent/discovery.sqlite"
python -m engine inventory assess "$s3_review_parent/discovery.sqlite" \
  "$s3_review_parent/review/findings.jsonl" --directory examples/ownership-directory.json \
  --export examples/s3-list-buckets.json --as-of 2026-11-24 \
  --assessed-at 2026-11-24T01:00:00Z --output "$s3_review_parent/assessment.sqlite"
s3_report_pin=$(sha256sum "$s3_review_parent/review/review.json" | cut -d ' ' -f 1)
python -m engine s3-policy verify examples/s3-list-buckets.json \
  examples/s3-policy-status.json examples/s3-policy-review.json --scope synthetic \
  --expected-listing-sha256 "$s3_listing_pin" --expected-policy-sha256 "$s3_policy_pin" \
  --expected-context-sha256 "$s3_context_pin" --report "$s3_review_parent/review/review.json" \
  --expected-report-sha256 "$s3_report_pin" --assessment "$s3_review_parent/assessment.sqlite"
```

The final command must return `s3_policy_review_reproduced` and
`assessment_input_verified: true`. All native assessment decisions reproduce from
the original listing before its entire retained findings byte digest is compared
with the reviewed generated JSONL. A valid assessment containing different scoring
facts, whitespace or extra findings rejects this exact-input check. The review
report binds the listing, policy, context and allowlisted current review source
digests. The finding's source field carries that binding ID. Keep the originals
and report separately; the assessment is not a self-contained policy archive.

Without `--assessment`, verification reproduces the report only and explicitly
returns `assessment_input_verified: false`. A forged/re-pinned report cannot change
the reproduced finding or trust flags. This is current-model consistency; old model
dispatch, reviewer signatures and independently distributed latest state are absent.

## Files and trust limits

Creation writes a new mode-0700 directory containing mode-0600 `review.json` and
`findings.jsonl`. Existing directories are preserved. Ordinary partial publication
failure removes newly created known files; publication is not directory-atomic and
termination or power loss can leave partial output. Use trusted private ancestors
and cooperative local writers. Every input uses bounded regular POSIX no-follow
reads. Limits: listing 4 MiB, policy 16 KiB, context 32 KiB, report 64 KiB. No incoming
path or code is selected from a received report. Diagnostics and success summaries
omit bucket/account IDs, raw findings and paths. Full private files contain them.

AWS documents the policy-status [CLI response](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-policy-status.html).
Its [Block Public Access documentation](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html)
explains that effective behavior also depends on applicable account and organization
controls. A separate [saved control review](s3-access-controls.md) now combines
bucket/account Block Public Access claims without changing these findings. This
policy tool does not parse those controls, ACLs, object policies or actual requests.
A saved true flag is evidence for review, not proof that anonymous users
can access objects. Account association, captures, exposure and scoring remain
supplied claims. No ownership acceptance, live collection or remediation occurs.

Run `python -m unittest discover -s tests -p test_s3_policy_review.py -v`.
Prepared with assistant support using synthetic inputs. Next: authenticate the
collector/context and review applicable access controls before operational conclusions.
