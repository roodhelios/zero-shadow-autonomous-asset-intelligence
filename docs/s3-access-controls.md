# Review saved S3 public-access controls

`IsPublic` is a policy-status claim, not an object-access test. This workflow adds
separately saved bucket/account Block Public Access settings to the existing
policy review. It preserves missing evidence as unknown and reproduces the full
report. It does not contact AWS or change the reviewed finding or scoring facts.

## Try the complete local exercise

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -m engine demo s3-access
```

No packages, accounts or credentials are needed. The temporary exercise uses native
SQLite retention/replay and the create/verify CLIs. Expected fields:

```json
{"status":"s3_access_review_exercise_passed","asset_count":2,"finding_count":1,"public_policy_review_state":"restriction_reported","account_restriction_retained":true,"unknown_account_state":"restriction_unknown","assessment_input_verified":true,"effective_exposure_verified":false,"source_truth_verified":false}
```

The bucket reports `RestrictPublicBuckets: false`; the account reports true. The
report retains account as the restricting level. Replacing that response with an
unknown record yields `restriction_unknown`. The original finding remains unchanged.
Dates are fixed November 24, 2026 fixtures, not current collection evidence.
Temporary files are removed at exit.

## Inputs and interpretation

Supply the three [policy review inputs](s3-policy-evidence.md), two saved control
responses and a separate [capture context](../examples/s3-control-context.json).
Each response has exactly one `PublicAccessBlockConfiguration` object containing
only boolean `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy` and
`RestrictPublicBuckets` fields. Omitted optional fields stay unknown. Metadata,
unknown fields, string/integer booleans and duplicate keys reject. This is a
selected CLI subset, not an arbitrary SDK envelope.

An unavailable response is exactly
`{"collection_status":"unknown","reason":"not_collected"}`. Other supported
reasons are `access_denied` and `no_saved_response`. Errors or missing files never
become all-false controls. The tool does not interpret AWS error text or establish
that a configuration is absent.

Context must match the policy review's scope, account and bucket. Its three capture/
status claim timestamps must fall inside a timezone-aware window and maximum skew
(integer 0 to 86400 seconds). Unknown-response timestamps describe the supplied
collection-status claim. Identity association, timestamps and expected pins require
an independent trusted process. Collector/reviewer authentication remains absent.

For each setting, any supplied true yields true, both false yield false, and every
remaining combination is unknown. Restricting and unknown levels are retained.
AWS documents the [most restrictive combination](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
and [individual settings](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PublicAccessBlockConfiguration.html).
`BlockPublicPolicy` rejects new public policy writes; it does not neutralize an
existing policy. Only the combined `RestrictPublicBuckets` claim drives this state:

| Policy flag | Combined restriction | Review state |
| --- | --- | --- |
| true | true | `restriction_reported` |
| true | false | `no_restriction_reported` |
| true | unknown | `restriction_unknown` |
| false | any | `no_public_policy_reported` |

No state proves a clean asset, anonymous access or enforcement. Organization and
access-point controls, propagation, ACLs, object permissions, policy contents and
current state remain outside this review. Controls do not suppress findings,
accept ownership or mark remediation complete.

## Retain and reproduce a report

This Bash recipe hashes bundled fixtures only. Hashing untrusted input does not
authenticate it. Keep operational originals and pins outside Git.

```bash
s3_access_root=$(mktemp -d)
s3_access_files=(examples/s3-list-buckets.json examples/s3-policy-status.json examples/s3-policy-review.json examples/s3-bucket-controls.json examples/s3-account-controls.json examples/s3-control-context.json)
s3_access_names=(listing policy context bucket-controls account-controls control-context)
s3_access_args=("${s3_access_files[@]}" --scope synthetic)
for s3_access_i in 0 1 2 3 4 5; do
  s3_access_pin=$(sha256sum "${s3_access_files[$s3_access_i]}" | cut -d ' ' -f 1)
  s3_access_args+=("--expected-${s3_access_names[$s3_access_i]}-sha256" "$s3_access_pin")
done
python -m engine s3-access create "${s3_access_args[@]}" --output "$s3_access_root/review.json"
s3_access_report_pin=$(sha256sum "$s3_access_root/review.json" | cut -d ' ' -f 1)
python -m engine s3-access verify "${s3_access_args[@]}" \
  --report "$s3_access_root/review.json" --expected-report-sha256 "$s3_access_report_pin"
```

Verification returns `s3_access_review_reproduced`. Add `--assessment` with an
existing retained S3 policy assessment to require full native replay and an exact
match to unchanged generated findings bytes. Without it, `assessment_input_verified`
is false. The demo exercises the true path. Reports never select their own files,
pins, scope, assessment or implementation.

All six pins precede parsing; the received report pin precedes replay. Every field,
including flags and references, must reproduce. Reports bind the current policy
model and access-review source digest. Historical code dispatch is absent. Inputs
use bounded regular POSIX no-follow reads. Controls/context are at most 16 KiB each;
reports at most 96 KiB. Output is new mode 0600 with no overwrite. Trusted private
ancestors and cooperative writers are required. CLI summaries/errors omit account/
bucket IDs, raw evidence and paths.

Run `python -m unittest discover -s tests -p test_s3_access_review.py -v`.
Prepared with assistant support and synthetic inputs. Next: authenticate collector
and capture-context claims before stronger operational conclusions.
