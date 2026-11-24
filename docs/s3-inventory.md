# Review a saved S3 bucket listing

Zero Shadow can now turn a saved `s3api list-buckets` JSON response into its asset
observation format and a correlated inventory. This covers bucket identity claims,
not an S3 security assessment. It never invokes AWS CLI, an SDK or a network client.

From the checkout with Python 3.11 or newer on POSIX:

```bash
python -m engine discover-s3 examples/s3-list-buckets.json --scope synthetic --account 123456789012
```

The bundled data is synthetic. Expect `report_type: saved-s3-inventory`,
`observation_count: 2` and `asset_count: 2`. Each asset has kind `object-storage`,
an `arn:aws:s3:::...` resource claim and no inferred hostname or IP address.

For a saved export you own or are authorized to review, keep names and account
identifiers private and select the corresponding scope. Retain a new output file:

```bash
python -m engine discover-s3 /private/list-buckets.json --scope owned --account 123456789012 --output /private/s3-inventory.json
```

The output uses mode 0600 and never replaces an existing path. The parent directory
must already exist under your private control. Without `--output`, the inventory
is printed to stdout, which may expose bucket names through terminal logs.
`--format fixture` instead emits observations compatible with the existing fixture
schema. The standalone command does not write a database.

## Retain discovery in SQLite

The inventory importer also accepts the exact saved listing, an explicit account
and a caller-supplied observation time. It creates a new private database:

```bash
review_dir=$(mktemp -d)
python -m engine inventory import examples/s3-list-buckets.json \
  --source-format s3 --account 123456789012 --scope synthetic \
  --observed-at 2026-11-24T00:00:00Z --output "$review_dir/discovery.sqlite"
python -m engine inventory export "$review_dir/discovery.sqlite" \
  --export examples/s3-list-buckets.json --output "$review_dir/inventory.json"
```

Expect `stored` with two observations. The exported import reconciliation contains
a version-2 receipt, `source: aws-s3-export`, supplied account and original bucket
row references. `original_export_checked: true` means the exact original bytes and
all converted observations reproduced. Even a change to an unselected input field
fails replay. Without `--export`, receipt consistency does not establish original
source reproduction. Receipt hashes are not signatures or ownership evidence.

Default import remains osquery and keeps version-1 receipts. `--account` is required
for S3 and rejected for osquery. Empty listings still work in the standalone
importer but cannot form the existing nonempty SQLite discovery batch. No findings
are inferred or written by discovery import. Use a private POSIX directory and
cooperative local writers; outputs never overwrite an earlier review.

## Assess supplied findings and reproduce the result

Continue in the same private directory. The separate findings file is deliberately
synthetic: its severity, exposure, control state and reviewed routing tags are
supplied claims. They are not conclusions drawn from the bucket listing.

```bash
python -m engine inventory assess "$review_dir/discovery.sqlite" \
  examples/s3-inventory-findings.jsonl --directory examples/ownership-directory.json \
  --export examples/s3-list-buckets.json --as-of 2026-11-24 \
  --assessed-at 2026-11-24T01:00:00Z --output "$review_dir/assessment.sqlite"
python -m engine inventory verify "$review_dir/assessment.sqlite" \
  --export examples/s3-list-buckets.json --require-model-binding
```

Expect `assessment_stored`, then `assessment_reproduced` with two assets, one
supplied finding and `model_binding.model_version: 2`. The remaining asset is
unassessed, not clean. The original discovery database is unchanged and is not
needed for subsequent verification. Retain the exact original listing separately.

S3 uses a separate current model contract that also pins the S3 converter and
import/receipt code. Legacy osquery model version 1 and its source-file selection
remain unchanged. A valid osquery binding cannot label an S3 receipt. This is
same-model consistency replay, not a signature, source authentication or historical
model dispatch. A changed model requires a new reviewed assessment.

The existing dated queue commands also work after complete assessment replay.
Follow the [pinned queue steps](inventory-commands.md#produce-and-reproduce-a-dated-queue)
with this assessment database and the S3 original in each `--export` argument.
The osquery version-1 archive format deliberately refuses S3 assessments until a
separate source-complete archive contract is implemented and tested.

The exact input SHA-256 and one-based `bucket_record` references identify original
`Buckets` array entries even though assets are sorted. Account-qualified source
record IDs prevent conflicting supplied account claims from merging merely because
S3 ARNs omit account IDs. A supplied account is not authenticated ownership.

## Supported input and limits

The importer accepts at most 4 MiB and 10,000 bucket records. It rejects duplicate
JSON keys, non-finite JSON numbers, duplicate names, unfinished `ContinuationToken`
or CLI `NextToken` pages, and conflicting supplied ARNs. Empty listings are valid.
Only modern global-namespace general purpose bucket names in the commercial AWS
partition are supported. Legacy names, access point aliases, directory/table
buckets and account regional namespaces are refused rather than guessed.

Owner identifiers, display names, creation dates, region and other unselected
fields are omitted. There is no inference about public access, IAM policy,
encryption, contents or present existence. A filtered or edited export can omit
buckets even without a continuation token, so coverage always remains
`not_established`. No score or finding is manufactured from a name.

The field selection and token checks follow the primary
[ListBuckets API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html),
[CLI response](https://docs.aws.amazon.com/cli/latest/reference/s3api/list-buckets.html)
and [bucket naming rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html).
No live AWS collection or permissions were tested. Prepared with assistant support.

Run `python -m unittest discover -s tests -p test_s3_discovery.py -v` for local
projection, correlation, bounds and private-file regression tests.
The separate [saved-policy evidence workflow](s3-policy-evidence.md) now binds a
pinned policy-status response and explicit scoring review to one account-qualified
bucket identity. It can also check that a native retained assessment used those
exact generated finding bytes. Source identity, capture time and effective exposure
remain unverified. Next: independently authenticate the collector/context and review
all applicable access controls before treating a claim as effective public access.
