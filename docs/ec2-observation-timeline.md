# Review a sequence of retained EC2 discoveries

The two-batch comparison identifies immediate discovery differences. The timeline
reviews 2 to 16 explicitly ordered saved batches together, including an identity
observed again after one or more omitted batches. Each original export must fully
reproduce its retained native SQLite inventory before its claims contribute.

## Run the offline example

From the repository root with Python 3.11 or newer on POSIX:

```bash
python -m engine.demo_ec2_timeline
```

The standard-library walkthrough creates four temporary inventories and a private
report, verifies it, rejects an altered original export, a truncated supplied sequence
and an incorrect report pin, and checks unchanged input database bytes. It uses fixed
October 24 to 27 synthetic observation dates, not current account measurements.

Expected summary fields:

```json
{"status": "ec2_timeline_exercise_passed", "batch_count": 4,
 "unique_asset_count": 3,
 "event_totals": {"first_observed": 3, "changed": 1, "unchanged": 3,
                  "observed_again": 1, "not_observed": 2},
 "negative_cases_rejected": 3, "inputs_unchanged": true}
```

One identity is omitted from batches 2 and 3, then supplied again in batch 4 with a
changed projected tag. Its event references the last actual observation in batch 1.
The second consecutive omission emits no additional absence transition. No account,
network, credential, Airflow deployment or cloud resource is used.

## Retain and reproduce your supplied sequence

First use the existing [EC2 retention workflow](ec2-import.md) to retain each saved,
owned or authorized export. Keep the original files and closed databases private.
All batches must claim the same scope, account and region, with strictly increasing
observation times. The tool uses your explicit order, not filename sorting or filesystem
times. The existing importer requires nonempty exports, so entirely empty batches
remain unsupported.

Supply every database with its respective original export, in oldest-to-newest order:

```bash
python -m database.ec2_observation_timeline create \
  --batch /private/review/first.sqlite /private/review/first.json \
  --batch /private/review/second.sqlite /private/review/second.json \
  --batch /private/review/third.sqlite /private/review/third.json \
  --output /private/review/new-timeline.json
```

These private paths are examples, not collection commands. Exit 0 prints aggregate
counts, source-check status and `report_sha256`. Only the new 0600 file contains
identifiers, addresses, tags and original row references. Existing destinations are
never overwritten. Keep the output directory private and all evidence outside Git.
Exit 2 prints a fixed diagnostic without a success document.

Retain the returned digest independently. To check the saved report, supply that
trusted pin and the same complete ordered sequence:

```bash
python -m database.ec2_observation_timeline verify /private/review/new-timeline.json \
  --batch /private/review/first.sqlite /private/review/first.json \
  --batch /private/review/second.sqlite /private/review/second.json \
  --batch /private/review/third.sqlite /private/review/third.json \
  --expected-sha256 TRUSTED_REPORT_SHA256
```

Replace the placeholder with the lowercase 64-character digest retained separately,
not a digest freshly copied from an untrusted report. Verification compares exact
canonical report bytes and every rebuilt field, including events, counts, contexts,
source-row references, completeness labels and complete snapshot digests. Changing
the report and recalculating its digest cannot bypass source reproduction. A current
trusted pin rejects an older internally consistent prefix. Without independently
trusted order and pin distribution, no global freshness is established.

## Interpret the events

| Status | Meaning within this supplied sequence |
| --- | --- |
| `first_observed` | First supplied observation of this stable source-claimed identity |
| `changed` | Present in consecutive batches with different projected claims |
| `unchanged` | Present in consecutive batches with equal projected claims |
| `observed_again` | Present after at least one omitted batch; changes compare with its last supplied observation |
| `not_observed` | Present in the previous batch but omitted from this batch |

`previous_observation` identifies the prior observed batch and its complete projected
claim record with original reservation/instance indexes. There is no such pointer for
a first observation. Absence events have no current observation. The first batch's
first-observed events are a baseline, not evidence of newly created cloud resources.
Event totals are transition counts across all steps, not current asset counts.

Every batch has `collection_completeness: not_established`. An omission does not
prove deletion, termination, downtime, remediation or complete collection. A return
does not prove recreation or recovery. The caller supplies observation-time claims;
the tool does not authenticate when collection happened or whether batches are missing.

Only the [existing selected projection](ec2-discovery-comparison.md) is compared:
instance identity, combined literal address sets and the environment/owner_group/service
tags. Formatting, source-row order, timestamps and unselected EC2 state/DNS/tags do
not become asset changes. Risk, accepted ownership and remediation are not inferred.

## Storage and trust boundaries

Each closed database is copied and reproduced once per operation. The timeline uses
only the verified snapshots even if original database paths disappear after copying.
Existing per-input bounds apply: 4 MiB per export and 16 MiB per database. Combined
export bytes are capped at 16 MiB and the report at 24 MiB. Symlinks, active SQLite
sidecars and invalid retained evidence are rejected by the existing reader. The copies
are not one atomic snapshot across all files; trusted local paths and binaries remain
required.

This is a reproducible private sequence review, not an append-only database history,
authenticated collector ledger, encrypted archive or authoritative asset lifecycle.
Verification still needs all retained databases and original exports. Digests establish
byte consistency, not source authenticity, legal authorization or independent latest
state. Existing assessment models, same-batch review histories and archive runtime
allowlists are unchanged.

```bash
python -S -m unittest discover -s tests -p 'test_ec2_observation_timeline.py' -v
```

A separate [recipient checkpoint review](ec2-sequence-checkpoint.md) now compares
expected time/export slots with the supplied sequence and retains explicit gaps.
Independent issuer enrollment, checkpoint freshness/distribution and future
collection scheduling remain unfinished before authoritative discovery history. Prepared with assistant
support and original synthetic fixtures.
