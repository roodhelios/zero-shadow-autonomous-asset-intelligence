# Compare two later saved EC2 discovery batches

The existing assessment comparison reviews two decisions over the same discovery
batch. This workflow compares selected discovery claims between two different saved
batches. Each retained SQLite database must independently reproduce against its own
original EC2 export before any comparison is published.

## Run the complete local example

On POSIX with Python 3.11 or newer, from the repository root:

```bash
python -m engine.demo_ec2_discovery_compare
```

Expect `ec2_discovery_comparison_exercise_passed`, one added identity, one identity
not observed later and one shared identity with changed projected addresses/tags.
The original export, derived later export, two native SQLite databases and private
comparison file are temporary. The exercise checks original input preservation,
rejects changed original bytes and rejects reversed observation order. It uses no
credentials, AWS service, model or network calls. Its October 24/25, 2026 observation
times are fixed synthetic claims, not measurements of a live account.

## Compare your own retained local batches

First retain each already saved owned or authorized export with the existing
`database.ec2_inventory store` command. See [EC2 retention](ec2-import.md). Choose
the same explicit account, region and scope for both imports, with the second claimed
observation time strictly later than the first. Empty discovery batches cannot be
retained by the existing EC2 importer, so an entirely empty later batch is unsupported.

Then supply both original files and a new private output path:

```bash
python -m database.ec2_inventory_compare /private/review/before.sqlite /private/review/after.sqlite \
  --previous-export /private/review/before-describe-instances.json \
  --current-export /private/review/after-describe-instances.json \
  --output /private/review/new-discovery-comparison.json
```

These are placeholders for your private local paths, not collection commands. Both
original exports are mandatory. The CLI never fetches missing data. Exit 0 prints
only aggregate counts, source-check flags and `status: ec2_discovery_compared`.
The detailed report is retained in the new 0600 file. Exit 2 prints a fixed diagnostic
and no success document. Existing outputs are never overwritten.

## Understand the report

Each side includes its verified import context, original source digest, row references
and a digest of the complete reproduced inventory snapshot. Both contexts must have
the same claimed scope/account/region. A later caller-supplied timestamp is required,
but it does not establish when collection actually happened.

| Field | Meaning in the supplied evidence |
| --- | --- |
| `added` | Current source-claimed identities absent from the previous batch |
| `not_observed` | Previous identities absent from the current supplied batch |
| `changes` | Shared stable identities with differing projected observation fields |
| `unchanged_asset_ids` | Shared identities whose projected claims are equal |
| `source_bytes_changed` | The original export files have different exact digests |

Each change lists the differing projected field names and both claim records. Each
record links its original one-based reservation and instance indexes. Input row
reordering can change these references and raw digests while still leaving the asset
claims unchanged. JSON formatting and later observation times alone also do not
count as an asset change. Identity uses the existing strong EC2 account/region/instance
keys; a shared address never merges instances.

The current importer projects instance identity, selected instance/interface literal address sets and only the
`environment`, `owner_group` and `service` tags. It omits EC2 state, DNS names, other
tags, interface identity/roles, security groups and many other fields. Private/public address roles
are not preserved in that combined address set. Changes to unselected fields are
not reported as asset changes. Do not interpret an unchanged projection as an
unchanged complete instance, unchanged exposure or an accepted owner assignment.

Not observed is not evidence of deletion, termination, stopped state, remediation,
or complete collection. Changed ownership tags are supplied metadata, not human team
acceptance. No risk finding, priority, due date or remediation action is inferred.
The new comparator does not alter existing osquery inventory comparison or same-batch
EC2 assessment comparison/history formats.

## Review interface address differences

```bash
python -S -m engine demo ec2-addresses
```

This no-install exercise imports two generated synthetic exports into native SQLite,
reproduces both against their original bytes, and retains a temporary private comparison.
The fixture changes a secondary private IPv4 claim, its associated public IPv4 claim,
and one IPv6 claim. It adds a second identity sharing an address to check that the
comparison does not merge instances by IP. No AWS endpoint or credential is used.

Expected selected output:

```json
{
  "status": "ec2_address_review_exercise_passed",
  "shared_identities_with_address_changes": 1,
  "added_address_claims": 3,
  "not_observed_address_claims": 3,
  "retained_address_claims": 3,
  "separate_added_identities": 1,
  "changed_original": "rejected",
  "inputs_unchanged": true
}
```

For retained evidence, use the existing comparison command above. Every entry in
`changes` now includes an `address_claims` object alongside the complete previous
and current records and their source references. In this fixture it contains:

```json
{
  "added": ["192.0.2.42", "198.51.100.42", "2001:db8::42"],
  "not_observed": ["192.0.2.41", "198.51.100.41", "2001:db8::41"],
  "retained": ["192.0.2.40", "198.51.100.40", "2001:db8::40"]
}
```

These sorted, normalized sets compare only the selected claims of the same strong
EC2 identity. Added and unobserved identities stay in their existing report sections;
their addresses are not assigned to another identity's differences. A tag-only change
has empty added/not-observed address lists and lists all retained addresses. Equal
projected claims remain in `unchanged_asset_ids`, with no change entry. Duplicate
paths, equivalent IPv6 spelling or reordered address records do not create changes.

An address no longer observed in one supplied file is not a removed interface,
revoked public association, unreachable service or reduction in exposure. The selected
combined address set discards public/private roles, interface identity and primary flags.
Role-only changes are invisible. Missing collection coverage remains unverified; both
files can be incomplete even when their local reproduction passes. The private report
contains addresses and identifiers; stdout still prints only the original aggregate
counts and source-check flags. This additive report field does not change the existing
discovery database or assessment schemas.

The comparator's source is included in exact-source EC2 sequence archives. Updating
this file changes that archive source fingerprint even though the timeline algorithm
is unchanged. Old archives require their matching trusted checkout; no historical
model dispatch or migration is added. Keep original files and the source revision.

## Evidence and storage limits

Each side uses the existing closed-file copy and full reproduction path. The final
report uses only the verified snapshots, even if the original database path disappears
after copying. Altered database metadata, payloads or source bytes cannot be reported
as legitimate changes. A formatting change to an original export still needs its own
new retained import; it cannot verify an older database tied to different bytes.

Existing bounds apply independently to both sides: 4 MiB exports and 16 MiB closed
databases. The comparison report is limited to 24 MiB. Active/uncheckpointed SQLite
sidecars, symlinks and unsupported evidence schemas are rejected by the existing
reader. Trusted local paths/binaries are required. The two copies are not one atomic
multi-database snapshot or a live concurrent-inventory view.

The private report contains instance/account identifiers, addresses, tags and row
references. Keep it and the original inputs outside Git. Stdout omits these values,
but private output and input paths may still appear in shell history. Verification
establishes consistency with supplied bytes, not source authenticity, permission,
global freshness or collection completeness. Existing frozen assessment/model source
files remain unchanged by this feature.

```bash
python -S -m unittest discover -s tests -p 'test_ec2_discovery_compare.py' -v
python -m unittest discover -s tests -v
```

Next: define a source-bound comparison history with explicit continuity and incomplete
collection rules before treating a series of files as authoritative asset lifecycle.
Prepared with assistant support and generated original synthetic data.
