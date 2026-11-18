# Review shared address claims in a saved EC2 export

An address search should show every distinct EC2 identity that claims it, without
turning those records into one asset or assuming an address collision. The normal
inventory deliberately avoids IP-based merging. This report makes the shared claims
and their exact original row references visible for local review.

From the repository root, use Python 3.11 or newer on POSIX. Only the standard
library is needed:

```bash
python -m engine.discovery.ec2_address_review demo
```

Expect `ec2_shared_address_exercise_passed`, `asset_count: 2`,
`shared_address_count: 6`, `shared_identity_count: 2`, `identities_merged: false`
and `collision_established: false`. The exercise creates two synthetic instance
claims from the bundled interface-address fixture and discards the in-memory report.
It makes no AWS call and creates no database, cloud resource or output file.

## Retain a private review

For a permitted local describe-instances export, select its explicit account,
region and scope, then choose a new output path under an existing trusted parent:

```bash
review_dir=$(mktemp -d)
python -m engine.discovery.ec2_address_review review \
  examples/ec2-interface-addresses.json --scope synthetic \
  --account 111122223333 --region us-east-1 --output "$review_dir/shared.json"
```

The unchanged fixture has one identity, so this retained example reports
`asset_count: 1`, `shared_address_count: 0` and `shared_identity_count: 0`.
That is a successful review with no repeated address claims, not a failed collection
or evidence that all addresses are unique in AWS. Use `owned` or `authorized` only
for data within the corresponding permitted scope. Scope remains a caller claim.

The private JSON contains the exact original SHA-256, selected account/region/scope,
asset count and sorted `shared_claims`. Each shared item records a normalized IPv4
or IPv6 literal, integer address family, distinct identity count and observations.
Each observation retains the instance ARN and one-based reservation/instance row
references from the original export. A reviewer can locate the specific claim in
that original, including when an instance appeared under a different reservation.

Equal address spellings and duplicate interface paths within one identity count
once. Equivalent IPv6 spellings normalize before grouping. Different instance IDs
remain separate even if every selected address matches. An instance sharing several
addresses is counted once in `shared_identity_count`. An empty valid export returns
zero counts. Duplicate instance IDs, account mismatch, malformed selected address
records and unfinished pagination reject under the existing importer contract.

Stdout returns `ec2_shared_address_review_created`, aggregate counts and a report
digest. It omits account, region, instance IDs and addresses. The private report
contains operational identifiers and addresses, so keep it and permitted originals
outside Git. The digest identifies report bytes, not source authority or approval.
Existing output files are preserved. Errors return 2 with a fixed diagnostic.

## Interpretation and limits

This reports shared *supplied claims*, not a confirmed collision, vulnerability,
reachable service, ownership relationship or exposure change. Public NAT addresses
may legitimately be shared. Private addresses can overlap across separate VPCs.
The existing address projection combines selected address roles and interfaces,
so this report cannot decide those cases or claim a common VPC. Do not score risk
or merge identities from this grouping alone. Collection completeness, capture time,
source authenticity and current state remain unverified.

The saved input is bounded to 4 MiB and report to 16 MiB. The existing POSIX bounded
regular-file reader and exclusive private output helper are reused. Trust ancestor
directories and cooperative writers; this is not file locking or live inventory.
No database/model schemas, existing comparator, risk model or archive fingerprints
are changed. No address lookup, scan, credential use or remediation runs.

Tests block socket creation and cover shared identities/lineage, per-identity
deduplication, IPv6 spelling, zero-result exports, context/pagination rejection,
private read-only publication, no overwrite and report bounds. Prepared with
assistant support and synthetic local data. Next: retain explicit interface/VPC and
address-role claims before interpreting which kinds of sharing need an operator review.
