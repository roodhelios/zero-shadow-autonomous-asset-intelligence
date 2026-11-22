# Compare saved EC2 claims with reviewed network expectations

The address-context report retains supplied VPC and interface fields, but cannot
tell whether a required instance was omitted or its interface context differs
from an operator's expectation. This separate review compares every supplied
instance, including instances with no shared address, with a pinned expected roster.
It creates no AWS requests, database rows, risk scores or remediation actions.

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -m engine.discovery.ec2_network_expectations demo
```

Only the standard library is needed. The temporary in-memory exercise adds
synthetic network context to the existing interface-address fixture, matches the
separate bundled roster, then detects a missing interface VPC claim and an omitted
instance. Selected output:

```json
{
  "status": "ec2_network_expectation_exercise_passed",
  "matching_instances": 1,
  "changed_context_detected": true,
  "missing_instances": 1,
  "collection_completeness_established": false,
  "collision_established": false
}
```

## Retain a review

The example roster is [ec2-network-expectations.json](../examples/ec2-network-expectations.json).
It deliberately expects VPC, subnet and interface identifiers absent from the
unchanged saved export. This retained command should therefore report one differing
instance, not a match:

```bash
review_dir=$(mktemp -d)
original_pin=$(python -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("examples/ec2-interface-addresses.json").read_bytes()).hexdigest())')
expectations_pin=$(python -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("examples/ec2-network-expectations.json").read_bytes()).hexdigest())')
python -m engine.discovery.ec2_network_expectations review \
  examples/ec2-interface-addresses.json examples/ec2-network-expectations.json \
  --original-sha256 "$original_pin" --expectations-sha256 "$expectations_pin" \
  --scope synthetic --account 111122223333 --region us-east-1 \
  --output "$review_dir/network-review.json"
```

Expect `ec2_network_expectation_review_created`, `expected_instance_count: 1`,
`observed_instance_count: 1`, `differs_instance_count: 1` and
`selected_roster_matches: false`. Exit 0 means a report was created, including when
claims differ. Exit 2 means invalid input, pin, context or output handling. The
commands above derive fixture pins for demonstration only. For permitted real
inputs, obtain and review the roster independently of the observed export, retain
its digest through your trusted review process, and select exact original bytes.
Regenerating expectations or pins from an untrusted export does not validate it.

Stdout includes counts, equality flags and the new report digest. Instance,
network and operational identifiers remain in the private mode-0600 report.
Existing destinations are preserved; both input files remain unchanged. Source
paths are zero-based JSON Pointers to exact instance/interface objects, including
when interface array order changes. Keep reports and permitted originals outside Git.

## Expectation contract and comparison

The strict version-1 JSON object has exactly `schema_version`, `scope`, `account`,
`region` and `instances`. Context must equal the explicit CLI values. Each instance
requires `instance_id`, `instance_vpc_id`, `instance_subnet_id` and `interfaces`.
Each interface requires `network_interface_id`, `interface_vpc_id` and
`interface_subnet_id`. IDs use the existing literal EC2 identifier grammar.
No extra keys, duplicate JSON fields or duplicate expected IDs are accepted.

VPC/subnet expectations are explicit IDs or null. Null requires absent selected
metadata; it is never a wildcard, inherited context or a default VPC. An explicitly
null original ID rejects, matching the existing version-2 context contract.
Instance and interface VPC/subnet claims are checked separately, even when the
instance claim matches. Interfaces without address records are still compared.

Instances are classified as `matches`, `differs`, `missing` or `unexpected`.
For shared instance IDs, the report compares network context and matches interface
identities by ID, retaining missing and unexpected interface rows. Interfaces
without an ID remain `unidentified_interfaces`, making the instance differ even
if no interface was expected. Duplicate observed interface IDs within an instance
reject as ambiguous. Missing instances are not treated as retired, fixed or safe.
Unexpected instances retain their selected context and original source paths.

An empty expected roster is allowed and explicitly means zero expected instances.
Two empty sets match that selected roster, but do not establish complete collection.
The private report includes both input digests and all comparison rows. It does
not accept a precomputed address report or trust its claimed counts.

## Boundaries and validation

Both pins are checked before JSON parsing. The existing strict saved EC2 importer
validates scope, account, region, address fields, duplicate instance identities and
unfinished pagination. The original is bounded to 4 MiB, expectations to 256 KiB,
expected instances to 1000 and interfaces per expectation to 100. Output uses the
existing 16 MiB report bound and private exclusive publication helper. POSIX regular
file readers reject leaf symlinks. Trust ancestor directories and cooperative
writers; this is not a lock, hostile-file sandbox or crash-durability guarantee.

Roster equality only establishes agreement between the selected bytes. A filtered
or stale export can omit systems outside the expected roster. Neither source is
authenticated. Capture time, full collection coverage, current interface attachment,
address role expectations, collision, exposure and legal ownership remain unverified.
No previous import, address report, database or model-source contract is changed.

Tests block socket creation and cover real CLI publication, exact pins, no mutation
or overwrite, missing/unexpected identities, absent metadata, interface reordering,
unidentified and duplicate interfaces, strict manifests, source validation and bounds:

```bash
python -m unittest tests.test_ec2_network_expectations tests.test_ec2_address_context \
  tests.test_ec2_address_review tests.test_ec2_import \
  tests.test_ec2_interface_ipv4 tests.test_ec2_ipv6
```

Prepared with assistant support and synthetic fixtures. Learning note: comparing
an explicit independent roster makes omissions visible, but completeness remains a
property of the collection process. The separate
[collector attestation](ec2-collector-attestation.md) now verifies an enrolled key's
exact export/roster and capture claims before reproducing this report. It does not
prove AWS origin or truthful collection time. Next: trusted current policy/roster
distribution and independently reviewed capture-process evidence.
