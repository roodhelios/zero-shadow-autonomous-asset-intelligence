# Import a saved EC2 export

From the repository root on POSIX with Python 3.11 or newer:

```bash
python -m engine.discovery.aws_discovery examples/ec2-describe-instances.json \
  --scope synthetic --account 111122223333 --region us-east-1 --format inventory
```

Expect one observation and one asset. The selected source identity is
`arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0`. Addresses are
documentation-only ranges. Supplied tags route reviewed work; they do not prove
accepted ownership. A public-address field is not an effective-exposure assessment.

The input is a saved JSON object in the AWS
[describe-instances output format](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html).
The importer reads `Reservations`, checks each `OwnerId` against the explicit
account, and projects each instance's ID, primary private/public IPv4 fields and
only the exact tag keys `environment`, `owner_group` and `service`. It preserves
the original byte digest and one-based reservation/instance references. DNS names,
instance state, other addresses and unselected metadata are not copied or inferred.
The fixture intentionally says `stopped`; inclusion never means running or reachable.

Without `--format inventory`, the output uses the existing fixture contract and can
feed the evidence workflow. A native SQLite regression test runs that complete path
with sockets blocked. `--output /private/new-ec2-fixture.json` publishes mode 0600
without replacing an existing file. Validate the full input before publishing.

The reader limits input to 4 MiB and 10,000 instances. It rejects duplicate JSON
fields, non-finite values, duplicate instance IDs, ambiguous tags, account mismatches
and nonempty pagination tokens. An export without a token can still be filtered or
incomplete. Empty reservations mean zero supplied observations, not zero real assets.

Only the commercial `aws` partition and the declared region-name subset are supported.
Region is caller supplied because it is not established by this projection. Incorrect
region claims produce incorrect identity context. China and GovCloud names fail.
Other sources must use the same full ARN to correlate by cloud identity; unqualified
instance IDs are deliberately different. Shared IP addresses never merge assets.

This command sends no AWS requests, needs no cloud credentials and creates no cloud
resources. Scope, source claims and account/region labels are not authenticated.
Live discovery, retained multi-source import receipts and region attestation remain
unfinished. Keep real exports private and outside Git. Assistant support was used
to implement and review this extension.

## Retain and reproduce a discovery batch

The dedicated EC2 evidence command retains projected observations and import context
in a new SQLite database. From the repository root, choose an unused private path:

```bash
python -m database.ec2_inventory store examples/ec2-describe-instances.json \
  --scope synthetic --account 111122223333 --region us-east-1 \
  --observed-at 2026-10-24T00:00:00Z --output /tmp/new-ec2-inventory.sqlite
python -m database.ec2_inventory verify /tmp/new-ec2-inventory.sqlite \
  --export examples/ec2-describe-instances.json
```

Expect `ec2_inventory_stored`, then `ec2_inventory_reproduced`, with one asset and one
observation. Both commands return aggregate results and byte/context digests, without
addresses, raw observations, account labels or asset IDs. The store command verifies
the complete closed database before exclusive mode-0600 publication. Existing paths
are never overwritten. Keep the original export separately, private and unchanged.

Verification copies one bounded closed-file snapshot, reads ordinary tables only and
rebuilds expected discovery in temporary SQLite from the supplied original export.
It checks context, exact source bytes, source-row references and every linked retained
record. Changed bytes fail even if JSON meaning is unchanged. Extra decisions do not
silently become verified discovery. The original database is not written. WAL/journal
sidecars, symlinks, views, databases over 16 MiB and contexts over 4 MiB are refused.
Temporary verification files are removed. Empty EC2 batches cannot be retained.

This EC2-specific context format is separate from the osquery import receipt and
assessment commands. Use the dedicated EC2 verifier; generic osquery assessment replay
does not dispatch EC2 inputs. No source code version is frozen. Reproduction establishes
local consistency under the current importer, not source authentication, complete
coverage, historical observation time, accepted ownership or remediation. Replacing
all source/context/evidence can create another internally consistent set. Retained
multi-source assessment and model-version dispatch remain future work.

## Export verified snapshots for review

After the store command above, export complete evidence for an analyst without
querying SQLite tables or manually copying asset IDs:

```bash
python -m database.ec2_inventory export /tmp/new-ec2-inventory.sqlite \
  --export examples/ec2-describe-instances.json --output /tmp/new-ec2-review.json
```

Expect `ec2_inventory_exported` on stdout with `asset_count: 1`,
`observation_count: 1` and `original_export_checked: true`. The new mode-0600 JSON
file has `report_type: retained-ec2-inventory` and three review sections:

| Field | Contents |
| --- | --- |
| `source_reconciliation` | Reproduction result and original-byte/context digests |
| `import_context` | Supplied scope, account, region, observation time, projection digest and source-row references |
| `assets` | Complete retained snapshots with stable asset IDs, observations and snapshot digests |

The fixture produces one snapshot with one observation and empty `findings`,
`ownership_decisions` and `remediation_plans` arrays. Those empty arrays mean
unassessed. They are not a clean bill of health or a reason to assign a risk score.

Export uses the same private database snapshot that passed full reproduction. It
does not reopen the original database to collect evidence after verification.
Changed source bytes or retained observations fail before publication. Existing
output files are never replaced. The original database and source export are not
modified. Stdout stays aggregate-only; the required private output contains
account labels, addresses, tags and asset identities. Keep it outside Git and
review it before sharing. There is no stdout mode for the full evidence.

This is the EC2-specific discovery report, not an osquery receipt or an assessment
input. Existing osquery assessment and queue commands do not accept this format.
Digests establish local consistency under the current importer, not source
authenticity or complete cloud coverage. Version-specific replay and multi-source
assessment dispatch remain unfinished.

## Plan explicit findings with source selection

Discovery alone does not establish a vulnerability or its severity. Supply a separately
reviewed finding that names an exact retained asset ID. After the store command above:

```bash
python -m engine.discovery_queue_cli /tmp/new-ec2-inventory.sqlite examples/ec2-findings.jsonl \
  --source ec2 --export examples/ec2-describe-instances.json \
  --directory examples/ownership-directory.json --as-of 2026-10-25 \
  --output /tmp/new-ec2-queues.json
```

Expect `queues_created`, `source_kind: ec2`, `asset_count: 1` and
`assets_with_supplied_findings: 1` on stdout. The private output has
`report_type: source-inventory-remediation-queues`, one queue for `cloud-platform`,
and the existing model's risk/priority explanation. This finding is deliberately
synthetic and independently supplied. Its `exposure: internal` is a reviewed input,
not an inference from the export's address fields. Its reviewed `asset_tags` drive
routing; empty reviewed tags leave it unassigned even when the EC2 export has tags.

The same command accepts `--source osquery` for databases created by `inventory_cli`,
using their original osquery export and matching finding IDs. This delegates to the
existing osquery planner and preserves its inventory binding and queue decisions.
Source selection is mandatory and does not guess the type from database contents.
The wrong source, changed export, unknown asset, duplicate finding, or invalid trailing
record fails before publication. Each call reviews one source batch; it does not join
EC2 and osquery identities or merge separate inventories.

All original-export bytes are required. For EC2, the planner uses the same closed-file
snapshot that passes full discovery reproduction. The report binds that complete
discovery document and exact finding/directory bytes with digests. Multiple findings
on one asset count as one assessed asset. Assets without supplied findings stay
unassessed. The existing limits apply: 4 MiB inputs, 64 KiB finding lines and 10,000
finding records. Output is a new private 0600 file; existing paths are not overwritten.
Stdout is aggregate-only. Keep real queues private because they contain identities
and reviewed finding details.

No decisions are appended to SQLite, no teams are contacted and no remediation is
performed. Risk and routing are lab model results, not verified exploitability or
accepted ownership. Existing model-bound assessment code and version-1 source hashes
are unchanged. The receipt workflow below can retain a first EC2 assessment separately.
Historical model replay and cross-source identity reconciliation remain unfinished.

## Retain and reproduce an EC2 assessment

Keep a first reviewed assessment after the original discovery database is no longer
available. From the repository root, after the EC2 store command above:

```bash
python -m database.ec2_assessment retain /tmp/new-ec2-inventory.sqlite examples/ec2-findings.jsonl \
  --directory examples/ownership-directory.json --as-of 2026-10-25 \
  --assessed-at 2026-10-25T01:00:00Z --export examples/ec2-describe-instances.json \
  --output /tmp/new-ec2-assessment.sqlite
python -m database.ec2_assessment verify /tmp/new-ec2-assessment.sqlite \
  --export examples/ec2-describe-instances.json
python -m database.ec2_assessment review /tmp/new-ec2-assessment.sqlite \
  --export examples/ec2-describe-instances.json --output /tmp/new-ec2-assessment-review.json
```

Expect `ec2_assessment_stored`, `ec2_assessment_reproduced`, then
`ec2_assessment_exported`. Each reports one asset, one assessed asset, one finding
and `original_export_checked: true`. The review JSON has
`report_type: retained-ec2-assessment-review`; inspect its `queue_report` for the
fixture cloud-platform queue and risk/priority explanation. Stdout contains only
aggregate results and payload/model digests. Both output paths must be unused.

The receipt is a **separate SQLite database**, not an append to discovery or the
osquery assessment tables. Its one append-only `ec2_assessment_record` stores a
canonical JSON review with verified discovery snapshots/context, exact finding and
ownership-directory strings, review/assessment dates, complete queue decisions and
selected implementation-file SHA-256 bindings. It does not insert normalized finding,
ownership or plan rows into the relational evidence repository. This format represents
one first assessment; reassessment history and batch joins are not implemented.

Retention copies one bounded closed discovery snapshot before reading or planning,
so a later change to the source database cannot retarget the receipt. It validates
the full receipt through replay before exclusive mode-0600 publication. The original
discovery database and supplied inputs are not changed. At least one explicit finding
is required. Observation time must not follow assessment time, and the review date
must fall between their UTC calendar dates. Dates and source context remain claims.

Verification and review require only the receipt and original saved EC2 export. They
do not need the original discovery database or separately retained finding/directory
files. They take one private receipt snapshot, rebuild native discovery from the
original export and retained context, then recompute every queue decision and compare
the entire canonical record. The review export uses the same verified receipt snapshot.
Mismatched source bytes or inconsistent snapshots, inputs, decisions, dates or model
binding fail. A consistently changed claimed assessment time can still reproduce;
this format does not authenticate when the review happened.
Recomputing the payload checksum alone cannot hide inconsistent decisions.

The receipt payload is limited to 12 MiB and the database to 16 MiB; discovery/review
inputs retain their existing bounds. Views, virtual/extra tables, live WAL/journal
sidecars and symlinked database inputs are refused. Existing output files are never
overwritten, and failed verification publishes no review output. Keep receipts and
review files private and outside Git: they contain asset identities and reviewed facts.
The review export omits the raw retained finding/directory strings, but its derived
queue can still contain sensitive details.

Only the exact current binding is supported. The selected source-file hashes do not
freeze Python/SQLite, dependencies, all transitive code or a historical environment.
Even a compatible edit to a bound file blocks replay; preserve the source checkout.
This is a replay guard, not trusted code attestation, source authentication, reviewer
approval, accepted ownership or remediation. A party able to replace the receipt and
all supplied evidence can construct another consistent review. Native SQLite storage
and append-only triggers do not make those claims authentic. Historical model dispatch,
normalized EC2 assessment persistence and multi-source identity remain future work.


## Compare two independent EC2 reviews

After retaining `/tmp/new-ec2-assessment.sqlite` above, retain a second review of the
same discovery batch. This synthetic example advances the review date so the
unchanged finding becomes overdue; it does not simulate a newly discovered exploit:

```bash
python -m database.ec2_assessment retain /tmp/new-ec2-inventory.sqlite examples/ec2-findings.jsonl \
  --directory examples/ownership-directory.json --as-of 2027-01-01 \
  --assessed-at 2027-01-01T01:00:00Z --export examples/ec2-describe-instances.json \
  --output /tmp/new-ec2-followup.sqlite
python -m database.ec2_assessment_compare /tmp/new-ec2-assessment.sqlite /tmp/new-ec2-followup.sqlite \
  --export examples/ec2-describe-instances.json --output /tmp/new-ec2-comparison.json
```

Expect `ec2_assessments_compared`, `changed: 1`, `added: 0`, `omitted: 0`,
`unchanged: 0`, `review_inputs_changed: false` and `original_export_checked: true`.
The private JSON has `report_type: ec2-assessment-comparison`. Its sorted `changes`
contain `finding_id`, `changed_fields`, `previous` and `current` derived decisions.
Here `overdue` changes while technical risk and due date remain the same. Explicitly
reviewed changes to severity or ownership can be compared using separately retained
receipts in the same way. Changed input bytes are flagged even when decisions match.
For a complete temporary severity-change exercise, run `python -m engine.demo_ec2_review`.

Both receipts undergo complete existing reproduction, including exact source-file
model binding, against the supplied original export before comparison. Discovery
snapshots and context must match exactly. The current review date and assessment
instant must not precede the previous ones. Matching finding IDs must stay attached
to the same asset. Both receipt inputs are snapshotted by the existing verifier;
comparison uses the verified in-memory records, not a later re-read of their paths.
Original discovery databases and separate review-input files are not required.

`added` means absent from the earlier review; `omitted` means absent from the later
review. Neither establishes discovery time or resolution. Full decision comparison
includes risk, priority, due date, overdue state, suggested actions and ownership
resolution evidence. Descriptions or directory metadata may change without affecting
these decisions; `review_inputs_changed` still records changed reviewed input bytes.
An identical pair reports one unchanged fixture finding and empty change lists.

Stdout is aggregate-only. The detailed output is a new private mode-0600 file, bounded
to 24 MiB, and never replaces an existing path. Invalid receipts, wrong exports,
changed model bindings, different batches or reversed dates publish no report.
Inputs are left unchanged; no AWS calls, tickets or remediation occur. Keep detailed
outputs private because they contain asset and finding identities and routing facts.

These are two independent first-assessment receipts, not an authenticated predecessor
chain or normalized append-only reassessment history. No new trust is created by
comparing consistent records. Historical code replay, reviewer approval, accepted
ownership and remediation evidence remain outside this workflow. Existing bound
model files and receipt version 1 remain unchanged.

## Retain an ordered same-model EC2 review history

Run `python -m engine.demo_ec2_history` for a complete temporary example. To retain
your own already-created EC2 assessment receipts, first create an owned private
directory (`mkdir -m 700 private-reviews` on POSIX). Then run:

```bash
python -m database.ec2_review_history start first-review.sqlite \
  --export saved-export.json --output private-reviews/history-1.sqlite
python -m database.ec2_review_history append private-reviews/history-1.sqlite next-review.sqlite \
  --export saved-export.json --expected-head HEAD_FROM_FIRST_COMMAND \
  --output private-reviews/history-2.sqlite
python -m database.ec2_review_history verify private-reviews/history-2.sqlite \
  --export saved-export.json --expected-head HEAD_FROM_APPEND_COMMAND
```

Replace the head placeholders with the exact `head_sha256` values returned by the
respective commands. Stdout contains only schema/status, review and decision counts,
the head digest, and original-export/head-check flags. It contains no finding, asset,
account, owner, path or reviewed-input content. Digests and counts are still private
operational metadata. Keep detailed files private because they retain the complete
discovery, review inputs and decisions.

Each publication creates a new mode-0600 SQLite artifact in an owned mode-0700
directory. It never overwrites a file or updates either input. The version-1 `reviews`
table stores ordered review payloads, receipt digests and predecessor-linked node
digests. The `decisions` table stores one canonical decision per revision and finding,
including asset identity. The verifier checks both tables, every receipt and node
digest, contiguous sequence numbers and every normalized decision against a full
rebuild using the original saved export. Existing version-1 receipts and their frozen
model-source bindings are unchanged.

All reviews must describe the same discovery context and exact current model.
Each input retains the existing receipt contract, including at least one explicitly
supplied finding. Empty reviews are not supported.
Review dates and assessment instants cannot move backwards, identical receipt
payloads cannot be appended twice, and a finding ID cannot move to another asset,
even after being omitted in an intermediate review. Omitted findings do not establish
resolution. Bounds are 32 reviews, 20000 total decision rows, 12 MiB combined canonical
receipt payloads and 16 MiB per database. Histories must be owned regular mode-0600
files; symlinks and active journal/WAL sidecars fail. Close/checkpoint a source before
inspection. This is a closed-file workflow, not a live database service.

An append requires an exact expected predecessor head. A stale head, changed export,
tampered normalized decision, unsupported model or invalid history publishes nothing.
Competing publications to the same output name retain one complete file; the other
fails without overwriting it. New artifacts are fully verified and file-synced before
exclusive publication. Parent-directory power-loss durability is not established.

Hash links establish internal consistency, not authenticated approval or protection
against an owner rewriting the entire history. `verify --expected-head` checks a
separately retained head; without it, an older internally consistent prefix can pass.
Protect and distribute that head independently if rollback detection matters. Different
output paths can create forks from the same predecessor. There is no global latest-head
registry, authenticated reviewer, accepted ownership, cross-model migration, historical
runtime replay or remediation. Same-user path races and malicious concurrent source
changes are outside this local cooperative-file boundary.

## Independent history approval

Install the optional `requirements-review.txt` package and run
`python -m engine.demo_ec2_approval` for a complete temporary example. It uses
native Ed25519 through [PyNaCl's signing API](https://pynacl.readthedocs.io/en/latest/signing/),
temporary SQLite and bundled synthetic EC2 data. Existing standard-library
history commands remain separate and unchanged.

The signer must have a privately enrolled 32-byte Ed25519 seed. The recipient
needs only the public authority policy, approval, history and original export.
Human enrollment and key distribution are external responsibilities. Do not
derive trust merely by accepting a policy and digest supplied by the same
untrusted sender. A trusted administrator must distribute the exact policy-file
SHA-256 through an independent trusted channel, along with the intended recipient
and an authoritative evaluation clock. Never put private seeds in Git or command
arguments. The signing CLI reads an owned POSIX mode-0600 regular seed file with
one hard link; final symlinks, FIFOs and oversized files fail.

Policy format (replace the public-key placeholder with canonical base64 of the
32-byte public key from your own enrollment, never a private seed):

```json
{
  "schema_version": 1,
  "purpose": "zero-shadow-ec2-history-approval-v1",
  "audience": "fixture-recipient",
  "max_validity_seconds": 3600,
  "keys": [{
    "key_id": "fixture-reviewer",
    "public_key_b64": "PUBLIC_KEY_BASE64_FROM_YOUR_ENROLLMENT",
    "state": "active",
    "not_before": "2026-10-28T00:00:00Z",
    "not_after": "2026-10-29T00:00:00Z"
  }]
}
```

These are fixed exercise times, not current validity advice. Use an appropriate
clock and windows for your own authorized evidence. Whole-second UTC strings
ending in `Z` are required. IDs and recipients use 3 to 64 lowercase letters,
digits, dots, underscores or hyphens and start with a letter or digit. Policies
contain 1 to 32 unique IDs and unique public keys. Unknown fields, duplicate JSON
fields, non-finite values, invalid types and noncanonical base64 fail. The maximum
approval lifetime is a policy-selected 1 to 604800 seconds. Active keys may sign;
active or retired keys may verify within their current validity window. Revoked
keys always fail. Issuance and expiry must fit both the policy limit and key window.

After independently checking the policy pin, sign an existing closed history:

```bash
python -m database.ec2_history_approval sign private-reviews/history-2.sqlite \
  --export saved-export.json --policy authority-policy.json \
  --expected-policy-sha256 TRUSTED_POLICY_SHA256 --audience fixture-recipient \
  --at 2026-10-28T01:00:00Z --issued-at 2026-10-28T01:00:00Z \
  --expires-at 2026-10-28T02:00:00Z --key-id fixture-reviewer \
  --seed-file private-reviews/reviewer.seed --output private-reviews/approval.json
```

The signer first reproduces the complete history, checks that its private seed
matches the enrolled public key, and publishes a new mode-0600 approval file.
An existing output is never overwritten. Stdout is only
`{"schema_version": 1, "status": "ec2_history_approval_stored"}`. Transfer the
approval, history and export privately, without transferring the seed. The recipient:

```bash
python -m database.ec2_history_approval verify private-reviews/history-2.sqlite \
  private-reviews/approval.json --export saved-export.json --policy authority-policy.json \
  --expected-policy-sha256 TRUSTED_POLICY_SHA256 --audience fixture-recipient \
  --at 2026-10-28T01:30:00Z
```

Success reports `ec2_history_approval_verified`, reproduced review/decision counts,
the head digest, authority key ID/policy digest, and original-export/head-check
flags. No finding, account, ownership, raw signature, seed or private path reaches
stdout. Digests, key IDs and counts are still private operational metadata. Failure
returns code 2 with a generic message. Neither command mutates history or export.
CLI policy/approval reads are bounded regular-file reads (64 KiB and 4 KiB);
original exports retain the 4 MiB limit. The existing history bounds still apply.

The purpose-separated signature covers the canonical approval's head, exact raw
export SHA-256, counts, key ID, recipient, issued time and expiry. JSON whitespace
in the approval does not matter; original export whitespace does. Verification
checks the required policy pin, recipient, lifecycle, time and signature before
opening the history, then checks the signed head and reproduces all decisions.
Approval is collective for the retained history, not per-revision author identity.
It authenticates a key enrolled in the supplied trusted policy, not a natural
person, independent reviewer judgment, source accuracy or remediation success.

The explicit clock is a trusted input, not a timestamping service or proof of when
the signature was produced. Reusing an old policy with its matching old pin can
bypass a later revocation unless policy freshness is enforced externally. An old
history with its own still-valid approval can pass; no latest-head registry,
one-time approval ledger, rollback-resistant policy distribution, cross-model
replay or gateway service is implemented. Retain the detached approval when
passing on verification evidence. The aggregate stdout result is unsigned.

```bash
python -m unittest discover -s tests -p test_ec2_history_approval.py -v
```
