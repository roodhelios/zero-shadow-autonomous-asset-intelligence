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
are unchanged. Retained EC2 assessments, historical model replay, and cross-source
identity reconciliation remain unfinished.
