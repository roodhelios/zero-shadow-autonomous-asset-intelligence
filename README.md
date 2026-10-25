# Zero Shadow

Local asset intelligence that explains why a finding matters, who should review it,
and which evidence supports its remediation priority.

Zero Shadow correlates explicitly scoped fixture observations, explains risk scores,
resolves ownership from tags, and preserves linked evidence in SQLite. It does not
scan networks, enumerate cloud accounts, or send remediation actions.

## Try the complete retained-inventory exercise

On POSIX with Python 3.11 or newer, use only the standard library:

```bash
python -m engine.demo_inventory
```

Expect `inventory_exercise_passed`, two assets, one finding,
`assessment_reproduced`, `bound_current_model`, and `changed_export: rejected`.
The command imports the bundled synthetic osquery export, retains a finding with
ownership/planning decisions, deletes the original discovery database, and verifies
the assessment against the original export with strict model binding. It also checks
that changed source bytes are rejected and neither input database was modified.
All temporary files are discarded. Only aggregate results reach stdout.

The observation and assessment dates are fixed October 23 fixtures. This exercise
uses native SQLite, not a database substitute. It does not collect live telemetry,
authenticate source or owner claims, perform remediation, or implement historical
model replay. Preserve the original export and source checkout for real retained data.

## Follow the evidence

For saved cloud inventory, the [EC2 review export](docs/ec2-import.md#export-verified-snapshots-for-review)
reproduces the original saved export before publishing complete retained snapshots
to a new private JSON file. It includes stable asset IDs and source-row references,
with empty decision arrays for unassessed assets. No AWS connection is needed.

To plan reviewed findings against retained EC2 or osquery evidence, use the
[source-selected queue workflow](docs/ec2-import.md#plan-explicit-findings-with-source-selection).
It requires the original export and an explicit source. Imported addresses and tags
never invent findings or accepted ownership.

| Stage | Working behavior | Implementation |
| --- | --- | --- |
| Discover | Validate local observations with synthetic, owned, or authorized scope | [Fixture discovery](engine/discovery/fixture_discovery.py) |
| Correlate | Merge strong identifiers while retaining observations; IP alone does not merge assets | [Asset graph](engine/correlation/asset_graph.py) |
| Score | Explain severity, exposure, exploit evidence, and control-state points | [Risk model](engine/risk.py) |
| Assign | Resolve ownership tags and preserve ambiguity as unassigned | [Ownership rules](docs/ownership-queues.md) |
| Plan | Produce P0 to P3 priorities with dates and visible factors | [Remediation policy](docs/remediation-model.md) |
| Preserve | Store linked records, reconstruct snapshots, compare evidence, authenticate manifests | [Architecture](docs/architecture.md) |

## Run a local example

Use Python 3.11 or newer. These examples need only the standard library, with no cloud
credentials, Airflow deployment, or database server. From the repository root:

```bash
python -m engine.remediation_cli examples/remediation-input.jsonl --as-of 2026-09-15
```

Selected fields from the fixture output:

```json
{
  "asset_id": "asset-example",
  "owner": "platform-team",
  "priority": "P2",
  "due_date": "2026-10-15",
  "risk_assessment": {"score": 35, "band": "moderate"}
}
```

The complete output includes every scoring factor and priority explanation. The
explicit review date makes the result reproducible. Risk inputs remain source claims,
not verified exploitability or a prediction of business impact.

Build ownership queues in a new local output file:

```bash
python -m engine.work_queue_cli examples/work-queue-input.jsonl \
  --directory examples/ownership-directory.json --as-of 2026-09-16 \
  --output work-queues.json
```

Inspect the file before using it as a task list. No tickets or notifications are sent.

## Validate locally

Run the complete fixture pipeline without Airflow:

```bash
python -m engine.workflow_cli examples/workflow-spec.json --run-id demo-001 \
  --output-root demo-runs --allowed-root .
```

The JSON result includes six checkpoints and a `run_key`. Its directory under
`demo-runs` holds `evidence.sqlite`, `workflow-report.json`, and `run-manifest.json`.
Repeat the command to verify and reuse the saved evidence (`reused: true`). Changed
inputs or altered saved artifacts fail the retry rather than silently replacing them.
Use a new run ID for a new observation. Outputs must stay under the explicit allowed root.

For a concise analyst handoff, repeat the same command with `--format text`:

```bash
python -m engine.workflow_cli examples/workflow-spec.json --run-id demo-001 \
  --output-root demo-runs --allowed-root . --format text
```

The summary shows the asset, risk score `75/100` (`critical`), ownership team
`application-security`, priority `P0`, due date `2026-09-20`, and evidence directory.
These dates and decisions belong to the fixed synthetic observation, not today's
environment. An unassigned owner is shown explicitly as `team null`. A verified retry
does not rewrite artifacts. JSON remains the default for scripts; the text summary
is a review aid, not a new evidence contract or an external remediation action.

Inspect the evidence behind those decisions directly from the same run:

```bash
python -m engine.workflow_cli examples/workflow-spec.json --run-id demo-001 \
  --output-root demo-runs --allowed-root . --format snapshot
```

This verifies the run's saved hashes, then reconstructs the asset through a read-only
SQLite connection. JSON includes observations, finding evidence, ownership decisions,
remediation actions and factors, and `snapshot_sha256`. For the fixture, inspect one
finding and its P0 plan with risk score 75. The run report remains the default output;
snapshot mode uses the existing evidence snapshot format and does not rewrite saved
artifacts. Snapshot data may be sensitive when using authorized non-fixture inputs.
Keep any redirected output private and outside Git. A digest is not source authentication.

```bash
python database/schema_check.py database/schema.sql
python -m unittest discover -s tests -v
```

The manual Airflow DAG delegates to the [fixture workflow](engine/evidence_workflow.py).
Python tests do not establish that an Airflow deployment has been exercised.

## Explore the interfaces

Assess one reviewed identity from a multi-asset batch without attaching its finding
to every discovered host:

```bash
python -m engine.workflow_cli examples/workflow-selection-spec.json --run-id selected-001 \
  --output-root demo-runs --allowed-root . --format text
```

This fixture has two correlated assets. The spec explicitly selects
`asset-0eb80d82444587d9`, the checkout server. Expect the existing synthetic risk
score 75 and P0 plan for that identity only. The `asset_correlated` checkpoint records
`batch_asset_count: 2`, `excluded_asset_count: 1`, and `selection: explicit`.
The other host receives no finding, risk score, ownership decision, or plan and is
not persisted by this single-bundle run. See [selection rules](docs/architecture.md#select-one-asset-from-a-batch)
before adapting the spec to authorized data.

Import a saved osquery host-identity export without running a collector:

```bash
python -m engine.discovery.osquery_collector examples/osquery-system-info.json \
  --scope synthetic --output /tmp/zero-shadow-osquery-assets.json
```

The synthetic example becomes a fixture-compatible host observation with a canonical
UUID and an input digest. The [osquery import guide](docs/osquery-import.md) documents
the two-column input, limits, privacy considerations, and connection to the existing
SQLite workflow. No ownership, exposure, or vulnerability finding is inferred.
Add `--format inventory` to the same command to see stable asset IDs, correlation
keys, retained observations, and the input digest directly. The included export
produces one observation and one asset. The default output remains a workflow fixture.

Retain discovery evidence without inventing a vulnerability finding:

```bash
python -m database.inventory_cli examples/osquery-system-info.json --scope synthetic \
  --observed-at 2026-10-19T00:00:00Z --output /tmp/zero-shadow-inventory.sqlite
python -m database.evidence_reader_cli /tmp/zero-shadow-inventory.sqlite \
  --asset-id asset-752c9c1b37e66798 --inventory
```

Use a fresh output path on POSIX. The snapshot contains one observation and empty
finding, ownership, and remediation arrays. Default reader mode still requires a
complete decision bundle. See the import guide for storage and privacy limits.

New inventories also retain their import receipt inside SQLite. Reconcile it with
the original export in another process:

```bash
python -m database.inventory_receipt /tmp/zero-shadow-inventory.sqlite \
  --export examples/osquery-system-info.json
```

Expect `status: consistent` and `original_export_checked: true`. This checks internal
consistency and the retained bytes, not the truth of source claims or authorization.

Export the complete retained batch without copying asset IDs into separate commands:

```bash
python -m database.inventory_cli examples/osquery-system-info-expanded.json --scope synthetic \
  --observed-at 2026-10-20T00:00:00Z --output /tmp/zero-shadow-two-hosts.sqlite
python -m database.inventory_export_cli /tmp/zero-shadow-two-hosts.sqlite \
  --export examples/osquery-system-info-expanded.json --output /tmp/zero-shadow-two-hosts.json
```

Use fresh paths on POSIX. Expect `report_type: retained-inventory`, `asset_count: 2`,
`observation_count: 2`, and two asset snapshots with empty finding, ownership, and
remediation arrays. Each snapshot keeps its evidence digest. The reconciled receipt
reports `original_export_checked: true`; without `--export`, that value is explicitly
false. Reading and reconciliation share one read-only SQLite transaction.
The export preserves any existing linked decisions but never invents missing ones.
Exit 0 means the complete batch was exported; exit 2 publishes no new output.

The receipt binds retained identities and observation metadata to the imported batch.
Only supplying the original export also checks exact input bytes and observation
payloads against that source. Neither mode authenticates the collector or establishes
that all hosts in an environment were collected. This command supports databases
created by `inventory_cli` with an import receipt, not arbitrary workflow databases.
Authorized hostnames and evidence can be sensitive: use `--output` for a private
0600 file outside Git. Omitting it prints the complete evidence to stdout.

For a readable review of that same batch, without opening the full JSON:

```bash
python -m database.inventory_export_cli /tmp/zero-shadow-two-hosts.sqlite \
  --export examples/osquery-system-info-expanded.json --format text
```

Selected output:

```text
Retained inventory: 2 assets, 2 observations
Claimed scope: "synthetic"
Observed at: "2026-10-20T00:00:00Z"
Receipt: "consistent"
Original export: checked
Asset: "asset-752c9c1b37e66798", hostname "checkout.example.test"
  Observations: 1
  Findings: 0 (not assessed by this import)
  Ownership decisions: 0; remediation plans: 0
```

The full summary also lists the worker host in stable asset-ID order. It reads and
verifies the same evidence as JSON mode before rendering any text. Without
`--export`, it says `Original export: not checked`. Zero findings do not establish a
clean host, and absent ownership or remediation records are not inferred decisions.
Existing findings, ownership decisions, and plans are counted, not rescored.
The text is a review aid, not a replacement evidence contract: keep JSON for linked
records, decision details, and digests. Supplied strings are JSON-quoted so terminal
control characters stay escaped. Hostnames can still be sensitive. Add `--output`
with a new path to retain a private text file; JSON remains the default.

When a reviewer needs coverage counts but should not receive hostnames, asset IDs,
finding details, or evidence, request aggregate JSON instead:

```bash
python -m database.inventory_export_cli /tmp/zero-shadow-two-hosts.sqlite \
  --export examples/osquery-system-info-expanded.json --format coverage
```

The fixture reports two assets without retained finding, ownership, or remediation
records. It also states whether the original export was checked. The summary contains
no asset or evidence identifiers and does not call missing records a clean result.
It counts record presence only, not assessment quality, source truth, authorization,
or discovery completeness. Complete JSON remains the evidence handoff when a reviewer
needs the linked records and digests.

Record a reproducible review checkpoint for the same metadata-only summary:

```bash
python -m database.inventory_export_cli /tmp/zero-shadow-two-hosts.sqlite \
  --export examples/osquery-system-info-expanded.json --format review \
  --reviewed-at 2026-10-22T05:30:00Z \
  --reviewer-note "Coverage checked for synthetic handoff." \
  --output /tmp/zero-shadow-review.json
```

The review record normalizes the timestamp to UTC and binds the time, note, and exact
included coverage summary with `review_sha256`. It still excludes
asset IDs, hostnames, findings, and evidence. The time and note are caller claims, not
proof of reviewer identity or approval. Notes are limited to 500 printable characters.
Use a private `--output` path to keep the note out of terminal output. Command-line
arguments may still be recorded in shell history.

Check that saved record against freshly reconstructed coverage in another process:

```bash
python -m database.inventory_review_verify /tmp/zero-shadow-two-hosts.sqlite \
  /tmp/zero-shadow-review.json --export examples/osquery-system-info-expanded.json
```

Expect `status: consistent`, `asset_count: 2`, and `original_export_checked: true`.
The verifier recomputes coverage and the review digest before reporting success.
An edited note, stale coverage, malformed record, or different source bytes exits 2
without a success document. Supply `--export` if it was used to create the review;
the checked/unchecked source state is part of the saved coverage summary.

This comparison does not authenticate the reviewer or identify a particular batch.
Two different inventories with identical coverage counts can match the same review.
Use the complete inventory export and its retained input receipt when identity matters.
Verification output includes the review digest and aggregate counts, without the note,
hostnames, asset IDs, or evidence payloads. The review JSON input is bounded to 16 KiB.

When the handoff must identify the complete reconstructed batch, add `--bind-batch`:

```bash
python -m database.inventory_export_cli /tmp/zero-shadow-two-hosts.sqlite \
  --export examples/osquery-system-info-expanded.json --format review --bind-batch \
  --reviewed-at 2026-10-23T05:00:00Z --reviewer-note "Synthetic batch handoff." \
  --output /tmp/zero-shadow-bound-review.json
python -m database.inventory_review_verify /tmp/zero-shadow-two-hosts.sqlite \
  /tmp/zero-shadow-bound-review.json --export examples/osquery-system-info-expanded.json \
  --require-batch-binding
```

This produces a version 2 review with `batch_sha256` over the complete canonical
inventory export, including observations, linked decisions, and the import receipt.
The review digest also binds that batch digest. Verification reconstructs the same
export and reports `batch_bound: true`; an inventory with equal counts but different
content fails. It still publishes no raw identifiers or evidence, but its digest can
correlate matching inventories. Treat it as sensitive metadata. Neither digest
authenticates the reviewer or collector. Version 1 remains the default coverage-only
record, and its documented equal-count limitation remains unchanged.
Use `--require-batch-binding` in workflows that require version 2, so a coverage-only
record cannot silently replace a batch-bound review.

Compare two retained imports with
`python -m database.inventory_diff_cli BASE.sqlite CURRENT.sqlite`.
The [worked comparison](docs/osquery-import.md#compare-two-discovery-imports) shows
new, shared, and not-observed identities without inventing deletion or risk claims.

| Need | Entry point |
| --- | --- |
| Read stored evidence | `python -m database.evidence_reader_cli --help` |
| Compare snapshots | `python -m database.evidence_diff_cli --help` |
| Authenticate a snapshot | `python -m database.evidence_auth_cli --help` |
| Check local storage | `python -m database.storage_probe --help` |
| Inspect a complete fixture workflow | [Workflow spec](examples/workflow-spec.json) |

Key lifecycle metadata rejects non-string operations and states, boolean schema
versions, oversized timestamps, and dates outside the UTC range. Private storage
permission checks require POSIX and fail before creating files on other platforms.

Keep secret keys outside Git. HMAC provides shared-secret authentication, not independent
signer identity. Storage checks do not prove crash guarantees or protection from
privileged users.

## Plan findings against a retained inventory

The standalone work-queue input can name arbitrary asset IDs. To require every
finding to reference an asset in a reconciled osquery inventory, use the linked
planner instead. From the repository root, create a fresh fixture inventory:

```bash
python -m database.inventory_cli examples/osquery-system-info-expanded.json \
  --scope synthetic --observed-at 2026-10-23T00:00:00Z \
  --output /tmp/zero-shadow-queue-inventory.sqlite
python -m engine.inventory_queue_cli /tmp/zero-shadow-queue-inventory.sqlite \
  examples/inventory-findings.jsonl --directory examples/ownership-directory.json \
  --as-of 2026-10-23 --export examples/osquery-system-info-expanded.json \
  --output /tmp/zero-shadow-inventory-queues.json
```

Expect two retained assets, one asset with a supplied finding, and one asset without
supplied findings. The queue has one item assigned to `cloud-platform`. The planner
uses the same risk, ownership, and remediation rules as `work_queue_cli`, without
attaching the finding to the other imported host. Unknown asset references and
duplicate finding IDs reject the whole output. Multiple distinct findings for one
asset create separate items but count that asset once in coverage. Empty findings
leave every asset unassessed and create no queue items.

The input is JSON Lines with `finding`, `asset_tags`, and `opened_on`, plus optional
`requested_due_date`, as in the included fixture. Finding asset IDs must match the
retained inventory exactly. Tags are explicitly reviewed assessment inputs; they
are not collected, inferred, or authenticated by osquery. Severity, exposure, exploit
and control evidence also remain caller claims. Missing findings do not mean clean
hosts, and resolving tags does not prove an owner accepted responsibility.

The output includes complete queue items, coverage counts, an inventory batch digest,
and digests of the findings and ownership directory. `--export` checks the retained
inventory against original input bytes; without it, `original_export_checked` is
false. Hashes establish consistency, not authentication. No decisions are written to
SQLite, no tickets are sent, and no remediation is performed. Existing evidence
remains unchanged. This is a planning handoff, not a persisted decision workflow.

The command accepts regular local POSIX inputs. Findings and ownership-directory
inputs are bounded to 4 MiB; findings have at most 10,000 non-empty lines and 64 KiB
per line. Duplicate JSON fields, non-finite values, and unknown record fields fail
before publishing a result. Use fresh private output paths outside Git. `--output`
creates a complete 0600 file and never overwrites; omitting it prints sensitive queue
content to stdout. Failure returns exit 2 with a fixed error and no success document.

Compare date-driven urgency against an earlier review without changing inventory,
finding facts, or ownership policy:

```bash
python -m engine.inventory_queue_cli /tmp/zero-shadow-queue-inventory.sqlite \
  examples/inventory-findings.jsonl --directory examples/ownership-directory.json \
  --as-of 2027-01-01 --baseline-as-of 2026-10-23 \
  --export examples/osquery-system-info-expanded.json \
  --output /tmp/zero-shadow-priority-comparison.json
```

The synthetic item becomes overdue at the later review date. `priority_comparison`
shows one changed item, with previous/current priority and overdue status. A priority
already at P0 cannot rise further, but a changed overdue state is still visible.
Both plans use the same reconstructed inventory and in-memory assessment inputs;
technical risk assessments, input digests, due dates, and inventory binding remain
unchanged. This is not a comparison of different observations or proof of remediation.
The current-date queues remain in the normal `queues` field. Default output is
unchanged when `--baseline-as-of` is omitted. Equal dates produce no changes; a
baseline later than the current review or earlier than a finding's opened date fails
without publishing output. Dates belong to the selected exercise, not live telemetry.

## Retain a reviewed inventory assessment

The inventory queue command remains read-only. To retain its supplied findings,
ownership decisions and plans, create a separate first-assessment database:

```bash
python -m database.inventory_assessment_cli /tmp/zero-shadow-queue-inventory.sqlite \
  examples/inventory-findings.jsonl --directory examples/ownership-directory.json \
  --as-of 2026-10-23 --assessed-at 2026-10-23T01:00:00Z \
  --export examples/osquery-system-info-expanded.json \
  --output /tmp/zero-shadow-assessed.sqlite
python -m database.inventory_export_cli /tmp/zero-shadow-assessed.sqlite \
  --export examples/osquery-system-info-expanded.json
```

Use the discovery-only database prepared in the inventory queue quickstart above and
fresh output paths. Expect `assessment_stored`, one finding, one assessed asset and
two inventory assets. The export now contains one linked finding, ownership decision
for `cloud-platform`, and P0 remediation plan. The other asset remains unassessed.
The original database is unchanged. No ticket or remediation action is sent.

The command reconstructs the reconciled inventory in a new private database using the
committed schema. It checks that discovery reconstruction is exact, validates all
finding references with the existing queue planner, and inserts all decisions in one
SQLite transaction. A failure in any decision rolls them all back. Only a complete,
validated database is published to a fresh 0600 path. It never copies an input database's
schema or triggers. Retained `inventory_assessment_input` rows preserve exact finding
JSON Lines, ownership-directory JSON, review date, assessment time, original inventory
binding and input digests. These inputs and assessment records are append-only under
the supplied schema. Treat the new database as sensitive evidence and keep it outside Git.

`assessed-at` is a caller-supplied UTC-offset time at or after inventory observation.
It timestamps the supplied finding assessment and ownership decision, not an independently
measured detection. `as-of` remains the planner's explicit review date. Scope, finding
facts, tags, times and ownership policy remain claims. Retention does not establish
accepted ownership, authenticated provenance, live exploitability, or remediation.
Only the first nonempty assessment of discovery-only inventory is supported. Existing
decisions, empty findings, unknown assets, duplicate IDs and changed retained exports
fail without publishing output. Later assessment versions, reviewer authentication,
retention policies and PostgreSQL support remain unfinished. A database administrator
can replace files or alter schema; append-only triggers do not prevent that.

## Reproduce retained assessment decisions

After retaining the first assessment above, check its stored findings, ownership and
plans against the exact retained inputs and original osquery export:

```bash
python -m database.inventory_assessment_verify /tmp/zero-shadow-assessed.sqlite \
  --export examples/osquery-system-info-expanded.json
```

Expect `assessment_reproduced`, two assets, one finding and `original_export_checked: true`.
The verifier copies a closed, checkpointed regular database of at most 16 MiB into a
private temporary directory, reconciles the original export, regenerates discovery
using the committed schema and re-runs the current assessment model. It compares the
complete reconstructed asset snapshots, decision rows, input digests and original
inventory binding. The supplied database is read-only and unchanged. Symlinks and
pending WAL/journal sidecars, views and virtual tables are rejected; do not run against a live writer.

The original export is required even when initial retention omitted its optional source
check. The stored flag remains a historical caller claim; verification reports the source
check performed now. Edited inputs with a recalculated digest must still reproduce the
stored decisions. A plan changed independently of the inputs fails. Failure exits 2
with a fixed error and no success document. Summary output contains counts and input
digests, not individual asset IDs, findings or ownership details.

This proves reproducibility under the current model, not reviewer identity, source truth,
accepted ownership, historical validation time or remediation. A party able to replace all
inputs and decisions can create another internally consistent database. No signing or
versioned reassessment is added. Temporary reconstruction uses the committed schema,
not triggers copied from the supplied database.

## Retained assessment model binding

New first-assessment databases retain model ID `zero-shadow-first-assessment`, version
`1`, and SHA-256 digests of the nine scoring, ownership, planning, input, discovery and
correlation source modules. The manifest has its own canonical digest and append-only
SQLite record. These digests bind an exact source-checkout implementation, including
formatting. They do not sign the code, authenticate its author or isolate runtime changes.

Require that binding when reproducing a newly retained assessment:

```bash
python -m database.inventory_assessment_verify /tmp/zero-shadow-assessed.sqlite \
  --export examples/osquery-system-info-expanded.json --require-model-binding
```

Success adds `model_binding.status: bound_current_model`. A changed source digest,
unknown model/version, corrupt binding or malformed manifest fails before replay;
there is no fallback from a bad binding to legacy mode. Legacy databases without the
new table still replay under the current model by default, with explicit
`legacy_unversioned` status. Strict mode rejects them, including a removed binding.
No migration rewrites an old database. A party controlling the whole database and
runtime can replace both, so this is consistency evidence, not authenticity.

Only the current version-1 implementation is supported. Source changes can prevent
reproduction even if they preserve behavior. This deliberately conservative binding
is a foundation for future version-specific replay, not an implementation of historic
model dispatch or reassessment history. Preserve the relevant source checkout with
retained evidence before changing model code.

## Import an already saved EC2 export

```bash
python -m engine.discovery.aws_discovery examples/ec2-describe-instances.json \
  --scope synthetic --account 111122223333 --region us-east-1 --format inventory
```

Expect one supplied asset with account/region-scoped ARN identity and source-row
references. This local importer makes no AWS requests. It can also generate fixtures
for the existing SQLite evidence workflow. See the [input contract and limits](docs/ec2-import.md).
The [dedicated EC2 evidence commands](docs/ec2-import.md#retain-and-reproduce-a-discovery-batch)
also retain a discovery batch in private SQLite and reproduce its complete contents
against the separately supplied original export before reporting success.

## Status and next work

The local fixture pipeline, saved osquery JSON import and bounded saved EC2 import work.
Live AWS/network connectors and some infrastructure files remain unimplemented. Live osquery
collection is not implemented; the importer reads only a supplied local file.
The workflow CLI is available; next work should validate deployment and persistence
boundaries before connecting an authorized external discovery source.

See the [threat model](docs/threat-model.md), [design decisions](docs/design-decisions.md),
and [remediation policy](docs/remediation-model.md). This is an ongoing implementation
with assistant support.


