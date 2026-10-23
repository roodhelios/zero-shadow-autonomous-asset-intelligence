# Zero Shadow

Local asset intelligence that explains why a finding matters, who should review it,
and which evidence supports its remediation priority.

Zero Shadow correlates explicitly scoped fixture observations, explains risk scores,
resolves ownership from tags, and preserves linked evidence in SQLite. It does not
scan networks, enumerate cloud accounts, or send remediation actions.

## Follow the evidence

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

## Status and next work

The local fixture pipeline and saved osquery JSON import work. AWS and network
connector files and some infrastructure files remain placeholders. Live osquery
collection is not implemented; the importer reads only a supplied local file.
The workflow CLI is available; next work should validate deployment and persistence
boundaries before connecting an authorized external discovery source.

See the [threat model](docs/threat-model.md), [design decisions](docs/design-decisions.md),
and [remediation policy](docs/remediation-model.md). This is an ongoing implementation
with assistant support.


