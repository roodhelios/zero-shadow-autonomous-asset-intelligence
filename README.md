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


