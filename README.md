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

```bash
python database/schema_check.py database/schema.sql
python -m unittest discover -s tests -v
```

The manual Airflow DAG delegates to the [fixture workflow](engine/evidence_workflow.py).
Python tests do not establish that an Airflow deployment has been exercised.

## Explore the interfaces

| Need | Entry point |
| --- | --- |
| Read stored evidence | `python -m database.evidence_reader_cli --help` |
| Compare snapshots | `python -m database.evidence_diff_cli --help` |
| Authenticate a snapshot | `python -m database.evidence_auth_cli --help` |
| Check local storage | `python -m database.storage_probe --help` |
| Inspect a complete fixture workflow | [Workflow spec](examples/workflow-spec.json) |

Keep secret keys outside Git. HMAC provides shared-secret authentication, not independent
signer identity. Storage checks do not prove crash guarantees or protection from
privileged users.

## Status and next work

The local fixture pipeline works. AWS, network, and osquery connector files and some
infrastructure files remain placeholders, not working discovery integrations.
The workflow CLI is available; next work should validate deployment and persistence
boundaries before connecting an authorized external discovery source.

See the [threat model](docs/threat-model.md), [design decisions](docs/design-decisions.md),
and [remediation policy](docs/remediation-model.md). This is an ongoing implementation
with assistant support.
