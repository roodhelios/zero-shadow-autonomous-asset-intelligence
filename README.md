# Zero Shadow Autonomous Asset Intelligence

Zero Shadow is being built as a local-first asset inventory and risk explanation
project. The repository began as a directory skeleton. Features are marked as working
only after code and deterministic tests exist.

## Current capability

The first working slice loads explicitly scoped JSON fixtures and correlates asset
observations without contacting any network or cloud account.

It supports:

- validated source records, hostnames, IP addresses, cloud identifiers, and tags
- an explicit `synthetic`, `owned`, or `authorized` scope on every fixture batch
- deterministic correlation using source record IDs, fully qualified hostnames, and
  complete cloud resource identities
- preservation of every source observation as evidence
- stable asset IDs and output ordering

The second working slice adds explainable scoring for fixture-backed findings. Each
assessment reports the exact points from severity, exposure, exploit evidence, and
control state. Scores are clamped from 0 to 100 and mapped to low, moderate, high, or
critical bands.

Asset identity confidence is reported beside the score but never changes it. A weak
correlation should trigger identity review instead of quietly lowering or raising the
technical risk of a finding.

The remediation planner turns that assessment into a reviewable P0 to P3 priority. It
applies visible rules for risk band, ownership, and due-date state while retaining the
complete risk assessment. Missing ownership and overdue work increase urgency, and a
requested due date cannot extend the risk-based target window.

The ownership directory resolves exact asset tags to synthetic teams. The work-queue
command groups resolved plans by team and keeps unmatched or ambiguous items visibly
unassigned. It never guesses between equally specific rules owned by different teams.

Run the local JSON Lines workflow with an explicit review date:

```bash
python -m engine.remediation_cli examples/remediation-input.jsonl \
  --as-of 2026-09-15
```

See [the remediation model](docs/remediation-model.md) for the exact priority and target
rules.

Build the example work queues without sending tickets or notifications:

```bash
python -m engine.work_queue_cli examples/work-queue-input.jsonl \
  --directory examples/ownership-directory.json \
  --as-of 2026-09-16 \
  --output work-queues.json
```

See [the ownership queue notes](docs/ownership-queues.md) for resolution and ambiguity
rules.

IP addresses do not cause merges by themselves. Addresses are often reassigned or
shared, so they remain evidence until another strong identifier supports correlation.

## Fixture format

```json
{
  "schema_version": 1,
  "scope": "synthetic",
  "source": "cmdb",
  "assets": [
    {
      "source_record_id": "server-1",
      "kind": "server",
      "hostname": "api.example.test",
      "ip_addresses": ["192.0.2.10"],
      "cloud_provider": "aws",
      "cloud_account": "111122223333",
      "cloud_resource_id": "i-0123456789abcdef0",
      "tags": {"owner": "security-lab"}
    }
  ]
}
```

The examples use reserved documentation ranges and synthetic identifiers.

## Run tests

From the repository root:

```bash
python -m unittest discover -s tests -v
```

## Security boundary

This milestone accepts local fixture files only. It does not enumerate DNS, query cloud
APIs, scan addresses, or authenticate to external systems. Later discovery connectors
must keep the same explicit scope checks and must be tested against mocks before any
authorized integration is considered.

Risk inputs are source claims, not verified facts. An `observed` exploit-evidence value
must come from an owned or explicitly authorized evidence source. The scoring model is
a transparent triage rule, not a prediction of exploitation or business impact.

## Next milestone

Define a reviewed database schema for assets, observations, findings, ownership
decisions, and remediation plans before connecting any Airflow workflow.
