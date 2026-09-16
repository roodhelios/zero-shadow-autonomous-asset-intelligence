# Ownership Directory and Work Queues

The ownership directory maps asset tags to accountable fixture teams. Resolution uses
the matching rule with the most tag conditions. If equally specific rules point to
different teams, the item remains unassigned and records every candidate. The engine
does not guess an owner.

## Local workflow

```bash
python -m engine.work_queue_cli examples/work-queue-input.jsonl \
  --directory examples/ownership-directory.json \
  --as-of 2026-09-16 \
  --output work-queues.json
```

The output groups resolved plans by team and sorts each queue by priority, due date,
and finding identifier. Unmatched and ambiguous plans appear in a separate
`unassigned` list. Each item retains the risk factors, priority factors, matching rule
identifiers, and candidate teams used in the decision.

Missing ownership continues through the existing remediation policy. It raises urgency
by one level but does not change the technical risk score.

## Directory rules

- Team and rule identifiers must be unique.
- Every rule must reference a declared team and contain at least one exact tag match.
- Tag keys are normalized to lowercase. Values remain exact strings.
- More tag conditions make a matching rule more specific.
- Tied rules for one team resolve to that team.
- Tied rules across teams remain ambiguous.

## Security boundary

The command reads local JSON and JSON Lines fixtures only. It does not query an asset
system, send a notification, open a ticket, or modify an asset. Team names and tags in
the examples are synthetic.

## Current limitations

- The directory supports exact tag matching only.
- It does not model schedules, secondary owners, team membership, or escalation paths.
- A stale or incorrect fixture can produce a wrong owner even when resolution is
  structurally valid.
- The queue document is an export for review, not a workflow system of record.

## Next step

Add a reviewed database schema for assets, observations, findings, ownership decisions,
and remediation plans before introducing any Airflow workflow.
