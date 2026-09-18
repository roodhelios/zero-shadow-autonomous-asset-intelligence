# Local Evidence Architecture

The first persistence contract uses SQLite so the schema can be created and tested
without a service account, network connection, or running container. It is a local
review target, not a claim that production persistence is complete.

## Evidence lineage

1. `assets` stores the stable identity produced by correlation.
2. `asset_observations` preserves each scoped source claim linked to that identity.
3. `findings` records the exact inputs accepted by the explainable risk model.
4. `ownership_decisions` records whether fixture rules resolved, failed to match, or
   remained ambiguous.
5. `remediation_plans` stores versioned priorities, risk results, dates, and factors.

Observations, findings, ownership decisions, and remediation plans are append-only.
Corrections require a new evidence identifier or plan version. Assets can be updated as
new observations change the consolidated view, but foreign keys prevent deleting an
asset that still has evidence.

JSON columns retain source payloads and decision factors that do not belong in identity
keys. SQLite checks that each value is the expected object or array. The schema also
checks the existing scope, scoring, ownership, and priority vocabularies.

## Validate locally

```bash
python database/schema_check.py database/schema.sql
python -m unittest discover -s tests -v
```

The checker creates an in-memory database and reports tables, indexes, triggers, and
foreign keys. Tests insert a complete synthetic evidence chain and exercise failure
boundaries.

## Transactional write adapter

`database/repository.py` accepts one correlated asset, its retained observations, one
finding, one ownership decision, and one remediation plan. It validates their shared
asset and finding identifiers before opening a transaction. SQLite then inserts the
linked rows together.

If a later constraint fails, the asset and observations written earlier in that call
are rolled back. Tests prove this with a duplicate finding identifier that fails after
a second asset and observation have been attempted. Evidence JSON uses sorted keys and
compact separators so saved rows remain deterministic for review.

The adapter requires an existing SQLite connection with the reviewed schema. It does
not create a database, discover assets, or schedule work on its own.

## Current limits

- SQLite is the review and test dialect. A PostgreSQL migration needs separate syntax,
  transaction, and JSONB tests before any deployed workflow uses it.
- The adapter handles one evidence bundle at a time. It does not yet support batch
  checkpoints, retries, or a read-side reconstruction API.
- Append-only triggers protect normal SQL statements, not an administrator who can
  replace the database file or alter the schema.
- No retention, encryption, backup, or access-control policy is implemented here.
