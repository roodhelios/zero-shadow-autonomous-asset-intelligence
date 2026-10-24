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

## Fixture workflow checkpoints

`engine/evidence_workflow.py` connects the existing local components without adding an
external discovery source. It loads one explicitly scoped fixture, selects one
correlated asset, scores one finding, resolves ownership, plans remediation, and writes
the linked bundle through the repository adapter.

The resulting JSON report records `fixture_loaded`, `asset_correlated`, `risk_scored`,
`ownership_resolved`, `remediation_planned`, and `evidence_persisted` checkpoints. The
SQLite database and report must be new paths inside the allowed local root. A failed
workflow removes its incomplete database rather than leaving partial evidence.

The Airflow DAG is a thin manual wrapper around this tested module. It has no schedule,
credentials, network connector, notification, or ticketing task.

## Select one asset from a batch

Version 1 workflow specs may include an optional non-empty `asset_id`. Correlation
still examines the complete fixture before selection. The supplied finding is then
bound only to that exact correlated ID; no first-host fallback or hostname guessing
is used. An absent selector retains the existing single-asset behavior and rejects
an ambiguous multi-asset fixture. A missing selected identity fails before storage.

The caller must independently establish that the finding applies to the selected
asset. Selection is not proof of that association. No finding or remediation state
is manufactured for excluded identities. New reports show the batch asset count,
excluded count, and selection mode in `asset_correlated`. The database holds only
the selected evidence bundle, not a complete inventory of the fixture.

Use `examples/workflow-selection-spec.json` for the two-asset example. To inspect
correlated IDs for a different reviewed fixture, run locally from the repository root:

```bash
python -c 'from engine.discovery import load_fixture; from engine.correlation import correlate_assets; import json; print(json.dumps([a.to_dict() for a in correlate_assets(load_fixture("examples/workflow-selection-assets.json").observations)], sort_keys=True))'
```

This prints supplied observation data, including identifiers and hostnames. Use only
synthetic or authorized files and keep redirected data private and outside Git.
Correlated IDs can change when strong identity keys change. An old selector then
fails instead of silently following a renamed host. The selector is inside the hashed
spec, so a completed run cannot be reused after changing the target; choose a new run
ID for a separately reviewed assessment. This remains one finding on one selected
asset, not multi-finding batch processing or an ownership enforcement boundary.

## Run identity and retries

`engine/workflow_runs.py` maps each scheduler run ID to a fixed local directory without
placing the raw ID in a path. The completed directory contains a database, JSON report,
and manifest. The manifest binds the run ID to hashes of the specification, schema,
asset fixture, ownership directory, database, and report.

A retry with unchanged evidence verifies and reuses those artifacts. It does not insert
the evidence bundle a second time. Changed input, artifact tampering, or a partially
created directory stops the retry for review. A failed first attempt removes only the
new directory created for that run.

## Read-side evidence reconstruction

`database/evidence_reader.py` rebuilds one asset snapshot from its linked SQLite rows.
It reads the database without writing, orders every evidence collection explicitly,
and checks duplicated source and finding fields against their canonical JSON payloads.
Missing observations, findings, ownership decisions, or remediation plans fail rather
than producing a partial asset view.

The export includes a SHA-256 digest over the canonical snapshot body. That digest is
useful for comparing two local exports. It does not authenticate the database or prove
who produced the evidence. `database/evidence_auth.py` can create a detached
HMAC-SHA256 manifest for independently stored snapshots. Verification checks the
version, asset ID, and digest before comparing the manifest, and binds the MAC to both
the asset ID and digest with a versioned domain prefix. The drift comparator remains
responsible for validating the complete snapshot record shape.

The HMAC key must remain outside the repository and exported evidence. HMAC provides
shared-secret authentication only. Every verifier able to check the manifest also has
the ability to create one, so the model does not provide non-repudiation or third-party
verification without disclosing the key.

Manifest version 2 includes a validated key ID inside the authenticated message. This
lets operators select a retained verification key during rotation without putting key
material in the manifest. The key ID is a label, not a secret or trust decision. Old
keys still need an explicit retirement and deletion procedure outside this repository.

`database/evidence_keyring.py` validates non-secret lifecycle metadata separately from
key bytes. Active keys can create or verify manifests only inside their stated window.
Retired keys can verify existing manifests until `verify_until`, but cannot create new
ones. The metadata does not load, store, encrypt, or delete secret material, and the
caller must supply a trusted UTC time rather than accepting a timestamp from evidence.

## Snapshot drift comparison

`database/evidence_diff.py` verifies two exported digests before comparing them. Both
snapshots must describe the same asset. Stable evidence identifiers separate added,
removed, and modified observations, findings, ownership decisions, and remediation
plans. Asset field changes are listed separately.

The comparator is detached from discovery and persistence. It cannot open a database,
contact a cloud account, or decide which snapshot is authoritative. The detached HMAC
manifest authenticates snapshots for holders of one shared secret. A future production
boundary that needs independent verification should use a public-key signature or an
independently controlled digest store before using a diff for enforcement.

## Current limits

- SQLite is the review and test dialect. A PostgreSQL migration needs separate syntax,
  transaction, and JSONB tests before any deployed workflow uses it.
- The adapter handles one evidence bundle at a time. It does not yet support batch
  checkpoints. Scheduler retries reuse a completed single-bundle run but do not resume
  from a partial checkpoint.
- The retry boundary is tested without Airflow. A disposable scheduler test is still
  needed before treating task-instance retry behavior as verified.
- Append-only triggers protect normal SQL statements, not an administrator who can
  replace the database file or alter the schema.
- Snapshot digests expose changed files but do not authenticate the exporter.
- No retention, encryption, backup, or access-control policy is implemented here.


## First retained inventory assessment

`database.inventory_assessment_cli` reconstructs reconciled discovery in a new private
SQLite database and uses the existing finding, ownership and remediation planner.
`EvidenceRepository.store_assessments` checks every bundle against retained source
observations, then inserts all finding/ownership/plan rows in one transaction without
rewriting inventory. A synthetic failure on the second bundle verifies rollback of all
three decision tables. Original inventory bytes remain unchanged. The original bundle
writer shares the same decision SQL; its existing transaction tests remain required.
The new file also retains exact reviewed inputs, dates and inventory binding before
exclusive publication. This is a first-assessment workflow, not versioned reassessment,
reviewer attestation, deployed discovery or automatic remediation.


`inventory_assessment_verify` reproduces the complete first assessment against retained
inputs and an externally supplied original export. A bounded private closed-file snapshot
keeps the separate read helpers on the same input bytes. Original input digests and
inventory binding are checked, all decision counts and linked records must match the
replayed current model, and foreign-key violations fail. Changed risk/priority, ownership,
extra decisions or incompatible model output prevent a success summary. The supplied file
is unchanged. This is local reproducibility, not authenticity or a migration between
model versions. A versioned model contract remains a prerequisite for durable reassessment.


## First-assessment model contract

`database.assessment_model` records an ID, integer version and exact implementation
source digests for nine fixed modules. New retention adds one append-only model row.
Verification compares canonical bytes and digest with the current contract before
replaying decisions. Unknown or changed bindings fail; an absent legacy binding has
an explicit unversioned status unless `--require-model-binding` requires one. This
protects against silently claiming the current implementation is a retained historical
model, but does not freeze a runtime, authenticate code or implement versioned replay.
The manifest lists its source paths, and source-checkout files must be available.
