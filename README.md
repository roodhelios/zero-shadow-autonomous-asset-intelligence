# Zero Shadow

Local asset intelligence that explains why a finding matters, who should review it,
and which evidence supports its remediation priority.

Import saved osquery or EC2 JSON, correlate scoped observations, explain risk and
ownership decisions, then retain and reproduce the evidence in SQLite. All examples
use synthetic data. The project does not scan networks, enumerate cloud accounts,
send tickets or perform remediation.

## Try the complete retained-inventory exercise

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -m engine demo inventory
```

No package installation, account or credential is needed. The exercise imports the
bundled [osquery export](examples/osquery-system-info-expanded.json), assesses one
supplied finding, removes the discovery database, and reproduces the retained
assessment against the original export. It also rejects changed export bytes.
Native SQLite and temporary private files are used; generated files are discarded.

Selected fields from the JSON output:

```json
{
  "status": "inventory_exercise_passed",
  "asset_count": 2,
  "finding_count": 1,
  "assessment_status": "assessment_reproduced",
  "model_status": "bound_current_model",
  "changed_export": "rejected"
}
```

Dates are fixed fixture dates. Reproduction checks consistency under the current
model. It does not establish live discovery, source truth, accepted ownership or
completed remediation. A nonzero exit means the exercise did not complete.

## Choose a local workflow

```bash
python -m engine list
python -m engine list --format json
python -m engine demo ec2-compare
```

The catalog lists all 15 bundled temporary exercises and their dependencies. Help
and listing do not load optional signing packages. Existing `python -m engine.demo_*`
commands still work. `demo` accepts only the listed names and no external input paths.

| Goal | Temporary exercise | Retained-file instructions |
| --- | --- | --- |
| Retain and reproduce an osquery assessment | `demo inventory` | [Inventory and assessment commands](docs/local-workflows.md#retain-a-reviewed-inventory-assessment) |
| Restore an assessment with its replay inputs | `demo assessment-archive` | [Assessment archive](docs/assessment-archive.md) |
| Compare saved EC2 batches | `demo ec2-compare` | [Discovery comparison](docs/ec2-discovery-comparison.md) |
| Review expected and missing EC2 batches | `demo ec2-checkpoint` | [Sequence checkpoint](docs/ec2-sequence-checkpoint.md) |
| Retain, restore and select ordered EC2 reviews | `demo ec2-history-archive` | [History archive](docs/ec2-history-archive.md), [enrollment](docs/ec2-history-enrollment.md) |
| Verify separately enrolled operator consent | `demo ec2-operator` | [Operator acceptance](docs/ec2-operator-acceptance.md) |

Signing exercises require the optional `requirements-review.txt` dependencies.
Install those in a virtual environment only if choosing a signing workflow:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-review.txt
python -m engine demo ec2-operator
```

Use the [local workflow reference](docs/local-workflows.md) for all existing detailed
commands, expected results, retained output paths and trust boundaries. Keep real
retained evidence and private keys outside Git. Closed database copies require
cooperative writers and the private POSIX filesystem conditions documented there.

## Implementation status and navigation

| Area | Current behavior |
| --- | --- |
| Discovery and correlation | Saved local osquery/EC2 imports and scoped fixtures. Strong identifiers merge; IP alone does not. |
| Decisions | Explainable scoring, tag-based ownership, P0 to P3 planning and explicit unassigned outcomes. Supplied claims are not independently verified. |
| Evidence | Local SQLite retention, same-model replay, comparison, closed-file backup/archive and pinned checkpoints. Optional enrolled-key approvals and operator consent. |
| Unfinished | Live discovery, historical model dispatch, live database backup, deployed Airflow persistence and independently distributed latest checkpoints. Some connector/infrastructure files remain placeholders. |

Start with the [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[risk and remediation policy](docs/remediation-model.md), [ownership queues](docs/ownership-queues.md)
and [design decisions](docs/design-decisions.md). The
[SQLite deployment exercise](docs/sqlite-deployment.md) checks local process locking
and rollback; it does not validate a network filesystem or power-loss durability.

Run the standard-library test suite with `python -m unittest discover -s tests`.
Signing tests require the optional dependencies for full coverage. This is an
ongoing implementation with assistant support.
