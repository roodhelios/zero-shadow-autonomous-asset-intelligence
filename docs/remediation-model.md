# Remediation Priority Model

The planner keeps technical risk, ownership, and schedule evidence separate so a
reviewer can see why an item received its priority.

## Base windows

| Risk band | Base priority | Target window |
| --- | --- | --- |
| Critical | P0 | 1 day |
| High | P1 | 7 days |
| Moderate | P2 | 30 days |
| Low | P3 | 90 days |

A missing owner raises urgency by one level. An overdue due date raises it by one more
level. Priority is capped at P0. A requested due date may shorten the target, but it
cannot extend the risk-based window.

These are lab policy values, not a claim about an employer's service-level agreement.
The caller supplies both `opened_on` and `as_of`, which keeps tests and historical
reviews deterministic.

## Evidence preserved

Every plan includes the original risk assessment, all four risk factors, and separate
priority factors for risk band, ownership, and due-date state. The planner never changes
the technical risk score. A reviewer can adjust the policy later without losing the
source explanation.

The generated action list begins with ownership or overdue escalation when applicable.
It always requires validation of finding evidence before an asset is changed.

## Retain a complete local plan

From the repository root on POSIX with Python 3.11+, no package, account or service
is needed. Choose a new output path under an existing trusted private directory:

```bash
review_dir=$(mktemp -d)
python -m engine.remediation_cli examples/remediation-input.jsonl \
  --as-of 2026-09-15 --output "$review_dir/plans.jsonl"
python - "$review_dir/plans.jsonl" <<'PY'
import json, sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
print(json.dumps({"plan_count": len(rows), "priority": rows[0]["priority"],
                  "due_date": rows[0]["due_date"], "overdue": rows[0]["overdue"]}))
PY
```

Expected: `plan_count: 1`, `priority: P2`, `due_date: 2026-10-15`, `overdue: false`.
Dates and ownership are synthetic supplied claims, not a live finding or accepted
assignment. The file retains the complete risk and priority explanations. Keep
private inputs and outputs outside Git, and remove the temporary directory when done.

The CLI now validates the whole input into a private temporary spool before writing
stdout or publishing a file. A malformed later row returns exit 2 without emitting
earlier plans, creating a result or truncating a prior review. File output requires
a new name, is mode 0600 on POSIX, and is published by linking a complete temporary
file at that name. Repeating a command with the same output, including the input's
own path, an existing hard link or symlink, returns 2 and preserves those bytes.
Use a separate new name for each review. This intentionally replaces the old
overwrite behavior; there is no force option. Exit 0 means the complete review was
written, including an empty result if the input contains only blank lines.

Input `-` and output `-` still mean stdin/stdout. Output JSON and priority semantics
are unchanged. The library's `plan_jsonl` remains a streaming API and can emit rows
before a later error; callers requiring complete-input validation should use the
CLI or stage their own destination. A downstream stdout failure can still leave a
partial transport write after validation. This is not a multi-file transaction,
crash-durability promise, hostile-input sandbox or authenticated evidence format.

Trust source files, output ancestors and cooperative local writers. Private temp
storage needs disk space; the command is not an input-size or filesystem quota.
Existing outputs remain safe if validation or publication fails. No scoring policy,
source enrollment, inventory database, Airflow action or remediation is changed.
Prepared with assistant support and synthetic tests. Run:
`python -m unittest tests.test_remediation_cli tests.test_remediation tests.test_risk`.
Next: connect reviewed plans to the retained inventory workflow without losing
finding lineage or treating proposed actions as completed work.
