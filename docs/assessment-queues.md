# Dated queues from a retained assessment

A retained first osquery assessment already stores its reviewed findings and
ownership directory. Reuse those exact inputs to review due dates without finding
the original discovery database or rebuilding separate input files. The command
first reproduces the complete assessment against the original export and requires
its retained current-model binding. Only then does it replan for the supplied date.

## Try the temporary fixture

```bash
python -m engine demo inventory
```

On POSIX with Python 3.11+, expect `inventory_exercise_passed`,
`dated_queue_assigned_items: 1` and `dated_queue_changed_items: 1`. Native SQLite and
synthetic data are used. The discovery database has been removed before this check;
the retained assessment remains unchanged. Dates are fixed fixture dates, not the
current clock. The finding is P0 at both dates but becomes overdue in the later
review. A changed item therefore does not necessarily mean a changed priority.

## Export a private dated queue

First [retain a reviewed assessment](local-workflows.md#retain-a-reviewed-inventory-assessment).
Independently retain the SHA-256 of that closed assessment database when accepting
it. Keep that digest through a trusted channel. Do not derive a replacement pin
from an untrusted incoming database just to make verification pass.

```bash
python -m database.inventory_assessment_queue /private/review/assessed.sqlite \
  --export /private/review/original-osquery.json \
  --expected-database-sha256 TRUSTED_ASSESSMENT_SHA256 \
  --as-of 2026-11-15 --output /private/review/new-queues.json
```

Use a date on or after the retained `as_of` date. The required output path must be
new and under an existing trusted private parent. The file is mode 0600 and existing
destinations are preserved. Stdout reports `assessment_queue_exported`, the review
date, assigned/unassigned counts, `changed_item_count` and the exact output digest.
It excludes finding IDs, descriptions, team names and local paths. Failures return
2 with no success JSON. Review the private file outside Git.

The output's `queue_document` contains the existing inventory binding, team queues,
unassigned items, risk/priority explanations and date-only comparison. A changed
item has a different overdue status or priority. `assessment_verification` records
the complete current-model reproduction that preceded planning. Assets with no
supplied findings remain explicitly unassessed. No assessment rows are appended
or updated, and no new findings, ownership rules or technical risk facts are inferred.

## Trust and filesystem limits

The supplied database is captured once as a bounded private regular-file snapshot.
Its independent digest is checked before SQLite replay. Both full verification and
queue planning read that same private snapshot, so changing the original path after
capture cannot substitute another assessment for planning. The database must be
closed without active journal/WAL sidecars; use cooperative writers and trusted
ancestors. This is not a live database backup protocol.

Original export bytes must match exactly. A missing/changed model binding, changed
retained decisions or incompatible current model blocks export. This does not add
historical model dispatch, versioned reassessment, source authentication, accepted
ownership, ticket delivery or remediation. A pin establishes byte equality only;
it does not establish that the retained caller claims are true. The private output
is unsigned and contains sensitive finding/queue data.

Validation uses deterministic native SQLite fixtures, changed decisions and exports,
pin/date/model failures, read-only originals, capture-time path replacement and
exclusive private CLI output. Prepared with assistant support.
