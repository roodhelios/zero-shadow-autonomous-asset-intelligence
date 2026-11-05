# Back up and restore a closed EC2 review history

The osquery assessment copy command does not understand EC2 review histories.
This separate standard-library workflow retains both ordered review and normalized
decision tables, reproducing every revision before publishing an exact copy.
It uses local files only and does not connect to AWS or an external backup service.

## Run the temporary exercise

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -S -m engine.demo_ec2_history_backup
```

Expected summary:

```json
{"status": "ec2_history_backup_exercise_passed", "review_count": 2,
 "decision_count": 2, "original_history_removed": true,
 "exact_bytes_restored": true, "negative_cases_rejected": 3}
```

The exercise creates two synthetic reviews with different supplied severities,
removes the discovery database and individual receipts, backs up their history,
then removes that history before restoring exact bytes. A wrong head, wrong raw
database digest and changed export must each fail without publishing an output.
Native SQLite and the current model run for real. Python sockets are forbidden.
The original export is held in memory; this is not an export archive or a live
collection. Fixed October dates are fixture claims. Temporary files are removed.

## Copy your retained history

First close the history and select its independently retained trusted head. Use
owned mode-0700 source and destination directories with trusted ancestors. The
database must be owned, mode 0600, regular, single-link, and at most 16 MiB, with no
`-wal`, `-shm` or `-journal` sidecars. The original export and matching current model
checkout remain required for replay.

```bash
python -m database.ec2_history_backup backup /private/reviews/history.sqlite \
  --output /private/backup/history.sqlite --export /private/evidence/ec2-export.json \
  --expected-head INDEPENDENTLY_RETAINED_HISTORY_HEAD
```

Paths and pin labels are placeholders. Expect `ec2_history_backup_stored` with
`database_sha256`, `byte_count`, `head_sha256`, `review_count`, `decision_count`,
`original_export_checked: true` and `expected_head_checked: true`.
Retain the returned raw database digest and selected history head independently
of the backup bytes. A candidate file and its own adjacent receipt are not an
independent trust source. Do not derive the expected current head from an untrusted
candidate solely to make it pass.

```bash
python -m database.ec2_history_backup restore /private/backup/history.sqlite \
  --output /private/restored/history.sqlite --export /private/evidence/ec2-export.json \
  --expected-head INDEPENDENTLY_RETAINED_HISTORY_HEAD \
  --expected-sha256 INDEPENDENTLY_RETAINED_DATABASE_SHA256
```

Expect `ec2_history_restored` and the same aggregate counts and digests. Exit 0
means all checks and publication completed. Exit 2 produces a fixed diagnostic
without exposing private paths, inputs or decisions.

## Validation and publication boundaries

The command captures bounded closed bytes, checks the raw digest for restoration,
and verifies a private copy against the selected head, original export and exact
current model. The existing history verifier checks every retained review, hash
link, normalized decision, table contract and integrity result. Only the captured
verified bytes are published, even if another process later changes the source.
It never rereads the source path to populate the destination.

Publication stages a mode-0600 file on the destination filesystem, syncs it and
links it without replacement. Existing destinations, including symlinks, are
preserved. A failed ordinary publication removes staging files. Neither input
database nor the original export is modified by this workflow.

This requires closed cooperative writers. It is not a backup of active SQLite
writers, encryption, automatic retention, cloud storage, historical code dispatch,
authenticated reviewer identity, accepted ownership or remediation. File sync does
not sync the parent directory or establish power-loss durability. Abrupt process
exit may leave a staging file. A same-user editor can replace files or pins. A stale
database and its own stale head/digest can match; latest-head enrollment and fresh
pin distribution remain external. Preserve the export separately for this exact-copy
workflow. The
[separate history archive](ec2-history-archive.md) retains the export and replay
source bytes together; it does not add historical dispatch or pin freshness.

```bash
python -m unittest discover -s tests -p test_ec2_history_backup.py -v
```

The implementation and synthetic fixtures were prepared with assistant support.
