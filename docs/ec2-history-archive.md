# Restore an EC2 review history without a separate original export

The [history backup](ec2-history-backup.md) retains exact database bytes but still
needs the original export for replay. This archive retains both inputs together
with an allowlisted source snapshot. Restoration requires a trusted matching
checkout and independently retained archive and history-head digests.

## Run the temporary walkthrough

On POSIX, from the repository root with Python 3.11 or newer:

```bash
python -S -m engine.demo_ec2_history_archive
```

Expected output includes:

```json
{"status": "ec2_history_archive_exercise_passed", "review_count": 2,
 "decision_count": 2, "original_history_removed": true,
 "original_export_removed": true, "exact_bytes_restored": true,
 "negative_cases_rejected": 3}
```

The exercise creates original synthetic EC2 evidence and two review revisions.
It archives the closed history and original export, removes both originals,
verifies the archive, restores exact bytes, then reproduces the restored history
using the restored export. Wrong archive/head pins and reuse of an existing output
directory are rejected. Native SQLite and current-model replay run for real with
socket creation forbidden. All files are temporary. No AWS endpoint, credentials,
backup service, cloud resources or external storage are used.

## Create and retain an archive

Close cooperative SQLite writers first. Use owned mode-0700 input and output
directories with trusted ancestors. The history must be a regular owned mode-0600
single-link file with no `-wal`, `-shm` or `-journal` sidecars.

```bash
python -m database.ec2_history_archive create /private/reviews/history.sqlite \
  --export /private/evidence/ec2-export.json \
  --expected-head INDEPENDENT_HISTORY_HEAD \
  --output /private/archives/review-history.json
```

Paths and pin labels are placeholders. Expect `ec2_history_archive_stored`,
`archive_sha256`, `database_sha256`, `head_sha256`, review/decision counts,
`original_export_checked: true` and `expected_head_checked: true`.
Keep the archive digest and selected current history head independently of the
candidate archive. A candidate and its adjacent receipt do not establish trust.

| Retained entry | Checked meaning |
| --- | --- |
| `history` | Exact closed SQLite bytes, every ordered review and normalized decision fully reproduced |
| `export` | Original export bytes required by every retained review |
| `sources` | Explicit allowlist of replay source bytes, compared with the trusted checkout |
| `model` and `head_sha256` | Exact current EC2 model contract and separately selected history head |

The standard-library format is canonical ASCII JSON with bounded base64 entries,
byte counts and SHA-256 digests. Bounds are 16 MiB for the history, 4 MiB for the
original export, 1 MiB total for retained source and 32 MiB for the encoded archive.
No arbitrary paths or executable archive loaders are accepted. Archived source
stays data inside JSON and is never executed or extracted to a code path.

## Verify and restore without the originals

```bash
python -m database.ec2_history_archive verify /private/archives/review-history.json \
  --expected-sha256 INDEPENDENT_ARCHIVE_SHA256 --expected-head INDEPENDENT_HISTORY_HEAD

python -m database.ec2_history_archive restore /private/archives/review-history.json \
  --expected-sha256 INDEPENDENT_ARCHIVE_SHA256 --expected-head INDEPENDENT_HISTORY_HEAD \
  --output /private/restored/review-history
```

Expect `ec2_history_archive_verified` or `ec2_history_archive_restored` with matching
digests and counts. Exit 0 means the requested operation completed. Exit 2 emits a
fixed diagnostic without private paths, source payloads or decision values.

Pin syntax and raw archive digest are checked before JSON parsing. Duplicate fields,
noncanonical representations, unknown entries, changed source/model, malformed
base64 and mismatched per-entry counts/digests fail. Even a repacked archive with
a newly matching raw digest must reproduce the complete history against its export
and independent head. A matching file digest alone is insufficient.

Restoration creates a new mode-0700 directory containing mode-0600 `history.sqlite`
and `export.json`. `RESTORE.json` is written last as the completion record. Existing
directories and files are preserved. Ordinary restoration failure removes only the
newly reserved directory. Verified captured bytes feed publication; the mutable
archive path is not reread for output. Inputs are not modified.

## Limits and next work

This is portable retention for a matching trusted checkout, not historical code
dispatch, encryption, live database backup, a deployed Airflow workflow or cloud
storage. Source matching is intentionally strict. A changed source checkout blocks
restoration; inspect and use a separately trusted matching checkout instead of
executing code supplied by an untrusted archive. The Python runtime, operating
system and optional packages are not archived. This path requires only Python's
standard library.

The archive and completion receipt are unsigned. They do not authenticate source,
reviewer or accepted ownership, prove remediation, enroll a journal or establish
the latest head. A stale archive and its own stale selected pins can match. Pin
distribution and freshness remain external. Same-user or privileged writers can
replace local evidence. Files contain private infrastructure and review details;
keep them outside Git and apply a separate retention policy.

Publication syncs individual files without replacement. It does not atomically
publish a whole directory, sync parent directories or guarantee power-loss
durability. Abrupt exit can leave partial directories or staging files; a missing
completion record means the restore did not finish. No active-writer lock is held.

Next: independent history-head enrollment and fresh checkpoint distribution before
treating a restored history as the currently accepted revision.

```bash
python -S -m unittest discover -s tests -p test_ec2_history_archive.py -v
```

Implementation and original synthetic validation were prepared with assistant support.
