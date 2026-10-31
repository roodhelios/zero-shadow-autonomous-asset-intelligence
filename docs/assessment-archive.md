# Portable retention for a closed assessment

A database backup alone still needs the original osquery export and matching model
code. The version-1 archive keeps these together in one private, non-executable JSON
file. It supports the same closed, model-bound osquery first assessments as the
[backup workflow](assessment-backup.md). EC2 receipts and histories are not supported.

## Run the complete local exercise

From the repository root on POSIX, with Python 3.11 or newer and the standard library:

```bash
python -m engine.demo_assessment_archive
```

Expect `assessment_archive_exercise_passed`, two assets, one finding,
`bound_current_model`, `original_database_and_export_removed: true`,
`exact_database_bytes_restored: true`, `archive_unchanged: true`,
`archived_code_executed: false` and two rejected pin cases. The exercise uses temporary
native SQLite and fixed synthetic October 23 dates. Nothing is downloaded or deployed.

## Create, verify and restore

Prepare a closed assessment using the existing retention guide. Source and output
parents must be owned mode-0700 directories outside Git, with trusted ancestors.
The following paths and digest are placeholders for your own private local files:

```bash
python -m database.assessment_archive create /private/original/assessment.sqlite \
  --export /private/original/export.json --output /private/archives/assessment.json
python -m database.assessment_archive verify /private/archives/assessment.json \
  --expected-sha256 YOUR_INDEPENDENT_ARCHIVE_SHA256
python -m database.assessment_archive restore /private/archives/assessment.json \
  --expected-sha256 YOUR_INDEPENDENT_ARCHIVE_SHA256 \
  --output /private/restored/assessment.sqlite
```

Creation performs SQLite integrity checking and full model-bound decision reproduction
before publishing. Keep the returned `archive_sha256` independently of the archive.
Both verify and restore require that original 64-character lowercase pin. Do not
replace it with a fresh digest supplied by an untrusted archive sender.

Restore needs neither original file: it uses the archived original export for full
reproduction, then publishes the exact checked database bytes into a new private file.
Archive and originals are unchanged. Receipts report counts, digests and model status,
without hostnames, paths, asset identifiers, findings or ownership details. Exit 0
means a checked operation completed, not source authenticity or accepted ownership.
Errors exit 2 with fixed text and no success JSON. No arbitrary output is overwritten.

## Archive contract

The file contains exactly a version, format, model contract, static runtime requirements
and a fixed entry map. Each entry has canonical base64 bytes, exact byte count and
SHA-256. Entries are the SQLite assessment, original export and an explicit allowlist
of source/schema files. This includes the nine frozen model files and the importer,
reader, verifier, storage and package files needed by this workflow. Optional cloud,
Airflow and unrelated application modules are not collected. Environment files,
credentials, arbitrary paths and working-tree contents are not scanned into an archive.

The source snapshot is review/retention data. No archive command extracts, imports,
executes or dispatches to its code. The running trusted checkout must match every
archived source file and current model contract before database replay. Unknown,
extra, missing or changed entries, changed model versions, duplicate JSON members,
incorrect base64/count/digests and invalid numeric types reject the archive, even when
someone recalculates its outer digest. A changed decision must still reproduce.

Retain a matching trusted checkout. Tests copy the allowlisted files from the trusted
checkout into a fresh directory and restore in a `python -S` subprocess with an empty
`PYTHONPATH`. That establishes the local source closure without third-party packages;
it does not authorize executing code extracted from an untrusted archive. The archive
records a standard-library/POSIX requirement, not a hermetic interpreter or operating
system image. Future edits to a retained runtime source, including this archive tool,
require the corresponding supported checkout. Historical dispatch is not implemented.

## Storage and privacy limits

The archive is plaintext and base64 is not encryption. It retains the entire database,
including possible free-page content, original export and source snapshot. Keep it
private and outside Git. An independent digest detects changed bytes, not a collector's
identity, truthful source claims, reviewer approval or the latest retained revision.

Archive reads require owned single-link mode-0600 regular files in mode-0700 parents.
Final symlinks, FIFOs, broad permissions and changed read metadata are rejected. The
database additionally rejects WAL/journal/SHM sidecars; close/checkpoint writers first,
without deleting sidecars to bypass the check. These are closed-file checks, not locks.

Bounds are 16 MiB database, 4 MiB original export, 1 MiB aggregate allowlisted source
bytes and 32 MiB complete archive. Complete output is synchronized and published through
a no-replace link in the destination directory. Ordinary failures clean staging. A
failure after publication may leave a complete output; process death can leave staging.
No parent-directory power-loss durability, encryption, remote storage, secure deletion,
retention policy or independent failure-domain test is claimed.

```bash
python -m unittest discover -s tests -p 'test_assessment_archive.py' -v
python -m unittest discover -s tests -v
```

Next: specify how operators retain and select a trusted supported checkout when code
changes, with explicit version support before claiming cross-version archive replay.
