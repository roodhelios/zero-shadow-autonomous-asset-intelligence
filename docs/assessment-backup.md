# Retain and restore a model-bound assessment backup

The backup workflow covers closed osquery first-assessment databases created by
`database.inventory_assessment_cli`. It copies exact SQLite bytes only after an
integrity check and full decision reproduction against the original osquery export,
with current model binding required. It is an offline copy workflow, not SQLite's
online backup API, and does not recover an active writer or its journal.

## Run the complete temporary exercise

From the repository root on POSIX with Python 3.11 or newer:

```bash
python -m engine.demo_assessment_backup
```

Expect `assessment_backup_exercise_passed`, two assets, one finding,
`assessment_reproduced`, `bound_current_model`, `original_databases_removed: true`,
`exact_bytes_restored: true`, `backup_unchanged: true` and three rejected negative
cases. The exercise retains a synthetic assessment, copies it into a separate private
directory, removes both original databases, then restores and reproduces the backup.
A wrong independent digest, changed export and modified backup bytes publish no
restored artifact. All generated files are temporary. Fixed October 23 observation
and assessment dates are fixture claims, not measurements taken during the exercise.

## Back up your retained assessment

First complete the [assessment retention quickstart](../README.md#retain-a-reviewed-inventory-assessment).
Move its closed output into an owned 0700 source directory outside Git, preserving
0600 file permissions. Use new, separately selected private backup and restore
directories. The following placeholders name your own local paths:

```bash
python -m database.assessment_backup backup /private/source/assessed.sqlite \
  --export examples/osquery-system-info-expanded.json \
  --output /private/backups/assessment.sqlite
```

Success reports `assessment_backup_stored`, `database_sha256`, `byte_count`, asset
and finding counts, `assessment_reproduced` and `bound_current_model`. Keep that exact
lowercase SHA-256 digest independently of the backup, along with the original export
and relevant source checkout. The summary contains no paths, hostnames, asset IDs,
findings or ownership details. The database itself retains all original bytes and
may contain sensitive evidence, free pages or other metadata. It is not redacted,
encrypted or securely erased by this workflow. Keep it private and outside Git.

## Restore into a new file

Use the digest you retained when backing up, not a newly calculated digest of the
backup being restored:

```bash
python -m database.assessment_backup restore /private/backups/assessment.sqlite \
  --export examples/osquery-system-info-expanded.json \
  --expected-sha256 YOUR_INDEPENDENTLY_RETAINED_SHA256 \
  --output /private/recovered/assessment.sqlite
```

Replace the digest placeholder with the complete 64-character lowercase value.
Expect `assessment_restored`, the same file digest, two assets and one finding for
the bundled fixture. Restore first checks exact backup bytes against the required
digest, then checks integrity and reproduces all supported assessment decisions.
It does not need the original assessment or discovery database. It still requires
the original export bytes and matching model code. Both backup and restore validate
a private snapshot and publish those same checked bytes, without rescoring or
rewriting the source database. Originals and backups are never removed automatically.

## Storage contract and failure behavior

- Source and destination parent directories must already exist, be owned by the
  current UID, have mode 0700 and not be final symlinks. Ancestor directories and
  runtime must be trusted. The command does not create an arbitrary directory tree.
- The source must be a nonempty owned 0600 regular file, with one hard link, at most
  16 MiB. Final symlinks, FIFOs and any `-wal`, `-journal` or `-shm` sidecar, including
  a dangling sidecar symlink, are rejected. Close and checkpoint all writers first.
  Do not delete sidecars to make the check pass.
- Source size and metadata changes during reading reject the copy. These checks
  are not a lock or an atomic filesystem snapshot. A concurrently replaced path or
  privileged writer is outside the supported closed-file contract.
- Only a fully reproduced artifact is published. Staging occurs in the destination
  directory with mode 0600, file synchronization and a no-replace hard link. Source
  and destination can be on different filesystems because publication stays local
  to the destination. This does not certify either filesystem or remote storage.
- Existing destination files, symlinks or a publication race never get overwritten.
  Ordinary errors clean staging files and produce exit 2 with a fixed error and no
  success JSON. A failure after publication can leave the complete output file;
  inspect it before retrying with a new path. Parent termination can leave staging.
  No directory power-loss durability or atomic multi-file archive is claimed.

The [SQLite copy guidance](https://www.sqlite.org/howtocorrupt.html) explains the
hazard of copying a database while it is changing or losing its journal. SQLite also
offers a separate [online backup API](https://www.sqlite.org/backup.html). That API,
live WAL snapshots and multi-process backup coordination are not implemented here.

## Trust and remaining work

The receipt and digest are unsigned metadata. A trusted independent digest detects
different bytes; a digest replaced alongside the backup does not authenticate either.
Successful replay establishes current-model consistency, not source truth, reviewer
identity, historic validation time, latest-version selection or remediation. It does
not validate EC2 assessment/history backup, legacy unbound assessments, cloud backup,
encryption, retention policy, device failure or secure deletion. The three directories
in the exercise are on one local filesystem, not separate failure domains.

For one private file retaining the original export and an allowlisted model/runtime
source snapshot, use the [assessment archive](assessment-archive.md). Its native exercise
restores after original database/export removal. Archived code is never executed and
restore still requires matching trusted code; historical model dispatch remains unfinished.
