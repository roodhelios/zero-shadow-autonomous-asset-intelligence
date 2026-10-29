# Check local SQLite persistence before retaining evidence

The existing storage probe checks exclusive creation, synchronization and no-replace
publication. It does not open SQLite or test its process locks. The separate SQLite
probe exercises those behaviors on the actual directory you select, with temporary
synthetic data and the committed asset schema. Neither command opens existing evidence.

Run from the repository root on POSIX with Python 3.11 or newer:

```bash
probe_dir=$(mktemp -d)
python -m database.storage_probe "$probe_dir" --require-private
python -m database.sqlite_probe "$probe_dir"
rmdir "$probe_dir"
```

For a proposed local evidence volume, create a private directory there first and pass
that directory instead. It must belong to the current UID, exclude group and other
permissions, and have trusted ancestor directories. A final directory symlink is
rejected. Do not run this on third-party storage without authorization. The command
writes only a newly created random child directory and removes it on ordinary success
or failure. Existing files are not inspected or replaced. Abrupt termination of the
parent or loss of the host can leave its temporary child for manual inspection.

Representative SQLite result (the runtime version varies):

```json
{
  "status": "sqlite_probe_passed",
  "journal_mode": "delete",
  "synchronous": "full",
  "competing_writer": "busy",
  "hot_journal_observed": true,
  "uncommitted_changes": "rolled_back",
  "integrity_check": "ok",
  "post_recovery_commit": "reopened",
  "temporary_files": "removed"
}
```

The full result also includes schema version, SQLite runtime version and a limitation
statement. It omits paths, UIDs, hostnames and database rows. Failure returns exit code
2 with a fixed error and no success JSON. Child processes each have a ten-second
timeout; a slow or restricted runtime fails rather than silently skipping a checkpoint.

## What is exercised

1. Initialize a private 0600 database with `database/schema.sql` and commit one synthetic
   asset. Require DELETE journaling, FULL synchronization and enabled foreign keys.
2. Hold `BEGIN IMMEDIATE` in the parent. A fresh Python process must receive SQLite's
   `SQLITE_BUSY` result when it attempts another immediate write transaction. Release
   the parent's transaction explicitly.
3. In another process, begin a transaction, change the committed asset and insert a
   256 KiB synthetic JSON value with a small page cache. Exit with `os._exit` before
   commit, rollback or connection cleanup. Require a rollback journal with its native
   header, so an ordinary Python exception rollback cannot stand in for this step.
4. Reopen SQLite, require the original asset and no uncommitted insert, then run
   `integrity_check` and `foreign_key_check`. A regression test also establishes that
   database pages changed before recovery and returned to their original bytes.
5. Commit an additional asset in a new process and verify it through a new connection.
   Remove the disposable directory before emitting success.

SQLite documents [immediate transactions and SQLITE_BUSY](https://www.sqlite.org/lang_transaction.html),
[hot-journal recovery](https://www.sqlite.org/atomiccommit.html), and why
[journals must stay with their database](https://www.sqlite.org/howtocorrupt.html).
Do not delete a real evidence database's journal to clear a lock. This probe removes
only its own disposable files after its connections and child processes have ended.

## Interpretation and next boundary

Success is evidence of this small local process-exit exercise on this runtime and
directory at this moment. It is not a filesystem certification, performance benchmark,
power-loss test, concurrent multi-host test, backup/restore validation, or a promise
that the host honors every synchronization request. WAL mode, network filesystems,
Airflow deployment, full disks, device failure and PostgreSQL are not validated here.
The check does not authenticate asset sources, make SQLite append-only against a
database owner, or change the existing inventory/assessment contracts.

Run the [retained inventory exercise](../README.md#try-the-complete-retained-inventory-exercise)
after storage checks to test the application path. Preserve frozen model source files
with retained assessments. Next work should exercise a recoverable backup/restore
workflow for retained evidence on a separately selected local directory before adding
an authorized external discovery connector.
