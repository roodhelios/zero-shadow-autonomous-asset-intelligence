"""Exercise SQLite process locking and rollback in disposable local storage."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRASH_EXIT = 73
BUSY_EXIT = 42
JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
STAMP = "2026-10-29T00:00:00Z"


class SQLiteProbeError(ValueError):
    """The local persistence exercise did not establish every required result."""


def _connect(path):
    connection = sqlite3.connect(path, timeout=0)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        if (connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1
                or connection.execute("PRAGMA synchronous").fetchone()[0] != 2):
            raise SQLiteProbeError("required SQLite settings unavailable")
    except Exception:
        connection.close()
        raise
    return connection


def _insert(connection, identity, kinds="[]"):
    connection.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?)",
                       (identity, kinds, "fixture.example.test", STAMP, STAMP))


def _worker(mode, path):
    """Internal subprocess entry point. Only the parent creates the database."""
    with closing(_connect(path)) as connection:
        if mode == "contend":
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                if getattr(exc, "sqlite_errorcode", -1) & 255 == sqlite3.SQLITE_BUSY:
                    return BUSY_EXIT
                raise
            connection.rollback()
            return 1
        if mode == "crash":
            # Spill dirty pages so recovery must use a real rollback journal.
            connection.execute("PRAGMA cache_size = 4")
            connection.execute("PRAGMA cache_spill = ON")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE assets SET primary_hostname='uncommitted.example.test'")
            _insert(connection, "uncommitted", json.dumps(["x" * (256 * 1024)]))
            # Deliberately skip Python cleanup, SQLite rollback and close.
            os._exit(CRASH_EXIT)
        if mode == "commit":
            with connection:
                _insert(connection, "after-recovery")
            return 0
    return 1


def _run_worker(mode, path, expected):
    command = [sys.executable, "-c",
               "import sys; from database.sqlite_probe import _worker; "
               "sys.exit(_worker(sys.argv[1], sys.argv[2]))", mode, str(path)]
    result = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=10, check=False)
    if result.returncode != expected or result.stdout or result.stderr:
        raise SQLiteProbeError("SQLite subprocess did not complete its expected checkpoint")


def probe_sqlite(directory: Path):
    """Use a new private child directory, never an existing evidence database."""
    try:
        if os.name != "posix":
            raise SQLiteProbeError("SQLite deployment probe requires POSIX")
        metadata = directory.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise SQLiteProbeError("probe directory must be owned, private and not a symlink")
        target = directory.resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix=".zero-shadow-sqlite-probe-", dir=target) as temp:
            database = Path(temp) / "probe.sqlite"
            descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            with closing(_connect(database)) as connection:
                connection.executescript((ROOT / "database/schema.sql").read_text(encoding="utf-8"))
                with connection:
                    _insert(connection, "committed")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    _run_worker("contend", database, BUSY_EXIT)
                finally:
                    connection.rollback()
            _run_worker("crash", database, CRASH_EXIT)
            journal = Path(str(database) + "-journal")
            with journal.open("rb") as source:
                if source.read(8) != JOURNAL_MAGIC:
                    raise SQLiteProbeError("crash did not leave a recoverable journal header")
            with closing(_connect(database)) as connection:
                rows = connection.execute("SELECT asset_id, primary_hostname FROM assets").fetchall()
                if rows != [("committed", "fixture.example.test")]:
                    raise SQLiteProbeError("uncommitted changes survived process exit")
                if (connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
                        or connection.execute("PRAGMA foreign_key_check").fetchall()):
                    raise SQLiteProbeError("recovered SQLite integrity check failed")
            _run_worker("commit", database, 0)
            with closing(_connect(database)) as connection:
                identities = connection.execute("SELECT asset_id FROM assets ORDER BY asset_id").fetchall()
                if identities != [("after-recovery",), ("committed",)]:
                    raise SQLiteProbeError("post-recovery commit did not survive reopening")
        return {"schema_version": 1, "status": "sqlite_probe_passed",
                "sqlite_version": sqlite3.sqlite_version, "journal_mode": "delete",
                "synchronous": "full", "competing_writer": "busy",
                "hot_journal_observed": True, "uncommitted_changes": "rolled_back",
                "integrity_check": "ok", "post_recovery_commit": "reopened",
                "temporary_files": "removed",
                "interpretation": "Local process-exit exercise only. No power-loss, remote filesystem or deployment guarantee."}
    except SQLiteProbeError:
        raise
    except (OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        raise SQLiteProbeError("SQLite deployment probe failed") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path,
                        help="existing owned private local directory with trusted ancestors")
    args = parser.parse_args(argv)
    try:
        result = probe_sqlite(args.directory)
    except SQLiteProbeError:
        print("error: SQLite deployment probe failed; check private local storage and runtime", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
