"""Native subprocess evidence for the disposable SQLite deployment exercise."""

import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from database.sqlite_probe import (
    BUSY_EXIT, CRASH_EXIT, JOURNAL_MAGIC, ROOT, SQLiteProbeError,
    _connect, _insert, _run_worker, main, probe_sqlite,
)


@unittest.skipUnless(os.name == "posix", "private storage contract requires POSIX")
class SQLiteProbeTests(unittest.TestCase):
    def test_native_probe_repeats_without_touching_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "evidence.sqlite"
            sentinel.write_bytes(b"existing input is never opened as SQLite")
            before = sentinel.stat()
            for _ in range(2):
                result = probe_sqlite(root)
                self.assertEqual(result["status"], "sqlite_probe_passed")
                self.assertEqual(result["competing_writer"], "busy")
                self.assertTrue(result["hot_journal_observed"])
                self.assertEqual(result["uncommitted_changes"], "rolled_back")
                self.assertEqual(result["post_recovery_commit"], "reopened")
                self.assertEqual(list(root.iterdir()), [sentinel])
                self.assertEqual(sentinel.stat().st_mtime_ns, before.st_mtime_ns)
                self.assertEqual(sentinel.read_bytes(), b"existing input is never opened as SQLite")

    def test_abrupt_worker_leaves_dirty_pages_and_hot_journal_then_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "probe.sqlite"
            with closing(_connect(database)) as connection:
                connection.executescript((ROOT / "database/schema.sql").read_text())
                with connection:
                    _insert(connection, "committed")
            original = database.read_bytes()
            _run_worker("crash", database, CRASH_EXIT)
            self.assertNotEqual(database.read_bytes(), original)
            journal = Path(str(database) + "-journal")
            self.assertEqual(journal.read_bytes()[:8], JOURNAL_MAGIC)
            with closing(_connect(database)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT asset_id, primary_hostname FROM assets").fetchall(),
                    [("committed", "fixture.example.test")])
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone(), ("ok",))
            self.assertEqual(database.read_bytes(), original)
            self.assertFalse(journal.exists())

    def test_real_second_process_sees_busy_and_then_can_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "probe.sqlite"
            with closing(_connect(database)) as connection:
                connection.executescript((ROOT / "database/schema.sql").read_text())
                connection.execute("BEGIN IMMEDIATE")
                _run_worker("contend", database, BUSY_EXIT)
                connection.rollback()
            _run_worker("commit", database, 0)
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("SELECT asset_id FROM assets").fetchall(),
                                 [("after-recovery",)])

    def test_fresh_cli_outputs_only_summary_and_cleans(self):
        with tempfile.TemporaryDirectory(prefix="private-probe-input-") as directory:
            result = subprocess.run([sys.executable, "-m", "database.sqlite_probe", directory],
                                    cwd=ROOT, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(summary["temporary_files"], "removed")
            self.assertEqual(summary["journal_mode"], "delete")
            self.assertEqual(summary["synchronous"], "full")
            self.assertNotIn(directory, result.stdout)
            self.assertNotIn("fixture.example.test", result.stdout)
            self.assertEqual(result.stderr, "")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_directory_policies_do_not_start_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "public"
            public.mkdir(mode=0o755)
            file = root / "file"
            file.write_text("preserved")
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            with patch("database.sqlite_probe._run_worker") as worker:
                for target in (public, file, link, root / "missing"):
                    with self.subTest(target=target.name), self.assertRaises(SQLiteProbeError):
                        probe_sqlite(target)
                with patch("database.sqlite_probe.os.getuid", return_value=os.getuid() + 1):
                    with self.assertRaises(SQLiteProbeError):
                        probe_sqlite(root)
                worker.assert_not_called()
            self.assertEqual(file.read_text(), "preserved")
            self.assertEqual(list(public.iterdir()), [])

    def test_worker_failure_and_timeout_never_report_success_and_clean(self):
        for failure in (SQLiteProbeError("child failure"),
                        subprocess.TimeoutExpired("synthetic private command", 10)):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                output, errors = io.StringIO(), io.StringIO()
                with patch("database.sqlite_probe._run_worker", side_effect=failure):
                    with redirect_stdout(output), redirect_stderr(errors):
                        self.assertEqual(main([directory]), 2)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn(directory, errors.getvalue())
                self.assertNotIn("synthetic private command", errors.getvalue())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unexpected_worker_status_or_output_is_rejected(self):
        for status, stdout, stderr in ((0, b"", b""), (BUSY_EXIT, b"unexpected", b""),
                                       (BUSY_EXIT, b"", b"unexpected")):
            result = subprocess.CompletedProcess([], status, stdout, stderr)
            with patch("database.sqlite_probe.subprocess.run", return_value=result):
                with self.assertRaises(SQLiteProbeError):
                    _run_worker("contend", Path("unused"), BUSY_EXIT)

    def test_database_and_child_directory_are_private_while_workers_run(self):
        def inspect_then_run(mode, database, expected):
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)
            self.assertEqual(database.parent.stat().st_mode & 0o777, 0o700)
            return _run_worker(mode, database, expected)

        with tempfile.TemporaryDirectory() as directory:
            with patch("database.sqlite_probe._run_worker", side_effect=inspect_then_run):
                self.assertEqual(probe_sqlite(Path(directory))["status"], "sqlite_probe_passed")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_missing_or_invalid_hot_journal_never_counts_as_recovery(self):
        for damaged in (None, b"invalid!"):
            def damage_after_crash(mode, database, expected):
                _run_worker(mode, database, expected)
                if mode == "crash":
                    journal = Path(str(database) + "-journal")
                    if damaged is None:
                        journal.unlink()
                    else:
                        with journal.open("r+b") as stream:
                            stream.write(damaged)

            with self.subTest(damaged=damaged), tempfile.TemporaryDirectory() as directory:
                with patch("database.sqlite_probe._run_worker", side_effect=damage_after_crash):
                    with self.assertRaises(SQLiteProbeError):
                        probe_sqlite(Path(directory))
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unsupported_platform_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("database.sqlite_probe.os.name", "unsupported"):
                with self.assertRaisesRegex(SQLiteProbeError, "POSIX"):
                    probe_sqlite(root)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
