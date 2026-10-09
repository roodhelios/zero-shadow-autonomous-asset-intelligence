from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from database.storage_probe import StorageProbeError, main, probe_storage_directory


class StorageProbeTests(unittest.TestCase):
    def test_probe_exercises_and_cleans_publication_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = probe_storage_directory(root)
            remaining = list(root.iterdir())

        self.assertTrue(result.exclusive_create)
        self.assertTrue(result.file_sync)
        self.assertTrue(result.hard_link_publish)
        self.assertTrue(result.directory_sync)
        self.assertEqual(remaining, [])

    def test_hard_link_failure_is_reported_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("database.storage_probe.os.link", side_effect=OSError("unsupported")):
                with self.assertRaisesRegex(StorageProbeError, "publication primitive"):
                    probe_storage_directory(root)
            remaining = list(root.iterdir())
        self.assertEqual(remaining, [])

    def test_symlink_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(StorageProbeError, "non-symlink"):
                probe_storage_directory(link)

    def test_cli_reports_machine_readable_capabilities(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            with redirect_stdout(output):
                status = main([directory])
        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "supported")
        self.assertTrue(result["directory_sync"])

    def test_cli_rejects_missing_directory(self) -> None:
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with redirect_stderr(errors):
                status = main([str(missing)])
        self.assertEqual(status, 2)
        self.assertIn("does not exist", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
