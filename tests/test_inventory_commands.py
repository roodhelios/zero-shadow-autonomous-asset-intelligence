"""Run the public retained-inventory command path with native temporary SQLite."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from engine.__main__ import main
from engine.inventory_cli import COMMANDS

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class InventoryCommandTests(unittest.TestCase):
    def invoke(self, arguments):
        output, errors = StringIO(), StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = main(["inventory", *arguments])
        return status, output.getvalue(), errors.getvalue()

    def test_inventory_help_is_discoverable_without_importing_tools(self):
        with patch("engine.inventory_cli.import_module", side_effect=AssertionError("no tool import")):
            status, output, errors = self.invoke([])
            self.assertEqual((status, errors), (0, ""))
            for name in COMMANDS:
                self.assertIn(name, output)
            with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as result:
                self.invoke(["--help"])
            self.assertEqual(result.exception.code, 0)
        result = subprocess.run([sys.executable, "-S", "-m", "engine", "--help"],
            cwd=ROOT, text=True, capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertIn("inventory", result.stdout)

    def test_each_selected_tool_retains_its_help_parser(self):
        for command in COMMANDS:
            with self.subTest(command=command), self.assertRaises(SystemExit) as result:
                self.invoke([command, "--help"])
            self.assertEqual(result.exception.code, 0)

    def test_arbitrary_modules_and_abbreviations_are_not_dispatched(self):
        with patch("engine.inventory_cli.import_module", side_effect=AssertionError("no tool import")):
            for command in ("database.repository", "imp", "../../other"):
                with self.subTest(command=command), self.assertRaises(SystemExit) as result:
                    self.invoke([command])
                self.assertEqual(result.exception.code, 2)

    @unittest.skipUnless(os.name == "posix", "private retained files require POSIX")
    def test_import_assess_verify_and_recipient_queue_reproduction(self):
        with tempfile.TemporaryDirectory() as directory, patch("socket.socket", side_effect=AssertionError("no network")):
            root = Path(directory)
            discovery, assessment, queue = root / "discovery.sqlite", root / "assessment.sqlite", root / "queue.json"
            export = root / "original.json"
            export.write_bytes((EXAMPLES / "osquery-system-info-expanded.json").read_bytes())
            source_before = export.read_bytes()

            def run(arguments):
                status, output, errors = self.invoke(list(map(str, arguments)))
                self.assertEqual((status, errors), (0, ""))
                return json.loads(output)

            imported = run(["import", export, "--output", discovery, "--scope", "synthetic",
                            "--observed-at", "2026-10-23T00:00:00Z"])
            self.assertEqual(imported["status"], "stored")
            discovery_before = discovery.read_bytes()
            inventory = run(["export", discovery, "--export", export])
            self.assertEqual(len(inventory["assets"]), 2)
            retained = run(["assess", discovery, EXAMPLES / "inventory-findings.jsonl",
                "--directory", EXAMPLES / "ownership-directory.json", "--export", export,
                "--output", assessment, "--as-of", "2026-10-23", "--assessed-at", "2026-10-23T01:00:00Z"])
            self.assertEqual(retained["status"], "assessment_stored")
            self.assertEqual(discovery.read_bytes(), discovery_before)
            discovery.unlink()
            assessment_before = assessment.read_bytes()
            pin = hashlib.sha256(assessment_before).hexdigest()
            verified = run(["verify", assessment, "--export", export, "--require-model-binding"])
            self.assertEqual(verified["status"], "assessment_reproduced")
            queued = run(["queue", assessment, "--export", export, "--expected-database-sha256", pin,
                          "--as-of", "2026-11-16", "--output", queue])
            self.assertEqual(queued["status"], "assessment_queue_exported")
            arguments = ["verify-queue", queue, assessment, "--export", export,
                "--expected-database-sha256", pin, "--expected-report-sha256", queued["output_sha256"],
                "--as-of", "2026-11-16"]
            self.assertEqual(run(arguments)["status"], "assessment_queue_reproduced")
            self.assertEqual(assessment.read_bytes(), assessment_before)
            self.assertEqual(export.read_bytes(), source_before)
            for retained_path in (assessment, queue):
                self.assertEqual(retained_path.stat().st_mode & 0o777, 0o600)

            # Changing the original is still a failure, without private diagnostics.
            export.write_bytes(source_before + b"\n")
            status, output, errors = self.invoke(list(map(str, arguments)))
            self.assertEqual((status, output), (2, ""))
            self.assertNotIn(str(root), errors)
            export.write_bytes(source_before)
            status, output, _ = self.invoke(["import", str(export), "--output", str(assessment),
                "--scope", "synthetic", "--observed-at", "2026-10-23T00:00:00Z"])
            self.assertEqual((status, output), (2, ""))
            self.assertEqual(assessment.read_bytes(), assessment_before)

    def test_fresh_standard_library_process_reaches_inventory_help(self):
        result = subprocess.run([sys.executable, "-S", "-m", "engine", "inventory", "queue", "--help"],
            cwd=ROOT, text=True, capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertIn("--expected-database-sha256", result.stdout)


if __name__ == "__main__":
    unittest.main()
