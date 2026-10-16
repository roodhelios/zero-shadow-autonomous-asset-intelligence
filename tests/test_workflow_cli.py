import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from engine.workflow_cli import main

ROOT = Path(__file__).resolve().parents[1]


class WorkflowCliTests(unittest.TestCase):
    def fixtures(self, root):
        for name in ("workflow-spec.json", "workflow-assets.json", "ownership-directory.json"):
            shutil.copyfile(ROOT / "examples" / name, root / name)
        shutil.copyfile(ROOT / "database/schema.sql", root / "schema.sql")
        return [str(root / "workflow-spec.json"), "--schema", str(root / "schema.sql"),
                "--allowed-root", str(root), "--output-root", str(root / "runs"),
                "--run-id", "fixture-demo"]

    def test_command_persists_evidence_and_verifies_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixtures(root)
            results = []
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(args), 0)
                results.append(json.loads(output.getvalue()))
            self.assertFalse(results[0]["reused"])
            self.assertTrue(results[1]["reused"])
            self.assertEqual(len(results[0]["report"]["checkpoints"]), 6)
            database = root / "runs" / results[0]["run_key"] / "evidence.sqlite"
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 1)
            (root / "runs" / results[0]["run_key"] / "workflow-report.json").write_text("{}")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)

    def test_scope_failure_emits_no_success_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixtures(root)
            args[args.index("--output-root") + 1] = str(root.parent / "outside-evidence")
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertFalse((root / "runs").exists())


if __name__ == "__main__":
    unittest.main()
