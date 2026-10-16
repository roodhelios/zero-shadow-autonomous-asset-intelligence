import io
import json
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from engine.workflow_cli import main
from engine.workflow_cli import review_summary
from engine.workflow_runs import WorkflowRunResult

ROOT = Path(__file__).resolve().parents[1]


class WorkflowCliTests(unittest.TestCase):
    def test_text_summary_covers_decisions_and_preserves_retry_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.fixtures(root) + ["--format", "text"]
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 0)
            text = output.getvalue()
            for expected in ('(created)', '75/100', '"critical"', '"application-security"',
                             '"P0"', '"2026-09-20"', 'no action was sent'):
                self.assertIn(expected, text)
            artifacts = {path: path.read_bytes() for path in (root / "runs").rglob("*") if path.is_file()}
            retry = io.StringIO()
            with redirect_stdout(retry):
                self.assertEqual(main(args), 0)
            self.assertIn("(verified retry)", retry.getvalue())
            self.assertEqual(artifacts, {path: path.read_bytes() for path in artifacts})

    def test_summary_escapes_terminal_controls_and_marks_unassigned_ownership(self):
        report = {"asset_id": "asset\x1b[31m", "checkpoints": [
            {"checkpoint": "risk_scored", "evidence": {"score": 0, "band": "low"}},
            {"checkpoint": "ownership_resolved", "evidence": {"status": "unassigned", "team_id": None}},
            {"checkpoint": "remediation_planned", "evidence": {"priority": "P3", "due_date": "2026-10-16"}},
        ]}
        result = WorkflowRunResult("demo\nforged", "run-example", False, report)
        text = review_summary(result, Path("runs"))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("demo\nforged", text)
        self.assertIn('"unassigned", team null', text)
        self.assertIn('demo\\nforged', text)

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
