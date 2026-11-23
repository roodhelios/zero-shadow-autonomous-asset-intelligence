"""Complete planning input must validate before the CLI publishes any review."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from engine import remediation_cli as cli


FIXTURE = Path(__file__).resolve().parents[1] / 'examples/remediation-input.jsonl'


class RemediationPublicationTests(unittest.TestCase):
    def test_bad_later_record_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.jsonl'
            source.write_bytes(FIXTURE.read_bytes() + b'not-json\n')
            output = root / 'existing.jsonl'
            output.write_bytes(b'prior reviewed evidence\n')
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main([str(source), '--as-of', '2026-09-15',
                                           '--output', str(output)]), 2)
            self.assertEqual(output.read_bytes(), b'prior reviewed evidence\n')

    def test_bad_later_record_emits_no_stdout_or_new_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.jsonl'
            source.write_bytes(FIXTURE.read_bytes() + b'not-json\n')
            for target in ('-', str(root / 'new.jsonl')):
                with self.subTest(target=target), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(cli.main([str(source), '--as-of', '2026-09-15', '--output', target]), 2)
                    self.assertEqual(out.getvalue(), '')
            self.assertEqual({p.name for p in root.iterdir()}, {'input.jsonl'})

    def test_success_retains_complete_plans_privately_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.jsonl'
            first = json.loads(FIXTURE.read_bytes())
            second = dict(first, owner=None)
            second['finding'] = dict(first['finding'], finding_id='finding-2')
            data = json.dumps(first) + '\n\n' + json.dumps(second) + '\n'
            source.write_text(data)
            output = root / 'plans.jsonl'
            self.assertEqual(cli.main([str(source), '--as-of', '2026-09-15', '--output', str(output)]), 0)
            rows = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual([r['priority'] for r in rows], ['P2', 'P1'])
            self.assertEqual([r['finding_id'] for r in rows], ['finding-1', 'finding-2'])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(source.read_text(), data)
            before = output.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main([str(source), '--as-of', '2026-09-15', '--output', str(output)]), 2)
            self.assertEqual(output.read_bytes(), before)
            self.assertEqual({p.name for p in root.iterdir()}, {'input.jsonl', 'plans.jsonl'})

    def test_input_aliases_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.jsonl'; source.write_bytes(FIXTURE.read_bytes())
            hard = root / 'hard.jsonl'; hard.hardlink_to(source)
            symbolic = root / 'symbolic.jsonl'; symbolic.symlink_to(source)
            for output in (source, hard, symbolic):
                with self.subTest(output=output), redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main([str(source), '--as-of', '2026-09-15', '--output', str(output)]), 2)
                    self.assertEqual(source.read_bytes(), FIXTURE.read_bytes())

    def test_failed_publication_cleans_temporary_and_leaves_new_path_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'new.jsonl'
            with patch.object(cli.os, 'link', side_effect=OSError('synthetic publication failure')):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(cli.main([str(FIXTURE), '--as-of', '2026-09-15', '--output', str(output)]), 2)
            self.assertEqual(list(root.iterdir()), [])

    def test_stdin_stdout_preserves_streaming_library_results(self):
        expected = io.StringIO()
        cli.plan_jsonl(io.StringIO(FIXTURE.read_text()), expected, as_of=cli.date(2026, 9, 15))
        with patch.object(cli.sys, 'stdin', io.StringIO(FIXTURE.read_text())), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(['--as-of', '2026-09-15']), 0)
        self.assertEqual(out.getvalue(), expected.getvalue())

    def test_fresh_standard_library_command_matches_documented_example(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'plans.jsonl'
            process = subprocess.run(
                [sys.executable, '-S', '-m', 'engine.remediation_cli', str(FIXTURE),
                 '--as-of', '2026-09-15', '--output', str(output)],
                cwd=FIXTURE.parent.parent, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout, '')
            row = json.loads(output.read_bytes())
            self.assertEqual((row['priority'], row['due_date'], row['overdue']),
                             ('P2', '2026-10-15', False))


if __name__ == '__main__':
    unittest.main()
