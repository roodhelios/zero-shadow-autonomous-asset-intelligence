"""Check public command discovery and actual synthetic dispatch."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from engine.__main__ import WORKFLOWS, main

ROOT = Path(__file__).resolve().parents[1]


class WorkflowCatalogTests(unittest.TestCase):
    def test_catalog_does_not_import_demo_modules(self):
        output = io.StringIO()
        with patch('engine.__main__.importlib.import_module') as importer:
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(['list', '--format', 'json']), 0)
            importer.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(len(report['workflows']), 15)
        self.assertEqual(len({item['name'] for item in report['workflows']}), 15)
        self.assertEqual(sum(item['dependencies'] == 'requirements-review.txt'
                             for item in report['workflows']), 3)

    def test_unknown_names_and_extra_paths_never_dispatch(self):
        with patch('engine.__main__.importlib.import_module') as importer:
            for args in (['demo', 'os.system'], ['demo', 'inventory', '/private/input'], []):
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        main(args)
                    self.assertEqual(raised.exception.code, 2)
            importer.assert_not_called()

    def test_missing_dependency_is_sanitized(self):
        output = io.StringIO()
        with patch('engine.__main__.importlib.import_module', side_effect=ImportError('private value')):
            with contextlib.redirect_stderr(output):
                self.assertEqual(main(['demo', 'ec2-operator']), 2)
        self.assertIn('requirements-review.txt', output.getvalue())
        self.assertNotIn('private value', output.getvalue())

    def test_dispatch_preserves_selected_exit_status(self):
        with patch('engine.__main__.importlib.import_module') as importer:
            importer.return_value.main.return_value = 2
            self.assertEqual(main(['demo', 'ec2-compare']), 2)
            importer.assert_called_once_with('engine.demo_ec2_discovery_compare')
            importer.return_value.main.assert_called_once_with()

    def test_all_catalog_modules_exist(self):
        for _, module, _, _ in WORKFLOWS:
            self.assertTrue((ROOT / 'engine' / (module + '.py')).is_file())

    def test_native_inventory_from_public_entry_point_without_site_packages(self):
        result = subprocess.run([sys.executable, '-S', '-m', 'engine', 'demo', 'inventory'],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'inventory_exercise_passed')
        self.assertEqual((report['asset_count'], report['finding_count']), (2, 1))
        self.assertEqual(report['changed_export'], 'rejected')
        self.assertEqual(report['model_status'], 'bound_current_model')

    def test_help_and_catalog_work_without_site_packages(self):
        for args in (['--help'], ['list'], ['list', '--format', 'json']):
            result = subprocess.run([sys.executable, '-S', '-m', 'engine', *args],
                                    cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout)


if __name__ == '__main__':
    unittest.main()
