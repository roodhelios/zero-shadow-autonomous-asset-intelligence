import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from engine.demo_inventory import exercise, main
from database.inventory_assessment_verify import verify_assessment


@unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
class InventoryDemoTests(unittest.TestCase):
    def test_native_sqlite_workflow_is_offline_and_aggregate_only(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = exercise()
        self.assertEqual(result["status"], "inventory_exercise_passed")
        self.assertEqual((result["asset_count"], result["finding_count"]), (2, 1))
        self.assertEqual(result["model_status"], "bound_current_model")
        rendered = json.dumps(result)
        for value in ("checkout.example.test", "asset-752", "/tmp/", "11111111"):
            self.assertNotIn(value, rendered)

    def test_negative_check_must_reject_changed_export(self):
        # Use the valid fixture bytes for both calls to simulate a broken verifier.
        from engine.demo_inventory import EXAMPLES
        valid = (EXAMPLES / "osquery-system-info-expanded.json").read_bytes()
        with patch("engine.demo_inventory.verify_assessment",
                   side_effect=lambda database, data, **kw: verify_assessment(database, valid, **kw)):
            with self.assertRaisesRegex(ValueError, "changed original export"):
                exercise()

    def test_cli_failure_has_no_success_or_private_error_detail(self):
        stdout, stderr = StringIO(), StringIO()
        with patch("engine.demo_inventory.exercise", side_effect=ValueError("private-fixture")), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("private-fixture", stderr.getvalue())
