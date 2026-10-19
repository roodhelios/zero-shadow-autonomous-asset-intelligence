"""Exercise saved host exports through validation and the existing asset graph."""

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from engine.discovery.osquery_collector import convert_inventory, main
from engine.models import AssetValidationError


def export(hostnames):
    return json.dumps([{"hostname": hostname,
                        "uuid": f"11111111-2222-4333-8444-{index:012d}"}
                       for index, hostname in enumerate(hostnames, 1)]).encode()


class InventoryTests(unittest.TestCase):
    def test_report_links_exact_export_and_preserves_observations(self):
        raw = export(["host.example.test", "HOST.EXAMPLE.TEST."])
        result = convert_inventory(raw, scope="synthetic")
        self.assertEqual((result["observation_count"], result["asset_count"]), (2, 1))
        self.assertEqual(result["input_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(result["assets"][0]["observations"]), 2)
        self.assertEqual(result["assets"][0]["ip_addresses"], [])
        self.assertNotIn("risk_score", json.dumps(result))
        self.assertNotIn("owner", result["assets"][0])

    def test_distinct_hosts_remain_distinct_and_order_is_deterministic(self):
        rows = json.loads(export(["one.example.test", "two.example.test"]))
        forward = convert_inventory(json.dumps(rows).encode(), scope="owned")
        reverse = convert_inventory(json.dumps(rows[::-1]).encode(), scope="owned")
        self.assertEqual(forward["asset_count"], 2)
        self.assertEqual(forward["assets"], reverse["assets"])
        self.assertNotEqual(forward["input_sha256"], reverse["input_sha256"])

    def test_cli_inventory_and_default_fixture_are_distinct_contracts(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "export.json"
            source.write_bytes(export(["host.example.test"]))
            outputs = []
            for extra in ([], ["--format", "inventory"]):
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main([str(source), "--scope", "synthetic", *extra]), 0)
                outputs.append(json.loads(output.getvalue()))
            self.assertNotIn("report_type", outputs[0])
            self.assertEqual(outputs[1]["report_type"], "osquery-inventory")

    def test_validation_and_exclusive_publication_apply_to_inventory(self):
        with self.assertRaises(AssetValidationError):
            convert_inventory(export(["host.example.test"]), scope="public")
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "export.json", Path(directory) / "inventory.json"
            source.write_bytes(export(["host.example.test"]))
            args = [str(source), "--scope", "authorized", "--format", "inventory",
                    "--output", str(output)]
            self.assertEqual(main(args), 0)
            original = output.read_bytes()
            with redirect_stderr(StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), original)
