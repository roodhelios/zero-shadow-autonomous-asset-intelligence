"""Saved interface IPv4 claims survive native SQLite without live AWS calls."""

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from database.ec2_inventory import export_ec2, store_ec2, verify_ec2
from engine.discovery.aws_discovery import convert_export, inventory, main

FIXTURE = Path(__file__).resolve().parents[1] / "examples/ec2-interface-addresses.json"
OPTIONS = {"scope": "synthetic", "account": "111122223333", "region": "us-east-1"}
EXPECTED = ["192.0.2.40", "192.0.2.41", "198.51.100.40", "198.51.100.41", "2001:db8::40", "2001:db8::41"]


class EC2InterfaceIPv4Tests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads(FIXTURE.read_bytes())
        self.instance = self.value["Reservations"][0]["Instances"][0]
        self.interface = self.instance["NetworkInterfaces"][0]

    def convert(self):
        return convert_export(json.dumps(self.value).encode(), **OPTIONS)

    def test_deduplicated_interface_private_public_and_ipv6_claims(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.convert()
        self.assertEqual(result["assets"][0]["ip_addresses"], EXPECTED)
        self.assertNotIn("omitted.example.test", json.dumps(result))
        self.assertNotIn("Primary", json.dumps(result))
        self.assertEqual(inventory(result)["asset_count"], 1)

    def test_interface_only_export_and_empty_association_are_supported(self):
        self.instance.pop("PrivateIpAddress")
        self.instance.pop("PublicIpAddress")
        self.interface["PrivateIpAddresses"][0]["Association"] = {}
        self.assertEqual(self.convert()["assets"][0]["ip_addresses"], EXPECTED)

    def test_shared_addresses_do_not_merge_distinct_instances(self):
        other = copy.deepcopy(self.instance)
        other["InstanceId"] = "i-0123456789abcdef1"
        self.value["Reservations"][0]["Instances"].append(other)
        self.assertEqual(inventory(self.convert())["asset_count"], 2)

    def test_malformed_records_associations_and_literals_reject_whole_export(self):
        original = copy.deepcopy(self.interface)
        changes = [{"PrivateIpAddresses": value} for value in (None, {}, [None], [{}],
                   [{"PrivateIpAddress": "2001:db8::1"}], [{"PrivateIpAddress": "192.0.2.1/32"}])]
        changes += [{"Association": value} for value in (None, [], {"PublicIp": None},
                    {"PublicIp": "2001:db8::1"}, {"PublicIp": "192.0.2.1%eth0"})]
        changes += [{"PrivateIpAddress": None}, {"PrivateIpAddress": "192.0.2.999"},
                    {"PrivateIpAddresses": [{"PrivateIpAddress": "192.0.2.1", "Association": False}]}]
        for change in changes:
            self.instance["NetworkInterfaces"][0] = original | change
            with self.subTest(change=change), self.assertRaises(ValueError): self.convert()

    def test_local_record_bound_and_empty_interface_records(self):
        self.interface["PrivateIpAddresses"] = [{"PrivateIpAddress": "192.0.2.41"}] * 101
        with self.assertRaises(ValueError): self.convert()
        self.interface["PrivateIpAddresses"].pop()
        self.assertIn("192.0.2.41", self.convert()["assets"][0]["ip_addresses"])
        self.interface["PrivateIpAddresses"] = []
        self.assertEqual(self.convert()["assets"][0]["ip_addresses"],
                         ["192.0.2.40", "198.51.100.40", "2001:db8::40", "2001:db8::41"])

    @unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
    def test_native_sqlite_reproduction_export_and_invalid_cli_no_partial_output(self):
        from contextlib import redirect_stderr
        from io import StringIO
        with tempfile.TemporaryDirectory() as directory, \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            root = Path(directory)
            database, output = root/"inventory.sqlite", root/"review.json"
            store_ec2(FIXTURE, database, **OPTIONS, observed_at=datetime(2026, 11, 17, tzinfo=timezone.utc))
            before = database.read_bytes()
            self.assertEqual(verify_ec2(database, FIXTURE.read_bytes())["status"], "ec2_inventory_reproduced")
            export_ec2(database, FIXTURE.read_bytes(), output)
            self.assertEqual(json.loads(output.read_bytes())["assets"][0]["observations"][0]["payload"]["ip_addresses"], EXPECTED)
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            invalid = root/"invalid.json"
            self.interface["PrivateIpAddresses"] = [{"PrivateIpAddress": "not-an-address"}]
            invalid.write_text(json.dumps(self.value))
            with redirect_stderr(StringIO()):
                self.assertEqual(main([str(invalid), "--scope", "synthetic", "--account", OPTIONS["account"],
                    "--region", OPTIONS["region"], "--output", str(root/"partial.json")]), 2)
            self.assertFalse((root/"partial.json").exists())


if __name__ == "__main__":
    unittest.main()
