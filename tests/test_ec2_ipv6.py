"""Saved EC2 dual-stack evidence uses synthetic addresses and native SQLite."""

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from database.ec2_inventory import export_ec2, store_ec2, verify_ec2
from engine.discovery.aws_discovery import convert_export, inventory

FIXTURE = Path(__file__).resolve().parents[1] / "examples/ec2-ipv6.json"
OPTIONS = {"scope": "synthetic", "account": "111122223333", "region": "us-east-1"}
EXPECTED = ["192.0.2.40", "198.51.100.40", "2001:db8::40", "2001:db8::41"]


class EC2IPv6Tests(unittest.TestCase):
    def setUp(self):
        self.value = json.loads(FIXTURE.read_bytes())
        self.instance = self.value["Reservations"][0]["Instances"][0]

    def convert(self):
        return convert_export(json.dumps(self.value).encode(), **OPTIONS)

    def test_primary_and_interface_addresses_are_canonical_unique_evidence(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.convert()
        self.assertEqual(result["assets"][0]["ip_addresses"], EXPECTED)
        self.assertNotIn("Ipv6Prefix", json.dumps(result))
        self.assertEqual(inventory(result)["asset_count"], 1)

    def test_shared_ipv6_never_merges_distinct_cloud_identities(self):
        other = copy.deepcopy(self.instance)
        other["InstanceId"] = "i-0123456789abcdef1"
        self.value["Reservations"][0]["Instances"].append(other)
        self.assertEqual(inventory(self.convert())["asset_count"], 2)

    def test_missing_or_empty_fields_remain_ipv4_only(self):
        self.instance.pop("Ipv6Address")
        for interfaces in ([], [{}], [{"Ipv6Addresses": []}]):
            self.instance["NetworkInterfaces"] = interfaces
            self.assertEqual(self.convert()["assets"][0]["ip_addresses"], EXPECTED[:2])
        self.instance.pop("NetworkInterfaces")
        self.assertEqual(self.convert()["assets"][0]["ip_addresses"], EXPECTED[:2])

    def test_malformed_present_ipv6_and_interface_fields_reject_whole_export(self):
        for value in (None, 1, "", "192.0.2.1", "2001:db8::/64", "fe80::1%eth0", "invalid"):
            self.instance["Ipv6Address"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.convert()
        self.instance.pop("Ipv6Address")
        for value in (None, {}, [None], [{"Ipv6Addresses": None}], [{"Ipv6Addresses": {}}],
                      [{"Ipv6Addresses": [None]}], [{"Ipv6Addresses": [{}]}],
                      [{"Ipv6Addresses": [{"Ipv6Address": "192.0.2.1"}]}]):
            self.instance["NetworkInterfaces"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): self.convert()

    def test_local_interface_and_record_bounds_reject_oversized_collections(self):
        self.instance["NetworkInterfaces"] = [{}] * 101
        with self.assertRaises(ValueError): self.convert()
        self.instance["NetworkInterfaces"] = [{"Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}] * 101}]
        with self.assertRaises(ValueError): self.convert()
        self.instance["NetworkInterfaces"][0]["Ipv6Addresses"].pop()
        self.assertIn("2001:db8::1", self.convert()["assets"][0]["ip_addresses"])

    @unittest.skipUnless(os.name == "posix", "private evidence requires POSIX")
    def test_native_sqlite_store_reproduction_and_export_keep_ipv6_without_network(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            database, output = Path(directory)/"inventory.sqlite", Path(directory)/"review.json"
            store_ec2(FIXTURE, database, **OPTIONS,
                      observed_at=datetime(2026, 11, 16, tzinfo=timezone.utc))
            before = database.read_bytes()
            self.assertEqual(verify_ec2(database, FIXTURE.read_bytes())["status"], "ec2_inventory_reproduced")
            export_ec2(database, FIXTURE.read_bytes(), output)
            document = json.loads(output.read_bytes())
            payload = document["assets"][0]["observations"][0]["payload"]
            self.assertEqual(payload["ip_addresses"], EXPECTED)
            self.assertEqual(database.read_bytes(), before)
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
