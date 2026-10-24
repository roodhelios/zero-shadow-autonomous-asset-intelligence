import copy
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from engine.discovery.aws_discovery import convert_export, inventory, main
from engine.discovery.fixture_discovery import load_fixture
from engine.workflow_runs import run_workflow_once
from database.evidence_reader import EvidenceReader

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples/ec2-describe-instances.json"
OPTIONS = {"scope": "synthetic", "account": "111122223333", "region": "us-east-1"}


class EC2ImportTests(unittest.TestCase):
    def convert(self, value=None, **options):
        data = FIXTURE.read_bytes() if value is None else json.dumps(value).encode()
        return convert_export(data, **(OPTIONS | options))

    def test_projection_digest_references_and_explicit_region_identity(self):
        result = self.convert()
        self.assertEqual(result, self.convert())
        asset = result["assets"][0]
        self.assertEqual(asset["cloud_resource_id"], "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0")
        self.assertIsNone(asset["hostname"])
        self.assertEqual(asset["tags"]["owner_group"], "cloud-platform")
        self.assertNotIn("unselected-note", json.dumps(result))
        self.assertNotIn("checkout.example.test", json.dumps(result))
        self.assertEqual(result["import_metadata"]["input_sha256"], hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
        self.assertEqual(result["import_metadata"]["source_records"][0]["instance_record"], 1)
        self.assertNotEqual(asset["cloud_resource_id"], self.convert(region="us-west-2")["assets"][0]["cloud_resource_id"])

    def test_shared_addresses_do_not_merge_different_instances(self):
        data = json.loads(FIXTURE.read_bytes())
        other = copy.deepcopy(data["Reservations"][0]["Instances"][0]); other["InstanceId"] = "i-0123456789abcdef1"
        data["Reservations"][0]["Instances"].append(other)
        self.assertEqual(inventory(self.convert(data))["asset_count"], 2)
        data["Reservations"][0]["Instances"][1]["InstanceId"] = "i-0123456789abcdef0"
        with self.assertRaises(ValueError): self.convert(data)

    def test_scope_account_partition_and_pagination_fail_closed(self):
        for options in ({"scope": "public"}, {"account": "999900001111"}, {"account": True},
                        {"region": "us-gov-west-1"}, {"region": "cn-north-1"}):
            with self.subTest(options=options), self.assertRaises(ValueError): self.convert(**options)
        for token in ("unfinished-page", True, []):
            value = json.loads(FIXTURE.read_bytes()); value["NextToken"] = token
            with self.assertRaises(ValueError): self.convert(value)

    def test_ambiguous_tags_invalid_ids_addresses_and_json_are_rejected(self):
        for change in ({"InstanceId": "invalid"}, {"PrivateIpAddress": 1},
                       {"PublicIpAddress": "192.0.2.1%interface"},
                       {"Tags": [{"Key": "service", "Value": "web"}]*2},
                       {"Tags": [{"Key": "service", "Value": "invalid\nlabel"}]}):
            value = json.loads(FIXTURE.read_bytes()); value["Reservations"][0]["Instances"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.convert(value)
        for data in (b'{"Reservations":[],"Reservations":[]}', b'{"Reservations":[],"other":NaN}'):
            with self.assertRaises(ValueError): convert_export(data, **OPTIONS)
        with patch("engine.discovery.aws_discovery.MAX_INPUT_BYTES", 1):
            with self.assertRaises(ValueError): self.convert()
        with patch("engine.discovery.aws_discovery.MAX_INSTANCES", 0):
            with self.assertRaises(ValueError): self.convert()
        self.assertEqual(inventory(self.convert({"Reservations": []}))["asset_count"], 0)

    @unittest.skipUnless(os.name == "posix", "private files require POSIX")
    def test_generated_fixture_runs_through_native_sqlite_workflow_without_network(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            root = Path(directory); fixture = root / "ec2.json"
            self.assertEqual(main([str(FIXTURE), "--scope", "synthetic", "--account", OPTIONS["account"],
                "--region", OPTIONS["region"], "--output", str(fixture)]), 0)
            self.assertEqual(fixture.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(load_fixture(fixture).observations), 1)
            shutil.copyfile(ROOT/"examples/ownership-directory.json", root/"ownership-directory.json")
            shutil.copyfile(ROOT/"database/schema.sql", root/"schema.sql")
            spec = json.loads((ROOT/"examples/workflow-spec.json").read_text())
            spec["asset_fixture"] = fixture.name
            spec_path = root/"spec.json"; spec_path.write_text(json.dumps(spec))
            result = run_workflow_once(spec_path=spec_path, schema_path=root/"schema.sql",
                run_id="ec2-fixture", output_root=root/"runs", allowed_root=root)
            self.assertEqual(result.report["status"], "completed")
            database = root/"runs"/result.run_key/"evidence.sqlite"
            with sqlite3.connect(database.as_uri()+"?mode=ro", uri=True) as connection:
                snapshot = EvidenceReader(connection).read_asset(result.report["asset_id"]).to_dict()
            self.assertEqual(snapshot["observations"][0]["source"], "aws-ec2-export")
            self.assertEqual(snapshot["observations"][0]["payload"]["cloud_resource_id"],
                             self.convert()["assets"][0]["cloud_resource_id"])
            self.assertEqual(snapshot["ownership_decisions"][0]["team_id"], "cloud-platform")

    @unittest.skipUnless(os.name == "posix", "private files require POSIX")
    def test_cli_never_replaces_output_or_publishes_partial_invalid_export(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/"inventory.json"
            args = [str(FIXTURE), "--scope", "synthetic", "--account", OPTIONS["account"],
                    "--region", OPTIONS["region"], "--format", "inventory", "--output", str(output)]
            self.assertEqual(main(args), 0); before = output.read_bytes()
            with redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), before)
            output.unlink(); args[args.index(OPTIONS["account"])] = "999900001111"
            stdout = StringIO()
            with redirect_stdout(stdout), redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
