"""Tests for safe fixture loading and deterministic asset correlation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from engine.correlation import correlate_assets
from engine.discovery import load_fixture
from engine.models import AssetObservation, AssetValidationError


def observation(source: str, record_id: str, **values: object) -> AssetObservation:
    payload = {"source_record_id": record_id, "kind": "server", **values}
    return AssetObservation.from_dict(source, payload)


class FixtureDiscoveryTests(unittest.TestCase):
    def write_fixture(self, directory: str, payload: object) -> Path:
        path = Path(directory) / "assets.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_requires_explicit_authorization_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(
                directory,
                {"schema_version": 1, "source": "cmdb", "assets": []},
            )

            with self.assertRaisesRegex(AssetValidationError, "scope must be"):
                load_fixture(path)

    def test_loads_and_normalizes_synthetic_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(
                directory,
                {
                    "schema_version": 1,
                    "scope": "synthetic",
                    "source": "CMDB",
                    "assets": [
                        {
                            "source_record_id": "srv-1",
                            "kind": "Server",
                            "hostname": "API.EXAMPLE.TEST.",
                            "ip_addresses": ["192.0.2.10", "192.0.2.10"],
                        }
                    ],
                },
            )

            batch = load_fixture(path)

        self.assertEqual(batch.source, "cmdb")
        self.assertEqual(batch.observations[0].hostname, "api.example.test")
        self.assertEqual(batch.observations[0].ip_addresses, ("192.0.2.10",))


class CorrelationTests(unittest.TestCase):
    def test_merges_matching_cloud_resource_ids_across_sources(self) -> None:
        left = observation(
            "cmdb",
            "server-1",
            cloud_provider="aws",
            cloud_account="111122223333",
            cloud_resource_id="i-0123456789abcdef0",
        )
        right = observation(
            "cloud-fixture",
            "instance-a",
            cloud_provider="AWS",
            cloud_account="111122223333",
            cloud_resource_id="i-0123456789abcdef0",
        )

        assets = correlate_assets([left, right])

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].sources, ("cloud-fixture", "cmdb"))

    def test_merges_matching_fully_qualified_hostnames(self) -> None:
        left = observation("cmdb", "server-1", hostname="api.example.test")
        right = observation("dns-fixture", "record-1", hostname="API.EXAMPLE.TEST.")

        self.assertEqual(len(correlate_assets([left, right])), 1)

    def test_does_not_merge_on_shared_ip_address_alone(self) -> None:
        left = observation("cmdb", "server-1", ip_addresses=["192.0.2.50"])
        right = observation("dhcp-fixture", "lease-9", ip_addresses=["192.0.2.50"])

        assets = correlate_assets([left, right])

        self.assertEqual(len(assets), 2)

    def test_output_is_stable_when_input_order_changes(self) -> None:
        left = observation("cmdb", "server-1", hostname="api.example.test")
        right = observation("dns-fixture", "record-1", hostname="api.example.test")

        forward = [item.to_dict() for item in correlate_assets([left, right])]
        reverse = [item.to_dict() for item in correlate_assets([right, left])]

        self.assertEqual(forward, reverse)


if __name__ == "__main__":
    unittest.main()
