"""Executable checks for the local asset evidence schema."""

from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from database.schema_check import inspect_schema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "database" / "schema.sql"
NOW = "2026-09-17T23:00:00Z"


class DatabaseSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.connection.close()

    def insert_asset(self) -> None:
        self.connection.execute(
            "INSERT INTO assets "
            "(asset_id, kind_summary_json, primary_hostname, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "asset-synthetic-001",
                json.dumps(["server"]),
                "api.example.test",
                NOW,
                NOW,
            ),
        )

    def insert_finding(self) -> None:
        self.connection.execute(
            "INSERT INTO findings "
            "(finding_id, asset_id, source, description, severity, exposure, "
            "exploit_evidence, control_state, identity_confidence, evidence_json, "
            "observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "finding-synthetic-001",
                "asset-synthetic-001",
                "fixture",
                "Synthetic missing-control observation",
                "high",
                "internet",
                "none",
                "missing",
                "high",
                json.dumps({"fixture": "finding-1"}),
                NOW,
            ),
        )

    def test_schema_checker_lists_required_objects(self) -> None:
        summary = inspect_schema(SCHEMA_PATH)

        self.assertEqual(len(summary["tables"]), 5)
        self.assertEqual(len(summary["indexes"]), 5)
        self.assertEqual(len(summary["triggers"]), 8)
        self.assertEqual(summary["foreign_key_count"], 4)
        self.assertTrue(summary["foreign_keys_enabled"])

    def test_valid_evidence_chain_can_be_inserted(self) -> None:
        self.insert_asset()
        self.connection.execute(
            "INSERT INTO asset_observations "
            "(observation_id, asset_id, source, source_record_id, scope, "
            "observed_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "observation-001",
                "asset-synthetic-001",
                "cmdb-fixture",
                "server-1",
                "synthetic",
                NOW,
                json.dumps({"hostname": "api.example.test"}),
            ),
        )
        self.insert_finding()
        self.connection.execute(
            "INSERT INTO ownership_decisions "
            "(decision_id, asset_id, status, team_id, matched_rule_ids_json, "
            "candidate_team_ids_json, explanation, decided_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ownership-001",
                "asset-synthetic-001",
                "resolved",
                "application-security",
                json.dumps(["rule-app-prod"]),
                json.dumps(["application-security"]),
                "The most specific fixture rule selected one team",
                NOW,
            ),
        )
        self.connection.execute(
            "INSERT INTO remediation_plans "
            "(plan_id, finding_id, plan_version, priority, owner_team_id, opened_on, "
            "due_date, overdue, risk_score, risk_band, actions_json, factors_json, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "plan-001",
                "finding-synthetic-001",
                1,
                "P1",
                "application-security",
                "2026-09-17",
                "2026-09-24",
                0,
                65,
                "high",
                json.dumps(["Validate evidence"]),
                json.dumps([{"factor_id": "severity", "points": 45}]),
                NOW,
            ),
        )

        counts = {
            table: self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "assets",
                "asset_observations",
                "findings",
                "ownership_decisions",
                "remediation_plans",
            )
        }
        self.assertEqual(set(counts.values()), {1})

    def test_scope_allowlist_rejects_unreviewed_origin(self) -> None:
        self.insert_asset()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK constraint"):
            self.connection.execute(
                "INSERT INTO asset_observations "
                "(observation_id, asset_id, source, source_record_id, scope, "
                "observed_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "observation-001",
                    "asset-synthetic-001",
                    "unknown-source",
                    "server-1",
                    "internet",
                    NOW,
                    "{}",
                ),
            )

    def test_foreign_key_rejects_orphan_finding(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert_finding()

    def test_resolved_ownership_requires_team(self) -> None:
        self.insert_asset()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "CHECK constraint"):
            self.connection.execute(
                "INSERT INTO ownership_decisions "
                "(decision_id, asset_id, status, team_id, matched_rule_ids_json, "
                "candidate_team_ids_json, explanation, decided_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "ownership-001",
                    "asset-synthetic-001",
                    "resolved",
                    None,
                    "[]",
                    "[]",
                    "Missing team should fail",
                    NOW,
                ),
            )

    def test_evidence_rows_are_append_only(self) -> None:
        self.insert_asset()
        self.insert_finding()

        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "UPDATE findings SET severity = 'low' "
                "WHERE finding_id = 'finding-synthetic-001'"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
            self.connection.execute(
                "DELETE FROM findings WHERE finding_id = 'finding-synthetic-001'"
            )

    def test_plan_versions_are_unique_per_finding(self) -> None:
        self.insert_asset()
        self.insert_finding()
        values = (
            "plan-001",
            "finding-synthetic-001",
            1,
            "P1",
            None,
            "2026-09-17",
            "2026-09-24",
            0,
            65,
            "high",
            "[]",
            "[]",
            NOW,
        )
        sql = (
            "INSERT INTO remediation_plans "
            "(plan_id, finding_id, plan_version, priority, owner_team_id, opened_on, "
            "due_date, overdue, risk_score, risk_band, actions_json, factors_json, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        self.connection.execute(sql, values)

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(sql, ("plan-002", *values[1:]))


if __name__ == "__main__":
    unittest.main()
