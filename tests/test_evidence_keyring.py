from __future__ import annotations

import unittest

from database.evidence_keyring import EvidenceKeyringError, authorize_key_use


def keyring(state="active"):
    return {"schema_version": 1, "keys": [{
        "key_id": "snapshot-key-2026-09", "state": state,
        "activate_at": "2026-09-01T00:00:00Z",
        "verify_until": "2026-11-01T00:00:00Z",
    }]}


class EvidenceKeyringTests(unittest.TestCase):
    def test_active_key_can_create_and_verify_inside_window(self):
        for operation in ("create", "verify"):
            authorize_key_use(keyring(), key_id="snapshot-key-2026-09",
                              operation=operation, at="2026-09-28T20:00:00Z")

    def test_retired_key_can_verify_but_not_create(self):
        authorize_key_use(keyring("retired"), key_id="snapshot-key-2026-09",
                          operation="verify", at="2026-09-28T20:00:00Z")
        with self.assertRaisesRegex(EvidenceKeyringError, "active key"):
            authorize_key_use(keyring("retired"), key_id="snapshot-key-2026-09",
                              operation="create", at="2026-09-28T20:00:00Z")

    def test_unknown_expired_and_future_keys_fail(self):
        for key_id, at, message in (
            ("missing", "2026-09-28T20:00:00Z", "not in"),
            ("snapshot-key-2026-09", "2026-11-01T00:00:00Z", "outside"),
            ("snapshot-key-2026-09", "2026-08-31T23:59:59Z", "outside"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(EvidenceKeyringError, message):
                authorize_key_use(keyring(), key_id=key_id, operation="verify", at=at)

    def test_duplicate_ids_and_invalid_window_fail(self):
        duplicate = keyring()
        duplicate["keys"].append(dict(duplicate["keys"][0]))
        with self.assertRaisesRegex(EvidenceKeyringError, "unique"):
            authorize_key_use(duplicate, key_id="snapshot-key-2026-09",
                              operation="verify", at="2026-09-28T20:00:00Z")
        invalid = keyring()
        invalid["keys"][0]["verify_until"] = "2026-08-01T00:00:00Z"
        with self.assertRaisesRegex(EvidenceKeyringError, "after"):
            authorize_key_use(invalid, key_id="snapshot-key-2026-09",
                              operation="verify", at="2026-09-28T20:00:00Z")


if __name__ == "__main__":
    unittest.main()
