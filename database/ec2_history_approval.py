"""Approve a reproduced EC2 history with a separately pinned Ed25519 authority."""

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from database.ec2_assessment import _canonical
from database.ec2_review_history import _check_digest, verify_history
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _read, _unique_fields

PURPOSE = "zero-shadow-ec2-history-approval-v1"
DOMAIN = PURPOSE.encode("ascii") + b"\x00"
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}", re.ASCII)
FIELDS = {"schema_version", "purpose", "key_id", "audience", "head_sha256", "export_sha256",
          "review_count", "decision_count", "issued_at", "expires_at", "signature_b64"}


def _crypto():
    try:
        from nacl.signing import SigningKey, VerifyKey
    except ImportError:
        raise ValueError("install requirements-review.txt for Ed25519 approval") from None
    return SigningKey, VerifyKey


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("expected a lowercase identifier of 3 to 64 characters")
    return value


def _time(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("expected a whole-second UTC timestamp ending in Z")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _decode(value, size):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("invalid base64 value")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("expected canonical base64 with the required length")
    return raw


def _json(data, limit):
    if not isinstance(data, bytes) or len(data) > limit:
        raise ValueError("JSON input limit exceeded")
    def reject(value):
        raise ValueError("non-finite JSON value")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=reject)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def _policy(data, pin, audience, key_id, at, *, signing=False):
    _check_digest(pin)
    if not isinstance(data, bytes) or len(data) > 64 * 1024 or hashlib.sha256(data).hexdigest() != pin:
        raise ValueError("authority policy does not match the required pin")
    policy = _json(data, 64 * 1024)
    if (set(policy) != {"schema_version", "purpose", "audience", "max_validity_seconds", "keys"} or
            type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or
            policy["purpose"] != PURPOSE or policy["audience"] != _identifier(audience)):
        raise ValueError("unsupported authority policy or recipient")
    maximum = policy["max_validity_seconds"]
    keys = policy["keys"]
    if type(maximum) is not int or not 1 <= maximum <= 604800 or not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        raise ValueError("invalid authority limits")
    seen_ids, seen_keys, selected = set(), set(), None
    for key in keys:
        if not isinstance(key, dict) or set(key) != {"key_id", "public_key_b64", "state", "not_before", "not_after"}:
            raise ValueError("invalid authority key shape")
        identifier = _identifier(key["key_id"])
        public = _decode(key["public_key_b64"], 32)
        start, end = _time(key["not_before"]), _time(key["not_after"])
        if (identifier in seen_ids or public in seen_keys or start >= end or
                key["state"] not in ("active", "retired", "revoked")):
            raise ValueError("invalid or duplicate authority key")
        seen_ids.add(identifier); seen_keys.add(public)
        if identifier == _identifier(key_id):
            selected = key
    if selected is None or selected["state"] == "revoked" or (signing and selected["state"] != "active"):
        raise ValueError("authority key cannot perform this operation")
    if not _time(selected["not_before"]) <= _time(at) < _time(selected["not_after"]):
        raise ValueError("authority key is outside its current validity window")
    return selected, maximum


def _context(approval, key, maximum, at):
    if (set(approval) != FIELDS or type(approval["schema_version"]) is not int or
            approval["schema_version"] != 1 or approval["purpose"] != PURPOSE):
        raise ValueError("unsupported history approval")
    _check_digest(approval["head_sha256"]); _check_digest(approval["export_sha256"])
    for field, limit in (("review_count", 32), ("decision_count", 20000)):
        if type(approval[field]) is not int or not 1 <= approval[field] <= limit:
            raise ValueError("invalid approval counts")
    issued, expires, now = _time(approval["issued_at"]), _time(approval["expires_at"]), _time(at)
    if (not issued <= now < expires or not 0 < (expires-issued).total_seconds() <= maximum or
            issued < _time(key["not_before"]) or expires > _time(key["not_after"])):
        raise ValueError("approval is future, expired or exceeds its allowed window")


def _message(approval):
    return DOMAIN + _canonical({k: v for k, v in approval.items() if k != "signature_b64"}).encode("ascii")


def _export(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise ValueError("original export must contain at most 4 MiB")
    return hashlib.sha256(data).hexdigest()


def approve_history(history, *, export_data, policy_data, expected_policy_sha256, audience,
                    key_id, seed, issued_at, expires_at, at):
    """Sign only after full same-model reproduction under an active enrolled key."""
    key, maximum = _policy(policy_data, expected_policy_sha256, audience, key_id, at, signing=True)
    SigningKey, _ = _crypto()
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("expected a private 32-byte Ed25519 seed")
    signer = SigningKey(seed)
    if signer.verify_key.encode() != _decode(key["public_key_b64"], 32):
        raise ValueError("private seed does not match the enrolled key")
    export_digest = _export(export_data)
    report = verify_history(history, export_data=export_data)
    approval = {"schema_version": 1, "purpose": PURPOSE, "key_id": key_id, "audience": audience,
                "head_sha256": report["head_sha256"], "export_sha256": export_digest,
                "review_count": report["review_count"], "decision_count": report["decision_count"],
                "issued_at": issued_at, "expires_at": expires_at, "signature_b64": ""}
    _context(approval, key, maximum, at)
    approval["signature_b64"] = base64.b64encode(signer.sign(_message(approval)).signature).decode("ascii")
    return approval


def verify_approval(history, approval_data, *, export_data, policy_data, expected_policy_sha256, audience, at):
    """Authenticate approval context, then reproduce every retained decision."""
    approval = _json(approval_data, 4096)
    if set(approval) != FIELDS:
        raise ValueError("unsupported history approval fields")
    key, maximum = _policy(policy_data, expected_policy_sha256, audience, approval["key_id"], at)
    if approval["audience"] != audience:
        raise ValueError("approval belongs to another recipient")
    _context(approval, key, maximum, at)
    _, VerifyKey = _crypto()
    from nacl.exceptions import BadSignatureError
    try:
        VerifyKey(_decode(key["public_key_b64"], 32)).verify(_message(approval), _decode(approval["signature_b64"], 64))
    except BadSignatureError:
        raise ValueError("history approval signature did not verify") from None
    if _export(export_data) != approval["export_sha256"]:
        raise ValueError("original export differs from the approved bytes")
    report = verify_history(history, export_data=export_data, expected_head=approval["head_sha256"])
    if any(report[field] != approval[field] for field in ("review_count", "decision_count")):
        raise ValueError("approved counts did not reproduce")
    return dict(report, status="ec2_history_approval_verified", authority_key_id=approval["key_id"],
                authority_policy_sha256=expected_policy_sha256)


def _file(path, limit, *, private=False):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("expected a regular local file")
        if private and (os.name != "posix" or info.st_uid != os.getuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError("private seed must be owned, mode 0600 and have one hard link")
        data = handle.read(limit+1)
    if len(data) > limit:
        raise ValueError("local file exceeds its size limit")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for operation in ("sign", "verify"):
        sub = commands.add_parser(operation)
        sub.add_argument("history", type=Path)
        if operation == "sign":
            sub.add_argument("--seed-file", type=Path, required=True)
            sub.add_argument("--key-id", required=True)
            sub.add_argument("--issued-at", required=True)
            sub.add_argument("--expires-at", required=True)
            sub.add_argument("--output", type=Path, required=True)
        else:
            sub.add_argument("approval", type=Path)
        sub.add_argument("--export", type=Path, required=True)
        sub.add_argument("--policy", type=Path, required=True)
        sub.add_argument("--expected-policy-sha256", required=True)
        sub.add_argument("--audience", required=True)
        sub.add_argument("--at", required=True, help="explicit trusted evaluation clock; UTC seconds ending in Z")
    args = parser.parse_args(argv)
    try:
        shared = dict(export_data=_read(args.export), policy_data=_file(args.policy, 64 * 1024),
                      expected_policy_sha256=args.expected_policy_sha256, audience=args.audience, at=args.at)
        if args.command == "sign":
            approval = approve_history(args.history, **shared, seed=_file(args.seed_file, 32, private=True),
                key_id=args.key_id, issued_at=args.issued_at, expires_at=args.expires_at)
            _publish(args.output, _canonical(approval)+"\n")
            result = {"schema_version": 1, "status": "ec2_history_approval_stored"}
        else:
            result = verify_approval(args.history, _file(args.approval, 4096), **shared)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError,
            RecursionError, OverflowError):
        print("error: EC2 history approval failed; check private inputs, authority pin, recipient and clock",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
