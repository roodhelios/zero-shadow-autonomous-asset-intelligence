"""Back up and restore a closed, model-bound osquery assessment locally."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from pathlib import Path

from database.inventory_assessment_verify import MAX_DATABASE_BYTES, verify_assessment
from engine.discovery.osquery_collector import _read


def _private_directory(path):
    info = path.lstat()
    if (os.name != "posix" or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("expected owned 0700 directory with trusted ancestors")


def _closed_bytes(path):
    _private_directory(path.parent)
    sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-journal", "-shm")]
    if any(os.path.lexists(p) for p in sidecars):
        raise ValueError("close and checkpoint the database before copying")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_DATABASE_BYTES):
            raise ValueError("expected owned, private, bounded single-link database")
        data = stream.read(MAX_DATABASE_BYTES + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or len(data) > MAX_DATABASE_BYTES
                or any(getattr(before, f) != getattr(after, f) for f in fields)
                or any(os.path.lexists(p) for p in sidecars)):
            raise ValueError("source changed while copying")
    return data


def _publish(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                         prefix=".assessment-backup-", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # The staging file is on the destination filesystem; collision never replaces.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _copy_verified(source, destination, export_data, *, expected_sha256, status):
    if os.name != "posix":
        raise ValueError("private assessment backups require POSIX")
    source, destination = Path(source), Path(destination)
    _private_directory(destination.parent)
    if os.path.lexists(destination):
        raise ValueError("destination must be a new path")
    data = _closed_bytes(source)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("backup bytes differ from independently retained digest")
    with tempfile.TemporaryDirectory(prefix="assessment-backup-check-") as directory:
        snapshot = Path(directory) / "assessment.sqlite"
        snapshot.write_bytes(data)
        snapshot.chmod(0o600)
        with closing(sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA trusted_schema=OFF")
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("assessment integrity check failed")
        verified = verify_assessment(snapshot, export_data, require_model_binding=True)
    _publish(destination, data)
    return {"schema_version": 1, "status": status, "database_sha256": digest,
            "byte_count": len(data), "asset_count": verified["asset_count"],
            "finding_count": verified["finding_count"],
            "assessment_status": verified["status"],
            "model_status": verified["model_binding"]["status"],
            "original_export_checked": True,
            "interpretation": "Unsigned local copy receipt. Preserve the digest independently. "
            "Current-model reproduction does not authenticate source, reviewer or backup history."}


def backup_assessment(source, destination, *, export_data):
    """Reproduce a closed assessment, then publish an exact private backup copy."""
    return _copy_verified(source, destination, export_data, expected_sha256=None,
                          status="assessment_backup_stored")


def restore_assessment(source, destination, *, export_data, expected_sha256):
    """Require an independent raw-file digest and full replay before publication."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("expected a separately retained lowercase SHA-256 digest")
    return _copy_verified(source, destination, export_data, expected_sha256=expected_sha256,
                          status="assessment_restored")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("backup", "restore"):
        sub = commands.add_parser(command)
        sub.add_argument("source", type=Path)
        sub.add_argument("--output", type=Path, required=True)
        sub.add_argument("--export", type=Path, required=True)
        if command == "restore":
            sub.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        options = {"export_data": _read(args.export)}
        operation = backup_assessment
        if args.command == "restore":
            operation = restore_assessment
            options["expected_sha256"] = args.expected_sha256
        result = operation(args.source, args.output, **options)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print("error: assessment copy failed; check closed private inputs, export, model and new output", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
