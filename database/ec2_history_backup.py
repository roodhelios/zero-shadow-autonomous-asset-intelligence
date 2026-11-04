"""Copy a closed EC2 review history only after original-export and head verification."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

from database.assessment_backup import _closed_bytes, _private_directory, _publish
from database.ec2_review_history import _check_digest, verify_history
from engine.discovery.osquery_collector import _read


def _copy_history(source, destination, *, export_data, expected_head, expected_sha256, status):
    _check_digest(expected_head)
    if expected_sha256 is not None:
        _check_digest(expected_sha256)
    source, destination = Path(source), Path(destination)
    _private_directory(destination.parent)
    if os.path.lexists(destination):
        raise ValueError('destination must be a new path')
    data = _closed_bytes(source)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError('backup differs from independently retained database digest')
    with tempfile.TemporaryDirectory(prefix='ec2-history-copy-check-') as directory:
        captured = Path(directory)/'history.sqlite'
        captured.write_bytes(data)
        captured.chmod(0o600)
        checked = verify_history(captured, export_data=export_data, expected_head=expected_head)
    # Publish the captured verified bytes, never a later read of the source path.
    _publish(destination, data)
    return dict(schema_version=1, status=status, database_sha256=digest, byte_count=len(data),
                review_count=checked['review_count'], decision_count=checked['decision_count'],
                head_sha256=checked['head_sha256'], original_export_checked=True,
                expected_head_checked=True,
                interpretation='Unsigned local exact-copy receipt. Independently retain database and head pins. '
                'Current-model replay does not authenticate the source, reviewer or latest history.')


def backup_history(source, destination, *, export_data, expected_head):
    return _copy_history(source, destination, export_data=export_data, expected_head=expected_head,
                         expected_sha256=None, status='ec2_history_backup_stored')


def restore_history(source, destination, *, export_data, expected_head, expected_sha256):
    _check_digest(expected_sha256)
    return _copy_history(source, destination, export_data=export_data, expected_head=expected_head,
                         expected_sha256=expected_sha256, status='ec2_history_restored')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('backup', 'restore'):
        sub = commands.add_parser(command)
        sub.add_argument('source', type=Path)
        sub.add_argument('--output', type=Path, required=True)
        sub.add_argument('--export', type=Path, required=True)
        sub.add_argument('--expected-head', required=True)
        if command == 'restore':
            sub.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        options = dict(export_data=_read(args.export), expected_head=args.expected_head)
        if args.command == 'restore':
            result = restore_history(args.source, args.output, expected_sha256=args.expected_sha256, **options)
        else:
            result = backup_history(args.source, args.output, **options)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 history copy failed; check closed private inputs, original export, pins and model',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
