"""Retain a closed EC2 review history together with its original export and replay sources."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

from database.assessment_archive import (
    MAX_ARCHIVE_BYTES, MAX_SOURCE_BYTES, REQUIREMENTS, RUNTIME_FILES,
    _archive_bytes, _canonical, _decode, _destination, _entry, _invalid_constant,
)
from database.assessment_backup import _closed_bytes, _private_directory, _publish
from database.ec2_assessment import MODEL_FILES, current_model
from database.ec2_review_history import _check_digest, verify_history
from database.inventory_assessment_verify import MAX_DATABASE_BYTES
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _read, _unique_fields

SOURCE_FILES = tuple(sorted(set(RUNTIME_FILES) | set(MODEL_FILES) | {
    'database/ec2_assessment_compare.py', 'database/ec2_review_history.py',
    'database/ec2_history_archive.py',
}))
HEADER = dict(schema_version=1, format='ec2-review-history-archive', requirements=REQUIREMENTS)


def _sources():
    root = Path(__file__).resolve().parents[1]
    sources = {name: (root/name).read_bytes() for name in SOURCE_FILES}
    if sum(map(len, sources.values())) > MAX_SOURCE_BYTES:
        raise ValueError('source snapshot exceeds 1 MiB')
    return sources


def _replay(database, export, head):
    if (not isinstance(export, bytes) or not 0 < len(export) <= MAX_INPUT_BYTES or
            not 0 < len(database) <= MAX_DATABASE_BYTES):
        raise ValueError('history or export exceeds retention bounds')
    with tempfile.TemporaryDirectory(prefix='ec2-history-archive-replay-') as directory:
        captured = Path(directory)/'history.sqlite'
        captured.write_bytes(database)
        captured.chmod(0o600)
        return verify_history(captured, export_data=export, expected_head=head)


def _summary(raw, database, report, status):
    return dict(schema_version=1, status=status, archive_sha256=hashlib.sha256(raw).hexdigest(),
                archive_bytes=len(raw), database_sha256=hashlib.sha256(database).hexdigest(),
                review_count=report['review_count'], decision_count=report['decision_count'],
                head_sha256=report['head_sha256'], expected_head_checked=True,
                original_export_checked=True, source_files=len(SOURCE_FILES),
                interpretation='Unsigned local archive receipt under independent archive and history-head pins. '
                'Archived source remains data and must match a trusted checkout. '
                'No source authentication, pin freshness, encryption or historical code execution.')


def create_archive(history, destination, *, export_data, expected_head):
    _check_digest(expected_head)
    if not isinstance(export_data, bytes) or not 0 < len(export_data) <= MAX_INPUT_BYTES:
        raise ValueError('original export exceeds 4 MiB or is empty')
    destination = _destination(destination)
    database = _closed_bytes(Path(history))
    report = _replay(database, export_data, expected_head)
    document = dict(HEADER, model=current_model(), head_sha256=expected_head,
                    history=_entry(database), export=_entry(export_data),
                    sources={name: _entry(data) for name, data in _sources().items()})
    raw = (_canonical(document)+'\n').encode('ascii')
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError('archive exceeds 32 MiB')
    _publish(destination, raw)
    return _summary(raw, database, report, 'ec2_history_archive_stored')


def _load(path, archive_pin, expected_head):
    _check_digest(archive_pin)
    _check_digest(expected_head)
    raw = _archive_bytes(path)
    if hashlib.sha256(raw).hexdigest() != archive_pin:
        raise ValueError('archive differs from independent pin')
    document = json.loads(raw.decode('ascii'), object_pairs_hook=_unique_fields,
                          parse_constant=_invalid_constant)
    header = dict(HEADER, model=current_model(), head_sha256=expected_head)
    if (type(document) is not dict or set(document) != set(header) | {'history', 'export', 'sources'} or
            _canonical({key: document[key] for key in header}) != _canonical(header) or
            (_canonical(document)+'\n').encode('ascii') != raw):
        raise ValueError('unsupported canonical archive, model or history head')
    sources = document['sources']
    if type(sources) is not dict or set(sources) != set(SOURCE_FILES):
        raise ValueError('unsupported replay source snapshot')
    for name, data in _sources().items():
        if _decode(sources[name], MAX_SOURCE_BYTES) != data:
            raise ValueError('archived source differs from trusted checkout')
    database = _decode(document['history'], MAX_DATABASE_BYTES)
    export = _decode(document['export'], MAX_INPUT_BYTES)
    return raw, database, export, _replay(database, export, expected_head)


def verify_archive(path, *, expected_sha256, expected_head):
    raw, database, _, report = _load(path, expected_sha256, expected_head)
    return _summary(raw, database, report, 'ec2_history_archive_verified')


def restore_archive(path, destination, *, expected_sha256, expected_head):
    destination = Path(destination)
    _private_directory(destination.parent)
    raw, database, export, report = _load(path, expected_sha256, expected_head)
    destination.mkdir(mode=0o700)
    try:
        _publish(destination/'history.sqlite', database)
        _publish(destination/'export.json', export)
        result = _summary(raw, database, report, 'ec2_history_archive_restored')
        # Publish completion last. This is not an atomic directory transaction.
        _publish(destination/'RESTORE.json', (_canonical(result)+'\n').encode('ascii'))
    except BaseException:
        shutil.rmtree(destination)
        raise
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('create', 'verify', 'restore'):
        sub = commands.add_parser(name)
        sub.add_argument('source', type=Path)
        sub.add_argument('--expected-head', required=True)
        if name == 'create':
            sub.add_argument('--export', required=True, type=Path)
        else:
            sub.add_argument('--expected-sha256', required=True)
        if name != 'verify':
            sub.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        # Pin syntax is checked before source access, including the create export read.
        _check_digest(args.expected_head)
        if args.command == 'create':
            result = create_archive(args.source, args.output, export_data=_read(args.export),
                                    expected_head=args.expected_head)
        else:
            options = dict(expected_sha256=args.expected_sha256, expected_head=args.expected_head)
            result = (verify_archive(args.source, **options) if args.command == 'verify' else
                      restore_archive(args.source, args.output, **options))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 history archive failed; inspect private closed inputs, checkout, independent pins and new output',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
