"""Private, non-executable archives for closed model-bound osquery assessments."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing

from database.assessment_backup import _closed_bytes, _private_directory, _publish
from database.assessment_model import SOURCE_FILES, current_contract
from database.inventory_assessment_verify import MAX_DATABASE_BYTES, verify_assessment
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _read, _unique_fields

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
RUNTIME_FILES = tuple(sorted(set(SOURCE_FILES) | {
    'engine/__init__.py', 'engine/correlation/__init__.py', 'engine/discovery/__init__.py',
    'engine/discovery/fixture_discovery.py', 'database/assessment_model.py',
    'database/assessment_backup.py', 'database/assessment_archive.py',
    'database/inventory_assessment_cli.py', 'database/inventory_assessment_verify.py',
    'database/inventory_cli.py', 'database/inventory_export_cli.py',
    'database/inventory_receipt.py', 'database/evidence_reader.py',
    'database/repository.py', 'database/schema.sql',
}))
REQUIREMENTS = {'python': '3.11 or newer', 'dependencies': 'standard-library', 'storage': 'POSIX'}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def _sources():
    root = Path(__file__).resolve().parents[1]
    sources = {name: (root/name).read_bytes() for name in RUNTIME_FILES}
    if sum(map(len, sources.values())) > MAX_SOURCE_BYTES:
        raise ValueError('source snapshot exceeds 1 MiB')
    return sources


def _entry(data):
    return {'bytes_b64': base64.b64encode(data).decode('ascii'), 'byte_count': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def _decode(entry, limit):
    if (type(entry) is not dict or set(entry) != {'bytes_b64', 'byte_count', 'sha256'} or
            type(entry['byte_count']) is not int or not 0 <= entry['byte_count'] <= limit or
            type(entry['bytes_b64']) is not str or len(entry['bytes_b64']) > 4*((limit+2)//3)):
        raise ValueError('invalid bounded archive entry')
    data = base64.b64decode(entry['bytes_b64'], validate=True)
    if _canonical(entry) != _canonical(_entry(data)) or len(data) > limit:
        raise ValueError('archive entry bytes or digest differ')
    return data


def _reproduce(data, export):
    if not 0 < len(data) <= MAX_DATABASE_BYTES or len(export) > MAX_INPUT_BYTES:
        raise ValueError('assessment or export exceeds bounds')
    with tempfile.TemporaryDirectory(prefix='assessment-archive-check-') as name:
        path = Path(name)/'assessment.sqlite'; path.write_bytes(data); path.chmod(0o600)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError('assessment integrity check failed')
        return verify_assessment(path, export, require_model_binding=True)


def _destination(path):
    path = Path(path); _private_directory(path.parent)
    if os.path.lexists(path):
        raise ValueError('output must be a new private path')
    return path


def _receipt(raw, database, verified, status):
    return {'schema_version': 1, 'status': status, 'archive_sha256': hashlib.sha256(raw).hexdigest(),
        'database_sha256': hashlib.sha256(database).hexdigest(), 'archive_bytes': len(raw),
        'asset_count': verified['asset_count'], 'finding_count': verified['finding_count'],
        'assessment_status': verified['status'], 'model_status': verified['model_binding']['status'],
        'source_files': len(RUNTIME_FILES), 'original_export_checked': True,
        'interpretation': 'Unsigned local archive receipt. Retain the archive digest independently. '
        'Archived code is data only; no source authentication, encryption or historical replay.'}


def create_archive(source, destination, *, export_data):
    destination = _destination(destination)
    data = _closed_bytes(Path(source))
    verified = _reproduce(data, export_data)
    entries = {'assessment.sqlite': _entry(data), 'export.json': _entry(export_data)}
    entries.update({'source/'+name: _entry(content) for name, content in _sources().items()})
    raw = (_canonical({'schema_version': 1, 'format': 'osquery-assessment-archive',
        'model': current_contract(), 'requirements': REQUIREMENTS, 'entries': entries})+'\n').encode('ascii')
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError('archive exceeds 32 MiB')
    _publish(destination, raw)
    return _receipt(raw, data, verified, 'assessment_archive_stored')


def _archive_bytes(path):
    path = Path(path); _private_directory(path.parent)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > MAX_ARCHIVE_BYTES):
            raise ValueError('expected bounded owned single-link 0600 archive')
        raw = source.read(MAX_ARCHIVE_BYTES+1); after = os.fstat(source.fileno())
    if (len(raw) != before.st_size or len(raw) > MAX_ARCHIVE_BYTES or
            any(getattr(before, field) != getattr(after, field) for field in ('st_size', 'st_mtime_ns', 'st_ctime_ns'))):
        raise ValueError('archive changed while reading')
    return raw


def _invalid_constant(value):
    raise ValueError('non-finite JSON number')


def _load_verified(path, expected_sha256):
    if type(expected_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('expected an independently retained archive digest')
    raw = _archive_bytes(path)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('archive differs from independent pin')
    document = json.loads(raw.decode('ascii'), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    header = {'schema_version': 1, 'format': 'osquery-assessment-archive',
              'model': current_contract(), 'requirements': REQUIREMENTS}
    if (type(document) is not dict or set(document) != set(header) | {'entries'} or
            _canonical({key: document[key] for key in header}) != _canonical(header)):
        raise ValueError('unsupported archive or model contract')
    entries = document['entries']; sources = _sources()
    if type(entries) is not dict or set(entries) != {'assessment.sqlite', 'export.json'} | {'source/'+n for n in sources}:
        raise ValueError('unsupported archive entries')
    for name, content in sources.items():
        if _decode(entries['source/'+name], MAX_SOURCE_BYTES) != content:
            raise ValueError('archive source snapshot differs from trusted checkout')
    data = _decode(entries['assessment.sqlite'], MAX_DATABASE_BYTES)
    export = _decode(entries['export.json'], MAX_INPUT_BYTES)
    return raw, data, _reproduce(data, export)


def verify_archive(path, *, expected_sha256):
    raw, data, verified = _load_verified(path, expected_sha256)
    return _receipt(raw, data, verified, 'assessment_archive_verified')


def restore_archive(path, destination, *, expected_sha256):
    destination = _destination(destination)
    raw, data, verified = _load_verified(path, expected_sha256)
    _publish(destination, data)
    return _receipt(raw, data, verified, 'assessment_archive_restored')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('create', 'verify', 'restore'):
        sub = commands.add_parser(name); sub.add_argument('source', type=Path)
        if name == 'create': sub.add_argument('--export', required=True, type=Path)
        else: sub.add_argument('--expected-sha256', required=True)
        if name != 'verify': sub.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != 'posix': raise ValueError('private archive requires POSIX')
        if args.command == 'create': result = create_archive(args.source, args.output, export_data=_read(args.export))
        elif args.command == 'verify': result = verify_archive(args.source, expected_sha256=args.expected_sha256)
        else: result = restore_archive(args.source, args.output, expected_sha256=args.expected_sha256)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError, RecursionError, OverflowError):
        print('error: assessment archive failed; check private closed inputs, model, pin and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
