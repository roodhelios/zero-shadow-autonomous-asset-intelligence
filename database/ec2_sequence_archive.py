"""Retain and restore a closed EC2 sequence with its original exports and checkpoint."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile

from database.assessment_archive import (RUNTIME_FILES, REQUIREMENTS, MAX_SOURCE_BYTES,
    _entry, _decode, _archive_bytes, _canonical, _invalid_constant, _destination)
from database.assessment_backup import _closed_bytes, _private_directory, _publish
from database.ec2_observation_timeline import MAX_BATCHES, MAX_TOTAL_EXPORT_BYTES
from database.ec2_timeline_checkpoint import (MAX_CHECKPOINT_BYTES, MAX_COVERAGE_BYTES,
    _coverage_bytes, _digest, read_checkpoint, assess_sequence)
from database.inventory_assessment_verify import MAX_DATABASE_BYTES
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _read, _unique_fields

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
SOURCE_FILES = tuple(sorted(set(RUNTIME_FILES) | {
    'database/ec2_sequence_archive.py', 'database/ec2_inventory.py',
    'database/ec2_inventory_compare.py', 'database/ec2_observation_timeline.py',
    'database/ec2_timeline_checkpoint.py', 'engine/discovery/aws_discovery.py',
}))
HEADER = dict(schema_version=1, format='ec2-sequence-archive', requirements=REQUIREMENTS)


def _sources():
    root = Path(__file__).resolve().parents[1]
    sources = {name: (root/name).read_bytes() for name in SOURCE_FILES}
    if sum(map(len, sources.values())) > MAX_SOURCE_BYTES:
        raise ValueError('source snapshot exceeds 1 MiB')
    return sources


def _reproduce(copies, checkpoint, checkpoint_pin):
    # Only the captured copies feed replay. Never read a mutable original again.
    with tempfile.TemporaryDirectory(prefix='ec2-archive-replay-') as name:
        batches = []
        for sequence, (database, export) in enumerate(copies, 1):
            path = Path(name)/f'{sequence:02d}.sqlite'
            path.write_bytes(database); path.chmod(0o600)
            batches.append((path, export))
        return assess_sequence(batches, checkpoint, expected_checkpoint_sha256=checkpoint_pin)


def _summary(raw, report, status):
    return dict(schema_version=1, status=status, archive_sha256=hashlib.sha256(raw).hexdigest(),
        archive_bytes=len(raw), supplied_batch_count=report['supplied_batch_count'],
        expected_batch_count=report['expected_batch_count'], counts=report['counts'],
        requirements_satisfied=report['requirements_satisfied'], checkpoint_sha256=report['checkpoint_sha256'],
        source_files=len(SOURCE_FILES), original_exports_checked=True,
        interpretation='Private local retention under independent archive and recipient-checkpoint pins. '
        'Archived code is data only and must match the trusted current checkout. Gaps remain gaps. '
        'No live collection, source authentication, checkpoint freshness, encryption or historical dispatch.')


def create_archive(batches, destination, *, checkpoint_data, expected_checkpoint_sha256):
    destination = _destination(destination)
    read_checkpoint(checkpoint_data, expected_sha256=expected_checkpoint_sha256)
    if not isinstance(batches, (tuple, list)) or not 2 <= len(batches) <= MAX_BATCHES:
        raise ValueError('archive requires 2 to 16 ordered batches')
    copies, total = [], 0
    for database, export in batches:
        if not isinstance(export, bytes) or len(export) > MAX_INPUT_BYTES:
            raise ValueError('original export exceeds 4 MiB')
        total += len(export)
        if total > MAX_TOTAL_EXPORT_BYTES:
            raise ValueError('combined exports exceed 16 MiB')
        copies.append((_closed_bytes(Path(database)), export))
        # Bound memory before serializing base64 or capturing another database.
        if sum(len(data)+len(source) for data, source in copies) > MAX_ARCHIVE_BYTES//2:
            raise ValueError('combined evidence exceeds 16 MiB retention bound')
    report = _reproduce(copies, checkpoint_data, expected_checkpoint_sha256)
    document = dict(HEADER, checkpoint=_entry(checkpoint_data), coverage=_entry(_coverage_bytes(report)),
        batches=[dict(database=_entry(data), export=_entry(export)) for data, export in copies],
        sources={name:_entry(data) for name,data in _sources().items()})
    raw = (_canonical(document)+'\n').encode('ascii')
    if len(raw) > MAX_ARCHIVE_BYTES: raise ValueError('archive exceeds 32 MiB')
    _publish(destination, raw)
    return _summary(raw, report, 'ec2_sequence_archive_stored')


def _load(path, archive_pin, checkpoint_pin):
    _digest(archive_pin); _digest(checkpoint_pin)
    raw = _archive_bytes(path)
    if hashlib.sha256(raw).hexdigest() != archive_pin:
        raise ValueError('archive differs from independent pin')
    document = json.loads(raw.decode('ascii'), object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)
    if (type(document) is not dict or set(document) != set(HEADER) | {'checkpoint','coverage','batches','sources'} or
            _canonical({key:document[key] for key in HEADER}) != _canonical(HEADER) or
            (_canonical(document)+'\n').encode('ascii') != raw):
        raise ValueError('unsupported canonical archive')
    sources = document['sources']
    if type(sources) is not dict or set(sources) != set(SOURCE_FILES):
        raise ValueError('unsupported source snapshot')
    for name, data in _sources().items():
        if _decode(sources[name], MAX_SOURCE_BYTES) != data:
            raise ValueError('archived source differs from trusted checkout')
    checkpoint = _decode(document['checkpoint'], MAX_CHECKPOINT_BYTES)
    read_checkpoint(checkpoint, expected_sha256=checkpoint_pin)
    entries = document['batches']
    if type(entries) is not list or not 2 <= len(entries) <= MAX_BATCHES:
        raise ValueError('unsupported archived batch count')
    copies, total, combined = [], 0, 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'database','export'}:
            raise ValueError('unsupported archived batch')
        database = _decode(entry['database'], MAX_DATABASE_BYTES)
        export = _decode(entry['export'], MAX_INPUT_BYTES)
        total += len(export); combined += len(database)+len(export)
        if total > MAX_TOTAL_EXPORT_BYTES or combined > MAX_ARCHIVE_BYTES//2:
            raise ValueError('combined evidence exceeds retention bounds')
        copies.append((database, export))
    retained = _decode(document['coverage'], MAX_COVERAGE_BYTES)
    report = _reproduce(copies, checkpoint, checkpoint_pin)
    if retained != _coverage_bytes(report):
        raise ValueError('complete coverage report did not reproduce')
    return raw, copies, checkpoint, retained, report


def verify_archive(path, *, expected_sha256, expected_checkpoint_sha256):
    raw, _, _, _, report = _load(path, expected_sha256, expected_checkpoint_sha256)
    return _summary(raw, report, 'ec2_sequence_archive_verified')


def restore_archive(path, destination, *, expected_sha256, expected_checkpoint_sha256):
    destination = Path(destination); _private_directory(destination.parent)
    raw, copies, checkpoint, coverage, report = _load(path, expected_sha256, expected_checkpoint_sha256)
    destination.mkdir(mode=0o700)  # Exclusive. Existing directories are preserved.
    try:
        for sequence, (database, export) in enumerate(copies, 1):
            _publish(destination/f'{sequence:02d}.sqlite', database)
            _publish(destination/f'{sequence:02d}.json', export)
        _publish(destination/'checkpoint.json', checkpoint)
        _publish(destination/'coverage.json', coverage)
        result = _summary(raw, report, 'ec2_sequence_archive_restored')
        # Last file marks completion, not an atomic directory rename or permission grant.
        _publish(destination/'RESTORE.json', (_canonical(result)+'\n').encode('ascii'))
    except BaseException:
        shutil.rmtree(destination)
        raise
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('create')
    create.add_argument('--batch', nargs=2, action='append', required=True, metavar=('DATABASE','EXPORT'))
    create.add_argument('--checkpoint', required=True, type=Path)
    create.add_argument('--output', required=True, type=Path)
    create.add_argument('--expected-checkpoint-sha256', required=True)
    for name in ('verify','restore'):
        command = commands.add_parser(name); command.add_argument('archive', type=Path)
        command.add_argument('--expected-sha256', required=True)
        command.add_argument('--expected-checkpoint-sha256', required=True)
        if name == 'restore': command.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            read_checkpoint(_read(args.checkpoint), expected_sha256=args.expected_checkpoint_sha256)
            if not 2 <= len(args.batch) <= MAX_BATCHES: raise ValueError('expected 2 to 16 batches')
            batches = []; total = 0
            for database, export in args.batch:
                data = _read(Path(export)); total += len(data)
                if total > MAX_TOTAL_EXPORT_BYTES: raise ValueError('combined exports exceed 16 MiB')
                batches.append((Path(database), data))
            result = create_archive(batches, args.output, checkpoint_data=_read(args.checkpoint),
                expected_checkpoint_sha256=args.expected_checkpoint_sha256)
        else:
            options = dict(expected_sha256=args.expected_sha256, expected_checkpoint_sha256=args.expected_checkpoint_sha256)
            result = (verify_archive(args.archive, **options) if args.command == 'verify' else
                      restore_archive(args.archive, args.output, **options))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 sequence archive failed; inspect private closed inputs, checkout, independent pins and new output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['requirements_satisfied'] else 1


if __name__ == '__main__': raise SystemExit(main())
