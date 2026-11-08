"""Select a reproduced EC2 history revision and advance only along its retained lineage."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import uuid

from database.assessment_backup import _closed_bytes, _private_directory, _publish
from database.ec2_assessment import _canonical
from database.ec2_assessment_compare import _items
from database.ec2_review_history import _check_digest, _head, _load, _sha, MAX_REVIEWS, MAX_DECISIONS
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _read, _unique_fields

MAX_ENROLLMENT_BYTES = 4096
PURPOSE = 'zero-shadow-ec2-history-enrollment-v1'
FIELDS = {'schema_version', 'purpose', 'enrollment_id', 'revision', 'previous_enrollment_sha256',
          'review_count', 'decision_count', 'head_sha256', 'database_sha256', 'export_sha256',
          'discovery_sha256', 'model_sha256'}


def _bytes(document):
    return (_canonical(document)+'\n').encode('utf-8')


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _parse(data, expected_sha256):
    _check_digest(expected_sha256)
    if (not isinstance(data, bytes) or not 0 < len(data) <= MAX_ENROLLMENT_BYTES or
            _digest(data) != expected_sha256):
        raise ValueError('enrollment differs from independently selected digest')
    document = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields)
    if (not isinstance(document, dict) or set(document) != FIELDS or _bytes(document) != data or
            type(document['schema_version']) is not int or document['schema_version'] != 1 or
            document['purpose'] != PURPOSE or not isinstance(document['enrollment_id'], str) or
            re.fullmatch('[0-9a-f]{32}', document['enrollment_id']) is None or
            any(type(document[key]) is not int for key in ('revision', 'review_count', 'decision_count')) or
            not 1 <= document['revision'] <= document['review_count'] <= MAX_REVIEWS or
            not 0 <= document['decision_count'] <= MAX_DECISIONS):
        raise ValueError('unsupported canonical enrollment')
    for key in ('head_sha256', 'database_sha256', 'export_sha256', 'discovery_sha256', 'model_sha256'):
        _check_digest(document[key])
    if document['revision'] == 1:
        if document['previous_enrollment_sha256'] is not None:
            raise ValueError('initial enrollment has no predecessor')
    else:
        _check_digest(document['previous_enrollment_sha256'])
    return document


def _capture(history, export_data, expected_head):
    _check_digest(expected_head)
    if not isinstance(export_data, bytes) or not 0 < len(export_data) <= MAX_INPUT_BYTES:
        raise ValueError('expected bounded original export bytes')
    database = _closed_bytes(Path(history))
    with tempfile.TemporaryDirectory(prefix='ec2-enrollment-replay-') as directory:
        captured = Path(directory)/'history.sqlite'
        captured.write_bytes(database)
        captured.chmod(0o600)
        records, summary = _load(captured, export_data, expected_head=expected_head)
    return database, records, summary


def _document(database, records, summary, export_data, *, enrollment_id, revision, previous):
    return dict(schema_version=1, purpose=PURPOSE, enrollment_id=enrollment_id, revision=revision,
        previous_enrollment_sha256=previous, review_count=summary['review_count'],
        decision_count=summary['decision_count'], head_sha256=summary['head_sha256'],
        database_sha256=_digest(database), export_sha256=_digest(export_data),
        discovery_sha256=_sha(_canonical(records[0]['discovery'])),
        model_sha256=_sha(_canonical(records[0]['model'])))


def _receipt(document, data, status):
    return dict(status=status, enrollment_sha256=_digest(data), enrollment_id=document['enrollment_id'],
        revision=document['revision'], review_count=document['review_count'],
        decision_count=document['decision_count'], head_sha256=document['head_sha256'],
        original_export_checked=True, latest_head_established=False,
        interpretation='Unsigned local selection under an independent enrollment pin. Lineage and current-model '
        'replay do not authenticate a reviewer, source, journal identity or latest accepted head.')


def _publish_selection(document, output, status):
    data = _bytes(document)
    _parse(data, _digest(data))
    destination = Path(output)
    _private_directory(destination.parent)
    _publish(destination, data)
    return _receipt(document, data, status)


def enroll_history(history, output, *, export_data, expected_head):
    database, records, summary = _capture(history, export_data, expected_head)
    document = _document(database, records, summary, export_data, enrollment_id=uuid.uuid4().hex,
                         revision=1, previous=None)
    return _publish_selection(document, output, 'ec2_history_enrolled')


def advance_enrollment(history, output, *, enrollment_data, expected_enrollment_sha256,
                       export_data, expected_head):
    previous = _parse(enrollment_data, expected_enrollment_sha256)
    database, records, summary = _capture(history, export_data, expected_head)
    candidate = _document(database, records, summary, export_data,
        enrollment_id=previous['enrollment_id'], revision=previous['revision']+1,
        previous=expected_enrollment_sha256)
    _check_extension(records, candidate, previous)
    return _publish_selection(candidate, output, 'ec2_history_enrollment_advanced')


def _check_extension(records, candidate, previous):
    if len(records) <= previous['review_count']:
        raise ValueError('advance requires a strictly longer history')
    prefix_head = None
    prefix_decisions = 0
    for sequence, record in enumerate(records[:previous['review_count']], 1):
        prefix_head = _head(sequence, prefix_head, _sha(_canonical(record)))
        prefix_decisions += len(_items(record))
    if (prefix_head != previous['head_sha256'] or prefix_decisions != previous['decision_count'] or
            any(candidate[key] != previous[key] for key in ('export_sha256', 'discovery_sha256', 'model_sha256'))):
        raise ValueError('new history is not an extension of the selected lineage')


def verify_enrollment(history, *, enrollment_data, expected_enrollment_sha256, export_data,
                      previous_enrollment_data=None, expected_previous_sha256=None):
    selected = _parse(enrollment_data, expected_enrollment_sha256)
    previous = None
    if previous_enrollment_data is not None or expected_previous_sha256 is not None:
        previous = _parse(previous_enrollment_data, expected_previous_sha256)
        if (selected['enrollment_id'] != previous['enrollment_id'] or
                selected['revision'] != previous['revision'] + 1 or
                selected['previous_enrollment_sha256'] != expected_previous_sha256):
            raise ValueError('selection does not directly advance the trusted checkpoint')
    database, records, summary = _capture(history, export_data, selected['head_sha256'])
    candidate = _document(database, records, summary, export_data, enrollment_id=selected['enrollment_id'],
                         revision=selected['revision'], previous=selected['previous_enrollment_sha256'])
    if _bytes(candidate) != enrollment_data:
        raise ValueError('history differs from the independently selected revision')
    result = _receipt(selected, enrollment_data, 'ec2_history_enrollment_verified')
    if previous is not None:
        _check_extension(records, candidate, previous)
        result['previous_checkpoint_verified'] = True
    return result


def read_enrollment(path):
    path = Path(path)
    _private_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_uid != os.getuid() or info.st_nlink != 1 or not 0 < info.st_size <= MAX_ENROLLMENT_BYTES):
            raise ValueError('expected private bounded enrollment')
        with os.fdopen(descriptor, 'rb') as stream:
            descriptor = None
            data = stream.read(MAX_ENROLLMENT_BYTES+1)
        if len(data) != info.st_size:
            raise ValueError('enrollment changed during capture')
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('enroll', 'advance', 'verify'):
        sub = commands.add_parser(name)
        sub.add_argument('history', type=Path)
        sub.add_argument('--export', type=Path, required=True)
        if name != 'verify':
            sub.add_argument('--expected-head', required=True)
            sub.add_argument('--output', type=Path, required=True)
        if name != 'enroll':
            sub.add_argument('--enrollment', type=Path, required=True)
            sub.add_argument('--expected-enrollment-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        options = {}
        if args.command != 'verify':
            _check_digest(args.expected_head)
            options['expected_head'] = args.expected_head
        if args.command != 'enroll':
            _check_digest(args.expected_enrollment_sha256)
            data = read_enrollment(args.enrollment)
            _parse(data, args.expected_enrollment_sha256)  # Pin before reading history or original export.
            options.update(enrollment_data=data, expected_enrollment_sha256=args.expected_enrollment_sha256)
        options['export_data'] = _read(args.export)
        if args.command == 'verify':
            result = verify_enrollment(args.history, **options)
        elif args.command == 'advance':
            result = advance_enrollment(args.history, args.output, **options)
        else:
            result = enroll_history(args.history, args.output, **options)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 history enrollment failed; inspect private originals, lineage, model and independent pins',
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
