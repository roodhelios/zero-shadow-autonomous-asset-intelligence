"""Reproduce a received dated queue using independently retained pins and review date."""

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import sqlite3

from database.inventory_assessment_queue import build_queues
from engine.discovery.osquery_collector import _read, _unique_fields

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))


def _invalid(value):
    raise ValueError('non-finite report value')


def verify_queues(data, database, export_data, *, expected_report_sha256, expected_database_sha256, as_of):
    for pin in (expected_report_sha256, expected_database_sha256):
        if not isinstance(pin, str) or re.fullmatch('[0-9a-f]{64}', pin) is None:
            raise ValueError('independent lowercase SHA-256 pins required')
    if type(as_of) is not date:
        raise ValueError('independent review date required')
    if type(data) is not bytes or not 0 < len(data) <= MAX_REPORT_BYTES or hashlib.sha256(data).hexdigest() != expected_report_sha256:
        raise ValueError('report differs from the independent pin or exceeds bounds')
    retained = json.loads(data.decode('utf-8'), object_pairs_hook=_unique_fields, parse_constant=_invalid)
    if type(retained) is not dict:
        raise ValueError('report must be a JSON object')
    rendered = _canonical(retained)
    expected = build_queues(database, export_data, expected_database_sha256=expected_database_sha256, as_of=as_of)
    if rendered != _canonical(expected):
        raise ValueError('complete dated queue report did not reproduce')
    queues = expected['queue_document']['queues']
    return {'status': 'assessment_queue_reproduced', 'as_of': as_of.isoformat(),
            'report_sha256': expected_report_sha256, 'database_sha256': expected_database_sha256,
            'assigned_item_count': queues['assigned_item_count'], 'unassigned_item_count': queues['unassigned_item_count'],
            'changed_item_count': expected['queue_document']['priority_comparison']['changed_item_count'],
            'interpretation': 'Complete report reproduced from a pinned retained assessment and original export '
                'under the current model and independently supplied date. Caller claims remain unauthenticated; '
                'no accepted ownership, ticketing or remediation established.'}


def _read_report(path):
    if os.name != 'posix': raise ValueError('private report reads require POSIX')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError('expected a bounded regular report')
        data = source.read(MAX_REPORT_BYTES+1)
    if len(data) > MAX_REPORT_BYTES: raise ValueError('report exceeds read bound')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('report', type=Path)
    parser.add_argument('database', type=Path)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--expected-report-sha256', required=True)
    parser.add_argument('--expected-database-sha256', required=True)
    parser.add_argument('--as-of', required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_queues(_read_report(args.report), args.database, _read(args.export),
            expected_report_sha256=args.expected_report_sha256, expected_database_sha256=args.expected_database_sha256,
            as_of=date.fromisoformat(args.as_of))
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError, RecursionError, OverflowError):
        print('error: dated queue did not reproduce; check private inputs, independent pins and review date', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
