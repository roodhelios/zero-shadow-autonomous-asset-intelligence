"""Compare a reproduced EC2 sequence with an independently pinned recipient checkpoint."""

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from database.ec2_inventory import _canonical
from database.ec2_observation_timeline import MAX_BATCHES, MAX_TOTAL_EXPORT_BYTES, build_timeline, _render
from database.repository import _timestamp
from engine.discovery.osquery_collector import _publish, _read, _unique_fields

MAX_CHECKPOINT_BYTES = 64 * 1024
MAX_COVERAGE_BYTES = 64 * 1024


def _digest(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('expected a lowercase SHA-256 digest')


def _instant(value):
    if not isinstance(value, str) or len(value) > 32 or not value.endswith('Z'):
        raise ValueError('checkpoint time must be canonical UTC')
    instant = datetime.fromisoformat(value[:-1]+'+00:00')
    if _timestamp(instant, 'observed_at') != value:
        raise ValueError('checkpoint time must be canonical UTC')
    return instant


def read_checkpoint(data, *, expected_sha256):
    """Authenticate exact checkpoint bytes only by the separately supplied trusted pin."""
    _digest(expected_sha256)
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_CHECKPOINT_BYTES:
        raise ValueError('checkpoint exceeds 64 KiB or is empty')
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('checkpoint differs from the independent pin')
    def invalid_constant(_):
        raise ValueError('non-finite checkpoint value')
    document = json.loads(data.decode('ascii'), object_pairs_hook=_unique_fields, parse_constant=invalid_constant)
    if (not isinstance(document, dict) or set(document) !=
            {'schema_version','checkpoint_type','scope','account','region','expected_batches'} or
            type(document['schema_version']) is not int or document['schema_version'] != 1 or
            document['checkpoint_type'] != 'ec2-observation-sequence'):
        raise ValueError('unsupported recipient checkpoint')
    if (document['scope'] not in ('synthetic','owned','authorized') or
            not isinstance(document['account'], str) or re.fullmatch('[0-9]{12}', document['account']) is None or
            not isinstance(document['region'], str) or re.fullmatch('[a-z0-9-]{1,32}', document['region']) is None):
        raise ValueError('invalid recipient context')
    slots = document['expected_batches']
    if not isinstance(slots, list) or not 2 <= len(slots) <= MAX_BATCHES:
        raise ValueError('checkpoint requires 2 to 16 expected batches')
    previous = None
    for slot in slots:
        if not isinstance(slot, dict) or set(slot) != {'observed_at','export_sha256'}:
            raise ValueError('invalid expected batch')
        instant = _instant(slot['observed_at'])
        _digest(slot['export_sha256'])
        if previous is not None and instant <= previous:
            raise ValueError('checkpoint times must strictly increase')
        previous = instant
    return document


def assess_sequence(batches, checkpoint_data, *, expected_checkpoint_sha256):
    """Reproduce every supplied batch once, then compare explicit recipient expectations."""
    checkpoint = read_checkpoint(checkpoint_data, expected_sha256=expected_checkpoint_sha256)
    timeline = build_timeline(batches)
    context = {name: checkpoint[name] for name in ('scope','account','region')}
    observed = {}
    for batch in timeline['batches']:
        supplied = batch['import_context']
        if {name: supplied[name] for name in context} != context:
            raise ValueError('supplied sequence differs from recipient context')
        observed[supplied['observed_at']] = batch
    counts = dict(matched=0, missing_batch=0, export_mismatch=0, unexpected_batch=0)
    slots = []
    expected_times = set()
    for sequence, slot in enumerate(checkpoint['expected_batches'], 1):
        expected_times.add(slot['observed_at'])
        batch = observed.get(slot['observed_at'])
        actual = batch['import_context']['input_sha256'] if batch else None
        status = 'missing_batch' if batch is None else 'matched' if actual == slot['export_sha256'] else 'export_mismatch'
        counts[status] += 1
        slots.append(dict(expected_sequence=sequence, observed_at=slot['observed_at'],
            expected_export_sha256=slot['export_sha256'], actual_export_sha256=actual,
            supplied_sequence=batch['sequence'] if batch else None, status=status))
    unexpected = []
    for batch in timeline['batches']:
        supplied = batch['import_context']
        if supplied['observed_at'] not in expected_times:
            unexpected.append(dict(supplied_sequence=batch['sequence'], observed_at=supplied['observed_at'],
                                   export_sha256=supplied['input_sha256']))
    counts['unexpected_batch'] = len(unexpected)
    return dict(schema_version=1, report_type='ec2-sequence-checkpoint-review', context=context,
        checkpoint_sha256=expected_checkpoint_sha256,
        timeline_sha256=hashlib.sha256(_render(timeline)).hexdigest(),
        expected_batch_count=len(slots), supplied_batch_count=timeline['batch_count'], counts=counts,
        requirements_satisfied=all(counts[name] == 0 for name in ('missing_batch','export_mismatch','unexpected_batch')),
        expected_batches=slots, unexpected_batches=unexpected,
        collection_completeness='not_established',
        interpretation='The supplied closed batches reproduce against each original export and are compared '
        'with exact time/export expectations from a separately pinned recipient checkpoint. Missing means an '
        'expected batch was not supplied, not proof of failed collection. Export mismatch means different bytes '
        'at the expected claimed time, not proof of malicious data. A satisfied checkpoint does not establish '
        'live account completeness, source authenticity, trusted collection time, deletion, recovery, risk, '
        'accepted ownership or an independently current global head. Checkpoint enrollment/freshness and pin '
        'distribution remain external. Detailed times and digests are private operational metadata.')


def _coverage_bytes(report):
    data = (_canonical(report)+'\n').encode('ascii')
    if len(data) > MAX_COVERAGE_BYTES:
        raise ValueError('coverage report exceeds 64 KiB')
    return data


def _summary(report, data):
    return dict(schema_version=1,
        status='ec2_sequence_checkpoint_satisfied' if report['requirements_satisfied'] else 'ec2_sequence_checkpoint_gaps',
        expected_batch_count=report['expected_batch_count'], supplied_batch_count=report['supplied_batch_count'],
        counts=report['counts'], requirements_satisfied=report['requirements_satisfied'],
        checkpoint_sha256=report['checkpoint_sha256'], report_sha256=hashlib.sha256(data).hexdigest(),
        original_exports_checked=True)


def export_checkpoint_review(batches, checkpoint_data, output, *, expected_checkpoint_sha256):
    report = assess_sequence(batches, checkpoint_data, expected_checkpoint_sha256=expected_checkpoint_sha256)
    data = _coverage_bytes(report)
    _publish(Path(output), data.decode('ascii'))
    return _summary(report, data)


def verify_checkpoint_review(path, batches, checkpoint_data, *, expected_checkpoint_sha256, expected_report_sha256):
    _digest(expected_report_sha256)
    data = _read(Path(path))
    if len(data) > MAX_COVERAGE_BYTES or hashlib.sha256(data).hexdigest() != expected_report_sha256:
        raise ValueError('coverage report differs from the independent report pin')
    report = assess_sequence(batches, checkpoint_data, expected_checkpoint_sha256=expected_checkpoint_sha256)
    if data != _coverage_bytes(report):
        raise ValueError('complete checkpoint review did not reproduce')
    return dict(_summary(report, data), report_reproduced=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('create','verify'):
        sub = commands.add_parser(name)
        sub.add_argument('--batch', nargs=2, action='append', required=True, metavar=('DATABASE','EXPORT'))
        sub.add_argument('--checkpoint', required=True, type=Path)
        sub.add_argument('--expected-checkpoint-sha256', required=True)
        if name == 'create':
            sub.add_argument('--output', required=True, type=Path)
        else:
            sub.add_argument('report', type=Path)
            sub.add_argument('--expected-report-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if not 2 <= len(args.batch) <= MAX_BATCHES:
            raise ValueError('expected 2 to 16 supplied batches')
        checkpoint = _read(args.checkpoint)
        # Validate the independent pin/contract before reading any candidate exports.
        read_checkpoint(checkpoint, expected_sha256=args.expected_checkpoint_sha256)
        batches, size = [], 0
        for database, export in args.batch:
            data = _read(Path(export)); size += len(data)
            if size > MAX_TOTAL_EXPORT_BYTES:
                raise ValueError('combined exports exceed 16 MiB')
            batches.append((Path(database), data))
        if args.command == 'create':
            result = export_checkpoint_review(batches, checkpoint, args.output,
                expected_checkpoint_sha256=args.expected_checkpoint_sha256)
        else:
            result = verify_checkpoint_review(args.report, batches, checkpoint,
                expected_checkpoint_sha256=args.expected_checkpoint_sha256, expected_report_sha256=args.expected_report_sha256)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 checkpoint review failed; inspect private expectations, pins, original evidence and output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['requirements_satisfied'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
