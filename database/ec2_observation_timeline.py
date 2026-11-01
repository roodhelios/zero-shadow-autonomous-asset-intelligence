"""Review an explicitly ordered sequence of reproduced local EC2 discovery batches."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from datetime import datetime
from pathlib import Path

from database.ec2_inventory import _canonical, read_ec2
from database.ec2_inventory_compare import _records
from engine.discovery.osquery_collector import _publish, _read, _unique_fields

MAX_BATCHES = 16
MAX_TOTAL_EXPORT_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 24 * 1024 * 1024


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('ascii')).hexdigest()


def build_timeline(batches):
    """Reproduce each database once; derive transitions only from verified copies."""
    if not isinstance(batches, (list, tuple)) or not 2 <= len(batches) <= MAX_BATCHES:
        raise ValueError('timeline requires 2 to 16 ordered batches')
    total = 0
    for batch in batches:
        if not isinstance(batch, (list, tuple)) or len(batch) != 2 or not isinstance(batch[1], bytes):
            raise ValueError('each batch requires a database and original export bytes')
        total += len(batch[1])
        if total > MAX_TOTAL_EXPORT_BYTES:
            raise ValueError('combined exports exceed 16 MiB')
    steps, last_seen, previous = [], {}, {}
    first_context, previous_time = None, None
    totals = dict(first_observed=0, changed=0, unchanged=0, observed_again=0, not_observed=0)
    for sequence, (database, export) in enumerate(batches, 1):
        document = read_ec2(database, export)
        context = document['import_context']
        identity = {key: context[key] for key in ('scope', 'account', 'region')}
        if first_context is not None and identity != first_context:
            raise ValueError('timeline requires the same claimed scope, account and region')
        observed_at = datetime.fromisoformat(context['observed_at'])
        if previous_time is not None and observed_at <= previous_time:
            raise ValueError('batches must have strictly increasing claimed observation times')
        current, events = _records(document), []
        counts = {name: 0 for name in totals}
        for identifier, record in sorted(current.items()):
            prior = last_seen.get(identifier)
            fields = [] if prior is None else sorted(
                key for key in prior['record']['claims'].keys() | record['claims'].keys()
                if prior['record']['claims'].get(key) != record['claims'].get(key))
            status = ('first_observed' if prior is None else 'observed_again' if identifier not in previous
                      else 'changed' if fields else 'unchanged')
            events.append({'asset_id': identifier, 'status': status, 'current': record,
                           'previous_observation': prior, 'changed_fields_since_last_observation': fields})
            last_seen[identifier] = {'batch_sequence': sequence, 'record': record}
            counts[status] += 1
        for identifier in sorted(previous.keys() - current.keys()):
            events.append({'asset_id': identifier, 'status': 'not_observed', 'current': None,
                           'previous_observation': last_seen[identifier],
                           'changed_fields_since_last_observation': []})
            counts['not_observed'] += 1
        for name in totals:
            totals[name] += counts[name]
        steps.append({'sequence': sequence, 'import_context': context,
                      'source_reconciliation': document['source_reconciliation'],
                      'snapshot_sha256': _digest(document), 'counts': counts,
                      'collection_completeness': 'not_established', 'events': events})
        previous, first_context, previous_time = current, identity, observed_at
    return {'schema_version': 1, 'report_type': 'ec2-observation-timeline', 'batch_count': len(steps),
            'unique_asset_count': len(last_seen), 'event_totals': totals, 'batches': steps,
            'interpretation': 'Every supplied batch reproduces against its respective original export. '
            'Order and timestamps are caller-supplied claims. First observed is first in this supplied sequence; '
            'observed again means present after an omitted batch, not recreated or recovered. '
            'Not observed is a transition out of the supplied projection, not deletion, resolution, downtime '
            'or complete collection. Repeated absence emits no new transition. Only selected claims are '
            'compared; this is not source authentication, an atomic multi-database snapshot, risk assessment, '
            'accepted ownership, an append-only ledger or a global latest lifecycle. Keep detailed evidence private.'}


def _render(report):
    data = (_canonical(report) + '\n').encode('ascii')
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError('timeline report exceeds 24 MiB')
    return data


def _summary(report, data, status):
    return {'schema_version': 1, 'status': status, 'batch_count': report['batch_count'],
            'unique_asset_count': report['unique_asset_count'], 'event_totals': report['event_totals'],
            'report_sha256': hashlib.sha256(data).hexdigest(), 'original_exports_checked': True}


def export_timeline(batches, output):
    report = build_timeline(batches)
    data = _render(report)
    _publish(Path(output), data.decode('ascii'))
    return _summary(report, data, 'ec2_observation_timeline_exported')


def _read_report(path):
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('expected a regular local timeline file')
        data = source.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError('timeline report exceeds 24 MiB')
    return data


def verify_timeline(path, batches, *, expected_sha256):
    """Require the independently retained report pin and reproduce every field."""
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ValueError('expected a lowercase SHA-256 report pin')
    data = _read_report(path)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('timeline report pin differs')
    retained = json.loads(data.decode('ascii'), object_pairs_hook=_unique_fields)
    report = build_timeline(batches)
    if data != _render(report) or retained != report:
        raise ValueError('complete timeline did not reproduce')
    return _summary(report, data, 'ec2_observation_timeline_reproduced')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('create', 'verify'):
        sub = commands.add_parser(name)
        sub.add_argument('--batch', nargs=2, action='append', required=True, metavar=('DATABASE', 'EXPORT'))
        if name == 'create':
            sub.add_argument('--output', required=True, type=Path, help='new private JSON file; never overwrite')
        else:
            sub.add_argument('report', type=Path)
            sub.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if not 2 <= len(args.batch) <= MAX_BATCHES:
            raise ValueError('timeline requires 2 to 16 ordered batches')
        batches, size = [], 0
        for database, export in args.batch:
            data = _read(Path(export)); size += len(data)
            if size > MAX_TOTAL_EXPORT_BYTES:
                raise ValueError('combined exports exceed 16 MiB')
            batches.append((Path(database), data))
        result = (export_timeline(batches, args.output) if args.command == 'create' else
                  verify_timeline(args.report, batches, expected_sha256=args.expected_sha256))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 timeline failed; check closed evidence, each original export, order, pin and output', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    raise SystemExit(main())
