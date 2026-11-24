"""Export dated work queues from a fully reproduced retained assessment."""

import argparse
from contextlib import closing
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

from database.inventory_assessment_verify import _snapshot, verify_assessment
from engine.discovery.osquery_collector import _read, _publish
from engine.inventory_queue_cli import plan_inventory


def build_queues(database, export_data, *, expected_database_sha256, as_of):
    if not isinstance(expected_database_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_database_sha256):
        raise ValueError('an independently retained database SHA-256 is required')
    if type(as_of) is not date:
        raise ValueError('explicit review date required')
    with tempfile.TemporaryDirectory(prefix='assessment-queue-') as directory:
        snapshot = Path(directory)/'assessment.sqlite'
        _snapshot(database, snapshot)
        digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        if digest != expected_database_sha256:
            raise ValueError('assessment differs from the independently retained pin')
        verified = verify_assessment(snapshot, export_data, require_model_binding=True)
        with closing(sqlite3.connect(snapshot.as_uri()+'?mode=ro', uri=True)) as connection:
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            findings, ownership, baseline = connection.execute(
                'SELECT findings_jsonl, ownership_directory_json, as_of FROM inventory_assessment_input'
            ).fetchone()
        baseline = date.fromisoformat(baseline)
        queues = plan_inventory(snapshot, findings.encode(), ownership.encode(), as_of=as_of,
                                baseline_as_of=baseline, export_data=export_data)
    return {'schema_version': 1, 'report_type': 'verified-assessment-work-queues',
            'database_sha256': digest, 'assessment_verification': verified,
            'retained_as_of': baseline.isoformat(), 'queue_document': queues,
            'interpretation': 'The complete retained assessment reproduced before dated queue planning. '
                'Only the review date changes; technical findings and tag-based routing remain retained '
                'caller claims. No accepted ownership, new discovery, ticket, or remediation is established.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('database', type=Path)
    parser.add_argument('--export', type=Path, required=True, help='original saved osquery or S3 export')
    parser.add_argument('--expected-database-sha256', required=True)
    parser.add_argument('--as-of', required=True, help='explicit date on or after the retained assessment date')
    parser.add_argument('--output', type=Path, required=True, help='new private JSON output file')
    args = parser.parse_args(argv)
    try:
        document = build_queues(args.database, _read(args.export),
            expected_database_sha256=args.expected_database_sha256, as_of=date.fromisoformat(args.as_of))
        rendered = json.dumps(document, sort_keys=True, indent=2, allow_nan=False)+'\n'
        _publish(args.output, rendered)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError, UnicodeError,
            RecursionError, OverflowError):
        print('error: assessment queue was not exported; check original evidence, pin, date and new output path',
              file=sys.stderr)
        return 2
    queues = document['queue_document']['queues']
    print(json.dumps({'status': 'assessment_queue_exported', 'as_of': queues['as_of'],
        'assigned_item_count': queues['assigned_item_count'], 'unassigned_item_count': queues['unassigned_item_count'],
        'changed_item_count': document['queue_document']['priority_comparison']['changed_item_count'],
        'output_sha256': hashlib.sha256(rendered.encode()).hexdigest()}, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
