"""Compare two fully reproduced saved EC2 discovery batches, never live accounts."""

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from database.ec2_inventory import _canonical, read_ec2
from engine.discovery.osquery_collector import _publish, _read

MAX_REPORT_BYTES = 24 * 1024 * 1024


def _records(document):
    references = {item['source_record_id']: item for item in document['import_context']['source_records']}
    result = {}
    for snapshot in document['assets']:
        observations = snapshot['observations']
        if len(observations) != 1:
            raise ValueError('expected one reproduced EC2 observation per identity')
        claims = observations[0]['payload']
        identifier = snapshot['asset']['asset_id']
        result[identifier] = {'asset_id': identifier, 'claims': claims,
                              'source_reference': references[claims['source_record_id']]}
    return result


def compare_inventories(previous, current, *, previous_export, current_export):
    """Use only the closed-file snapshots that independently passed source reproduction."""
    old = read_ec2(previous, previous_export)
    new = read_ec2(current, current_export)
    before_context, after_context = old['import_context'], new['import_context']
    if any(before_context[key] != after_context[key] for key in ('scope', 'account', 'region')):
        raise ValueError('comparison requires the same claimed scope, account and region')
    if datetime.fromisoformat(after_context['observed_at']) <= datetime.fromisoformat(before_context['observed_at']):
        raise ValueError('current claimed observation time must be strictly later')
    before, after = _records(old), _records(new)
    common = before.keys() & after.keys()
    changes = []
    for identifier in sorted(common):
        left, right = before[identifier]['claims'], after[identifier]['claims']
        fields = sorted(key for key in left.keys() | right.keys() if left.get(key) != right.get(key))
        if fields:
            changes.append({'asset_id': identifier, 'changed_fields': fields,
                            'previous': before[identifier], 'current': after[identifier]})
    added = [after[key] for key in sorted(after.keys()-before.keys())]
    not_observed = [before[key] for key in sorted(before.keys()-after.keys())]
    def context(document):
        return {'import_context': document['import_context'],
                'verification': document['source_reconciliation'],
                'snapshot_sha256': hashlib.sha256(_canonical(document).encode('ascii')).hexdigest()}
    return {'schema_version': 1, 'report_type': 'ec2-discovery-comparison',
            'previous': context(old), 'current': context(new),
            'source_bytes_changed': before_context['input_sha256'] != after_context['input_sha256'],
            'counts': {'previous_assets': len(before), 'current_assets': len(after), 'added': len(added),
                       'not_observed': len(not_observed), 'changed': len(changes), 'unchanged': len(common)-len(changes)},
            'added': added, 'not_observed': not_observed, 'changes': changes,
            'unchanged_asset_ids': sorted(common-{item['asset_id'] for item in changes}),
            'interpretation': 'Both saved discovery batches reproduce completely against their respective original '
            'exports. Stable source-claimed cloud identities are compared within one claimed scope/account/region. '
            'Only projected claims are compared; input formatting, source-row positions and later observation '
            'times alone are not asset changes. Not observed does not mean deleted, stopped, resolved or absent '
            'from the environment. This is not source authentication, complete collection, accepted ownership, '
            'risk assessment, remediation, a history append or an atomic snapshot of both databases. Keep this '
            'detailed report and original evidence private.'}


def export_comparison(previous, current, output, *, previous_export, current_export):
    report = compare_inventories(previous, current, previous_export=previous_export, current_export=current_export)
    rendered = json.dumps(report, sort_keys=True, indent=2, allow_nan=False)+'\n'
    if len(rendered.encode('utf-8')) > MAX_REPORT_BYTES:
        raise ValueError('comparison exceeds report bound')
    _publish(output, rendered)
    return {'schema_version': 1, 'status': 'ec2_discovery_compared', **report['counts'],
            'original_exports_checked': True, 'source_bytes_changed': report['source_bytes_changed']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('previous', type=Path); parser.add_argument('current', type=Path)
    parser.add_argument('--previous-export', type=Path, required=True)
    parser.add_argument('--current-export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new private comparison file, never overwrite')
    args = parser.parse_args(argv)
    try:
        result = export_comparison(args.previous, args.current, args.output,
            previous_export=_read(args.previous_export), current_export=_read(args.current_export))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.DatabaseError,
            UnicodeError, RecursionError, OverflowError):
        print('error: EC2 discovery batches were not compared; check closed evidence, original exports, context and output',
              file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
