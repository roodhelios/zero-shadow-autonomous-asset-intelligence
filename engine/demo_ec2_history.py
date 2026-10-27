"""Exercise immutable EC2 review-history publication with temporary synthetic data."""

import json
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from database.ec2_assessment import retain_assessment
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history, verify_history


def exercise():
    root = Path(__file__).resolve().parents[1]
    export = (root/'examples/ec2-describe-instances.json').read_bytes()
    findings = (root/'examples/ec2-findings.jsonl').read_bytes()
    directory = (root/'examples/ownership-directory.json').read_bytes()
    with tempfile.TemporaryDirectory(prefix='zero-shadow-ec2-history-') as name:
        work = Path(name); source = work/'export.json'; discovery = work/'discovery.sqlite'
        source.write_bytes(export); source.chmod(0o600)
        store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        updated = json.loads(findings); updated['finding']['severity'] = 'critical'
        receipts = []
        for index, (data, day) in enumerate(((findings, '2026-10-25'),
                                            (json.dumps(updated).encode(), '2026-10-26'))):
            output = work/('review-'+str(index)+'.sqlite')
            retain_assessment(discovery, data, directory, output, export_data=export,
                              as_of=date.fromisoformat(day),
                              assessed_at=datetime.fromisoformat(day+'T01:00:00+00:00'))
            receipts.append(output)
        discovery.unlink()
        saved = {path: path.read_bytes() for path in receipts+[source]}
        first, second = work/'history-1.sqlite', work/'history-2.sqlite'
        initial = retain_history(receipts[0], first, export_data=export)
        saved[first] = first.read_bytes()
        result = retain_history(receipts[1], second, export_data=export, history=first,
                                expected_head=initial['head_sha256'])
        checked = verify_history(second, export_data=export, expected_head=result['head_sha256'])
        if checked['review_count'] != 2 or checked['decision_count'] != 2:
            raise ValueError('history did not retain both reviews')
        for data, head in ((export, initial['head_sha256']), (export+b'\n', result['head_sha256'])):
            try:
                verify_history(second, export_data=data, expected_head=head)
            except ValueError:
                pass
            else:
                raise ValueError('stale head or changed export accepted')
        refused = work/'refused.sqlite'
        try:
            retain_history(receipts[1], refused, export_data=export, history=second,
                           expected_head=initial['head_sha256'])
        except ValueError:
            if refused.exists():
                raise ValueError('stale predecessor published an artifact')
        else:
            raise ValueError('stale predecessor accepted')
        if any(path.read_bytes() != data for path, data in saved.items()):
            raise ValueError('input evidence changed')
    return dict(checked, status='ec2_history_exercise_passed', inputs_unchanged=True,
                stale_predecessor='rejected', changed_export='rejected', original_discovery_removed=True)


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: local EC2 review-history exercise failed', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
