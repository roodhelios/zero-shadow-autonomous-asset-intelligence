"""Run a temporary, offline EC2 review comparison with bundled synthetic inputs."""

import json
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from database.ec2_assessment import retain_assessment
from database.ec2_assessment_compare import export_comparison
from database.ec2_inventory import store_ec2


def exercise():
    root = Path(__file__).resolve().parents[1]
    export = (root/'examples/ec2-describe-instances.json').read_bytes()
    findings = (root/'examples/ec2-findings.jsonl').read_bytes()
    directory = (root/'examples/ownership-directory.json').read_bytes()
    with tempfile.TemporaryDirectory(prefix='zero-shadow-ec2-review-') as name:
        work = Path(name); source = work/'export.json'; discovery = work/'discovery.sqlite'
        previous, current = work/'previous.sqlite', work/'current.sqlite'
        source.write_bytes(export); source.chmod(0o600)
        store_ec2(source, discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        updated = json.loads(findings); updated['finding']['severity'] = 'critical'
        for output, data, day in ((previous, findings, '2026-10-25'),
                                  (current, json.dumps(updated).encode(), '2026-10-26')):
            retain_assessment(discovery, data, directory, output, export_data=export,
                              as_of=date.fromisoformat(day),
                              assessed_at=datetime.fromisoformat(day+'T01:00:00+00:00'))
        saved = {path: path.read_bytes() for path in (previous, current, source)}
        discovery.unlink()
        result = export_comparison(previous, current, work/'comparison.json', export_data=export)
        report = json.loads((work/'comparison.json').read_bytes())
        change = report['changes'][0]
        if (result['changed'] != 1 or not result['review_inputs_changed'] or
                change['previous']['risk_assessment'] == change['current']['risk_assessment'] or
                any(path.read_bytes() != data for path, data in saved.items())):
            raise ValueError('EC2 comparison exercise did not reproduce')
        invalid = work/'invalid.json'
        try:
            export_comparison(previous, current, invalid, export_data=export+b'\n')
        except ValueError:
            if invalid.exists(): raise ValueError('invalid comparison was published')
        else:
            raise ValueError('changed source bytes were accepted')
    return dict(result, status='ec2_review_exercise_passed', changed_export='rejected',
                original_discovery_removed=True, inputs_unchanged=True)


def main():
    try:
        result = exercise()
    except (OSError, ValueError, TypeError, KeyError):
        print('error: local EC2 review exercise failed', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
