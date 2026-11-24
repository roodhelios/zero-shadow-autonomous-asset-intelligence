"""Exercise saved S3 policy review through actual local assessment retention."""

from contextlib import redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile

from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export
from engine.discovery.s3_policy_review import _digest, main as policy_main


def _run(arguments):
    output = StringIO()
    with redirect_stdout(output):
        if policy_main(arguments) != 0:
            raise ValueError('saved policy exercise did not complete')
    return json.loads(output.getvalue())


def exercise():
    examples = Path(__file__).resolve().parents[1] / 'examples'
    paths = [examples / name for name in ('s3-list-buckets.json', 's3-policy-status.json', 's3-policy-review.json')]
    common = [str(path) for path in paths] + ['--scope', 'synthetic']
    for name, path in zip(('listing', 'policy', 'context'), paths):
        common += ['--expected-' + name + '-sha256', _digest(path.read_bytes())]
    with tempfile.TemporaryDirectory(prefix='s3-policy-review-') as temporary:
        root = Path(temporary); output = root / 'review'
        created = _run(['create', *common, '--directory', str(output)])
        discovery, assessment = root / 'discovery.sqlite', root / 'assessment.sqlite'
        store_export(paths[0], discovery, source_format='s3', account='123456789012', scope='synthetic',
            observed_at=datetime(2026, 11, 24, tzinfo=timezone.utc))
        retained = retain_assessment(discovery, (output / 'findings.jsonl').read_bytes(),
            (examples / 'ownership-directory.json').read_bytes(), assessment,
            as_of=date(2026, 11, 24), assessed_at=datetime(2026, 11, 24, 1, tzinfo=timezone.utc),
            export_data=paths[0].read_bytes())
        verified = _run(['verify', *common, '--report', str(output / 'review.json'),
            '--expected-report-sha256', created['report_sha256'], '--assessment', str(assessment)])
        return {'status': 's3_policy_assessment_exercise_passed', 'asset_count': retained['inventory_asset_count'],
            'finding_count': created['finding_count'], 'assessment_input_verified': verified['assessment_input_verified'],
            'effective_exposure_verified': False, 'source_truth_verified': False}


def main():
    print(json.dumps(exercise(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
