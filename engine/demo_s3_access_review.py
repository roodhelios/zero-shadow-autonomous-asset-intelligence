"""Exercise saved S3 control review against a real local SQLite assessment."""

from contextlib import redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile

from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export
from engine.discovery import s3_access_review as access
from engine.discovery import s3_policy_review as policy


def _run(args):
    output = StringIO()
    with redirect_stdout(output):
        if access.main(args) != 0:
            raise ValueError('saved access exercise did not complete')
    return json.loads(output.getvalue())


def exercise():
    examples = Path(__file__).resolve().parents[1] / 'examples'
    paths = [examples / name for name in ('s3-list-buckets.json', 's3-policy-status.json',
        's3-policy-review.json', 's3-bucket-controls.json', 's3-account-controls.json', 's3-control-context.json')]
    originals = [path.read_bytes() for path in paths]
    options = dict(scope='synthetic', **{'expected_' + name + '_sha256': policy._digest(data)
        for name, data in zip(access.INPUTS, originals)})
    common = [str(p) for p in paths] + ['--scope', 'synthetic']
    for name, data in zip(access.INPUTS, originals):
        common += ['--expected-' + name.replace('_', '-') + '-sha256', policy._digest(data)]
    with tempfile.TemporaryDirectory(prefix='s3-access-review-') as directory:
        root = Path(directory); report_path = root / 'review.json'
        created = _run(['create', *common, '--output', str(report_path)])
        report = json.loads(report_path.read_bytes())
        discovery, assessment = root / 'discovery.sqlite', root / 'assessment.sqlite'
        store_export(paths[0], discovery, source_format='s3', account='123456789012', scope='synthetic',
            observed_at=datetime(2026, 11, 24, tzinfo=timezone.utc))
        retained = retain_assessment(discovery, policy.finding_bytes(report['policy_review']),
            (examples / 'ownership-directory.json').read_bytes(), assessment,
            as_of=date(2026, 11, 24), assessed_at=datetime(2026, 11, 24, 1, tzinfo=timezone.utc),
            export_data=originals[0])
        checked = _run(['verify', *common, '--report', str(report_path),
            '--expected-report-sha256', created['report_sha256'], '--assessment', str(assessment)])
        unknown = list(originals)
        unknown[4] = policy._canonical(dict(collection_status='unknown', reason='not_collected'))
        unknown_options = dict(options, expected_account_controls_sha256=policy._digest(unknown[4]))
        unresolved = access.review_access(*unknown, **unknown_options)
        return dict(status='s3_access_review_exercise_passed', asset_count=retained['inventory_asset_count'],
            finding_count=1, public_policy_review_state=checked['public_policy_review_state'],
            account_restriction_retained=report['combined_settings']['RestrictPublicBuckets']['restricting_levels'] == ['account'],
            unknown_account_state=unresolved['public_policy_review_state'],
            assessment_input_verified=checked['assessment_input_verified'], effective_exposure_verified=False,
            source_truth_verified=False)


def main():
    print(json.dumps(exercise(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
