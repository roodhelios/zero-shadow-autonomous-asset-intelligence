from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from database.inventory_assessment_cli import retain_assessment
from database.inventory_cli import store_export
from engine.discovery import s3_policy_review as review

ROOT = Path(__file__).resolve().parents[1]


class S3PolicyReviewTests(unittest.TestCase):
    def setUp(self):
        self.listing = (ROOT / 'examples/s3-list-buckets.json').read_bytes()
        self.policy = (ROOT / 'examples/s3-policy-status.json').read_bytes()
        self.context = (ROOT / 'examples/s3-policy-review.json').read_bytes()
        self.options = dict(scope='synthetic', expected_listing_sha256=review._digest(self.listing),
            expected_policy_sha256=review._digest(self.policy), expected_context_sha256=review._digest(self.context))
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def report(self, *, policy=None, context=None):
        policy = self.policy if policy is None else policy
        context = self.context if context is None else context
        return review.review_policy(self.listing, policy, context, **(self.options |
            {'expected_policy_sha256': review._digest(policy), 'expected_context_sha256': review._digest(context)}))

    def assessment(self, finding_data):
        source = self.root / 'listing.json'; source.write_bytes(self.listing)
        discovery = self.root / ('discovery-' + str(len(list(self.root.glob('discovery-*')))) + '.sqlite')
        store_export(source, discovery, source_format='s3', account='123456789012', scope='synthetic',
            observed_at=datetime(2026, 11, 24, tzinfo=timezone.utc))
        output = discovery.with_name(discovery.stem + '-assessment.sqlite')
        retain_assessment(discovery, finding_data, (ROOT / 'examples/ownership-directory.json').read_bytes(),
            output, as_of=date(2026, 11, 24), assessed_at=datetime(2026, 11, 24, 1, tzinfo=timezone.utc),
            export_data=self.listing)
        return output

    def test_real_native_assessment_binds_exact_review_inputs_and_one_bucket(self):
        report = self.report(); data = review._canonical(report)
        self.assertEqual(report['source_record']['bucket_record'], 2)
        self.assertEqual(report['finding_record']['finding']['exposure'], 'limited')
        self.assertFalse(report['effective_exposure_verified'])
        self.assertFalse(report['source_truth_verified'])
        assessment = self.assessment(review.finding_bytes(report))
        result = review.verify_review(data, self.listing, self.policy, self.context,
            expected_report_sha256=review._digest(data), assessment=assessment, **self.options)
        self.assertTrue(result['assessment_input_verified'])
        self.assertEqual(result['finding_count'], 1)

    def test_valid_but_different_assessment_cannot_claim_policy_provenance(self):
        report = self.report(); data = review._canonical(report)
        finding = json.loads(review.finding_bytes(report))
        finding['finding']['severity'] = 'high'
        assessment = self.assessment(review._canonical(finding) + b'\n')
        with self.assertRaises(ValueError):
            review.verify_review(data, self.listing, self.policy, self.context,
                expected_report_sha256=review._digest(data), assessment=assessment, **self.options)

    def test_context_retarget_or_missing_bucket_and_account_fail(self):
        context = json.loads(self.context)
        for changes in ({'bucket': 'absent-fixture-bucket'}, {'account': 'not-an-account'},
                        {'scope': 'owned'}, {'schema_version': True}, {'captured_at': '2026-11-24T00:00:00'}):
            with self.subTest(changes=list(changes)), self.assertRaises(ValueError):
                self.report(context=review._canonical(context | changes))
        changed = review._canonical(context | {'bucket': 'fixture-research-archive'})
        report = self.report(); data = review._canonical(report)
        with self.assertRaises(ValueError):
            review.verify_review(data, self.listing, self.policy, changed,
                expected_report_sha256=review._digest(data), **(self.options | {'expected_context_sha256': review._digest(changed)}))

    def test_all_pins_precede_parsing(self):
        with patch.object(review, '_json', side_effect=AssertionError('must not parse')):
            for name in ('listing', 'policy', 'context'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    review.review_policy(self.listing, self.policy, self.context,
                        **(self.options | {'expected_' + name + '_sha256': '0' * 64}))

    def test_nonpublic_claim_emits_no_finding_and_never_clean_assessment(self):
        policy = b'{"PolicyStatus":{"IsPublic":false}}'
        context = json.loads(self.context)
        with self.assertRaises(ValueError): self.report(policy=policy)
        report = self.report(policy=policy, context=review._canonical(context | {'finding': None}))
        self.assertIsNone(report['finding_record'])
        self.assertEqual(review.finding_bytes(report), b'')
        self.assertFalse(report['effective_exposure_verified'])
        with self.assertRaises(ValueError): self.assessment(b'')

    def test_ambiguous_policy_and_implicit_scoring_reject(self):
        for policy in (b'{}', b'{"PolicyStatus":{"IsPublic":"true"}}',
                b'{"PolicyStatus":{"IsPublic":1}}', b'{"PolicyStatus":{"IsPublic":true,"other":0}}',
                b'{"PolicyStatus":{"IsPublic":true,"IsPublic":false}}',
                b'{"PolicyStatus":{"IsPublic":true},"ResponseMetadata":{}}'):
            with self.subTest(size=len(policy)), self.assertRaises(ValueError): self.report(policy=policy)
        context = json.loads(self.context)
        for changes in ({'finding': None}, {'finding': context['finding'] | {'exposure': 'unknown'}},
                        {'finding': context['finding'] | {'asset_id': 'arbitrary'}}, {'asset_tags': {'Owner': 'team'}}):
            with self.assertRaises(ValueError): self.report(context=review._canonical(context | changes))

    def test_report_forgery_and_source_changes_reject_even_with_new_report_pin(self):
        report = self.report(); report['effective_exposure_verified'] = True
        data = review._canonical(report)
        with self.assertRaises(ValueError):
            review.verify_review(data, self.listing, self.policy, self.context,
                expected_report_sha256=review._digest(data), **self.options)
        report = self.report(); data = review._canonical(report)
        with self.assertRaises(ValueError):
            review.verify_review(data, self.listing + b' ', self.policy, self.context,
                expected_report_sha256=review._digest(data), **self.options)

    def call(self, args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err): code = review.main(args)
        return code, out.getvalue(), err.getvalue()

    def arguments(self):
        paths = []
        for name, data in (('listing', self.listing), ('policy', self.policy), ('context', self.context)):
            path = self.root / (name + '.json'); path.write_bytes(data); paths.append(str(path))
        return [*paths, '--scope', 'synthetic', '--expected-listing-sha256', self.options['expected_listing_sha256'],
            '--expected-policy-sha256', self.options['expected_policy_sha256'], '--expected-context-sha256', self.options['expected_context_sha256']]

    def test_cli_private_outputs_verify_and_no_overwrite(self):
        common = self.arguments(); directory = self.root / 'review'
        args = ['create', *common, '--directory', str(directory)]
        code, out, err = self.call(args); self.assertEqual((code, err), (0, ''))
        created = json.loads(out); self.assertNotIn('fixture-audit-records', out)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        before = {}
        for name in ('review.json', 'findings.jsonl'):
            before[name] = (directory / name).read_bytes()
            self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
        self.assertEqual(self.call(args)[0], 2)
        self.assertEqual(before, {name: (directory / name).read_bytes() for name in before})
        code, out, err = self.call(['verify', *common, '--report', str(directory / 'review.json'),
            '--expected-report-sha256', created['report_sha256']])
        self.assertEqual((code, err), (0, '')); self.assertFalse(json.loads(out)['assessment_input_verified'])

    def test_partial_output_failure_symlinks_and_input_bounds(self):
        common = self.arguments(); directory = self.root / 'review'
        publish = review._publish
        def fail_second(path, rendered):
            if path.name == 'findings.jsonl': raise OSError('private failure detail')
            return publish(path, rendered)
        with patch.object(review, '_publish', side_effect=fail_second):
            code, out, err = self.call(['create', *common, '--directory', str(directory)])
        self.assertEqual((code, out), (2, '')); self.assertNotIn(str(self.root), err)
        self.assertFalse(directory.exists())
        path = self.root / 'policy.json'; path.unlink(); path.symlink_to(self.root / 'context.json')
        self.assertEqual(self.call(['create', *common, '--directory', str(directory)])[0], 2)
        with self.assertRaises(ValueError):
            self.report(policy=b'x' * (review.POLICY_LIMIT + 1))

    def test_fresh_process_runs_complete_documented_demo(self):
        result = subprocess.run([sys.executable, '-m', 'engine', 's3-policy', 'demo'], cwd=ROOT,
            capture_output=True, text=True, check=True, timeout=30)
        self.assertEqual(result.stderr, '')
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 's3_policy_assessment_exercise_passed')
        self.assertTrue(value['assessment_input_verified'])
        self.assertFalse(value['effective_exposure_verified'])


if __name__ == '__main__':
    unittest.main()
