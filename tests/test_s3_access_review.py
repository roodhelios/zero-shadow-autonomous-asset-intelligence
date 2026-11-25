"""Check local control composition, evidence replay and CLI publication."""

from contextlib import redirect_stderr, redirect_stdout
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

from engine.discovery import s3_access_review as access
from engine.discovery import s3_policy_review as policy
from engine.demo_s3_access_review import exercise

ROOT = Path(__file__).resolve().parents[1]


class AccessReviewTests(unittest.TestCase):
    def setUp(self):
        self.paths = [ROOT / 'examples' / name for name in ('s3-list-buckets.json', 's3-policy-status.json',
            's3-policy-review.json', 's3-bucket-controls.json', 's3-account-controls.json', 's3-control-context.json')]
        self.inputs = [p.read_bytes() for p in self.paths]
        guard = patch('socket.socket', side_effect=AssertionError('network forbidden'))
        guard.start(); self.addCleanup(guard.stop)

    def options(self, inputs=None):
        return dict(scope='synthetic', **{'expected_' + name + '_sha256': policy._digest(data)
            for name, data in zip(access.INPUTS, self.inputs if inputs is None else inputs)})

    def report(self, inputs=None):
        inputs = self.inputs if inputs is None else inputs
        return access.review_access(*inputs, **self.options(inputs))

    def controls(self, value):
        return policy._canonical({'PublicAccessBlockConfiguration': value})

    def test_native_cli_sqlite_demo_and_catalog_dispatch(self):
        result = exercise()
        self.assertEqual(result['public_policy_review_state'], 'restriction_reported')
        self.assertEqual(result['unknown_account_state'], 'restriction_unknown')
        self.assertTrue(result['account_restriction_retained'])
        self.assertTrue(result['assessment_input_verified'])
        self.assertFalse(result['effective_exposure_verified'])
        child = subprocess.run([sys.executable, '-S', '-m', 'engine', 'demo', 's3-access'],
            cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['status'], result['status'])

    def test_each_setting_uses_true_over_unknown_over_false_with_evidence(self):
        for key in access.SETTINGS:
            for bucket in (True, False, None):
                for account in (True, False, None):
                    inputs = list(self.inputs)
                    inputs[3] = self.controls({} if bucket is None else {key: bucket})
                    inputs[4] = self.controls({} if account is None else {key: account})
                    result = self.report(inputs)['combined_settings'][key]
                    expected = True if bucket is True or account is True else None if bucket is None or account is None else False
                    with self.subTest(key=key, bucket=bucket, account=account):
                        self.assertIs(result['combined_claim'], expected)
                        self.assertEqual(result['restricting_levels'], [level for level, value in
                            [('bucket', bucket), ('account', account)] if value is True])
                        self.assertEqual(result['unknown_levels'], [level for level, value in
                            [('bucket', bucket), ('account', account)] if value is None])

    def test_blocking_new_public_policies_does_not_restrict_existing_policy_claim(self):
        inputs = list(self.inputs)
        inputs[3] = self.controls(dict(BlockPublicPolicy=True, RestrictPublicBuckets=False))
        inputs[4] = self.controls(dict(BlockPublicPolicy=True, RestrictPublicBuckets=False))
        report = self.report(inputs)
        self.assertEqual(report['public_policy_review_state'], 'no_restriction_reported')
        self.assertFalse(report['effective_exposure_verified'])
        self.assertIsNotNone(report['policy_review']['finding_record'])

    def test_controls_never_suppress_or_change_separately_reviewed_finding(self):
        report = self.report()
        expected = policy.review_policy(*self.inputs[:3], **{k:v for k,v in self.options().items()
            if k in ('scope','expected_listing_sha256','expected_policy_sha256','expected_context_sha256')})
        self.assertEqual(policy.finding_bytes(report['policy_review']), policy.finding_bytes(expected))
        self.assertEqual(report['policy_review']['finding_record']['finding']['exposure'], 'limited')
        self.assertTrue(report['finding_unchanged'])

    def test_unknown_records_preserve_reason_and_nonpublic_is_not_clean(self):
        for reason in ('not_collected', 'access_denied', 'no_saved_response'):
            inputs = list(self.inputs); inputs[4] = policy._canonical(dict(collection_status='unknown',reason=reason))
            report = self.report(inputs)
            self.assertEqual(report['public_policy_review_state'], 'restriction_unknown')
            self.assertEqual(report['control_sources']['account']['reason'], reason)
        inputs[1] = b'{"PolicyStatus":{"IsPublic":false}}'
        context = json.loads(inputs[2]); context['finding'] = None; inputs[2] = policy._canonical(context)
        report = self.report(inputs)
        self.assertEqual(report['public_policy_review_state'], 'no_public_policy_reported')
        self.assertFalse(report['effective_exposure_verified'])
        self.assertFalse(report['source_truth_verified'])

    def test_control_json_types_unknown_fields_and_duplicate_keys_reject(self):
        invalid = [b'[]', b'{"PublicAccessBlockConfiguration":{},"ResponseMetadata":{}}',
            b'{"PublicAccessBlockConfiguration":{"RestrictPublicBuckets":true,"RestrictPublicBuckets":false}}',
            b'{"collection_status":"unknown","reason":"unbounded reason"}']
        invalid += [self.controls({'RestrictPublicBuckets':value}) for value in (1,0,'true',None,[])]
        invalid += [self.controls({'Unexpected':False})]
        for original in invalid:
            inputs = list(self.inputs); inputs[3] = original
            with self.subTest(original=original), self.assertRaises((ValueError, TypeError)):
                self.report(inputs)

    def test_context_identity_scope_schema_and_capture_bounds_reject(self):
        for changes in (dict(account='000000000000'),dict(bucket='other-bucket'),dict(scope='owned'),
                dict(schema_version=True),dict(maximum_skew_seconds=True),dict(maximum_skew_seconds=-1),
                dict(maximum_skew_seconds=86401),dict(bucket_captured_at='2026-11-24T00:01:00'),
                dict(account_captured_at='2026-11-24T00:06:00Z'),dict(maximum_skew_seconds=119),
                dict(window_start='2026-11-24T00:06:00Z'),dict(extra='field')):
            inputs = list(self.inputs); context = json.loads(inputs[5]);context.update(changes)
            inputs[5] = policy._canonical(context)
            with self.subTest(changes=changes), self.assertRaises((ValueError,TypeError)):
                self.report(inputs)
        # The two-minute exact boundary and equivalent timezone offsets are accepted.
        context = json.loads(self.inputs[5]); context['maximum_skew_seconds'] = 120
        context['bucket_captured_at'] = '2026-11-23T19:01:00-05:00'
        inputs = list(self.inputs); inputs[5] = policy._canonical(context)
        self.assertEqual(self.report(inputs)['public_policy_review_state'], 'restriction_reported')

    def test_all_input_pins_precede_any_parsing_and_bounds_apply(self):
        for name in access.INPUTS:
            options = self.options(); options['expected_'+name+'_sha256'] = '0'*64
            with patch.object(policy,'_json',side_effect=AssertionError('must not parse')):
                with self.assertRaises(ValueError): access.review_access(*self.inputs,**options)
        inputs = list(self.inputs); inputs[3] = b' '*(access.CONTROL_LIMIT+1)
        with self.assertRaises(ValueError): self.report(inputs)

    def test_full_replay_rejects_repinned_changed_report_and_input(self):
        report = self.report(); original = policy._canonical(report)
        result = access.verify_access(original,*self.inputs,expected_report_sha256=policy._digest(original),**self.options())
        self.assertFalse(result['assessment_input_verified'])
        report['effective_exposure_verified'] = True; forged = policy._canonical(report)
        with self.assertRaises(ValueError):
            access.verify_access(forged,*self.inputs,expected_report_sha256=policy._digest(forged),**self.options())
        inputs = list(self.inputs); inputs[4] += b' '
        with self.assertRaises(ValueError):
            access.verify_access(original,*inputs,expected_report_sha256=policy._digest(original),**self.options(inputs))

    def cli_args(self):
        args = ['create',*[str(p) for p in self.paths], '--scope','synthetic']
        for name,data in zip(access.INPUTS,self.inputs):
            args += ['--expected-'+name.replace('_','-')+'-sha256',policy._digest(data)]
        return args

    def test_cli_private_no_overwrite_redacted_errors_and_no_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'report.json'; args = self.cli_args()+['--output',str(output)]
            stdout,stderr = StringIO(),StringIO()
            with redirect_stdout(stdout),redirect_stderr(stderr):self.assertEqual(access.main(args),0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode),0o600)
            data = output.read_bytes();self.assertNotIn('fixture-audit-records',stdout.getvalue())
            with redirect_stdout(StringIO()),redirect_stderr(stderr):self.assertEqual(access.main(args),2)
            self.assertEqual(output.read_bytes(),data)
            self.assertNotIn(directory,stderr.getvalue())
            linked = Path(directory)/'linked';linked.symlink_to(self.paths[3])
            args = self.cli_args();args[4]=str(linked);args += ['--output',str(Path(directory)/'new.json')]
            with redirect_stdout(StringIO()),redirect_stderr(StringIO()):self.assertEqual(access.main(args),2)
            self.assertFalse((Path(directory)/'new.json').exists())


if __name__ == '__main__':
    unittest.main()
