"""A shared queue must reproduce every field under independent recipient requirements."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import date
import hashlib
from io import StringIO
import json
import os
import unittest
from unittest.mock import patch

from database.inventory_assessment_queue_verify import verify_queues, main
from tests import test_assessment_queue_export as sender


@unittest.skipUnless(os.name == 'posix', 'private evidence requires POSIX')
class QueueRecipientTests(unittest.TestCase):
    # Reuse the native retained assessment setup, not the sender test methods.
    def setUp(self):
        sender.AssessmentQueueTests.setUp(self)
        self.payload = sender.AssessmentQueueTests.build(self)
        self.data = json.dumps(self.payload, sort_keys=True, indent=2).encode()
        self.report_pin = hashlib.sha256(self.data).hexdigest()

    def receive(self, data=None, **changes):
        return verify_queues(self.data if data is None else data, self.database, self.original.read_bytes(),
            **(dict(expected_report_sha256=self.report_pin, expected_database_sha256=self.pin,
                    as_of=date(2026, 11, 15)) | changes))

    def test_recipient_reproduces_complete_report_and_omits_private_queue_data(self):
        before = self.database.read_bytes()
        result = self.receive()
        self.assertEqual(result['status'], 'assessment_queue_reproduced')
        self.assertEqual(result['assigned_item_count'], 1)
        self.assertNotIn('synthetic-checkout-review', json.dumps(result))
        self.assertNotIn('cloud-platform', json.dumps(result))
        self.assertEqual(self.database.read_bytes(), before)

    def test_changed_counts_findings_policy_dates_and_unknown_fields_fail_with_new_report_pin(self):
        def changed(path, value):
            document = json.loads(self.data); node = document
            for key in path[:-1]: node = node[key]
            node[path[-1]] = value
            data = json.dumps(document).encode()
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.receive(data, expected_report_sha256=hashlib.sha256(data).hexdigest())
        for path, value in ((['schema_version'], True), (['schema_version'], 1.0), (['extra'], 1),
                            (['queue_document','queues','assigned_item_count'], 0),
                            (['queue_document','queues','queues',0,'items',0,'priority'], 'P3'),
                            (['queue_document','input_sha256','ownership_directory'], '0'*64),
                            (['retained_as_of'], '2026-10-24')):
            changed(path, value)
        with self.assertRaises(ValueError): self.receive(as_of=date(2026, 11, 14))
        with self.assertRaises(ValueError): self.receive(expected_database_sha256='0'*64)

    def test_invalid_pin_bound_and_json_reject_before_database_replay(self):
        with patch('database.inventory_assessment_queue_verify.build_queues', side_effect=AssertionError('must not replay')):
            with self.assertRaises(ValueError): self.receive(expected_report_sha256='0'*64)
            with self.assertRaises(ValueError): self.receive(expected_database_sha256='bad')
            with patch('database.inventory_assessment_queue_verify.MAX_REPORT_BYTES', 1), self.assertRaises(ValueError): self.receive()
            for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'\xff', b'[]'):
                with self.assertRaises(ValueError):
                    self.receive(data, expected_report_sha256=hashlib.sha256(data).hexdigest())

    def test_received_file_cli_is_read_only_and_has_minimized_failure(self):
        report = self.root/'received.json'; report.write_bytes(self.data)
        before = self.database.read_bytes(), report.read_bytes()
        args = [str(report), str(self.database), '--export', str(self.original),
                '--expected-report-sha256', self.report_pin, '--expected-database-sha256', self.pin,
                '--as-of', '2026-11-15']
        with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
            self.assertEqual(main(args), 0)
        self.assertEqual(json.loads(output.getvalue())['status'], 'assessment_queue_reproduced')
        self.assertEqual(errors.getvalue(), '')
        report.write_bytes(self.data+b'\n')
        with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
            self.assertEqual(main(args), 2)
        self.assertEqual(output.getvalue(), '')
        self.assertNotIn(str(self.root), errors.getvalue())
        report.write_bytes(self.data)
        self.assertEqual(before, (self.database.read_bytes(), report.read_bytes()))
