import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path
import threading
from unittest.mock import patch

from database.ec2_assessment import retain_assessment
from database.ec2_inventory import store_ec2
from database.ec2_review_history import retain_history, verify_history, main, _head, _validate

ROOT = Path(__file__).resolve().parents[1]
EXPORT = (ROOT/'examples/ec2-describe-instances.json').read_bytes()
FINDINGS = (ROOT/'examples/ec2-findings.jsonl').read_bytes()
DIRECTORY = (ROOT/'examples/ownership-directory.json').read_bytes()


@unittest.skipUnless(os.name == 'posix', 'private history requires POSIX')
class EC2HistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.discovery = self.root/'discovery.sqlite'
        source = self.root/'export.json'; source.write_bytes(EXPORT)
        store_ec2(source, self.discovery, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        self.first = self.receipt('first', '2026-10-25')
        item = json.loads(FINDINGS); item['finding']['severity'] = 'critical'
        self.second = self.receipt('second', '2026-10-26', json.dumps(item).encode())
        self.history = self.root/'history.sqlite'

    def receipt(self, name, day, findings=FINDINGS, discovery=None):
        output = self.root/(name+'.sqlite')
        retain_assessment(discovery or self.discovery, findings, DIRECTORY, output, export_data=EXPORT,
                          as_of=date.fromisoformat(day), assessed_at=datetime.fromisoformat(day+'T01:00:00+00:00'))
        return output

    def start(self, receipt=None):
        return retain_history(receipt or self.first, self.history, export_data=EXPORT)

    def append(self, head, receipt=None, output=None, history=None):
        return retain_history(receipt or self.second, output or self.root/'next.sqlite', export_data=EXPORT,
                              history=history or self.history, expected_head=head)

    def test_two_reviews_are_reproduced_and_normalized_without_discovery(self):
        saved = {p: p.read_bytes() for p in (self.first, self.second)}
        first = self.start(); saved[self.history] = self.history.read_bytes()
        self.assertFalse(first['expected_head_checked'])
        self.discovery.unlink()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            second = self.append(first['head_sha256'])
            self.assertTrue(second['expected_head_checked'])
            result = verify_history(self.root/'next.sqlite', export_data=EXPORT, expected_head=second['head_sha256'])
        self.assertEqual((result['review_count'], result['decision_count']), (2, 2))
        self.assertTrue(result['expected_head_checked'])
        self.assertEqual(saved, {p: p.read_bytes() for p in saved})
        self.assertEqual((self.root/'next.sqlite').stat().st_mode & 0o777, 0o600)
        with sqlite3.connect(self.root/'next.sqlite') as connection:
            rows = connection.execute('SELECT sequence,finding_id,decision_json FROM decisions ORDER BY sequence').fetchall()
        self.assertEqual(rows[0][1], rows[1][1])
        self.assertNotEqual(json.loads(rows[0][2])['risk_assessment'], json.loads(rows[1][2])['risk_assessment'])

    def test_stale_missing_or_invalid_predecessor_publishes_nothing(self):
        result = self.start()
        for head in ('0'*64, None, 'bad', 'A'*64):
            with self.subTest(head=head), self.assertRaises(ValueError): self.append(head)
        self.assertFalse((self.root/'next.sqlite').exists())
        result2 = self.append(result['head_sha256'])
        with self.assertRaises(ValueError):
            self.append(result['head_sha256'], history=self.root/'next.sqlite', output=self.root/'third.sqlite')
        self.assertNotEqual(result['head_sha256'], result2['head_sha256'])
        self.assertFalse((self.root/'third.sqlite').exists())

    def test_no_overwrite_or_duplicate_review(self):
        result = self.start(); saved = self.history.read_bytes()
        with self.assertRaises(FileExistsError): self.start()
        with self.assertRaises(ValueError): self.append(result['head_sha256'], receipt=self.first)
        self.assertEqual(self.history.read_bytes(), saved)
        self.assertFalse((self.root/'next.sqlite').exists())

    def test_reverse_time_and_different_batch_are_rejected(self):
        first = self.start(self.second)
        with self.assertRaisesRegex(ValueError, 'precede'): self.append(first['head_sha256'], receipt=self.first)
        other = self.root/'other.sqlite'; source = self.root/'export.json'
        store_ec2(source, other, scope='synthetic', account='111122223333', region='us-east-1',
                  observed_at=datetime(2026, 10, 24, 1, tzinfo=timezone.utc))
        alternate = self.receipt('other-review', '2026-10-27', discovery=other)
        with self.assertRaisesRegex(ValueError, 'same discovery'): self.append(first['head_sha256'], receipt=alternate)

    def test_changed_export_and_current_model_fail(self):
        result = self.start()
        with self.assertRaises(ValueError): verify_history(self.history, export_data=EXPORT+b'\n')
        with patch('database.ec2_assessment.current_model', return_value={}), self.assertRaises(ValueError):
            verify_history(self.history, export_data=EXPORT)
        with self.assertRaises(ValueError):
            retain_history(self.second, self.root/'next.sqlite', export_data=EXPORT+b'\n', history=self.history,
                           expected_head=result['head_sha256'])
        self.assertFalse((self.root/'next.sqlite').exists())

    def test_normalized_decision_tampering_is_detected(self):
        self.start()
        with sqlite3.connect(self.history) as connection:
            connection.execute('DROP TRIGGER decisions_no_update')
            connection.execute("UPDATE decisions SET asset_id='different-asset'")
        with self.assertRaisesRegex(ValueError, 'normalized decisions'): verify_history(self.history, export_data=EXPORT)

    def test_recomputed_receipt_and_node_hash_do_not_hide_wrong_decisions(self):
        self.start()
        with sqlite3.connect(self.history) as connection:
            connection.execute('DROP TRIGGER reviews_no_update')
            record = json.loads(connection.execute('SELECT receipt_json FROM reviews').fetchone()[0])
            record['queue_report']['queues']['queues'][0]['items'][0]['priority'] = 'P0'
            payload = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
            digest = hashlib.sha256(payload.encode()).hexdigest()
            connection.execute('UPDATE reviews SET receipt_json=?,receipt_sha256=?,node_sha256=?',
                               (payload, digest, _head(1, None, digest)))
        with self.assertRaisesRegex(ValueError, 'reproduce'): verify_history(self.history, export_data=EXPORT)

    def test_wrong_chain_link_missing_node_and_extra_table_are_rejected(self):
        head = self.start()['head_sha256']; self.append(head)
        path = self.root/'next.sqlite'; saved = path.read_bytes()
        for sql in ("UPDATE reviews SET previous_sha256='wrong' WHERE sequence=2",
                    'DELETE FROM reviews WHERE sequence=1', 'CREATE TABLE extra(value TEXT)'):
            path.write_bytes(saved)
            with sqlite3.connect(path) as connection:
                connection.execute('DROP TRIGGER reviews_no_update'); connection.execute('DROP TRIGGER reviews_no_delete')
                connection.execute(sql)
            with self.subTest(sql=sql), self.assertRaises(ValueError): verify_history(path, export_data=EXPORT)

    def test_history_and_parent_modes_symlinks_and_sidecars_are_rejected(self):
        self.start(); self.history.chmod(0o644)
        with self.assertRaises(ValueError): verify_history(self.history, export_data=EXPORT)
        self.history.chmod(0o600)
        link = self.root/'link.sqlite'; link.symlink_to(self.history)
        with self.assertRaises(ValueError): verify_history(link, export_data=EXPORT)
        journal = Path(str(self.history)+'-journal'); journal.write_bytes(b'synthetic')
        with self.assertRaises(ValueError): verify_history(self.history, export_data=EXPORT)
        journal.unlink()
        public = self.root/'public'; public.mkdir(mode=0o755); public.chmod(0o755)
        with self.assertRaises(ValueError): retain_history(self.first, public/'out.sqlite', export_data=EXPORT)
        self.assertFalse((public/'out.sqlite').exists())

    def test_limits_and_publication_failure_leave_inputs_and_no_staging_files(self):
        result = self.start(); saved = self.history.read_bytes()
        for limit in ('MAX_REVIEWS', 'MAX_TOTAL_RECEIPT_BYTES', 'MAX_DECISIONS', 'MAX_DATABASE_BYTES'):
            with patch('database.ec2_review_history.'+limit, 1), self.assertRaises(ValueError):
                self.append(result['head_sha256'])
        with patch('database.ec2_review_history.os.link', side_effect=OSError('synthetic failure')), self.assertRaises(OSError):
            self.append(result['head_sha256'])
        self.assertEqual(saved, self.history.read_bytes())
        self.assertFalse((self.root/'next.sqlite').exists())
        self.assertEqual(list(self.root.glob('.ec2-history-*')), [])

    def test_finding_cannot_move_after_omission_even_with_valid_replayed_records(self):
        records = [dict(discovery={}, model={}, as_of='2026-10-25', assessed_at='2026-10-25T01:00:00+00:00', marker=i)
                   for i in range(3)]
        items = [{'f': {'asset_id': 'first'}}, {}, {'f': {'asset_id': 'second'}}]
        with patch('database.ec2_review_history._reproduce'), patch('database.ec2_review_history._items', side_effect=items):
            with self.assertRaisesRegex(ValueError, 'moved between assets'): _validate(records, b'synthetic')

    def test_optional_head_pin_detects_truncation_but_unpinned_prefix_is_consistent(self):
        first = self.start(); second = self.append(first['head_sha256'])
        self.assertEqual(verify_history(self.history, export_data=EXPORT)['review_count'], 1)
        with self.assertRaises(ValueError):
            verify_history(self.history, export_data=EXPORT, expected_head=second['head_sha256'])

    def test_cli_is_aggregate_only_and_failure_does_not_echo_inputs(self):
        source = self.root/'export.json'; stdout = StringIO()
        args = ['start', str(self.first), '--export', str(source), '--output', str(self.history)]
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        result = json.loads(stdout.getvalue())
        for private in ('synthetic-ec2-review', '111122223333', 'cloud-platform', str(self.root)):
            self.assertNotIn(private, stdout.getvalue())
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['verify', str(self.history), '--export', str(source),
                                   '--expected-head', result['head_sha256']]), 0)
        error = StringIO()
        with redirect_stderr(error): self.assertEqual(main(args), 2)
        self.assertNotIn(str(self.root), error.getvalue())

    def test_cli_append_requires_and_verifies_prior_head(self):
        first = self.start(); stdout = StringIO(); output = self.root/'cli-next.sqlite'
        args = ['append', str(self.history), str(self.second), '--export', str(self.root/'export.json'),
                '--output', str(output), '--expected-head', first['head_sha256']]
        with redirect_stdout(stdout): self.assertEqual(main(args), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result['review_count'], 2)
        self.assertEqual(verify_history(output, export_data=EXPORT)['head_sha256'], result['head_sha256'])

    def test_competing_publications_keep_one_complete_valid_file(self):
        first = self.start(); barrier = threading.Barrier(2); link = os.link
        output = self.root/'shared-next.sqlite'
        def synchronized(source, destination):
            if Path(source).name.startswith('.ec2-history-') and Path(destination) == output:
                barrier.wait(timeout=10)
            return link(source, destination)
        def publish(_):
            try:
                self.append(first['head_sha256'], output=output)
                return 'stored'
            except FileExistsError:
                return 'exists'
        with patch('database.ec2_review_history.os.link', side_effect=synchronized):
            with ThreadPoolExecutor(max_workers=2) as workers:
                results = list(workers.map(publish, range(2)))
        self.assertEqual(sorted(results), ['exists', 'stored'])
        self.assertEqual(verify_history(output, export_data=EXPORT)['review_count'], 2)
        self.assertEqual(list(self.root.glob('.ec2-history-*')), [])


if __name__ == '__main__':
    unittest.main()
