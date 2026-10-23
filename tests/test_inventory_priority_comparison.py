import json
import os
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO

from database.inventory_cli import store_export
from engine.inventory_queue_cli import plan_inventory, main

ROOT=Path(__file__).resolve().parents[1]
EXPORT=ROOT/'examples/osquery-system-info-expanded.json'
FINDINGS=ROOT/'examples/inventory-findings.jsonl'
DIRECTORY=ROOT/'examples/ownership-directory.json'


@unittest.skipUnless(os.name=='posix','private inventories require POSIX')
class InventoryPriorityComparisonTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        self.root=Path(directory.name);self.database=self.root/'inventory.sqlite'
        store_export(EXPORT,self.database,scope='synthetic',
                     observed_at=datetime(2026,10,23,tzinfo=timezone.utc))

    def plan(self,as_of,baseline=None,data=None):
        return plan_inventory(self.database,FINDINGS.read_bytes() if data is None else data,
            DIRECTORY.read_bytes(),as_of=as_of,baseline_as_of=baseline,export_data=EXPORT.read_bytes())

    def test_later_review_identifies_overdue_without_changing_technical_risk(self):
        initial=self.plan(date(2026,10,23))
        current=self.plan(date(2027,1,1),date(2026,10,23))
        comparison=current['priority_comparison']
        self.assertEqual(comparison['changed_item_count'],1)
        change=comparison['changes'][0]
        self.assertFalse(change['previous_overdue']);self.assertTrue(change['current_overdue'])
        old=initial['queues']['queues'][0]['items'][0]
        new=current['queues']['queues'][0]['items'][0]
        self.assertEqual(old['risk_assessment'],new['risk_assessment'])
        self.assertEqual(old['due_date'],new['due_date'])
        self.assertEqual(initial['inventory_binding'],current['inventory_binding'])
        self.assertEqual(initial['input_sha256'],current['input_sha256'])

    def test_equal_date_and_empty_findings_have_explicit_unchanged_counts(self):
        result=self.plan(date(2026,10,23),date(2026,10,23))['priority_comparison']
        self.assertEqual((result['changed_item_count'],result['unchanged_item_count']),(0,1))
        empty=self.plan(date(2027,1,1),date(2026,10,23),b'\n')['priority_comparison']
        self.assertEqual(empty['changes'],[])
        self.assertEqual(empty['unchanged_item_count'],0)

    def test_reversed_dates_and_findings_not_open_at_baseline_fail(self):
        with self.assertRaises(ValueError):self.plan(date(2026,10,23),date(2026,10,24))
        with self.assertRaises(ValueError):self.plan(date(2026,10,24),date(2026,10,22))

    def test_cli_rejects_invalid_baseline_without_publishing(self):
        output=self.root/'comparison.json'
        args=[str(self.database),str(FINDINGS),'--directory',str(DIRECTORY),
              '--as-of','2027-01-01','--baseline-as-of','2026-10-23','--output',str(output)]
        self.assertEqual(main(args),0)
        self.assertEqual(json.loads(output.read_bytes())['priority_comparison']['changed_item_count'],1)
        args[args.index('2026-10-23')]='not-a-date';args[-1]=str(self.root/'failed.json')
        with redirect_stderr(StringIO()):self.assertEqual(main(args),2)
        self.assertFalse((self.root/'failed.json').exists())


if __name__=='__main__':unittest.main()
