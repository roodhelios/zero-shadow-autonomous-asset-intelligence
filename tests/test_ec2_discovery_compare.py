"""Two original EC2 exports must reproduce before discovery changes are published."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from database.ec2_inventory import store_ec2
from database.ec2_inventory_compare import compare_inventories, export_comparison, main
from database.inventory_assessment_verify import _snapshot
from engine.demo_ec2_discovery_compare import exports

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix', 'private closed evidence requires POSIX')
class EC2DiscoveryComparisonTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.before,self.after=exports()
        self.old=self.store('old',self.before,24);self.new=self.store('new',self.after,25)

    def store(self,name,data,day,**options):
        source=self.root/(name+'.json');source.write_bytes(data);database=self.root/(name+'.sqlite')
        store_ec2(source,database,scope=options.get('scope','synthetic'),account=options.get('account','111122223333'),
                  region=options.get('region','us-east-1'),observed_at=datetime(2026,10,day,tzinfo=timezone.utc))
        return database

    def compare(self,**options):
        return compare_inventories(self.old,self.new,**dict(previous_export=self.before,current_export=self.after,**options))

    def test_reproduced_changes_and_original_row_references(self):
        before=[p.read_bytes() for p in (self.old,self.new)]
        with patch('socket.socket',side_effect=AssertionError('network forbidden')): result=self.compare()
        self.assertEqual(result['counts'],dict(previous_assets=2,current_assets=2,added=1,not_observed=1,changed=1,unchanged=0))
        changed=result['changes'][0]
        self.assertEqual(changed['changed_fields'],['ip_addresses','tags'])
        self.assertEqual(changed['previous']['source_reference']['instance_record'],1)
        self.assertEqual(changed['current']['source_reference']['instance_record'],2)
        self.assertEqual(changed['previous']['asset_id'],changed['current']['asset_id'])
        self.assertTrue(result['previous']['verification']['original_export_checked'])
        self.assertTrue(result['current']['verification']['original_export_checked'])
        self.assertEqual(before,[p.read_bytes() for p in (self.old,self.new)])
        self.assertNotIn('deleted',result);self.assertNotIn('risk_score',json.dumps(result))

    def test_later_time_and_reordered_rows_do_not_invent_changes(self):
        data=json.loads(self.before);data['Reservations'][0]['Instances'].reverse()
        current_data=json.dumps(data,indent=3).encode();current=self.store('reordered',current_data,25)
        result=compare_inventories(self.old,current,previous_export=self.before,current_export=current_data)
        self.assertEqual(result['counts']['unchanged'],2);self.assertEqual(result['changes'],[])
        self.assertTrue(result['source_bytes_changed'])

    def test_unselected_state_dns_and_tag_changes_are_outside_projection(self):
        data=json.loads(self.before)
        first=data['Reservations'][0]['Instances'][0]
        first['State']['Name']='running';first['PrivateDnsName']='different.example.test'
        first['Tags'][-1]['Value']='different omitted fixture metadata'
        current_data=json.dumps(data).encode();current=self.store('unselected',current_data,25)
        result=compare_inventories(self.old,current,previous_export=self.before,current_export=current_data)
        self.assertEqual(result['counts']['unchanged'],2);self.assertTrue(result['source_bytes_changed'])
        self.assertNotIn('different.example.test',json.dumps(result))

    def test_equal_or_older_observation_time_is_rejected(self):
        for day in (24,23):
            current=self.store('time'+str(day),self.after,day)
            with self.assertRaisesRegex(ValueError,'strictly later'):
                compare_inventories(self.old,current,previous_export=self.before,current_export=self.after)

    def test_account_region_and_claimed_scope_must_match(self):
        data=json.loads(self.after);data['Reservations'][0]['OwnerId']='444455556666';other=json.dumps(data).encode()
        cases=[(self.store('account',other,25,account='444455556666'),other),
               (self.store('region',self.after,25,region='us-west-2'),self.after),
               (self.store('scope',self.after,25,scope='owned'),self.after)]
        for current,data in cases:
            with self.assertRaisesRegex(ValueError,'scope, account and region'):
                compare_inventories(self.old,current,previous_export=self.before,current_export=data)

    def test_each_exact_original_export_is_required_before_publication(self):
        output=self.root/'comparison.json'
        for before,after in ((self.before+b'\n',self.after),(self.before,self.after+b'\n'),(self.after,self.before)):
            with self.assertRaises(ValueError):
                export_comparison(self.old,self.new,output,previous_export=before,current_export=after)
            self.assertFalse(output.exists())

    def test_tampered_retained_metadata_or_payload_cannot_become_a_change(self):
        output=self.root/'comparison.json'
        for name in ('metadata','payload'):
            current=self.store(name,self.after,25)
            with sqlite3.connect(current) as connection:
                if name=='metadata':connection.execute("UPDATE assets SET primary_hostname='forged.example.test'")
                else:
                    connection.execute('DROP TRIGGER asset_observations_no_update')
                    connection.execute("UPDATE asset_observations SET payload_json='{}'")
            with self.assertRaises(ValueError):
                export_comparison(self.old,current,output,previous_export=self.before,current_export=self.after)
            self.assertFalse(output.exists())

    def test_uses_only_verified_closed_copies_after_originals_disappear(self):
        def copy_then_remove(source,destination):
            _snapshot(source,destination);source.unlink()
        with patch('database.ec2_inventory._snapshot',side_effect=copy_then_remove) as copied:
            result=self.compare()
        self.assertEqual(copied.call_count,2);self.assertEqual(result['counts']['changed'],1)
        self.assertFalse(self.old.exists());self.assertFalse(self.new.exists())

    def test_symlink_or_wal_input_and_oversized_report_do_not_publish(self):
        output=self.root/'comparison.json';link=self.root/'link.sqlite';link.symlink_to(self.new)
        with self.assertRaises((OSError,ValueError)):
            export_comparison(self.old,link,output,previous_export=self.before,current_export=self.after)
        wal=Path(str(self.new)+'-wal');wal.touch()
        with self.assertRaises(ValueError):self.compare()
        wal.unlink()
        with patch('database.ec2_inventory_compare.MAX_REPORT_BYTES',1):
            with self.assertRaises(ValueError):
                export_comparison(self.old,self.new,output,previous_export=self.before,current_export=self.after)
        self.assertFalse(output.exists())

    def test_cli_private_exclusive_output_and_metadata_only_stdout(self):
        output=self.root/'comparison.json'
        args=[str(self.old),str(self.new),'--previous-export',str(self.root/'old.json'),
              '--current-export',str(self.root/'new.json'),'--output',str(output)]
        stdout=StringIO()
        with redirect_stdout(stdout):self.assertEqual(main(args),0)
        self.assertEqual(json.loads(stdout.getvalue())['changed'],1)
        for value in ('111122223333','192.0.2.40','i-0123456789abcdef0','cloud-platform',str(self.root)):
            self.assertNotIn(value,stdout.getvalue())
        self.assertEqual(output.stat().st_mode&0o777,0o600);before=output.read_bytes()
        with redirect_stderr(StringIO()):self.assertEqual(main(args),2)
        self.assertEqual(output.read_bytes(),before)
        output.unlink();(self.root/'new.json').write_bytes(self.after+b'\n');stdout=StringIO()
        with redirect_stdout(stdout),redirect_stderr(StringIO()):self.assertEqual(main(args),2)
        self.assertEqual(stdout.getvalue(),'');self.assertFalse(output.exists())

    def test_fresh_standard_library_demo(self):
        run=subprocess.run([sys.executable,'-S','-m','engine.demo_ec2_discovery_compare'],cwd=ROOT,
                           capture_output=True,text=True,timeout=30)
        self.assertEqual(run.returncode,0,run.stderr);result=json.loads(run.stdout)
        self.assertEqual(result['status'],'ec2_discovery_comparison_exercise_passed')
        self.assertEqual((result['added'],result['not_observed'],result['changed']),(1,1,1))
        self.assertTrue(result['inputs_unchanged'])


if __name__=='__main__':unittest.main()
