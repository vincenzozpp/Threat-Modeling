"""Sanity and regression checks for Task 2 threat enumeration."""
import csv
import tempfile
import unittest
from pathlib import Path

from script.loader import load_network
from script.stride import generate_threats, export_task2, FIELDS

DATA=Path(__file__).resolve().parents[1]/'network.json'


class StrideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=load_network(DATA)

    def test_rows_have_required_columns_and_unique_ids(self):
        threats,_,_=generate_threats(self.data)
        self.assertTrue(threats)
        self.assertEqual(len(set(t['id'] for t in threats)),len(threats))
        self.assertTrue(all(set(row)==set(FIELDS) for row in threats))
        self.assertTrue(all(t['description'] and t['evidence'] and t['required_preconditions'] for t in threats))

    def test_severe_external_network_exposures(self):
        threats,_,_=generate_threats(self.data)
        for cve in ('CVE-2019-11510','CVE-2021-26855','CVE-2021-41773'):
            self.assertTrue(any(cve in t['evidence'] and 'S1' in t['scenario'] for t in threats),cve)

    def test_zerologon_from_phished_workstation(self):
        threats,_,_=generate_threats(self.data)
        self.assertTrue(any('CVE-2020-1472' in t['evidence'] and 'S2' in t['scenario'] for t in threats))

    def test_no_remote_exploit_from_local_only_polkit(self):
        threats,filtered,_=generate_threats(self.data)
        self.assertFalse(any('CVE-2021-4034' in t['evidence'] and t['feasibility'].startswith('direct-entry') for t in threats))
        self.assertTrue(any('H09' in r['element'] and 'local-only' in r['reason'] for r in filtered))

    def test_missing_backup_ssh_not_fabricated(self):
        threats,filtered,checks=generate_threats(self.data)
        for flow in ('F5','F6','F7'):
            self.assertTrue(any(r['id']==flow and r['status']=='MISSING_DECLARED_SERVICE' for r in checks))
            self.assertFalse(any(t['element']==f'flow:{flow}' for t in threats))
            self.assertTrue(any(r['element']==f'flow:{flow}' for r in filtered))

    def test_trusts_do_not_bypass_firewall(self):
        threats,_,checks=generate_threats(self.data)
        self.assertFalse(any(t['element']=='trust:T2' for t in threats))
        self.assertTrue(any(r['id']=='T2' and r['status'].startswith('NOT_SUBSTANTIATED') for r in checks))

    def test_plaintext_flows_only_with_onpath_condition(self):
        threats,_,_=generate_threats(self.data)
        plaintext=[t for t in threats if t['element_type']=='data flow']
        self.assertTrue(plaintext)
        self.assertTrue(all(t['feasibility']=='conditional-on-network-position' for t in plaintext))
        self.assertFalse(any(t['element']=='flow:F1' for t in plaintext))  # HTTPS

    def test_strict_policy_sensitivity_and_export(self):
        allow,_,_=generate_threats(self.data,'allow')
        deny,_,_=generate_threats(self.data,'deny')
        self.assertNotEqual(len(allow),len(deny))
        with tempfile.TemporaryDirectory() as tmp:
            result=export_task2(self.data,tmp)
            self.assertEqual(result['threats'],len(allow))
            with (Path(tmp)/'stride_threat_table.csv').open(encoding='utf-8') as f:
                self.assertEqual(len(list(csv.DictReader(f))),len(allow))
            self.assertTrue((Path(tmp)/'stride_top5_discussion.md').exists())

if __name__=='__main__':
    unittest.main()
