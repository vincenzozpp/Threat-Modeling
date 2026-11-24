"""Run: python -m unittest discover -s test -v"""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from script.loader import (ModelValidationError,load_network,validate_network,
                           network_decision,build_reachability,analyze_data_flows)

ROOT=Path(__file__).resolve().parents[1]

class LoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=load_network(ROOT/'network.json')

    def mutated(self):
        return copy.deepcopy(self.data)

    def test_valid_input(self):
        self.assertTrue(validate_network(self.data))
        self.assertEqual(len(self.data['network']['hosts']),27)

    def test_malformed_json_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'broken.json'; path.write_text('{"x": }')
            with self.assertRaisesRegex(ModelValidationError,'line 1, column'):
                load_network(path)

    def test_reject_duplicate_json_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'broken.json'; path.write_text('{"metadata":{},"metadata":{}}')
            with self.assertRaisesRegex(ModelValidationError,'Duplicate JSON key'):
                load_network(path)

    def test_unknown_host_zone(self):
        data=self.mutated(); data['network']['hosts'][0]['zone']='mars'
        with self.assertRaisesRegex(ModelValidationError,'unknown or external zone'):
            validate_network(data)

    def test_duplicate_host_id(self):
        data=self.mutated(); data['network']['hosts'][1]['id']='H01'
        with self.assertRaisesRegex(ModelValidationError,'duplicated id'):
            validate_network(data)

    def test_unknown_firewall_host(self):
        data=self.mutated(); data['network']['firewall_rules'][0]['dst_host']='H99'
        with self.assertRaisesRegex(ModelValidationError,'host not in'):
            validate_network(data)

    def test_invalid_vulnerability_service(self):
        data=self.mutated(); data['network']['hosts'][0]['vulnerabilities'][0]['service']='nonexistent'
        with self.assertRaisesRegex(ModelValidationError,'missing service'):
            validate_network(data)

    def test_invalid_mitigation_target(self):
        data=self.mutated(); data['mitigations'][0]['targets']=[['H01','CVE-2000-0000']]
        with self.assertRaisesRegex(ModelValidationError,'invalid patch target'):
            validate_network(data)

    def test_budget_total(self):
        data=self.mutated(); data['total_mitigation_cost']=1
        with self.assertRaisesRegex(ModelValidationError,'mitigations sum'):
            validate_network(data)

    def test_external_web_shop_reachable(self):
        self.assertEqual(network_decision(self.data,'INTERNET','H01',443)[0],True)
        self.assertEqual(network_decision(self.data,'INTERNET','H20',3306)[0],False)

    def test_dmz_to_database_exception(self):
        self.assertTrue(network_decision(self.data,'H01','H20',3306)[0])
        self.assertFalse(network_decision(self.data,'H05','H20',3306)[0])

    def test_local_service_not_remote(self):
        self.assertEqual(network_decision(self.data,'H04','H11',0),(False,'no-declared-listening-service'))

    def test_intra_zone_policy_changes_result(self):
        self.assertTrue(network_decision(self.data,'H07','H11',22,'allow')[0])
        self.assertFalse(network_decision(self.data,'H07','H11',22,'deny')[0])

    def test_denies_override_allows(self):
        data=self.mutated()
        data['network']['firewall_rules'].append({'src_zone':'internet','src_host':'*','dst_zone':'dmz','dst_host':'H01','ports':[443],'action':'deny'})
        self.assertTrue(validate_network(data))
        self.assertFalse(network_decision(data,'INTERNET','H01',443)[0])

    def test_backup_data_flows_are_missing_declared_ssh_service(self):
        checks={c['flow_id']:c for c in analyze_data_flows(self.data)}
        for ident in ('F5','F6','F7'):
            self.assertEqual(checks[ident]['status'],'MISSING_DECLARED_SERVICE')
        for ident in ('F1','F2','F3','F4','F8','F9','F10'):
            self.assertEqual(checks[ident]['status'],'REACHABLE')

    def test_reachability_matrix_is_directional(self):
        nodes,mat,allowed=build_reachability(self.data)
        self.assertEqual(len(nodes),28)
        self.assertEqual(mat['INTERNET']['H01'],1)
        self.assertEqual(mat['H01']['INTERNET'],0)
        self.assertTrue(any(e['source']=='H01' and e['destination']=='H20' and e['port']==3306 for e in allowed))

if __name__=='__main__':
    unittest.main()
