"""Task 5 correctness checks against the actual HW3 network model."""
import copy
import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

from script.ag import build_attack_graph
from script.loader import load_network, network_decision
from script.mitigate import (
    Optimizer, apply_mitigations, mitigated_graph, export_task5, edge_ids,
)

ROOT=Path(__file__).resolve().parents[1]

class MitigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=load_network(ROOT/'network.json')

    def test_patch_applies_to_named_host_cve_only_and_does_not_mutate_original(self):
        before=copy.deepcopy(self.data)
        modified,factor,audit=apply_mitigations(self.data,['M07','M08'])
        dc=next(h for h in modified['network']['hosts'] if h['id']=='H13')
        self.assertFalse(dc['vulnerabilities'])
        self.assertEqual(self.data,before)
        self.assertEqual(factor,1)
        self.assertEqual(len(audit),2)

    def test_ssh_and_printer_misconfig_fix(self):
        modified,_,_=apply_mitigations(self.data,['M16','M17'])
        for h in modified['network']['hosts']:
            self.assertFalse(h.get('misconfigurations',[]))

    def test_m12_uses_all_three_encoded_trust_targets(self):
        modified,_,audit=apply_mitigations(self.data,['M12'])
        self.assertEqual(set(audit[0]['removed_trusts']),{'T6','T9','T4'})
        self.assertEqual(len(modified['network']['trust_relations']),6)

    def test_direct_dmz_to_db_deny_overrides_allow(self):
        modified,_,_=apply_mitigations(self.data,['M10'])
        before,_=network_decision(self.data,'H01','H20',3306)
        after,basis=network_decision(modified,'H01','H20',3306)
        self.assertTrue(before)
        self.assertFalse(after)
        self.assertEqual(basis,'explicit-deny')
        # Do not block an independently authorized application-tier flow.
        self.assertTrue(network_decision(modified,'H17','H20',3306)[0])

    def test_zone_deny_m11_precise_ports(self):
        modified,_,_=apply_mitigations(self.data,['M11'])
        self.assertFalse(network_decision(modified,'H10','H17',8080)[0])
        self.assertTrue(network_decision(modified,'H10','H13',445)[0])

    def test_unknown_duplicate_and_invalid_scope_rejected(self):
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            apply_mitigations(self.data,['M01','M01'])
        with self.assertRaisesRegex(ValueError,'Unknown'):
            apply_mitigations(self.data,['M999'])
        invalid=copy.deepcopy(self.data)
        next(m for m in invalid['mitigations'] if m['id']=='M14')['scope']='some-servers'
        with self.assertRaisesRegex(ValueError,'scope'):
            apply_mitigations(invalid,['M14'])

    def test_detect_only_no_attack_graph_effect(self):
        original,_=build_attack_graph(self.data)
        after,_,_,_=mitigated_graph(self.data,['M18'])
        self.assertEqual(edge_ids(original),edge_ids(after))
        for u,v,k,e in original.edges(keys=True,data=True):
            self.assertEqual(e['probability'],after[u][v][k]['probability'])

    def test_edr_halves_cve_probability_and_keeps_trust(self):
        original,_=build_attack_graph(self.data)
        after,_,_,_=mitigated_graph(self.data,['M14'])
        exploit=next((u,v,k,e) for u,v,k,e in original.edges(keys=True,data=True)
                     if e['mechanism']=='local-cve')
        u,v,k,e=exploit
        self.assertAlmostEqual(after[u][v][k]['probability'],e['probability']/2)
        self.assertAlmostEqual(after[u][v][k]['attempt_hours'],e['attempt_hours'])
        trust=next((u,v,k,e) for u,v,k,e in original.edges(keys=True,data=True)
                   if e['mechanism']=='trust')
        u,v,k,e=trust
        self.assertEqual(after[u][v][k]['probability'],e['probability'])

    def test_recomputation_agrees_for_independent_combined_mitigations(self):
        optimizer=Optimizer(self.data,max_hops=5,max_paths=10000)
        for chosen in ([],['M03'],['M06','M07'],['M09','M12'],['M07','M14'],
                       ['M11','M16','M17'],['M02','M18']):
            evaluated=optimizer.evaluate(chosen)
            recomputed,_,_=optimizer.recompute_plan(chosen)
            self.assertAlmostEqual(recomputed['objective'],evaluated['objective'])
            self.assertEqual(recomputed['spent'],evaluated['cost'])

    def test_bounded_path_truncation_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'Path cap hit'):
            Optimizer(self.data,max_hops=5,max_paths=1)

    def test_strict_db_removes_g1_risk(self):
        optimizer=Optimizer(self.data,strict_db=True,max_hops=5)
        self.assertEqual(optimizer.evaluate([])['goals']['G1'],0)
        self.assertGreater(optimizer.evaluate([])['goals']['G2'],0)

    def test_budget_and_exact_solution(self):
        optimizer=Optimizer(self.data,max_hops=7)
        self.assertAlmostEqual(optimizer.evaluate([])['objective'],1.7145)
        for budget in (74010,148020):
            greedy=optimizer.greedy(budget)
            exact=optimizer.exact(budget)
            self.assertLessEqual(exact['cost'],budget)
            self.assertLessEqual(greedy['cost'],budget)
            self.assertLessEqual(exact['objective'],greedy['objective']+1e-10)
            # Sensible: no more risk than single Zerologon patch.
            self.assertLessEqual(exact['objective'],optimizer.evaluate(['M07'])['objective']+1e-10)
        self.assertEqual(optimizer.exact(74010)['ids'],['M06','M07'])

    def test_output_exports_and_custom_subset(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=export_task5(self.data,tmp,max_hops=5,selected=['M07','M18'])
            dest=Path(tmp)
            for filename in ('mitigation_summary.json','mitigation_plan.csv','mitigation_marginals.csv',
                             'mitigation_goal_comparison.csv','mitigation_selected_details.csv',
                             'critical_transitions.csv','critical_references.csv',
                             'mitigation_application_audit.json','residual_stride_threats.csv',
                             'mitigation_risk_comparison.png','attack_graph_exact_30pct.graphml',
                             'attack_graph_exact_60pct.graphml','attack_graph_custom.graphml'):
                self.assertGreater((dest/filename).stat().st_size,0,filename)
            self.assertEqual(len(result['budget_comparisons']),2)
            self.assertEqual(len(result['plans']),6)
            with (dest/'mitigation_plan.csv').open() as file:
                plans=list(csv.DictReader(file))
            self.assertEqual(len(plans),6)
            self.assertIn('Custom',{p['plan'] for p in plans})

if __name__=='__main__':
    unittest.main()
