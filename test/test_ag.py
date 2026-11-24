"""Task 4 independent behavioral tests for privilege / reachability / risk."""
import copy
import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

from script.ag import (
    build_attack_graph, enough_privilege, enumerate_paths, export_task4,
    postcondition, _path_risk,
)
from script.loader import load_network


PROJECT = Path(__file__).resolve().parents[1]


class AttackGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_network(PROJECT / 'network.json')

    def test_privilege_lattice_separates_vpn_from_os_shell(self):
        self.assertTrue(enough_privilege('root','user'))
        self.assertFalse(enough_privilege('vpn','user'))
        self.assertFalse(enough_privilege('user','vpn'))
        self.assertEqual(postcondition('root'),'root')
        with self.assertRaises(ValueError):
            postcondition('superuser')

    def test_internet_to_vpn_is_conditional_credential_not_shell(self):
        graph,_=build_attack_graph(self.data)
        self.assertTrue(graph.has_edge(('INTERNET','none'),('H04','vpn')))
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H04','user')))
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H04','root')))

    def test_pwnkit_is_local_not_remotely_exploited(self):
        graph,_=build_attack_graph(self.data)
        self.assertTrue(graph.has_edge(('H09','user'),('H09','root')))
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H09','root')))
        edges=graph.get_edge_data(('H09','user'),('H09','root'))
        self.assertTrue(any(e['reference']=='CVE-2021-4034' and e['mechanism']=='local-cve'
                            for e in edges.values()))

    def test_no_fake_services_for_backup_and_database_trusts(self):
        graph,excluded=build_attack_graph(self.data)
        self.assertFalse(graph.has_edge(('H18','user'),('H21','user')))
        self.assertFalse(graph.has_edge(('H26','user'),('H20','user')))
        self.assertTrue(any(x['cve']=='T3' for x in excluded))
        self.assertTrue(any(x['cve']=='T2' for x in excluded))

    def test_zerologon_requires_reachable_netlogon(self):
        graph,_=build_attack_graph(self.data)
        self.assertTrue(graph.has_edge(('H10','user'),('H13','root')))
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H13','root')))

    def test_t9_is_conditional_abstract_privilege_and_strict_mode_removes_it(self):
        ordinary,_=build_attack_graph(self.data)
        strict,excluded=build_attack_graph(self.data,db_credentials_as_host_user=False)
        self.assertTrue(ordinary.has_edge(('H17','user'),('H20','user')))
        self.assertFalse(strict.has_edge(('H17','user'),('H20','user')))
        self.assertTrue(any(e['cve']=='T9' for e in excluded))

    def test_ssrf_and_file_read_do_not_grant_host_shell(self):
        graph,excluded=build_attack_graph(self.data)
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H03','user')))
        self.assertFalse(graph.has_edge(('INTERNET','none'),('H01','user')))
        self.assertTrue(any(e['cve']=='CVE-2021-26855' for e in excluded))

    def test_path_risk_and_mtao(self):
        steps=[{'probability':.5,'attempt_hours':2},{'probability':.2,'attempt_hours':4}]
        likelihood,mtao,risk=_path_risk(steps,5)
        self.assertAlmostEqual(likelihood,.1)
        self.assertAlmostEqual(mtao,24.0)
        self.assertAlmostEqual(risk,.5)

    def test_path_enumeration_bounded_and_unreachable_finance(self):
        graph,_=build_attack_graph(self.data)
        goals,cap=enumerate_paths(graph,('H10','user'),('H13','root'),max_hops=2,limit=200)
        self.assertTrue(goals)
        self.assertFalse(cap)
        none,cap=enumerate_paths(graph,('H10','user'),('H21','user'),max_hops=5,limit=100)
        self.assertEqual(none,[])
        self.assertFalse(cap)

    def test_path_limit_marks_truncation_not_exhaustiveness(self):
        graph,_=build_attack_graph(self.data)
        paths,cap=enumerate_paths(graph,('H10','user'),('H13','root'),max_hops=5,limit=1)
        self.assertTrue(cap)
        self.assertEqual(len(paths),1)

    def test_stricter_intra_zone_reduces_graph_edges(self):
        permissive,_=build_attack_graph(self.data,'allow')
        restrictive,_=build_attack_graph(self.data,'deny')
        self.assertGreater(permissive.number_of_edges(),restrictive.number_of_edges())

    def test_exports_all_three_goals_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=export_task4(self.data,tmp,max_hops=4,max_paths=250)
            self.assertEqual(len(result['goal_summaries']),6)
            self.assertEqual(result['goals'],3)
            self.assertEqual(result['scenarios'],2)
            files=['attack_paths.csv','attack_goal_summary.csv','attack_graph_edges.csv',
                   'attack_graph_exclusions.csv','attack_graph_top3.png','attack_top3_paths.png',
                   'attack_graph.graphml','attack_summary.json']
            for f in files:
                self.assertGreater((Path(tmp)/f).stat().st_size,0)
            summary=json.loads((Path(tmp)/'attack_summary.json').read_text())
            self.assertTrue(any(x['goal']=='G3' and x['path_count']==0 for x in summary['goal_summaries']))
            with (Path(tmp)/'attack_paths.csv').open() as file:
                for row in csv.DictReader(file):
                    self.assertIn(row['goal'],['G1','G2','G3'])
                    self.assertTrue(float(row['likelihood'])>=0)
                    self.assertTrue(float(row['mtao_hours'])>0)
                    break


if __name__=='__main__':
    unittest.main()
