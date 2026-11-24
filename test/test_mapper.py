"""Task 3 tests use tiny SYNTHETIC catalogue fixtures, never claimed real mappings."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from script.loader import load_network
from script.mapper import (
    _parse_nvd_record, parse_capec, parse_attack, find_techniques,
    map_vulnerabilities, map_misconfigurations, export_task3,
    ATTACK_VERSION, CAPEC_VERSION
)

ROOT = Path(__file__).resolve().parents[1]
CAPEC = '''<?xml version="1.0"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.9">
<Attack_Patterns>
  <Attack_Pattern ID="66" Name="Synthetic web injection" Status="Stable">
   <Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses>
   <Taxonomy_Mappings><Taxonomy_Mapping Taxonomy_Name="ATTACK"><Entry_ID>1190</Entry_ID></Taxonomy_Mapping></Taxonomy_Mappings>
  </Attack_Pattern>
  <Attack_Pattern ID="150" Name="Synthetic child" Status="Stable">
   <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
   <Related_Attack_Patterns><Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="66"/></Related_Attack_Patterns>
  </Attack_Pattern>
  <Attack_Pattern ID="70" Name="Default passwords" Status="Stable"/>
  <Attack_Pattern ID="49" Name="Brute force" Status="Stable"/>
  <Attack_Pattern ID="999" Name="Deprecated mapping" Status="Deprecated"><Related_Weaknesses><Related_Weakness CWE_ID="79"/></Related_Weaknesses></Attack_Pattern>
</Attack_Patterns></Attack_Pattern_Catalog>'''
STIX = {'type':'bundle','objects':[
    {'type':'attack-pattern','name':'Exploit Public-Facing Application',
     'external_references':[{'source_name':'mitre-attack','external_id':'T1190'}],
     'kill_chain_phases':[{'kill_chain_name':'mitre-attack','phase_name':'initial-access'}]},
    {'type':'attack-pattern','name':'Revoked synthetic', 'revoked':True,
     'external_references':[{'source_name':'mitre-attack','external_id':'T9999'}],
     'kill_chain_phases':[{'kill_chain_name':'mitre-attack','phase_name':'execution'}]}
]}


class MapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_network(ROOT/'network.json')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base/'capec.xml').write_text(CAPEC, encoding='utf-8')
        (self.base/'attack.json').write_text(json.dumps(STIX), encoding='utf-8')

    def test_capec_reference_and_cwe_parsing(self):
        patterns, by_cwe = parse_capec(self.base/'capec.xml')
        self.assertEqual(by_cwe['CWE-79'], {'CAPEC-66'})
        self.assertEqual(patterns['CAPEC-66']['techniques'], {'T1190'})
        self.assertNotIn('CAPEC-999',patterns)

    def test_capec_inheritance_is_traced_and_optional(self):
        patterns, _ = parse_capec(self.base/'capec.xml')
        self.assertIn(('T1190','direct CAPEC taxonomy mapping'),find_techniques('CAPEC-66',patterns))
        self.assertEqual(find_techniques('CAPEC-150',patterns,include_inherited=False),[])
        mapping = find_techniques('CAPEC-150',patterns)
        self.assertEqual(mapping,[('T1190','CAPEC inherited via parent CAPEC-66 (1 hop(s))')])

    def test_attack_skips_revoked_and_reads_tactics(self):
        techniques = parse_attack(self.base/'attack.json')
        self.assertEqual(techniques['T1190']['tactics'], ['initial-access'])
        self.assertNotIn('T9999',techniques)

    def test_nvd_cwe_parsing_and_reject_mismatch(self):
        path = self.base/'nvd.json'
        path.write_text(json.dumps({'vulnerabilities':[{'cve':{'id':'CVE-2021-41773','weaknesses':[
            {'description':[{'lang':'en','value':'CWE-79'},{'lang':'en','value':'NVD-CWE-noinfo'}]}
        ]}}]}),encoding='utf-8')
        self.assertEqual(_parse_nvd_record(path,'CVE-2021-41773')['cwes'],['CWE-79'])
        with self.assertRaisesRegex(ValueError,'matching CVE records'):
            _parse_nvd_record(path,'CVE-2021-0000')

    def test_unmapped_are_kept_explicitly(self):
        patterns, by_cwe = parse_capec(self.base/'capec.xml')
        techniques = parse_attack(self.base/'attack.json')
        data = copy.deepcopy(self.data)
        # Only one occurrence, two CVEs with synthetic NVD records.
        host=copy.deepcopy(data['network']['hosts'][0])
        host['vulnerabilities']=[{'cve':'CVE-2021-41773','service':'http'},
                                 {'cve':'CVE-2021-22205','service':'http'}]
        data['network']['hosts']=[host]
        nvd={ 'CVE-2021-41773': {'cwes':['CWE-79'],'nvd_url':'https://example.test/nvd'},
              'CVE-2021-22205': {'cwes':['CWE-999'],'nvd_url':'https://example.test/nvd'}}
        rows=map_vulnerabilities(data,nvd,patterns,by_cwe,techniques)
        self.assertEqual(len(rows),2)
        mapped=next(r for r in rows if r['status']=='mapped')
        missed=next(r for r in rows if r['status']=='unmapped')
        self.assertEqual(mapped['attack_technique'],'T1190')
        self.assertEqual(mapped['stride_tag'],'Spoofing')
        self.assertIn('No CAPEC',missed['unmapped_reason'])

    def test_not_confusing_24_occurrences_with_22_cves(self):
        cves=[v['cve'] for h in self.data['network']['hosts'] for v in h['vulnerabilities']]
        self.assertEqual(len(cves),24)
        self.assertEqual(len(set(cves)),22)

    def test_misconfigurations_have_manual_capec_treatment(self):
        patterns,_=parse_capec(self.base/'capec.xml')
        techniques=parse_attack(self.base/'attack.json')
        rows=map_misconfigurations(self.data,patterns,techniques)
        self.assertEqual({r['misconfiguration'] for r in rows}, {'MC1','MC2'})
        self.assertEqual({r['capec'] for r in rows}, {'CAPEC-70','CAPEC-49'})
        self.assertTrue(all(r['status']=='partial:CAPEC-only' for r in rows))

    def test_offline_mode_fails_when_catalogues_absent(self):
        from script.mapper import download_sources
        with self.assertRaisesRegex(FileNotFoundError,'Missing offline catalogue'):
            download_sources(['CVE-2021-41773'], self.base/'empty',offline=True)

    def test_full_export_using_synthetic_fixtures_offline(self):
        # Synthetic fixtures cover whole input, and we verify counts and file creation.
        library=self.base/'library'
        library.mkdir()
        (library/'capec_v3.9.xml').write_text(CAPEC,encoding='utf-8')
        (library/'enterprise-attack-20.1.json').write_text(json.dumps(STIX),encoding='utf-8')
        (library/'nvd').mkdir()
        cves={v['cve'] for h in self.data['network']['hosts'] for v in h['vulnerabilities']}
        for cve in cves:
            weak='CWE-79' if cve=='CVE-2021-41773' else 'CWE-999'
            (library/'nvd'/(cve+'.json')).write_text(json.dumps({'vulnerabilities':[{'cve':{
                'id':cve,'weaknesses':[{'description':[{'lang':'en','value':weak}]}]}}]}),encoding='utf-8')
        report=export_task3(self.data,self.base/'out',library,offline=True)
        self.assertEqual(report['unique_cves_total'],22)
        self.assertEqual(report['host_cve_occurrences'],24)
        self.assertEqual(report['unique_cves_mapped'],1)
        self.assertEqual(len(report['unmapped_cves']),21)
        for name in ('mapping_summary.json','cve_attack_mapping.csv','cve_unmapped.csv',
                     'misconfiguration_mapping.csv','attack_tactic_heatmap.png','mapping_source_manifest.json'):
            self.assertTrue((self.base/'out'/name).is_file(),name)


if __name__ == '__main__':
    unittest.main()
