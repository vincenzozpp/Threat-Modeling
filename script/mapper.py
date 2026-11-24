"""Task 3: traceable NVD CVE -> CWE -> CAPEC -> ATT&CK -> tactic mapping.

Uses pinned CAPEC 3.9 and Enterprise ATT&CK 20.1; NVD CVE API 2.0 records
are downloaded individually and SHA256-manifested. No made-up mappings.

Run: python -m script.mapper --input network.json --output output
For cached runs: python -m script.mapper --offline ...
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from .loader import load_network

CAPEC_VERSION = '3.9'
ATTACK_VERSION = '20.1'
CAPEC_URL = 'https://capec.mitre.org/data/xml/capec_v3.9.xml'
ATTACK_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json'
NVD_ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CWE_RE = re.compile(r'^CWE-(\d+)$', re.IGNORECASE)
TECH_RE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
FIELDS = ['host', 'host_name', 'service', 'cve', 'cwe', 'capec', 'capec_name',
          'attack_technique', 'technique_name', 'tactic', 'stride_tag', 'mapping_evidence',
          'status', 'unmapped_reason', 'nvd_url', 'capec_url', 'attack_url']

# One primary STRIDE label per ATT&CK tactic: analytical classification, NOT
# taxonomy identity and not evidence of the exploit having taken place.
TACTIC_TO_STRIDE = {
    'reconnaissance': 'Information Disclosure',
    'resource-development': 'Spoofing',
    'initial-access': 'Spoofing',
    'execution': 'Elevation of Privilege',
    'persistence': 'Elevation of Privilege',
    'privilege-escalation': 'Elevation of Privilege',
    'defense-evasion': 'Repudiation',
    'credential-access': 'Information Disclosure',
    'discovery': 'Information Disclosure',
    'lateral-movement': 'Spoofing',
    'collection': 'Information Disclosure',
    'command-and-control': 'Spoofing',
    'exfiltration': 'Information Disclosure',
    'impact': 'Tampering',
}


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def _children(elem, tag):
    return [node for node in elem if _local(node.tag) == tag]


def _child(elem, tag):
    return next((node for node in elem if _local(node.tag) == tag), None)


def _sha256(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as file:
        for part in iter(lambda: file.read(1 << 20), b''):
            result.update(part)
    return result.hexdigest()


def _download(url, destination, *, api_key=None, attempts=3):
    """Download atomically, use cache, bound data size; fail clearly on errors."""
    destination = Path(destination)
    if destination.is_file() and destination.stat().st_size > 0:
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    headers = {'User-Agent': 'HW3-Threat-Modeling/1.0 (university coursework)',
               'Accept': 'application/json, application/xml, text/xml, */*'}
    if api_key:
        headers['apiKey'] = api_key
    for attempt in range(attempts):
        temp = destination.with_name(destination.name + '.part')
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=75) as response, temp.open('wb') as out:
                total = 0
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > 80 * 1024 * 1024:
                        raise ValueError(f'Download too large: {url}')
                    out.write(block)
            if total == 0:
                raise ValueError(f'Empty download: {url}')
            temp.replace(destination)
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            temp.unlink(missing_ok=True)
            if attempt + 1 == attempts:
                raise RuntimeError(f'Could not download {url}: {exc}. Try again or copy the catalogue manually to {destination}') from exc
            time.sleep(8 * (attempt + 1))
    return False


def download_sources(cve_ids, library_dir, *, offline=False, nvd_api_key=None):
    """Download pinned catalogues and exact NVD record set, caching between runs."""
    library_dir = Path(library_dir)
    capec_path = library_dir / 'capec_v3.9.xml'
    attack_path = library_dir / 'enterprise-attack-20.1.json'
    nvd_dir = library_dir / 'nvd'
    nvd_dir.mkdir(parents=True, exist_ok=True)
    external = [(CAPEC_URL, capec_path), (ATTACK_URL, attack_path)]
    for url, path in external:
        if not path.is_file():
            if offline:
                raise FileNotFoundError(f'Missing offline catalogue: {path}. Run without --offline to download it.')
            print(f'Downloading {path.name} ...', flush=True)
            _download(url, path)
    ordered = sorted(set(cve_ids))
    misses = [cve for cve in ordered if not (nvd_dir / (cve + '.json')).is_file()]
    if offline and misses:
        raise FileNotFoundError(f'NVD offline cache missing {len(misses)} records, for example {misses[0]}; rerun without --offline.')
    print(f'NVD cache: {len(ordered)-len(misses)}/{len(ordered)} records, {len(misses)} to fetch', flush=True)
    for index, cve in enumerate(misses):
        if index and not nvd_api_key:
            time.sleep(7)  # NVD without an API key: avoid >5 calls/30 seconds
        url = NVD_ENDPOINT + '?' + urllib.parse.urlencode({'cveId': cve})
        print(f'  NVD {index+1}/{len(misses)}: {cve}', flush=True)
        path = nvd_dir / (cve + '.json')
        _download(url, path, api_key=nvd_api_key)
        # Reject wrong/empty/irrelevant API responses instead of caching as valid.
        try:
            _parse_nvd_record(path, cve)
        except (ValueError, json.JSONDecodeError):
            path.unlink(missing_ok=True)
            raise
    return capec_path, attack_path, nvd_dir


def _parse_nvd_record(path, expected_cve):
    with Path(path).open(encoding='utf-8') as file:
        record = json.load(file)
    matches = [x['cve'] for x in record.get('vulnerabilities', [])
               if x.get('cve', {}).get('id') == expected_cve]
    if len(matches) != 1:
        raise ValueError(f'NVD response for {expected_cve} has {len(matches)} matching CVE records (expected 1): {path}')
    entry = matches[0]
    cwes = set()
    for weak in entry.get('weaknesses', []):
        for description in weak.get('description', []):
            value = description.get('value', '').strip().upper()
            if CWE_RE.fullmatch(value):
                cwes.add(value)
    return {'cwes': sorted(cwes, key=lambda x: int(x.split('-')[1])),
            'status': entry.get('vulnStatus', 'unknown'),
            'nvd_url': f'https://nvd.nist.gov/vuln/detail/{expected_cve}'}


def load_nvd(nvd_dir, cves):
    return {cve: _parse_nvd_record(Path(nvd_dir) / (cve + '.json'), cve)
            for cve in sorted(set(cves))}


def parse_capec(xml_path):
    """Parse authoritative related CWEs, ATTACK taxonomy mappings, ChildOf parents."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ValueError(f'Invalid CAPEC XML {xml_path}: {exc}') from exc
    root = tree.getroot()
    if root.attrib.get('Version') != CAPEC_VERSION:
        raise ValueError(f'Expected CAPEC {CAPEC_VERSION}, got {root.attrib.get("Version")}')
    patterns = {}
    by_cwe = defaultdict(set)
    for element in root.iter():
        if _local(element.tag) != 'Attack_Pattern':
            continue
        cid = 'CAPEC-' + str(element.attrib['ID'])
        status = element.attrib.get('Status', '')
        if status.lower() == 'deprecated':
            continue
        related = _child(element, 'Related_Weaknesses')
        cwes = set()
        if related is not None:
            for ref in _children(related, 'Related_Weakness'):
                val = 'CWE-' + ref.attrib.get('CWE_ID', '')
                if CWE_RE.fullmatch(val):
                    cwes.add(val)
                    by_cwe[val].add(cid)
        taxonomy = _child(element, 'Taxonomy_Mappings')
        techniques = set()
        if taxonomy is not None:
            for tax in _children(taxonomy, 'Taxonomy_Mapping'):
                if tax.attrib.get('Taxonomy_Name', '').upper() not in ('ATTACK', 'ATT&CK'):
                    continue
                ident = _child(tax, 'Entry_ID')
                if ident is None or not ident.text:
                    continue
                tid = ident.text.strip().upper()
                if not tid.startswith('T'):
                    tid = 'T' + tid
                if TECH_RE.fullmatch(tid):
                    techniques.add(tid)
        parents = set()
        related_patterns = _child(element, 'Related_Attack_Patterns')
        if related_patterns is not None:
            for rel in _children(related_patterns, 'Related_Attack_Pattern'):
                if rel.attrib.get('Nature', '').lower() == 'childof' and rel.attrib.get('CAPEC_ID'):
                    parents.add('CAPEC-' + rel.attrib['CAPEC_ID'])
        patterns[cid] = {'name': element.attrib.get('Name', ''),
                         'cwes': cwes, 'techniques': techniques, 'parents': parents}
    if not patterns:
        raise ValueError('CAPEC XML contained no active attack patterns')
    return patterns, dict(by_cwe)


def parse_attack(json_path):
    """Return active Enterprise techniques + their tactics from STIX 2.1."""
    with Path(json_path).open(encoding='utf-8') as file:
        obj = json.load(file)
    if not isinstance(obj.get('objects'), list):
        raise ValueError('ATT&CK bundle has no STIX objects list')
    # STIX data releases can express bundle version in collection name rather than
    # x_mitre_version; use the version-specific URL and store SHA256 in manifest.
    techniques = {}
    for element in obj['objects']:
        if element.get('type') != 'attack-pattern' or element.get('revoked') or element.get('x_mitre_deprecated'):
            continue
        ids = [r.get('external_id') for r in element.get('external_references', [])
               if r.get('source_name') == 'mitre-attack' and TECH_RE.fullmatch(r.get('external_id', ''))]
        if not ids:
            continue
        tactics = {p['phase_name'] for p in element.get('kill_chain_phases', [])
                   if p.get('kill_chain_name') == 'mitre-attack' and p.get('phase_name')}
        if tactics:
            techniques[ids[0]] = {'name': element.get('name', ''), 'tactics': sorted(tactics)}
    if not techniques:
        raise ValueError('No active Enterprise ATT&CK techniques found')
    return techniques


def find_techniques(capec_id, patterns, *, include_inherited=True):
    """Direct taxonomy links first; optionally use nearest parent-level mappings.

    CAPEC explicitly supports inheritance of its ATT&CK taxonomy crossrefs;
    ATT&CK itself does not inherit CAPEC relationships.
    """
    pattern = patterns[capec_id]
    if pattern['techniques']:
        return [(tid, 'direct CAPEC taxonomy mapping') for tid in sorted(pattern['techniques'])]
    if not include_inherited:
        return []
    frontier = [(parent, 1) for parent in sorted(pattern['parents'])]
    visited = {capec_id}
    found = []
    nearest = None
    while frontier:
        parent, depth = frontier.pop(0)
        if parent in visited or depth > 10:
            continue
        visited.add(parent)
        if nearest is not None and depth > nearest:
            break
        item = patterns.get(parent)
        if not item:
            continue
        if item['techniques']:
            nearest = depth
            found += [(tid, f'CAPEC inherited via parent {parent} ({depth} hop(s))')
                      for tid in sorted(item['techniques'])]
        else:
            frontier += [(p, depth + 1) for p in sorted(item['parents'])]
    return sorted(set(found))


def _row(**kwargs):
    return {k: kwargs.get(k, '') for k in FIELDS}


def map_vulnerabilities(data, nvd, patterns, by_cwe, techniques, *, include_inherited=True):
    """Return rows at host occurrence granularity, with explicit partial/unmapped rows."""
    rows = []
    for host in sorted(data['network']['hosts'], key=lambda h: h['id']):
        for vuln in sorted(host['vulnerabilities'], key=lambda v: v['cve']):
            cve = vuln['cve']
            if cve not in nvd:
                raise ValueError(f'Missing NVD CVE data: {cve}')
            base = {'host': host['id'], 'host_name': host['name'],
                    'service': vuln['service'], 'cve': cve,
                    'nvd_url': nvd[cve]['nvd_url']}
            cwes = nvd[cve]['cwes']
            if not cwes:
                rows.append(_row(**base, status='unmapped',
                                 unmapped_reason='NVD has no numeric CWE assignment (or marks it as Other/noinfo)'))
                continue
            for cwe in cwes:
                capecs = sorted(by_cwe.get(cwe, []), key=lambda x: int(x.split('-')[1]))
                if not capecs:
                    rows.append(_row(**base, cwe=cwe, status='unmapped',
                                     unmapped_reason='No CAPEC related-weakness cross-reference for this CWE'))
                    continue
                for capec in capecs:
                    capec_base = dict(base, cwe=cwe, capec=capec,
                                      capec_name=patterns[capec]['name'],
                                      capec_url='https://capec.mitre.org/data/definitions/' + capec.split('-')[1] + '.html')
                    candidate = find_techniques(capec, patterns, include_inherited=include_inherited)
                    if not candidate:
                        rows.append(_row(**capec_base, status='unmapped',
                                         unmapped_reason='No CAPEC ATT&CK taxonomy reference, direct or inherited'))
                        continue
                    active = False
                    for tid, evidence in candidate:
                        technique = techniques.get(tid)
                        if technique is None:
                            continue  # outdated or deprecated technique in pinned ATT&CK
                        active = True
                        for tactic in technique['tactics']:
                            rows.append(_row(**capec_base,
                                             attack_technique=tid, technique_name=technique['name'],
                                             tactic=tactic, stride_tag=TACTIC_TO_STRIDE.get(tactic, 'Unclassified'),
                                             mapping_evidence=evidence, status='mapped',
                                             attack_url='https://attack.mitre.org/techniques/' + tid[1:].replace('.', '/') + '/'))
                    if not active:
                        rows.append(_row(**capec_base, status='unmapped',
                                         unmapped_reason='CAPEC references ATT&CK techniques absent, revoked, or deprecated in pinned Enterprise 20.1'))
    return rows


def map_misconfigurations(data, patterns, techniques):
    """Documented manual CAPEC treatment, kept separate from CVE coverage denominator."""
    recommended = {'MC1': ('CAPEC-70', 'Spoofing',
                           'Default credentials; manual analogy to CAPEC-70'),
                   'MC2': ('CAPEC-49', 'Spoofing',
                           'Password authentication with no lockout; manual analogy to CAPEC-49')}
    result = []
    for host in data['network']['hosts']:
        for mc in host.get('misconfigurations', []):
            cid, stride, evidence = recommended.get(mc['id'], ('', '', 'No reviewed CAPEC mapping'))
            if cid not in patterns:
                result.append({'host': host['id'], 'misconfiguration': mc['id'], 'description': mc['description'],
                               'capec': cid, 'attack_technique': '', 'tactic': '', 'stride_tag': stride,
                               'mapping_evidence': evidence, 'status': 'unmapped:CAPEC unavailable'})
                continue
            matches = find_techniques(cid, patterns)
            mapped = [(tid, tactic, why) for tid, why in matches if tid in techniques
                      for tactic in techniques[tid]['tactics']]
            if not mapped:
                mapped = [('', '', 'CAPEC documented; no active ATT&CK link')]
            for tid, tactic, why in mapped:
                result.append({'host': host['id'], 'misconfiguration': mc['id'], 'description': mc['description'],
                               'capec': cid, 'attack_technique': tid, 'tactic': tactic, 'stride_tag': stride,
                               'mapping_evidence': evidence + '; ' + why,
                               'status': 'manual-analogy' if tid else 'partial:CAPEC-only'})
    return result


def _write_csv(path, rows, fields):
    with Path(path).open('w', newline='', encoding='utf-8') as file:
        w = csv.DictWriter(file, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _plot_heatmap(tech_counts, output):
    labels = list(TACTIC_TO_STRIDE)
    values = [len(tech_counts.get(tactic, set())) for tactic in labels]
    fig, ax = plt.subplots(figsize=(12, 5))
    # Heatmap uses a one-row matrix: exactly one count of distinct active techniques per tactic.
    heat = ax.imshow([values], aspect='auto', cmap='Blues', vmin=0, vmax=max(values or [1]))
    ax.set_yticks([0], ['Distinct techniques'])
    ax.set_xticks(range(len(labels)), labels, rotation=55, ha='right', fontsize=8)
    for col, count in enumerate(values):
        ax.text(col, 0, str(count), ha='center', va='center', fontsize=9,
                color='white' if count > max(values or [1]) * .65 else 'black')
    ax.set_title('Enterprise ATT&CK tactic heatmap — CVE mappings (distinct techniques)')
    fig.colorbar(heat, ax=ax, shrink=.8, label='Techniques')
    fig.tight_layout()
    fig.savefig(Path(output) / 'attack_tactic_heatmap.png', dpi=175, bbox_inches='tight')
    plt.close(fig)
    return dict(zip(labels, values))


def export_task3(data, output, library_dir, *, offline=False, nvd_api_key=None, include_inherited=True):
    """Generate evidence-linked mapping table, explicit misses, heatmap and manifest."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cves = sorted({v['cve'] for h in data['network']['hosts'] for v in h['vulnerabilities']})
    capec_file, attack_file, nvd_dir = download_sources(cves, library_dir, offline=offline, nvd_api_key=nvd_api_key)
    nvd = load_nvd(nvd_dir, cves)
    patterns, by_cwe = parse_capec(capec_file)
    techniques = parse_attack(attack_file)
    mapping = map_vulnerabilities(data, nvd, patterns, by_cwe, techniques, include_inherited=include_inherited)
    manual = map_misconfigurations(data, patterns, techniques)
    _write_csv(output / 'cve_attack_mapping.csv', mapping, FIELDS)
    _write_csv(output / 'misconfiguration_mapping.csv', manual,
               ['host','misconfiguration','description','capec','attack_technique','tactic','stride_tag','mapping_evidence','status'])
    mapped_cves = {r['cve'] for r in mapping if r['status'] == 'mapped'}
    missing_cves = set(cves) - mapped_cves
    unmapped = []
    for cve in sorted(missing_cves):
        reasons = sorted({r['unmapped_reason'] for r in mapping if r['cve']==cve and r['unmapped_reason']})
        unmapped.append({'cve': cve, 'reason': ' | '.join(reasons) or 'No validated ATT&CK technique'})
    _write_csv(output / 'cve_unmapped.csv', unmapped, ['cve','reason'])
    tactic_techniques = defaultdict(set)
    for r in mapping:
        if r['status'] == 'mapped':
            tactic_techniques[r['tactic']].add(r['attack_technique'])
    counts = _plot_heatmap(tactic_techniques, output)
    # SHA of every source shows exact input snapshots; NVD content is mutable.
    sources = [{'name':'CAPEC', 'version':CAPEC_VERSION, 'url':CAPEC_URL,
                'file':str(capec_file), 'sha256':_sha256(capec_file)},
               {'name':'Enterprise ATT&CK', 'version':ATTACK_VERSION, 'url':ATTACK_URL,
                'file':str(attack_file), 'sha256':_sha256(attack_file)}]
    for cve in cves:
        path = nvd_dir / (cve + '.json')
        sources.append({'name':cve, 'version':'NVD CVE API 2.0 snapshot',
                        'url':NVD_ENDPOINT+'?cveId='+cve, 'file':str(path), 'sha256':_sha256(path)})
    manifest = {'downloaded_utc':datetime.now(timezone.utc).isoformat(),
                'versions':{'CAPEC':CAPEC_VERSION,'Enterprise ATT&CK':ATTACK_VERSION,'NVD API':'2.0'},
                'capec_patterns_loaded':len(patterns), 'attack_active_techniques_loaded':len(techniques),
                'sources':sources}
    (output / 'mapping_source_manifest.json').write_text(json.dumps(manifest, indent=2),encoding='utf-8')
    result = {'unique_cves_total':len(cves), 'unique_cves_mapped':len(mapped_cves),
              'coverage_percent':round(100*len(mapped_cves)/len(cves),2) if cves else 0,
              'unmapped_cves':sorted(missing_cves),
              'host_cve_occurrences':sum(len(h['vulnerabilities']) for h in data['network']['hosts']),
              'mapped_occurrences':len({(r['host'],r['cve']) for r in mapping if r['status']=='mapped'}),
              'mapping_table_rows':len(mapping), 'misconfiguration_table_rows':len(manual),
              'tactic_distinct_technique_counts':counts,
              'mapping_rule':'CVE -> NVD weaknesses CWE -> CAPEC Related_Weakness CWE_ID -> CAPEC ATTACK taxonomy Entry_ID (direct, else nearest ancestor) -> active Enterprise STIX technique and its kill_chain_phases -> primary heuristic STRIDE tag',
              'caveat':'Catalogue associations are generic; they do NOT prove a specific CVE exploit implements the linked ATT&CK technique or that an attack path is feasible.'}
    (output / 'mapping_summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Task 3: evidence-linked CVE/CWE/CAPEC/ATT&CK mapper')
    parser.add_argument('--input', default='network.json')
    parser.add_argument('--output', default='output')
    parser.add_argument('--library-dir', default='data/threat_libraries')
    parser.add_argument('--offline', action='store_true', help='Require previously downloaded source files')
    parser.add_argument('--nvd-api-key', default=None, help='Optional NVD API key; never commit it to Git')
    parser.add_argument('--no-inheritance', action='store_true', help='Disable CAPEC parent ATT&CK taxonomy mappings')
    args = parser.parse_args(argv)
    try:
        data = load_network(args.input)
        result = export_task3(data,args.output,args.library_dir,offline=args.offline,
                              nvd_api_key=args.nvd_api_key,include_inherited=not args.no_inheritance)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f'Task 3 FAILED: {exc}',file=sys.stderr)
        return 1
    print('Task 3 completed.')
    print(json.dumps(result,indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
