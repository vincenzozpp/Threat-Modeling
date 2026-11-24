"""Task 2: evidence-traceable STRIDE candidate threats derived from Task 1 model.

No exploit success is asserted. Requires Task 1's validation and firewall semantics.
Run: python -m script.stride --input network.json --output output
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from .loader import load_network, build_reachability, analyze_data_flows, network_decision

# Curated *hypotheses* of the primary effect, not CVE->CWE/CAPEC mapping.
# A formal externally sourced mapping belongs to Task 3.
REMOTE_EFFECT = {
    'CVE-2021-41773': ('Information Disclosure', 'confidentiality', 'Potential path traversal/file disclosure; Apache configuration matters'),
    'CVE-2021-26855': ('Elevation of Privilege', 'authorization', 'Potential Exchange server-side request forgery enabling privileged follow-on activity'),
    'CVE-2019-11510': ('Information Disclosure', 'confidentiality', 'Potential VPN appliance file disclosure including stored credentials'),
    'CVE-2011-2523': ('Elevation of Privilege', 'authorization', 'Potential backdoor in affected compromised vsftpd distribution; version alone is insufficient'),
    'CVE-2017-0144': ('Elevation of Privilege', 'authorization', 'Potential remote code execution via SMB'),
    'CVE-2019-0708': ('Elevation of Privilege', 'authorization', 'Potential remote code execution via RDP'),
    'CVE-2021-34527': ('Elevation of Privilege', 'authorization', 'Potential abuse of Print Spooler; check exploit prerequisites'),
    'CVE-2020-1472': ('Elevation of Privilege', 'authorization', 'Potential Netlogon authentication abuse against the domain controller'),
    'CVE-2017-7494': ('Elevation of Privilege', 'authorization', 'Potential remote code execution via Samba; requires vulnerable share conditions'),
    'CVE-2022-26134': ('Elevation of Privilege', 'authorization', 'Potential code execution via Confluence; deployment-specific prerequisites apply'),
    'CVE-2021-22205': ('Elevation of Privilege', 'authorization', 'Potential remote code execution through GitLab file processing; version/configuration require verification'),
    'CVE-2017-5638': ('Elevation of Privilege', 'authorization', 'Potential remote code execution through Struts'),
    'CVE-2021-44228': ('Elevation of Privilege', 'authorization', 'Potential JNDI injection when attacker-controlled strings reach vulnerable Log4j; reachability is not enough'),
    'CVE-2012-2122': ('Spoofing', 'authentication', 'Potential MySQL authentication bypass; affected build is not proven by version alone'),
    'CVE-2022-22965': ('Elevation of Privilege', 'authorization', 'Potential code execution in affected Spring deployment; check environment prerequisites'),
    'CVE-2018-7600': ('Elevation of Privilege', 'authorization', 'Potential remote code execution through Drupal'),
    'CVE-2018-15473': ('Information Disclosure', 'confidentiality', 'Potential SSH username enumeration, NOT automatic login'),
    'CVE-2021-43798': ('Information Disclosure', 'confidentiality', 'Potential Grafana arbitrary-file read'),
}
LOCAL_EFFECT = {
    'CVE-2021-4034': 'Potential local privilege escalation through polkit (PwnKit)',
    'CVE-2021-3156': 'Potential local privilege escalation through sudo (Baron Samedit)',
    'CVE-2022-0847': 'Potential local privilege escalation through Linux kernel (Dirty Pipe)',
    'CVE-2016-5195': 'Potential local privilege escalation through Linux kernel (Dirty COW)',
}
FIELDS = ['id','element','element_type','stride_category','violated_property',
          'description','trust_boundary_crossed','scenario','feasibility',
          'required_preconditions','evidence','source_reference','host','criticality']


def _zone_cross(src, dst, hosts):
    a = 'internet' if src == 'INTERNET' or src.startswith('ext-') else hosts[src]['zone']
    b = 'internet' if dst == 'INTERNET' or dst.startswith('ext-') else hosts[dst]['zone']
    return f'{a} -> {b}' if a != b else 'none (within ' + a + ')'


def _make(rows, **kw):
    item = {name: kw.get(name, '') for name in FIELDS}
    item['id'] = f'ST-{len(rows)+1:03d}'
    rows.append(item)


def generate_threats(data, same_zone_policy='allow'):
    """Return (threat rows, filtered observations, provenance checks).

    Initial scenario host privileges are only starting conditions; no lateral
    footholds are silently granted. Service reachability is NOT exploitability.
    """
    hosts = {h['id']:h for h in data['network']['hosts']}
    _, _, reachable = build_reachability(data, same_zone_policy)
    by_dst = {}
    for edge in reachable:
        by_dst.setdefault((edge['destination'],edge['port']),[]).append(edge['source'])
    scenarios = {}
    scenario_by_id = {s['id']: s for s in data['attacker_scenarios']}
    for scenario in data['attacker_scenarios']:
        scenarios[scenario['id']] = 'INTERNET' if 'entry_zone' in scenario else scenario['entry_host']
    rows, filtered, checks = [], [], []
    for host in data['network']['hosts']:
        hid = host['id']
        services = {s['name']: s for s in host['services']}
        for vuln in host['vulnerabilities']:
            cve = vuln['cve']; service = services[vuln['service']]
            port = service['port']
            element = f'service:{hid}:{service["name"]}:{port}'
            if port == 0:
                # The local code-execution prerequisite is not established by a remote
                # listener. Include only where a modeled path to *some* remote service
                # on the same host exists, or the scenario directly begins on the host.
                inbound = sorted({src for (dst,p),sources in by_dst.items() if dst==hid for src in sources})
                foothold_entry = [sid for sid,src in scenarios.items() if src==hid and scenario_by_id[sid]['initial_privilege'] in ('user','root')]
                if not inbound and not foothold_entry:
                    filtered.append({'element':element,'reason':'local-only CVE without a modeled way to establish a host foothold','reference':cve})
                    continue
                _make(rows,element=element,element_type='process/local service',
                      stride_category='Elevation of Privilege',violated_property='authorization',
                      description=LOCAL_EFFECT.get(cve,'Local privilege escalation candidate requiring external CVE confirmation'),
                      trust_boundary_crossed='none (local privilege boundary)',scenario=','.join(foothold_entry),
                      feasibility='requires-local-user-foothold',
                      required_preconditions=f'An attacker must first obtain a user session/code execution on {hid}; no such success is implied',
                      evidence=f'{cve} is attached to local port 0 on {hid}; other modeled inbound hosts={len(inbound)}',
                      source_reference=f'network.hosts[{hid}].vulnerabilities, .services',host=hid,criticality=host['criticality'])
                continue
            inbound=by_dst.get((hid,port),[])
            if not inbound:
                filtered.append({'element':element,'reason':'no modeled inbound service reachability','reference':cve})
                continue
            entry_hits = [(sid, src) for sid,src in scenarios.items() if src in inbound]
            typ, prop, effect = REMOTE_EFFECT.get(cve, ('Tampering','integrity','Potential abuse of the listed CVE; impact must be verified against NVD before treating as actionable'))
            if entry_hits:
                scenario_text=','.join(sid for sid,_ in entry_hits)
                source=entry_hits[0][1]
                feasibility='direct-entry-reachable; exploit-conditional'
                pre='Attacker reaches the service; affected configuration, CVE preconditions and exploit outcome require validation'
            else:
                scenario_text=''
                source=inbound[0]
                feasibility='lateral-foothold-required; exploit-conditional'
                pre=f'Attacker first gains control of one of {len(inbound)} modeled source hosts, then satisfies exploit prerequisites'
            _make(rows,element=element,element_type='process/service',
                  stride_category=typ,violated_property=prop,
                  description=f'{effect} ({cve})',trust_boundary_crossed=_zone_cross(source,hid,hosts),
                  scenario=scenario_text,feasibility=feasibility,required_preconditions=pre,
                  evidence=f'{cve}; {hid} {service["name"]}:{port}; sources with allowed connectivity={len(inbound)}; sample={source}',
                  source_reference=f'network.hosts[{hid}].vulnerabilities + firewall_rules',host=hid,criticality=host['criticality'])

        for misc in host.get('misconfigurations', []):
            svc=services[misc['service']]
            inbound=by_dst.get((hid,svc['port']),[])
            if not inbound:
                filtered.append({'element':f'service:{hid}:{svc["name"]}:{svc["port"]}', 'reason':'misconfiguration service not reachable','reference':misc['id']})
                continue
            hits=[sid for sid,src in scenarios.items() if src in inbound]
            _make(rows,element=f'service:{hid}:{svc["name"]}:{svc["port"]}',element_type='process/service',
                  stride_category='Spoofing',violated_property='authentication',
                  description=('Default administrative credentials may let an attacker impersonate printer admin' if misc['id']=='MC1' else
                               'SSH password authentication without lockout may enable password guessing/identity abuse'),
                  trust_boundary_crossed=_zone_cross(scenarios[hits[0]] if hits else inbound[0],hid,hosts),
                  scenario=','.join(hits),feasibility='direct-entry-reachable; authentication-conditional' if hits else 'lateral-foothold-required; authentication-conditional',
                  required_preconditions='Credentials remain default and valid' if misc['id']=='MC1' else 'A guessable valid password and enough attempts are required',
                  evidence=f'{misc["id"]}: {misc["description"]}; allowed inbound sources={len(inbound)}',
                  source_reference=f'network.hosts[{hid}].misconfigurations + firewall_rules',host=hid,criticality=host['criticality'])

    # Each *documented* data flow is evaluated; do not mistake the declared
    # business flow for confirmed service reachability or TLS configuration.
    checked = {r['flow_id']:r for r in analyze_data_flows(data,same_zone_policy)}
    for flow in data['network']['data_flows']:
        status=checked[flow['id']]['status']
        boundary=_zone_cross(flow['src'],flow['dst'],hosts)
        checks.append({'id':flow['id'],'kind':'data_flow','status':status,'reason':checked[flow['id']]['basis']})
        if status!='REACHABLE':
            filtered.append({'element':f'flow:{flow["id"]}','reason':f'cannot substantiate executable data flow: {status}', 'reference':flow['id']})
            continue
        if flow['protocol'].lower() not in ('http','ftp'):
            continue
        # HTTP/FTP provide no transport confidentiality or integrity by default;
        # path interception still requires a position on the network.
        for cat,prop,action in [('Information Disclosure','confidentiality','Observation of'),('Tampering','integrity','Manipulation of')]:
            _make(rows,element=f'flow:{flow["id"]}',element_type='data flow',stride_category=cat,
                  violated_property=prop,description=f'{action} {flow["data"]} over {flow["protocol"]} on {flow["src"]} -> {flow["dst"]}',
                  trust_boundary_crossed=boundary,scenario='',feasibility='conditional-on-network-position',
                  required_preconditions='Adversary must gain on-path visibility/control; no such position is assigned in scenario inputs',
                  evidence=f'{flow["id"]} is reachable, protocol={flow["protocol"]}',
                  source_reference=f'network.data_flows[{flow["id"]}] + firewall_rules',
                  host=flow['dst'] if flow['dst'] in hosts else '',
                  criticality=hosts[flow['dst']]['criticality'] if flow['dst'] in hosts else 0)

    # Trusts are separate from firewall paths. Report inaccessible ones explicitly.
    for trust in data['network']['trust_relations']:
        src=trust['from_host']; dst=trust['to_host']
        # SSH keys require an SSH listener; domain creds and app creds rely on an
        # allowed service matching the intended endpoint category.
        required_type= ('ssh' if trust['type'] in ('ssh-key','ci-deploy-key','backup-agent-credentials') else
                        'https' if trust['type']=='runner-token' else
                        'mysql' if trust['type']=='db-credentials-in-config' else
                        'smb' if trust['type'] in ('cached-domain-admin-credentials','domain-admin') else None)
        candidates = [s for s in hosts[dst]['services'] if s['port']>0 and
                      (required_type is None or s['name']==required_type)]
        matches = [(s['name'],s['port']) for s in candidates if network_decision(data,src,dst,s['port'],same_zone_policy)[0]]
        status='REACHABLE_PROTOCOL_CANDIDATE' if matches else 'NOT_SUBSTANTIATED_BY_DECLARED_SERVICES_AND_FIREWALL'
        checks.append({'id':trust['id'],'kind':'trust','status':status,'reason':str(matches)})
        if not matches:
            filtered.append({'element':f'trust:{trust["id"]}','reason':'no matching permitted destination service for stated trust type','reference':trust['id']})
            continue
        _make(rows,element=f'trust:{trust["id"]}',element_type='trust relation',
              stride_category='Elevation of Privilege' if trust['grants']=='root' else 'Spoofing',
              violated_property='authorization' if trust['grants']=='root' else 'authentication',
              description=f'Compromise of {src} may enable abuse of {trust["type"]} to access {dst} with {trust["grants"]} privilege',
              trust_boundary_crossed=_zone_cross(src,dst,hosts),scenario='',
              feasibility='conditional-on-source-compromise-and-valid-credential',
              required_preconditions=f'Compromise {src} with appropriate privileges ({trust.get("requires","usable credential")}); credentials remain usable on {dst}',
              evidence=f'{trust["id"]}, service candidates {matches}, trust grants={trust["grants"]}',
              source_reference=f'network.trust_relations[{trust["id"]}] + firewall_rules',host=dst,criticality=hosts[dst]['criticality'])

    # A unique segmentation exception: the public-facing shop has direct database
    # network access, distinct from the intended app backend flow F3.
    allowed,basis=network_decision(data,'H01','H20',3306,same_zone_policy)
    if allowed:
        _make(rows,element='flow:FW-H01-H20-3306',element_type='firewall flow',
              stride_category='Information Disclosure',violated_property='confidentiality',
              description='Direct DMZ web-shop to customer database MySQL access may expose PII after compromise of the web tier and DB authentication',
              trust_boundary_crossed='dmz -> db-zone',scenario='S1',
              feasibility='conditional-on-web-tier-compromise-and-DB-authorization',
              required_preconditions='Successful control of H01 and ability to authenticate/exploit H20; firewall connectivity alone is insufficient',
              evidence=f'Explicit firewall allow H01->H20:3306, basis={basis}; customer PII on H20',
              source_reference='network.firewall_rules + hosts[H20].data_assets',host='H20',criticality=hosts['H20']['criticality'])

    # Accountable audit records matter for integrity and repudiation. Attack
    # requires actual log-server compromise: not an asserted logging deficiency.
    if 'audit-logs' in hosts['H19']['data_assets']:
        _make(rows,element='asset:H19:audit-logs',element_type='data store',
              stride_category='Repudiation',violated_property='accountability',
              description='If the central logging host is compromised, alteration or deletion of audit logs could obstruct attribution',
              trust_boundary_crossed='none (server-lan)',scenario='',
              feasibility='conditional-on-log-server-compromise',
              required_preconditions='Attacker acquires rights to alter H19 audit records; no automatic log write privilege is inferred',
              evidence='H19 holds audit-logs and lists CVE-2021-44228; exploitation not established',
              source_reference='network.hosts[H19].data_assets + vulnerabilities',host='H19',criticality=3)

    for hid in ('H01','H04'):
        host=hosts[hid]
        inbound_internet=[s for s in host['services'] if s['port']>0 and network_decision(data,'INTERNET',hid,s['port'],same_zone_policy)[0]]
        if inbound_internet:
            _make(rows,element=f'host:{hid}',element_type='process',stride_category='Denial of Service',violated_property='availability',
                  description=f'Internet-accessible {host["name"]} could be overwhelmed, disrupting a business-critical service',
                  trust_boundary_crossed='internet -> dmz',scenario='S1',feasibility='exposed-service; resource-threshold-unknown',
                  required_preconditions='Attacker generates sufficient load; capacity, rate limits and service defenses are unspecified',
                  evidence=f'{hid} criticality={host["criticality"]}; Internet reaches ports {[s["port"] for s in inbound_internet]}',
                  source_reference=f'network.hosts[{hid}].services + firewall_rules',host=hid,criticality=host['criticality'])
    return rows,filtered,checks


def export_task2(data,output_dir='output',same_zone_policy='allow'):
    output = Path(output_dir); output.mkdir(parents=True,exist_ok=True)
    rows,filtered,checks=generate_threats(data,same_zone_policy)
    with (output/'stride_threat_table.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=FIELDS); writer.writeheader(); writer.writerows(rows)
    for filename,items,fields in [('stride_filtered_observations.csv',filtered,['element','reason','reference']),
                                   ('stride_support_checks.csv',checks,['id','kind','status','reason'])]:
        with (output/filename).open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(items)
    summary={'threats':len(rows),'by_stride':dict(sorted(Counter(r['stride_category'] for r in rows).items())),
             'by_feasibility':dict(sorted(Counter(r['feasibility'] for r in rows).items())),
             'filtered_observations':len(filtered),'same_zone_policy':same_zone_policy,
             'warning':'Candidate threat inventory, not confirmed exploitability or numerical risk; validate CVEs with NVD in Task 3 and attack prerequisites in Task 4.'}
    (output/'stride_summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    # Select five explicitly justified high-value candidates from the generated table.
    selected = [next((r for r in rows if key in r['evidence']),None) for key in
                ('CVE-2019-11510','CVE-2021-26855','CVE-2021-41773','CVE-2020-1472','MC2')]
    selected=[r for r in selected if r]
    with (output/'stride_top5_discussion.md').open('w',encoding='utf-8') as f:
        f.write('# Task 2 — Five high-priority threat hypotheses (manual analysis)\n\n')
        f.write('Priority is qualitative, driven by initial attack exposure, asset criticality and observed firewall permissions, **not** a computed path-risk ranking. None of the listed CVEs is assumed exploited.\n\n')
        f.write('| Threat | Candidate and why it deserves attention | What is established / what remains conditional |\n|---|---|---|\n')
        rationales={
          'CVE-2019-11510':'The Internet-facing VPN has credentials as a stored asset. Possible compromise may have wide consequences for remote access.',
          'CVE-2021-26855':'The public mail gateway can communicate with the AD controller using LDAP/SMB; this makes follow-on access worth analyzing.',
          'CVE-2021-41773':'The public shopping front end has an Apache path-traversal CVE and an explicit direct firewall exception into the customer database.',
          'CVE-2020-1472':'The phished HR workstation is allowed to reach the domain controller on SMB/Netlogon; the domain controller has criticality 5.',
          'MC2':'The SSH jump host is reachable from the phished HR workstation, with password login and no lockout; it holds SSH keys.'}
        for r in selected:
            key=next(k for k in rationales if k in r['evidence'])
            f.write(f'| {r["id"]} ({key}) | {rationales[key]} | {r["feasibility"]}; {r["required_preconditions"]} |\n')
        f.write('\n**Threat-model caveats.** Allowed ports and declared CVEs support plausible attack surfaces, not successful exploitation. For Zerologon, confirm the actual Netlogon RPC endpoint configuration; for Apache path traversal, confirm vulnerable configuration and any CGI prerequisites. The printer and VPN/jump-host credentials require separate authentication validation. The flow and trust-check exports enumerate unsubstantiated paths so they are not silently used later.\n\n')
        f.write('**STRIDE rules:** known authentication bypass/default-password/credential misuse → Spoofing; confidentiality exposure or clear-text traffic with on-path condition → Information Disclosure; manipulation of clear-text traffic → Tampering; log deletion after server compromise → Repudiation; service overload → Denial of Service; known remote/local code execution and privilege escalation → Elevation of Privilege. Labels are initial analyst hypotheses; no automated CVE-to-CWE assertion is made.\n')
    return summary


def main(argv=None):
    parser=argparse.ArgumentParser(description='Task 2 — STRIDE threats grounded in network model')
    parser.add_argument('--input',default='network.json')
    parser.add_argument('--output',default='output')
    parser.add_argument('--same-zone-policy',choices=('allow','deny'),default='allow')
    args=parser.parse_args(argv)
    data=load_network(args.input)
    print('Task 2 completed.\n'+json.dumps(export_task2(data,args.output,args.same_zone_policy),indent=2))


if __name__=='__main__':
    main()
