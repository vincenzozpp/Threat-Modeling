"""Task 4: privilege-state attack multigraph with conditional, auditable transitions.

Run: python -m script.ag --input network.json --output output

This is a defensible *scenario model*, not empirical exploit confirmation. The
fixed likelihood/time priors in EXPLOIT_PROFILES are educational assumptions;
software versions and actual exploit prerequisites must be validated on assets.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import time
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import networkx as nx

from .loader import load_network, network_decision

# Each profile is a *modeled effect*, not an assertion that exploitation succeeds.
# probability is a conditional per-attempt prior; time_hours is attempt duration.
# No CVSS score is converted to a probability, and no measured MTAO is claimed.
EXPLOIT_PROFILES = {
    'CVE-2011-2523': dict(effect='root', service='ftp', p=.13, hours=3, note='Backdoored vsftpd distribution must actually be installed'),
    'CVE-2017-0144': dict(effect='root', service='smb', p=.30, hours=2, note='SMBv1 RCE; payload and target configuration conditional'),
    'CVE-2019-0708': dict(effect='root', service='rdp', p=.19, hours=3, note='RDP RCE; target service configuration conditional'),
    'CVE-2020-1472': dict(effect='root', service='netlogon', p=.27, hours=2, note='Netlogon attack, vulnerable DC and protocol access required'),
    'CVE-2017-7494': dict(effect='user', service='smb', p=.19, hours=4, note='Samba RCE conditional on writable share; *unverified*'),
    'CVE-2022-26134': dict(effect='user', service='http', p=.32, hours=2, note='Confluence unauthenticated RCE; configuration-dependent'),
    'CVE-2021-22205': dict(effect='user', service='https', p=.28, hours=3, note='GitLab image processing RCE on a vulnerable deployment'),
    'CVE-2017-5638': dict(effect='user', service='http', p=.36, hours=2, note='Struts RCE requires vulnerable endpoint reached'),
    'CVE-2021-44228': dict(effect='user', service='logstash', p=.16, hours=5, note='Log4Shell requires attacker-controlled data reaching the vulnerable logger'),
    'CVE-2022-22965': dict(effect='user', service='http', p=.17, hours=4, note='Spring4Shell requires deployment/JDK prerequisites not proven by version'),
    'CVE-2018-7600': dict(effect='user', service='http', p=.32, hours=3, note='Drupal RCE; patch/configuration prerequisites assumed'),
    'CVE-2021-3156': dict(effect='root', service='sudo', p=.50, hours=2, local=True, note='Local sudo privilege escalation; requires user shell'),
    'CVE-2021-4034': dict(effect='root', service='polkit', p=.55, hours=2, local=True, note='Local polkit privilege escalation; requires user shell'),
    'CVE-2016-5195': dict(effect='root', service='kernel', p=.45, hours=3, local=True, note='Local Dirty COW; requires user shell'),
    'CVE-2022-0847': dict(effect='root', service='kernel', p=.52, hours=2, local=True, note='Local Dirty Pipe; requires user shell'),
}
# Explicitly exclude CVEs that cannot be equated with host code execution.
NON_RCE_EFFECTS = {
    'CVE-2021-41773': 'Apache path traversal; CGI RCE prerequisite not declared',
    'CVE-2021-26855': 'Exchange SSRF; companion vulnerabilities needed for a full RCE chain',
    'CVE-2019-11510': 'VPN arbitrary file read, NOT host shell (handled as conditional VPN session)',
    'CVE-2012-2122': 'MySQL authentication bypass gives DB access, NOT an OS shell',
    'CVE-2021-34527': 'Print Spooler RCE prerequisites/permissions not evidenced in network.json',
    'CVE-2018-15473': 'OpenSSH user enumeration, NOT host access',
    'CVE-2021-43798': 'Grafana file read, NOT host shell',
}
SOURCE_URLS = {
    'CVE-2021-41773': 'https://httpd.apache.org/security/vulnerabilities_24.html',
    'CVE-2021-26855': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855',
    'CVE-2019-11510': 'https://nvd.nist.gov/vuln/detail/CVE-2019-11510',
    'CVE-2012-2122': 'https://nvd.nist.gov/vuln/detail/CVE-2012-2122',
}

PRIVILEGES = {'none': 0, 'vpn': 1, 'user': 2, 'root': 3}


def enough_privilege(actual: str, needed: str) -> bool:
    """The host-level privilege lattice; VPN session is a network vantage, not shell."""
    if actual == 'vpn':
        return needed == 'vpn'
    if needed == 'vpn':
        return actual == 'vpn'
    return PRIVILEGES[actual] >= PRIVILEGES[needed]


def postcondition(effect: str) -> str:
    """A successful transition grants precisely its modeled privilege/effect."""
    if effect not in PRIVILEGES:
        raise ValueError(f'Unsupported effect {effect}')
    return effect


def host_vulnerable(host, cve, service):
    return any(v['cve'] == cve and v['service'] == service
               for v in host['vulnerabilities']) and any(
        s['name'] == service for s in host['services'])


def _reachable_port(data, src: str, dst: str, service: str, same_zone_policy: str):
    hosts = {h['id']: h for h in data['network']['hosts']}
    dest = hosts[dst]
    for svc in dest['services']:
        if svc['name'] == service and svc['port'] > 0:
            allowed, basis = network_decision(data, src, dst, svc['port'], same_zone_policy)
            if allowed:
                return svc['port'], basis
    return None


def _trust_service(trust):
    kind = trust['type']
    return {
        'ssh-key': 'ssh',
        'ci-deploy-key': 'ssh',
        'backup-agent-credentials': 'ssh',
        'runner-token': 'https',
        'cached-domain-admin-credentials': 'netlogon',
        'domain-admin': 'smb',
        'db-credentials-in-config': 'mysql',
    }.get(kind)


def build_attack_graph(data, same_zone_policy='allow', *, db_credentials_as_host_user=True):
    """Build TVA-like privilege state MultiDiGraph from *verified* network paths.

    Multiple mechanisms to the same state are parallel edges. Transition edges
    are added only if service, port, vulnerability/trust and conditions match.
    """
    hosts = {h['id']: h for h in data['network']['hosts']}
    graph = nx.MultiDiGraph()
    excluded = []
    for h in hosts:
        for level in ('user', 'root'):
            graph.add_node((h, level), label=f'{h}:{level}', zone=hosts[h]['zone'])
    graph.add_node(('INTERNET', 'none'), label='Internet', zone='internet')
    graph.add_node(('H04', 'vpn'), label='H04:VPN session', zone='dmz')

    vantages = [('INTERNET','none'), ('H04','vpn')] + [
        (h,level) for h in hosts for level in ('user','root')
    ]
    # For each source vantage, only service-reachable vulnerabilities provide
    # remote exploit edges. Local privilege escalation is separate.
    for host in data['network']['hosts']:
        dst = host['id']
        for vulnerability in host['vulnerabilities']:
            cve, svc = vulnerability['cve'], vulnerability['service']
            profile = EXPLOIT_PROFILES.get(cve)
            if profile is None:
                excluded.append({'host':dst, 'cve':cve, 'reason': NON_RCE_EFFECTS.get(cve, 'No validated privilege effect profile')})
                continue
            if profile['service'] != svc or not host_vulnerable(host,cve,svc):
                excluded.append({'host':dst,'cve':cve,'reason':'Profile service mismatch'})
                continue
            if profile.get('local'):
                graph.add_edge((dst,'user'), (dst,'root'), key=f'{dst}:{cve}:local',
                               mechanism='local-cve', reference=cve, port=0,
                               conditional_note=profile['note'],
                               probability=profile['p'], attempt_hours=profile['hours'],
                               precondition='user shell on target',
                               postcondition='root shell on same host')
                continue
            for src,level in vantages:
                if src == dst:
                    continue
                if src == 'INTERNET' and level != 'none':
                    continue
                link = _reachable_port(data,src,dst,svc,same_zone_policy)
                if not link:
                    continue
                port,basis = link
                target = (dst,postcondition(profile['effect']))
                graph.add_edge((src,level),target,key=f'{src}:{level}:{dst}:{cve}',
                               mechanism='remote-cve', reference=cve, port=port,
                               conditional_note=profile['note'],
                               probability=profile['p'], attempt_hours=profile['hours'],
                               precondition=f'vantage {src}:{level}; service {svc}/{port} reachable ({basis}); conditions noted',
                               postcondition=f'{profile["effect"]} shell on {dst}')

    # VPN arbitrary-file-read may expose credentials but does not yield H04 shell.
    if host_vulnerable(hosts['H04'],'CVE-2019-11510','https') and _reachable_port(data,'INTERNET','H04','https',same_zone_policy):
        graph.add_edge(('INTERNET','none'),('H04','vpn'),key='H04:VPN-CVE-2019-11510',
                       mechanism='credential-conditional',reference='CVE-2019-11510',port=443,
                       conditional_note='Successful arbitrary-file-read PLUS extraction of still-valid VPN credentials PLUS login; not a shell on H04',
                       probability=.12,attempt_hours=6,
                       precondition='Internet can reach H04/443 and usable VPN credentials are disclosed and accepted',
                       postcondition='Authenticated VPN network session (not OS access)')

    # Two non-CVE misconfigurations, each checked against reachable service.
    for host in data['network']['hosts']:
        dst = host['id']
        for mc in host.get('misconfigurations',[]):
            svc = mc['service']
            if mc['id'] == 'MC1':
                # Default printer web UI grants only its declared user privilege.
                for src,level in vantages:
                    if src == dst:
                        continue
                    link = _reachable_port(data,src,dst,svc,same_zone_policy)
                    if link:
                        port,basis=link
                        graph.add_edge((src,level),(dst,postcondition(mc['grants'])), key=f'{src}:{level}:MC1',
                                       mechanism='misconfiguration',reference='MC1',port=port,
                                       conditional_note='Factory password still valid; printer control is not access to another host',
                                       probability=.32,attempt_hours=1,
                                       precondition=f'HTTP UI reachable ({basis}); default credentials work',postcondition=f'{mc["grants"]} access on {dst}')
            if mc['id'] == 'MC2':
                for src,level in vantages:
                    if src == dst:
                        continue
                    link = _reachable_port(data,src,dst,svc,same_zone_policy)
                    if link:
                        port,basis=link
                        graph.add_edge((src,level),(dst,postcondition(mc['grants'])),key=f'{src}:{level}:MC2',
                                       mechanism='misconfiguration',reference='MC2',port=port,
                                       conditional_note='Guessable existing SSH password and no lockout required; low success prior',
                                       probability=.08,attempt_hours=12,
                                       precondition=f'port 22 reachable ({basis}); guessable password',postcondition='user shell on jump host')

    # Trust edges require BOTH source compromise and usable destination service.
    for trust in data['network']['trust_relations']:
        source,dst = trust['from_host'],trust['to_host']
        service = _trust_service(trust)
        if not service:
            excluded.append({'host':dst,'cve':trust['id'],'reason':'Unknown trust transport'})
            continue
        if trust['id']=='T9' and not db_credentials_as_host_user:
            excluded.append({'host':dst,'cve':trust['id'], 'reason':'Strict DB model: MySQL credentials do not confer target OS shell'})
            continue
        link = _reachable_port(data,source,dst,service,same_zone_policy)
        if not link:
            excluded.append({'host':dst,'cve':trust['id'],'reason':f'Trust {source}->{dst} lacks reachable destination {service} listener'})
            continue
        port,basis=link
        require_root = trust.get('requires','').lower().startswith('root')
        for level in (('root',) if require_root else ('user','root')):
            if not enough_privilege(level,'root' if require_root else 'user'):
                continue
            graph.add_edge((source,level),(dst,postcondition(trust['grants'])), key=f'{trust["id"]}:{level}',
                           mechanism='trust',reference=trust['id'],port=port,
                           conditional_note=('Credential on source remains valid; administrative auth works' if trust['id'] != 'T9' else
                                             'ABSTRACTION: JSON grants user, though DB login is not necessarily OS shell; compare --strict-db'),
                           probability=.70 if trust['id']!='T9' else .45,
                           attempt_hours=2 if trust['id']!='T9' else 3,
                           precondition=f'{source}:{level}, valid {trust["type"]}; reachable {dst}/{port} ({basis})',
                           postcondition=f'{trust["grants"]} on {dst} per JSON trust semantics')

    return graph, excluded


def _path_risk(path_edges, impact):
    """Independent per-step successes, geometric retry expected time heuristic."""
    likelihood=math.prod(float(e['probability']) for e in path_edges)
    mtao=sum(float(e['attempt_hours'])/float(e['probability']) for e in path_edges)
    return likelihood, mtao, impact*likelihood


def enumerate_paths(graph, start, goal, *, max_hops=7, limit=10000):
    """Enumerate simple state paths with an explicit bounded scalability policy.

    Returns (paths, cap_hit). All paths of <=max_hops are enumerated only if
    cap_hit=False; longer paths are never claimed enumerated.
    """
    if max_hops < 1 or limit < 1:
        raise ValueError('max_hops and limit must be positive')
    rows=[]
    cap_hit=False

    def dfs(node, seen, edges):
        nonlocal cap_hit
        if cap_hit:
            return
        if node==goal:
            if len(rows)>=limit:
                cap_hit=True
                return
            rows.append(list(edges))
            return
        if len(edges)>=max_hops:
            return
        if node not in graph:
            return
        for u,v,key,data in sorted(graph.out_edges(node,keys=True,data=True),
                                   key=lambda x:(str(x[1]),str(x[2]))):
            if v in seen:
                continue
            edges.append((u,v,key,data))
            seen.add(v)
            dfs(v,seen,edges)
            seen.remove(v)
            edges.pop()
            if cap_hit:
                break
    if start in graph and goal in graph:
        dfs(start,{start},[])
    return rows,cap_hit


def _goal_state(goal):
    return (goal['host'],goal['privilege'])


def _scenario_state(scenario):
    return (scenario.get('entry_host','INTERNET'), scenario['initial_privilege'])


def _plot_graph(graph, highlighted, filename):
    """Show complete privilege graph plus top three paths (if any)."""
    plt.figure(figsize=(19,13))
    # Fixed seed ensures reproducibility. Draw nodes by zones as context.
    pos=nx.spring_layout(nx.DiGraph(graph),seed=12,k=1.0,iterations=110)
    nx.draw_networkx_edges(graph,pos,arrows=True,arrowsize=9,alpha=.06,edge_color='#777777',width=.7)
    colors={('INTERNET','none'):'#d98828',('H04','vpn'):'#d98828'}
    base_colors=[colors.get(n, '#dfe9ee' if n[1]=='user' else '#bbd4db') for n in graph.nodes]
    nx.draw_networkx_nodes(graph,pos,node_color=base_colors,edgecolors='#486479',linewidths=.7,node_size=560)
    nx.draw_networkx_labels(graph,pos,labels={n:f'{n[0]}\n{n[1]}' for n in graph.nodes},font_size=6)
    for idx,edges in enumerate(highlighted[:3]):
        color=('#d03634','#29884a','#7657b8')[idx]
        segments=[(u,v) for u,v,_,_ in edges]
        nx.draw_networkx_edges(graph,pos,edgelist=segments,edge_color=color, width=3.2-idx*.4,
                               arrows=True,arrowsize=17,alpha=.95)
    plt.title('HW3 – Privilege-state attack graph (top 3 paths highlighted, if reachable)',fontsize=15)
    plt.axis('off')
    plt.tight_layout()
    plt.savefig(filename,dpi=180,bbox_inches='tight')
    plt.close()


def _plot_top_three_paths(ranked_rows, filename):
    """A readable companion diagram to the full attack graph."""
    ranked_rows=ranked_rows[:3]
    fig,ax=plt.subplots(figsize=(15,5.2))
    ax.set_xlim(0,1); ax.set_ylim(-.75,3.0)
    ax.axis('off')
    if not ranked_rows:
        ax.text(.5,1.4,'No modeled attack paths for these assumptions',ha='center',fontsize=16)
    for idx,row in enumerate(ranked_rows):
        y=2.3-idx*1.06
        states=row['states'].split(' -> ')
        width=.79/(max(1,len(states)-1))
        color=('#d03634','#29884a','#7657b8')[idx]
        ax.text(.01,y+.32,f"#{idx+1}  {row['scenario']} → {row['goal']}     "
                f"risk={row['risk']:.4f}  (likelihood={row['likelihood']:.4f}, "
                f"MTAO={row['mtao_hours']:.1f}h)",fontsize=11,fontweight='bold',color=color)
        for j,label in enumerate(states):
            x=.015+j*width
            ax.text(x,y,label.replace(':','\n'),ha='center',va='center',fontsize=8.2,
                    bbox=dict(boxstyle='round,pad=.38',fc='#eaf0f4',ec=color,lw=1.3))
            if j<len(states)-1:
                ax.annotate('',xy=(x+width-.027,y),xytext=(x+.027,y),
                            arrowprops=dict(arrowstyle='->',color=color,lw=2))
    ax.set_title('Top 3 ranked attack paths – privilege-state transitions',fontsize=14,pad=15)
    fig.tight_layout()
    fig.savefig(filename,dpi=180,bbox_inches='tight')
    plt.close(fig)


def export_task4(data, output_dir, *, same_zone_policy='allow', max_hops=7,
                 max_paths=10000, strict_db=False):
    dest=Path(output_dir)
    dest.mkdir(parents=True, exist_ok=True)
    graph,excluded=build_attack_graph(data,same_zone_policy, db_credentials_as_host_user=not strict_db)
    scenarios=data['attacker_scenarios']; goals=data['goals']
    rows=[]; totals=[]; highlighted=[]
    for scenario in scenarios:
        for goal in goals:
            t0=time.perf_counter()
            start=_scenario_state(scenario); end=_goal_state(goal)
            paths,cap=enumerate_paths(graph,start,end,max_hops=max_hops,limit=max_paths)
            elapsed=time.perf_counter()-t0
            impact=int(next(h['criticality'] for h in data['network']['hosts'] if h['id']==goal['host']))
            group=[]
            for edges in paths:
                step_edges=[e for _,_,_,e in edges]
                likelihood,mtao,risk=_path_risk(step_edges,impact)
                group.append(dict(scenario=scenario['id'], goal=goal['id'],
                                  likelihood=round(likelihood,10),mtao_hours=round(mtao,3),
                                  impact=impact,risk=round(risk,10),hops=len(edges),
                                  states=' -> '.join([f'{start[0]}:{start[1]}']+[f'{v[0]}:{v[1]}' for _,v,_,_ in edges]),
                                  mechanisms=' | '.join(f'{d["reference"]}:{d["mechanism"]}' for _,_,_,d in edges),
                                  edge_keys=' | '.join(str(k) for _,_,k,_ in edges),
                                  raw_edges=edges))
            group.sort(key=lambda r:(-r['risk'],r['mtao_hours'],r['states'],r['mechanisms']))
            for rank,p in enumerate(group,1):
                p['rank_in_scenario_goal']=rank
                p['path_id']=f'{scenario["id"]}-{goal["id"]}-P{rank:05d}'
                rows.append(p)
            totals.append(dict(scenario=scenario['id'],goal=goal['id'],
                               path_count=len(paths),max_path_risk=max((p['risk'] for p in group),default=0),
                               min_mtao_hours=min((p['mtao_hours'] for p in group),default=None),
                               computation_seconds=round(elapsed,6),cap_hit=cap,
                               completeness=('TRUNCATED' if cap else f'ALL_SIMPLE_PATHS_WITHIN_{max_hops}_HOPS')))
    rows.sort(key=lambda r:(-r['risk'],r['mtao_hours'],r['scenario'],r['goal'],r['path_id']))
    highlighted=[r['raw_edges'] for r in rows[:3]]

    path_cols=['path_id','scenario','goal','rank_in_scenario_goal','hops','states','mechanisms','likelihood','mtao_hours','impact','risk','edge_keys']
    with (dest/'attack_paths.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=path_cols);w.writeheader()
        for r in rows:
            w.writerow({k:r[k] for k in path_cols})
    with (dest/'attack_goal_summary.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(totals[0]));w.writeheader();w.writerows(totals)
    with (dest/'attack_graph_edges.csv').open('w',newline='',encoding='utf-8') as f:
        columns=['src_host','src_priv','dst_host','dst_priv','key','mechanism','reference','port','probability','attempt_hours','precondition','postcondition','conditional_note']
        w=csv.DictWriter(f,fieldnames=columns);w.writeheader()
        for u,v,key,edge in graph.edges(keys=True,data=True):
            w.writerow(dict(src_host=u[0],src_priv=u[1],dst_host=v[0],dst_priv=v[1],key=key,**edge))
    with (dest/'attack_graph_exclusions.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=['host','cve','reason']);w.writeheader();w.writerows(excluded)
    _plot_graph(graph,highlighted,dest/'attack_graph_top3.png')
    _plot_top_three_paths(rows, dest/'attack_top3_paths.png')
    # GraphML cannot natively serialize tuple ids; use labels and primitive attrs.
    graph_export=nx.MultiDiGraph()
    for n,attr in graph.nodes(data=True):
        graph_export.add_node(f'{n[0]}:{n[1]}',**attr)
    for u,v,k,attr in graph.edges(keys=True,data=True):
        graph_export.add_edge(f'{u[0]}:{u[1]}',f'{v[0]}:{v[1]}',key=k,**attr)
    nx.write_graphml(graph_export,dest/'attack_graph.graphml')

    result=dict(nodes=graph.number_of_nodes(),edges=graph.number_of_edges(),
                scenarios=len(scenarios),goals=len(goals),max_hops=max_hops,max_paths_per_pair=max_paths,
                same_zone_policy=same_zone_policy,strict_db=strict_db,
                paths_total=len(rows),goal_summaries=totals,
                risk_definition='max path risk per goal = max(path likelihood × target impact 1..5)',
                likelihood_definition='product of independent per-step, conditional heuristic probabilities',
                mtao_definition='sum(step attempt-hours / per-attempt success probability), geometric retry approximation',
                limitations=[
                    'Each scenario uses a single attacker vantage/state, not arbitrary compound multi-host preconditions.',
                    'Complete only within max_hops and only if cap_hit=false; no all-length exhaustiveness claim.',
                    'Probability/time priors are educational assumptions, not empirical CVSS-derived estimates.',
                    'Trust T9 grants target host user under explicit JSON privilege abstraction; --strict-db removes this unproven OS equivalence.',
                    'Some exploit prerequisites are not declared in network.json; modeled edges remain conditional.',
                    'Missing services/credentials are not invented (e.g. T3 to H21 via SSH).',
                    'An unreachable goal is not proof of security, only lack of a supported chain in the model.',
                ])
    (dest/'attack_summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description='HW3 Task 4 attack graph and risk')
    parser.add_argument('--input',default='network.json')
    parser.add_argument('--output',default='output')
    parser.add_argument('--same-zone-policy',choices=('allow','deny'),default='allow')
    parser.add_argument('--max-hops',type=int,default=7)
    parser.add_argument('--max-paths',type=int,default=10000)
    parser.add_argument('--strict-db',action='store_true',help='Do not equate database credentials with target OS user')
    args=parser.parse_args(argv)
    try:
        data=load_network(args.input)
        result=export_task4(data,args.output,same_zone_policy=args.same_zone_policy,
                            max_hops=args.max_hops,max_paths=args.max_paths,strict_db=args.strict_db)
        print('Task 4 completed.')
        print(json.dumps({k:result[k] for k in ('nodes','edges','paths_total','goal_summaries','limitations')},indent=2))
        print(f'Files saved to {Path(args.output).resolve()}')
    except (ValueError,OSError,nx.NetworkXError) as exc:
        parser.exit(2, f'Task 4 FAILED: {exc}\n')


if __name__=='__main__':
    main()
