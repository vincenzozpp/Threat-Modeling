"""HW3 Task 5: auditable mitigation application and budgeted risk optimization.

Uses the Task 4 bounded TVA-like graph and its explicit conditional priors.
The 18-item search is exact *for this bounded, simplified graph*, not for real
enterprise risk; see TASK5_GUIDE.md for methodological qualifications.
"""
from __future__ import annotations

import argparse
import copy
import csv
import json
import math
import time
from array import array
from collections import defaultdict
from decimal import Decimal, ROUND_FLOOR
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import networkx as nx

from .ag import (
    build_attack_graph, enumerate_paths, _path_risk, _scenario_state,
    _goal_state,
)
from .loader import load_network
from .stride import generate_threats

EDR_MECHANISMS = frozenset({'remote-cve', 'local-cve', 'credential-conditional'})
EPS = 1e-10


def _mitigation_by_id(data):
    return {m['id']: m for m in data['mitigations']}


def _firewall_deny(data, src, dst, port):
    """Turn a zone-or-host flow triple into a directional explicit deny rule."""
    hosts = {h['id']: h for h in data['network']['hosts']}
    zones = {z['id'] for z in data['network']['zones']}
    if src in hosts:
        src_zone, src_host = hosts[src]['zone'], src
    elif src in zones:
        src_zone, src_host = src, '*'
    else:
        raise ValueError(f'Unknown flow source {src}')
    if dst in hosts:
        dst_zone, dst_host = hosts[dst]['zone'], dst
    elif dst in zones:
        dst_zone, dst_host = dst, '*'
    else:
        raise ValueError(f'Unknown flow destination {dst}')
    return dict(src_zone=src_zone,src_host=src_host,dst_zone=dst_zone,
                dst_host=dst_host,ports=[port],action='deny')


def apply_mitigations(original, selected):
    """Return (modified network, EDR factor, audit actions), without mutating input.

    The returned network is an *analytical post-mitigation model*. Original
    mitigation definitions are retained for audit, so do not revalidate it as
    an untouched input configuration (some patch targets have been removed).
    """
    lookup = _mitigation_by_id(original)
    chosen = tuple(selected)
    if len(set(chosen)) != len(chosen):
        raise ValueError('Duplicate mitigation ID in selection')
    for ident in chosen:
        if ident not in lookup:
            raise ValueError(f'Unknown mitigation ID: {ident}')
    data = copy.deepcopy(original)
    network = data['network']
    edr_factor = 1.0
    actions = []
    for ident in chosen:
        m = lookup[ident]
        typ = m['type']
        action = {'id': ident, 'type': typ, 'cost': m['cost']}
        if typ == 'patch':
            targets = {tuple(pair) for pair in m['targets']}
            actual = []
            for host in network['hosts']:
                keep = []
                for vul in host['vulnerabilities']:
                    if (host['id'], vul['cve']) in targets:
                        actual.append([host['id'], vul['cve']])
                    else:
                        keep.append(vul)
                host['vulnerabilities'] = keep
            action['removed_host_cves'] = actual
        elif typ == 'fix_misconfig':
            targets = set(m['targets'])
            actual = []
            for host in network['hosts']:
                keep = []
                for weakness in host.get('misconfigurations',[]):
                    if weakness['id'] in targets:
                        actual.append(weakness['id'])
                    else:
                        keep.append(weakness)
                if 'misconfigurations' in host:
                    host['misconfigurations'] = keep
            action['fixed_weaknesses'] = actual
        elif typ == 'remove_trust':
            ids = set(m['trusts'])
            existing = [t['id'] for t in network['trust_relations'] if t['id'] in ids]
            network['trust_relations'] = [t for t in network['trust_relations'] if t['id'] not in ids]
            action['removed_trusts'] = existing
        elif typ == 'block_flow':
            rules = [_firewall_deny(data,src,dst,port) for src,dst,port in m['flows']]
            network['firewall_rules'].extend(rules)
            action['added_denies'] = rules
        elif typ == 'scale_time':
            if m['scope'] != 'all-hosts':
                raise ValueError(f'Unsupported EDR scope {m["scope"]!r}; no silent scope assumptions')
            if float(m['factor']) < 1:
                raise ValueError('EDR scaling factor must be >=1 to be a mitigation')
            edr_factor *= float(m['factor'])
            action['edr_factor'] = float(m['factor'])
        elif typ == 'detect_only':
            action['graph_effect'] = 'none (detection-only; monitoring benefit is outside quantitative model)'
        else:
            raise ValueError(f'Unsupported mitigation type {typ}')
        actions.append(action)
    return data, edr_factor, actions


def mitigated_graph(data, selected, same_zone_policy='allow', strict_db=False):
    modified, edr_factor, actions = apply_mitigations(data, selected)
    graph, excluded = build_attack_graph(modified,same_zone_policy,
                                        db_credentials_as_host_user=not strict_db)
    if edr_factor > 1:
        for _u,_v,_key,edge in graph.edges(keys=True,data=True):
            if edge['mechanism'] in EDR_MECHANISMS:
                # M14's JSON description: halve success, hence double t/p for
                # each exploit step. Keep attempt duration t unchanged.
                edge['probability'] /= edr_factor
                edge['conditional_note'] += f'; EDR success factor 1/{edr_factor:g}'
    return graph, modified, actions, excluded


def edge_ids(graph):
    return set(graph.edges(keys=True))


def _goal_groups(data, graph, max_hops, max_paths):
    """Enumerate baseline paths once; fail closed on truncated search."""
    groups = defaultdict(list)
    meta = []
    t0 = time.perf_counter()
    for scenario in data['attacker_scenarios']:
        for goal in data['goals']:
            start, target = _scenario_state(scenario),_goal_state(goal)
            begin = time.perf_counter()
            paths, cap = enumerate_paths(graph,start,target,max_hops=max_hops,limit=max_paths)
            elapsed = time.perf_counter()-begin
            if cap:
                raise ValueError(f'Path cap hit for {scenario["id"]}/{goal["id"]}; '
                                 'increase --max-paths or reduce --max-hops. '
                                 'Optimization requires complete bounded path data.')
            impact = next(h['criticality'] for h in data['network']['hosts'] if h['id']==goal['host'])
            for edges in paths:
                p,mtao,risk = _path_risk([d for _,_,_,d in edges],impact)
                groups[(scenario['id'],goal['id'])].append(dict(edges=edges,risk=risk,likelihood=p,
                                                                  impact=impact,mtao=mtao))
            meta.append(dict(scenario=scenario['id'],goal=goal['id'],path_count=len(paths),
                             seconds=round(elapsed,6)))
    return groups,meta,time.perf_counter()-t0


def _zeta_subset_max(items, bit_count):
    """Best risk among paths whose mitigation-kill mask is a subset of index."""
    size = 1 << bit_count
    values = array('d',[0.0])*size
    for mask,value in items.items():
        if value > values[mask]:
            values[mask] = value
    for bit in range(bit_count):
        step = 1 << bit
        for mask in range(size):
            if mask & step and values[mask ^ step] > values[mask]:
                values[mask] = values[mask ^ step]
    return values


class Optimizer:
    """Exact search using per-path monotone kill masks + subset-max DP."""
    def __init__(self, data, *, same_zone_policy='allow', strict_db=False,
                 max_hops=7, max_paths=10000):
        self.data = data
        self.same_zone_policy = same_zone_policy
        self.strict_db = strict_db
        self.max_hops = max_hops
        self.max_paths = max_paths
        self.mitigations = sorted(data['mitigations'],key=lambda m:m['id'])
        self.ids = [m['id'] for m in self.mitigations]
        self.costs = {m['id']:m['cost'] for m in self.mitigations}
        self.edr = [m['id'] for m in self.mitigations if m['type']=='scale_time']
        if len(self.edr) > 1:
            raise ValueError('Optimizer supports one scale_time item; arbitrary subsets still supported by apply_mitigations')
        self.edr_id = self.edr[0] if self.edr else None
        self.action_ids = [i for i in self.ids if i != self.edr_id]
        self.bit_by_id = {ident:1<<i for i,ident in enumerate(self.action_ids)}
        self.full_mask = (1<<len(self.action_ids))-1
        self.edr_cost = self.costs[self.edr_id] if self.edr_id else 0
        self.edr_factor = float(_mitigation_by_id(data)[self.edr_id]['factor']) if self.edr_id else 1
        self.graph, self.excluded = build_attack_graph(data,same_zone_policy,
                                        db_credentials_as_host_user=not strict_db)
        self.groups, self.path_meta, self.enumeration_seconds = _goal_groups(data,self.graph,max_hops,max_paths)
        self.goals = [goal['id'] for goal in data['goals']]
        self.scenarios = [s['id'] for s in data['attacker_scenarios']]
        base_edges = edge_ids(self.graph)
        self.edge_kill = defaultdict(int)
        self.single_graph_removals = {}
        for ident in self.action_ids:
            after,_,_,_ = mitigated_graph(data,[ident],same_zone_policy,strict_db)
            removed = base_edges - edge_ids(after)
            added = edge_ids(after) - base_edges
            if added:
                raise ValueError(f'Mitigation {ident} added attack edges; monotone optimizer cannot be used')
            self.single_graph_removals[ident] = removed
            for edge in removed:
                self.edge_kill[edge] |= self.bit_by_id[ident]
        self.flat_paths = []
        self.exact_risks = {edr:{g:{} for g in self.goals} for edr in (False,True)}
        for (scenario,goal),rows in self.groups.items():
            for row in rows:
                mask=0
                seen_edges=set()
                edr_step_count=0
                for u,v,key,edge in row['edges']:
                    ident=(u,v,key)
                    mask |= self.edge_kill[ident]
                    seen_edges.add(ident)
                    if edge['mechanism'] in EDR_MECHANISMS:
                        edr_step_count+=1
                path=dict(**row,scenario=scenario,goal=goal,kill_mask=mask,
                          edge_ids=seen_edges,edr_step_count=edr_step_count)
                self.flat_paths.append(path)
                for edr_on in (False,True):
                    risk = row['risk']/(self.edr_factor**edr_step_count if edr_on else 1.0)
                    risks=self.exact_risks[edr_on][goal]
                    risks[mask]=max(risks.get(mask,0.0),risk)
        self.zeta = {edr:{g:_zeta_subset_max(self.exact_risks[edr][g],len(self.action_ids))
                          for g in self.goals} for edr in (False,True)}
        self.eval_cache={}

    def mask(self, selected):
        s=set(selected)
        unknown=s-set(self.ids)
        if unknown:
            raise ValueError('Unknown mitigation IDs: '+', '.join(sorted(unknown)))
        mask=0
        for ident in s-set(self.edr):
            mask |= self.bit_by_id[ident]
        return mask, bool(self.edr_id and self.edr_id in s)

    def selected_ids(self, mask, edr=False):
        names=[ident for ident in self.action_ids if mask & self.bit_by_id[ident]]
        if edr and self.edr_id:
            names.append(self.edr_id)
        return sorted(names)

    def costs_for(self,selected):
        return sum(self.costs[ident] for ident in selected)

    def risk_by_goal(self, mask, edr):
        available = self.full_mask ^ mask
        return {g:self.zeta[edr][g][available] for g in self.goals}

    def objective(self, mask, edr):
        return sum(self.risk_by_goal(mask,edr).values())

    def evaluate(self, selected):
        mask,edr=self.mask(selected)
        goal_risks=self.risk_by_goal(mask,edr)
        return dict(cost=self.costs_for(selected),objective=sum(goal_risks.values()),goals=goal_risks,
                    ids=sorted(selected))

    def greedy(self, budget):
        selected=[]
        remaining=set(self.ids)
        current=self.evaluate(selected)['objective']
        while remaining:
            best=None
            for ident in sorted(remaining):
                amount=self.costs[ident]
                if self.costs_for(selected)+amount>budget:
                    continue
                new=self.evaluate(selected+[ident])['objective']
                gain=current-new
                if gain <= EPS:
                    continue
                option=(gain/amount, gain, -amount, ident, new)
                if best is None or option[:3] > best[:3] or (option[:3]==best[:3] and ident<best[3]):
                    best=option
            if best is None:
                break
            selected.append(best[3]); remaining.remove(best[3]); current=best[4]
        return self.evaluate(selected)

    def exact(self, budget):
        """Exhaustive 2^18 selections; O(n 2^n) precomputation, O(2^n) search."""
        size=self.full_mask+1
        subset_cost=array('I',[0])*size
        for mask in range(1,size):
            low=mask & -mask
            bit=low.bit_length()-1
            subset_cost[mask]=subset_cost[mask ^ low]+self.costs[self.action_ids[bit]]
        best = None
        checked=0
        for mask in range(size):
            base_cost=subset_cost[mask]
            for edr_on in (False,True) if self.edr_id else (False,):
                cost=base_cost+(self.edr_cost if edr_on else 0)
                if cost>budget:
                    continue
                checked+=1
                objective=self.objective(mask,edr_on)
                ids=self.selected_ids(mask,edr_on)
                candidate=(objective,cost,tuple(ids),ids)
                if (best is None or objective<best[0]-EPS or
                    (abs(objective-best[0])<=EPS and (cost,tuple(ids))<(best[1],best[2]))):
                    best=candidate
        if best is None:
            raise RuntimeError('No feasible selection; even empty plan unexpectedly excluded')
        result=self.evaluate(best[3])
        result['searched_feasible_subsets']=checked
        result['search_space']=1<<len(self.ids)
        return result

    def recompute_plan(self, selected):
        """Independent graph rebuild + path enumeration for validation and reporting."""
        graph,modified,actions,exclusions=mitigated_graph(
            self.data,selected,self.same_zone_policy,self.strict_db)
        groups,meta,elapsed=_goal_groups(self.data,graph,self.max_hops,self.max_paths)
        pair=[]
        for s in self.scenarios:
            for g in self.goals:
                paths=groups[(s,g)]
                pair.append(dict(scenario=s,goal=g,path_count=len(paths),
                                 max_path_risk=max((p['risk'] for p in paths),default=0.0),
                                 min_mtao_hours=min((p['mtao'] for p in paths),default=None)))
        goal_risks={g:max(p['max_path_risk'] for p in pair if p['goal']==g) for g in self.goals}
        objective=sum(goal_risks.values())
        predicted=self.evaluate(selected)
        if not math.isclose(objective,predicted['objective'],rel_tol=1e-9,abs_tol=1e-10):
            raise AssertionError('Optimized mask-based risk differs from rebuilt attack graph')
        # Additional invariant: independent network rebuild does not add base edges.
        if not edge_ids(graph).issubset(edge_ids(self.graph)):
            raise AssertionError('Mitigation unexpectedly created attack edge')
        return dict(ids=sorted(selected),spent=self.costs_for(selected),objective=objective,
                    goal_risks=goal_risks,paths=sum(p['path_count'] for p in pair),pairs=pair,
                    nodes=graph.number_of_nodes(),edges=graph.number_of_edges(),
                    computation_seconds=round(elapsed,6),actions=actions),graph,modified


def _write_csv(path,rows,cols):
    with Path(path).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore')
        w.writeheader();w.writerows(rows)


def _graphml(graph,path):
    serial=nx.MultiDiGraph()
    for node,attrs in graph.nodes(data=True):
        serial.add_node(f'{node[0]}:{node[1]}',**attrs)
    for u,v,key,attrs in graph.edges(keys=True,data=True):
        serial.add_edge(f'{u[0]}:{u[1]}',f'{v[0]}:{v[1]}',key=key,**attrs)
    nx.write_graphml(serial,path)


def _residual_threats(before,after):
    """STRIDE candidate inventory after selected actions; not a proof of exploit."""
    original,_,_ = generate_threats(before)
    remaining,_,_=generate_threats(after)
    def key(row):
        return (row['element'],row['stride_category'],row['source_reference'],row['description'].split(';')[0])
    remaining_keys={key(r) for r in remaining}
    treatments={
        'Repudiation':('reduce','Protect audit-log integrity, off-host immutable storage and privileged access review'),
        'Denial of Service':('reduce/transfer','Rate limiting, failover, DDoS scrubbing and response contract'),
        'Information Disclosure':('reduce','Apply least privilege, secrets rotation and authenticated encryption for data flows'),
        'Spoofing':('reduce','Enforce MFA and strong authentication; audit service accounts'),
        'Tampering':('reduce','Use integrity-protected channels and application input validation'),
        'Elevation of Privilege':('reduce/avoid','Patch affected systems and restrict lateral movement with segmentation/EDR'),
    }
    result=[]
    for row in original:
        treatment,note=treatments.get(row['stride_category'],('accept only if justified','Review owner and compensating controls'))
        if key(row) in remaining_keys:
            result.append(dict(threat_id=row['id'],host=row['host'],element=row['element'],
                               stride=row['stride_category'],feasibility=row['feasibility'],
                               treatment=treatment,recommendation=note,description=row['description']))
    return result,len(original),len(remaining)


def _plot_comparison(reports,path):
    names=['Baseline']+[r['name'] for r in reports if r['name']!='Baseline']
    values=[next(r for r in reports if r['name']==name)['objective'] for name in names]
    fig,ax=plt.subplots(figsize=(12,5.5))
    ax.bar(range(len(names)),values)
    ax.set_xticks(range(len(names)),names,rotation=15,ha='right')
    ax.set_ylabel('Sum of max goal risks (heuristic risk units)')
    ax.set_title('Before vs after: risk objective at each budget')
    for i,val in enumerate(values):
        ax.text(i,val+max(values+[.1])*.015, f'{val:.4f}',ha='center',fontsize=9)
    ax.set_ylim(0,max(values+[.1])*1.15)
    fig.tight_layout()
    fig.savefig(path,dpi=180)
    plt.close(fig)


def export_task5(data, output_dir='output/mitigations',*,same_zone_policy='allow',
                 strict_db=False,max_hops=7,max_paths=10000,selected=None):
    dest=Path(output_dir);dest.mkdir(parents=True,exist_ok=True)
    t0=time.perf_counter()
    optimizer=Optimizer(data,same_zone_policy=same_zone_policy,strict_db=strict_db,
                        max_hops=max_hops,max_paths=max_paths)
    original,base_graph,_=optimizer.recompute_plan([])
    plans=[dict(name='Baseline',method='none',budget=0,**original)]
    budget_summary=[]
    for percentage in (30,60):
        budget=int((Decimal(data['total_mitigation_cost'])*Decimal(percentage)/100).to_integral_value(rounding=ROUND_FLOOR))
        greedy=optimizer.greedy(budget)
        exact=optimizer.exact(budget)
        for method,result in (('Greedy',greedy),('Exact',exact)):
            report,graph,_=optimizer.recompute_plan(result['ids'])
            report.update(name=f'{method} {percentage}%',method=method,budget=budget)
            plans.append(report)
            if method=='Exact':
                _graphml(graph,dest/f'attack_graph_exact_{percentage}pct.graphml')
        budget_summary.append(dict(budget_percent=percentage,budget_euros=budget,
                                   greedy_ids=greedy['ids'],exact_ids=exact['ids'],
                                   greedy_cost=greedy['cost'],exact_cost=exact['cost'],
                                   greedy_objective=greedy['objective'],exact_objective=exact['objective'],
                                   feasible_subsets=exact['searched_feasible_subsets'],
                                   search_space=exact['search_space']))
    if selected is not None:
        cost=optimizer.costs_for(selected)
        report,graph,_=optimizer.recompute_plan(selected)
        report.update(name='Custom',method='manual',budget=cost)
        plans.append(report)
        _graphml(graph,dest/'attack_graph_custom.graphml')
    _write_csv(dest/'mitigation_plan.csv',
               [dict(plan=r['name'],method=r['method'],budget_euros=r['budget'],spent_euros=r['spent'],
                     selected_ids=';'.join(r['ids']),objective_risk=round(r['objective'],10),
                     risk_reduction_pct=round((1-r['objective']/original['objective'])*100,3) if original['objective'] else 0,
                     surviving_paths=r['paths'],attack_edges=r['edges']) for r in plans],
               ['plan','method','budget_euros','spent_euros','selected_ids','objective_risk',
                'risk_reduction_pct','surviving_paths','attack_edges'])
    comparison=[]
    for plan in plans:
        for pair in plan['pairs']:
            comparison.append(dict(plan=plan['name'],scenario=pair['scenario'],goal=pair['goal'],
                                   goal_max_across_scenarios=round(plan['goal_risks'][pair['goal']],10),
                                   path_count=pair['path_count'],max_path_risk=round(pair['max_path_risk'],10),
                                   min_mtao_hours=round(pair['min_mtao_hours'],3) if pair['min_mtao_hours'] is not None else ''))
    _write_csv(dest/'mitigation_goal_comparison.csv',comparison,
               ['plan','scenario','goal','goal_max_across_scenarios','path_count','max_path_risk','min_mtao_hours'])
    selection_details=[]
    for plan in plans:
        for ident in plan['ids']:
            mit=_mitigation_by_id(data)[ident]
            selection_details.append(dict(plan=plan['name'],mitigation=ident,name=mit['name'],
                                          cost_euros=mit['cost'],type=mit['type']))
    _write_csv(dest/'mitigation_selected_details.csv',selection_details,
               ['plan','mitigation','name','cost_euros','type'])
    marginals=[]
    for mitigation in optimizer.mitigations:
        ident=mitigation['id']
        removed=optimizer.single_graph_removals.get(ident,set())
        interrupted=sum(bool(p['edge_ids'] & removed) for p in optimizer.flat_paths)
        ev=optimizer.evaluate([ident])
        marginals.append(dict(mitigation=ident,name=mitigation['name'],type=mitigation['type'],
                              cost_euros=mitigation['cost'],paths_broken=interrupted,
                              single_action_risk_reduction=round(original['objective']-ev['objective'],10),
                              risk_reduction_per_euro=round((original['objective']-ev['objective'])/mitigation['cost'],12)))
    _write_csv(dest/'mitigation_marginals.csv',marginals,
               ['mitigation','name','type','cost_euros','paths_broken','single_action_risk_reduction','risk_reduction_per_euro'])
    edge_counts=defaultdict(int)
    edge_info={}
    for path in optimizer.flat_paths:
        for u,v,key,edge in path['edges']:
            ident=(u,v,key)
            edge_counts[ident]+=1
            edge_info[ident]=(u,v,key,edge['mechanism'],edge['reference'])
    edge_ranking=[]
    for ident,count in sorted(edge_counts.items(),key=lambda x:(-x[1],str(x[0]))):
        u,v,key,mech,ref=edge_info[ident]
        edge_ranking.append(dict(source=f'{u[0]}:{u[1]}',destination=f'{v[0]}:{v[1]}',key=key,
                                 mechanism=mech,reference=ref,paths_using_edge=count))
    _write_csv(dest/'critical_transitions.csv',edge_ranking,
               ['source','destination','key','mechanism','reference','paths_using_edge'])
    reference_counts=defaultdict(int)
    for path in optimizer.flat_paths:
        references={edge['reference'] for _u,_v,_k,edge in path['edges']}
        for reference in references:
            reference_counts[reference]+=1
    critical_references=[dict(reference=ref,paths_containing_reference=count)
                         for ref,count in sorted(reference_counts.items(),key=lambda x:(-x[1],x[0]))]
    _write_csv(dest/'critical_references.csv',critical_references,
               ['reference','paths_containing_reference'])
    # STRIDE residual candidates: compare original to exact 60% reconstructed network.
    exact60=next(p for p in plans if p['name']=='Exact 60%')
    modified,_,_=apply_mitigations(data,exact60['ids'])
    residual,before_count,after_count=_residual_threats(data,modified)
    _write_csv(dest/'residual_stride_threats.csv',residual,
               ['threat_id','host','element','stride','feasibility','treatment','recommendation','description'])
    (dest/'mitigation_application_audit.json').write_text(
        json.dumps({p['name']:p['actions'] for p in plans},indent=2)+'\n',encoding='utf-8')
    _plot_comparison(plans,dest/'mitigation_risk_comparison.png')
    result={
        'methodology':'Exact enumeration of 2^18 mitigation subsets using max-over-submasks DP for bounded attack paths',
        'baseline_risk':original['objective'],
        'risk_objective':'sum over G1,G2,G3 of max across S1,S2 and bounded paths (path likelihood × goal criticality)',
        'max_hops':max_hops,'max_paths_per_pair':max_paths,'strict_db':strict_db,
        'same_zone_policy':same_zone_policy,'total_mitigation_cost':data['total_mitigation_cost'],
        'budget_comparisons':budget_summary,
        'plans':[{**{k:v for k,v in p.items() if k not in ('pairs','actions')},
            'risk_reduction_percent':round((1-p['objective']/original['objective'])*100,3) if original['objective'] else 0}
                 for p in plans],
        'critical_transition':edge_ranking[0] if edge_ranking else None,
        'critical_reference':critical_references[0] if critical_references else None,
        'most_paths_broken_by_single_mitigation':max(marginals,key=lambda m:m['paths_broken']) if marginals else None,
        'stride_candidates_before':before_count,'stride_candidates_after_exact_60pct':after_count,
        'residual_stride_candidates_listed':len(residual),
        'execution_seconds':round(time.perf_counter()-t0,3),
        'baseline_simple_paths_total':len(optimizer.flat_paths),
        'limitations':[
            'Optimization is exact only for enumerated simple paths <=max_hops; never an unbounded-graph guarantee.',
            'Only conditional educational per-step success priors, not empirical probabilities or real loss euros.',
            'EDR M14 applied per JSON scope all-hosts and interpreted as p/2 for remote/local CVE and credential-CVE steps; step MTAO t/p doubles, not necessarily whole-path MTAO.',
            'M18 IDS is detection-only: costs money and does not reduce modeled likelihood or feasibility. Operational benefit excluded from this objective.',
            'M12 removes T6,T9,T4 as encoded in the JSON despite its narrower human-readable name.',
            'G3 has no bounded modeled paths; zero risk is an evidence/model gap, not proof of safety.',
            'The default T9 MySQL-credentials-as-OS-user assumption is fragile; compare --strict-db.',
            'STRIDE residual threat listing reflects inventory changes, not proven elimination of attack opportunities.',
            'Greedy can stall when two complementary mitigations jointly remove all dominating paths.',
            'Impact is unchanged because input provides no impact-reduction mitigation; maximum path risk is not additive across attackers.',
        ],
    }
    (dest/'mitigation_summary.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description='HW3 Task 5 mitigation selection + exact vs greedy')
    p.add_argument('--input',default='network.json')
    p.add_argument('--output',default='output/mitigations')
    p.add_argument('--same-zone-policy',choices=['allow','deny'],default='allow')
    p.add_argument('--strict-db',action='store_true')
    p.add_argument('--max-hops',type=int,default=7)
    p.add_argument('--max-paths',type=int,default=10000)
    p.add_argument('--select',nargs='+',metavar='MXX',help='Also evaluate a custom subset, e.g. --select M07 M12')
    args=p.parse_args(argv)
    try:
        data=load_network(args.input)
        result=export_task5(data,args.output,same_zone_policy=args.same_zone_policy,
                            strict_db=args.strict_db,max_hops=args.max_hops,
                            max_paths=args.max_paths,selected=args.select)
    except (ValueError,OSError,AssertionError) as exc:
        p.exit(2,f'Task 5 FAILED: {exc}\n')
    print('Task 5 completed.')
    print(json.dumps({k:result[k] for k in ('baseline_risk','budget_comparisons',
            'critical_transition','most_paths_broken_by_single_mitigation',
            'stride_candidates_before','stride_candidates_after_exact_60pct','execution_seconds')},indent=2))
    print(f'Files saved to {Path(args.output).resolve()}')

if __name__=='__main__':
    main()
