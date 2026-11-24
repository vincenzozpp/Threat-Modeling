"""HW3 Task 1 — validate network.json, derive host reachability, export a system model.

Run from repository root:
    python -m script.loader --input network.json --output output
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import subprocess
import matplotlib
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from .visualizations import draw_level0, draw_level1

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
VALID_PRIVILEGES = {"none", "user", "root"}
VALID_MITIGATION_TYPES = {"patch", "block_flow", "remove_trust", "scale_time", "fix_misconfig", "detect_only"}
SERVICE_BY_PROTOCOL = {"http": "http", "https": "https", "ftp": "ftp", "ssh": "ssh", "mysql": "mysql", "postgresql": "postgres", "smtp": "smtp", "dns": "dns"}


class ModelValidationError(ValueError):
    """Input JSON is syntactically or semantically invalid."""


def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ModelValidationError(f"Duplicate JSON key: {key!r}")
        obj[key] = value
    return obj


def _need(obj, key, typ, where):
    if not isinstance(obj, dict) or key not in obj:
        raise ModelValidationError(f"{where}: missing required key '{key}'")
    value = obj[key]
    if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
        raise ModelValidationError(f"{where}.{key}: expected {typ.__name__}, got {type(value).__name__}")
    return value


def _nonempty(value, where):
    if not isinstance(value, str) or not value.strip():
        raise ModelValidationError(f"{where}: expected non-empty string")


def _check_unique(items, where):
    ids = set()
    for i, item in enumerate(items):
        ident = _need(item, 'id', str, f'{where}[{i}]')
        _nonempty(ident, f'{where}[{i}].id')
        if ident in ids:
            raise ModelValidationError(f"{where}: duplicated id {ident!r}")
        ids.add(ident)
    return ids


def _port(value, where, local_allowed=False):
    if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 65535):
        raise ModelValidationError(f"{where}: port must be an integer in [0, 65535]")
    if value == 0 and not local_allowed:
        raise ModelValidationError(f"{where}: port 0 is reserved for local services, not network rules")


def load_network(path):
    """Load JSON, rejecting syntax errors, duplicate keys and bad references."""
    path = Path(path)
    try:
        with path.open(encoding='utf-8') as file:
            data = json.load(file, object_pairs_hook=_no_duplicate_keys)
    except OSError as exc:
        raise ModelValidationError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ModelValidationError(f"Malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    validate_network(data)
    return data


def validate_network(data):
    if not isinstance(data, dict):
        raise ModelValidationError("Top-level JSON must be an object")
    metadata = _need(data, 'metadata', dict, 'root')
    network = _need(data, 'network', dict, 'root')
    for key in ('zones', 'hosts', 'firewall_rules', 'trust_relations', 'data_flows'):
        _need(network, key, list, 'network')
    for key in ('goals', 'attacker_scenarios', 'mitigations'):
        _need(data, key, list, 'root')
    zones = network['zones']; hosts = network['hosts']
    zone_ids = _check_unique(zones, 'network.zones')
    host_ids = _check_unique(hosts, 'network.hosts')
    _check_unique(network['trust_relations'], 'network.trust_relations')
    _check_unique(network['data_flows'], 'network.data_flows')
    _check_unique(data['goals'], 'goals')
    _check_unique(data['attacker_scenarios'], 'attacker_scenarios')
    _check_unique(data['mitigations'], 'mitigations')
    if 'internet' not in zone_ids:
        raise ModelValidationError("network.zones must include external zone 'internet'")
    if any(h.startswith('ext-') or h == 'INTERNET' for h in host_ids):
        raise ModelValidationError("host IDs must not use reserved external identifiers")
    for i, z in enumerate(zones):
        _need(z, 'trusted', bool, f'network.zones[{i}]')
    if _need(metadata, 'hosts', int, 'metadata') != len(hosts):
        raise ModelValidationError(f"metadata.hosts does not equal number of hosts ({len(hosts)})")

    host_by_id = {h['id']: h for h in hosts}
    all_cve_pairs = set(); all_misconfigs = set()
    for i, host in enumerate(hosts):
        at = f'network.hosts[{i}] ({host["id"]})'
        for key in ('name', 'zone', 'os', 'role'):
            _nonempty(_need(host, key, str, at), f'{at}.{key}')
        if host['zone'] not in zone_ids or host['zone'] == 'internet':
            raise ModelValidationError(f"{at}.zone: unknown or external zone {host['zone']!r}")
        crit = _need(host, 'criticality', int, at)
        if not 1 <= crit <= 5:
            raise ModelValidationError(f"{at}.criticality must be between 1 and 5")
        services = _need(host, 'services', list, at)
        service_names = set()
        for j, service in enumerate(services):
            loc = f'{at}.services[{j}]'
            for key in ('name', 'product', 'version'):
                _nonempty(_need(service, key, str, loc), f'{loc}.{key}')
            port = _need(service, 'port', int, loc)
            _port(port, f'{loc}.port', local_allowed=True)
            if service['name'] in service_names:
                raise ModelValidationError(f"{at}: duplicate service name {service['name']!r}")
            service_names.add(service['name'])
        for key in ('vulnerabilities', 'accounts', 'data_assets'):
            _need(host, key, list, at)
        for j, v in enumerate(host['vulnerabilities']):
            loc = f'{at}.vulnerabilities[{j}]'
            cve = _need(v, 'cve', str, loc)
            service = _need(v, 'service', str, loc)
            if not CVE_PATTERN.fullmatch(cve):
                raise ModelValidationError(f"{loc}.cve: invalid CVE identifier {cve!r}")
            if service not in service_names:
                raise ModelValidationError(f"{loc}: vulnerability {cve} references missing service {service!r}")
            if (host['id'], cve) in all_cve_pairs:
                raise ModelValidationError(f"{at}: duplicate CVE {cve}")
            all_cve_pairs.add((host['id'], cve))
        for j, account in enumerate(host['accounts']):
            loc = f'{at}.accounts[{j}]'
            _nonempty(_need(account, 'user', str, loc), f'{loc}.user')
            if _need(account, 'privilege', str, loc) not in VALID_PRIVILEGES:
                raise ModelValidationError(f"{loc}.privilege: expected one of {sorted(VALID_PRIVILEGES)}")
        for j, asset in enumerate(host['data_assets']):
            _nonempty(asset, f'{at}.data_assets[{j}]')
        for j, misc in enumerate(host.get('misconfigurations', [])):
            loc = f'{at}.misconfigurations[{j}]'
            ident = _need(misc, 'id', str, loc)
            if ident in all_misconfigs:
                raise ModelValidationError(f"Duplicate misconfiguration id {ident!r}")
            all_misconfigs.add(ident)
            service = _need(misc, 'service', str, loc)
            if service not in service_names:
                raise ModelValidationError(f"{loc}: references missing service {service!r}")
            if _need(misc, 'grants', str, loc) not in VALID_PRIVILEGES:
                raise ModelValidationError(f"{loc}.grants: invalid privilege")
            _nonempty(_need(misc, 'description', str, loc), f'{loc}.description')

    for i, rule in enumerate(network['firewall_rules']):
        at = f'network.firewall_rules[{i}]'
        for direction in ('src', 'dst'):
            zone = _need(rule, f'{direction}_zone', str, at)
            target = _need(rule, f'{direction}_host', str, at)
            if zone not in zone_ids:
                raise ModelValidationError(f"{at}.{direction}_zone: unknown zone {zone!r}")
            if target != '*' and (target not in host_by_id or host_by_id[target]['zone'] != zone):
                raise ModelValidationError(f"{at}.{direction}_host {target!r}: host not in {zone!r}")
        if _need(rule, 'action', str, at) not in ('allow', 'deny'):
            raise ModelValidationError(f"{at}.action must be 'allow' or 'deny'")
        ports = _need(rule, 'ports', list, at)
        if not ports:
            raise ModelValidationError(f"{at}.ports must be nonempty")
        for port in ports:
            _port(port, f'{at}.ports')

    trust_ids = {t['id'] for t in network['trust_relations']}
    for i, trust in enumerate(network['trust_relations']):
        at = f'network.trust_relations[{i}]'
        for direction in ('from_host', 'to_host'):
            if _need(trust, direction, str, at) not in host_ids:
                raise ModelValidationError(f"{at}.{direction}: unknown host")
        if _need(trust, 'grants', str, at) not in VALID_PRIVILEGES:
            raise ModelValidationError(f"{at}.grants: invalid privilege")
        _nonempty(_need(trust, 'type', str, at), f'{at}.type')
        if 'requires' in trust:
            _nonempty(trust['requires'], f'{at}.requires')

    for i, flow in enumerate(network['data_flows']):
        at = f'network.data_flows[{i}]'
        for key in ('src', 'dst'):
            endpoint = _need(flow, key, str, at)
            if endpoint not in host_ids and not endpoint.startswith('ext-'):
                raise ModelValidationError(f"{at}.{key}: unknown endpoint {endpoint!r}")
        for key in ('protocol', 'data'):
            _nonempty(_need(flow, key, str, at), f'{at}.{key}')

    for i, scenario in enumerate(data['attacker_scenarios']):
        at = f'attacker_scenarios[{i}]'
        if ('entry_zone' in scenario) == ('entry_host' in scenario):
            raise ModelValidationError(f"{at}: provide exactly one entry_zone or entry_host")
        if scenario.get('entry_zone') is not None and scenario['entry_zone'] not in zone_ids:
            raise ModelValidationError(f"{at}: unknown entry_zone")
        if scenario.get('entry_host') is not None and scenario['entry_host'] not in host_ids:
            raise ModelValidationError(f"{at}: unknown entry_host")
        if _need(scenario, 'initial_privilege', str, at) not in VALID_PRIVILEGES:
            raise ModelValidationError(f"{at}: invalid initial_privilege")
    for i, goal in enumerate(data['goals']):
        at = f'goals[{i}]'
        if _need(goal, 'host', str, at) not in host_ids:
            raise ModelValidationError(f"{at}: unknown target host")
        if _need(goal, 'privilege', str, at) not in VALID_PRIVILEGES:
            raise ModelValidationError(f"{at}: invalid target privilege")
        if _need(goal, 'property', str, at) not in ('confidentiality','integrity','availability'):
            raise ModelValidationError(f"{at}: invalid property")

    for i, mitigation in enumerate(data['mitigations']):
        at = f'mitigations[{i}]'
        if _need(mitigation, 'type', str, at) not in VALID_MITIGATION_TYPES:
            raise ModelValidationError(f"{at}: unknown mitigation type")
        cost = _need(mitigation, 'cost', int, at)
        if cost < 0:
            raise ModelValidationError(f"{at}.cost must be nonnegative")
        typ = mitigation['type']
        if typ == 'patch':
            for item in _need(mitigation, 'targets', list, at):
                if not isinstance(item, list) or len(item)!=2 or tuple(item) not in all_cve_pairs:
                    raise ModelValidationError(f"{at}: invalid patch target {item!r}")
        elif typ == 'fix_misconfig':
            for ident in _need(mitigation, 'targets', list, at):
                if ident not in all_misconfigs:
                    raise ModelValidationError(f"{at}: unknown misconfiguration {ident!r}")
        elif typ == 'remove_trust':
            for ident in _need(mitigation, 'trusts', list, at):
                if ident not in trust_ids:
                    raise ModelValidationError(f"{at}: unknown trust {ident!r}")
        elif typ == 'block_flow':
            for item in _need(mitigation, 'flows', list, at):
                if not isinstance(item,list) or len(item)!=3:
                    raise ModelValidationError(f"{at}: flow target must be [source, destination, port]")
                src,dst,port = item
                if src not in host_ids|zone_ids or dst not in host_ids|zone_ids:
                    raise ModelValidationError(f"{at}: unknown flow endpoint in {item!r}")
                _port(port, f'{at}.flows')
        elif typ == 'scale_time':
            factor = mitigation.get('factor')
            if not isinstance(factor, (int,float)) or isinstance(factor,bool) or factor <= 0:
                raise ModelValidationError(f"{at}.factor must be positive")
            _nonempty(_need(mitigation, 'scope', str, at), f'{at}.scope')
    total = _need(data, 'total_mitigation_cost', int, 'root')
    expected = sum(m['cost'] for m in data['mitigations'])
    if total != expected:
        raise ModelValidationError(f"total_mitigation_cost={total}, but mitigations sum to {expected}")
    return True


def _zone_of(host_or_internet, hosts):
    return 'internet' if host_or_internet == 'INTERNET' else hosts[host_or_internet]['zone']


def _rule_applies(rule, src, dst, port, hosts):
    return (rule['src_zone'] == _zone_of(src, hosts)
            and rule['dst_zone'] == _zone_of(dst, hosts)
            and (rule['src_host'] == '*' or rule['src_host'] == src)
            and (rule['dst_host'] == '*' or rule['dst_host'] == dst)
            and port in rule['ports'])


def network_decision(data, src, dst, port, same_zone_policy='allow'):
    """Decide directional reachability to a port (not exploit feasibility).

    Explicit deny overrides allow. Intra-zone access is an explicit *assumption*,
    configurable as allow/deny; all other unmatched flows are denied by default.
    """
    if same_zone_policy not in ('allow','deny'):
        raise ValueError('same_zone_policy must be allow or deny')
    hosts = {h['id']:h for h in data['network']['hosts']}
    if src == dst:
        return False,'self-traffic-not-modeled'
    if src not in hosts and src != 'INTERNET':
        raise ValueError(f'Unknown source host {src}')
    if dst not in hosts and dst != 'INTERNET':
        raise ValueError(f'Unknown destination host {dst}')
    if dst != 'INTERNET' and not any(s['port'] == port and port > 0 for s in hosts[dst]['services']):
        return False,'no-declared-listening-service'
    applicable = [r for r in data['network']['firewall_rules'] if _rule_applies(r,src,dst,port,hosts)]
    if any(r['action']=='deny' for r in applicable):
        return False,'explicit-deny'
    if any(r['action']=='allow' for r in applicable):
        return True,'explicit-allow'
    if _zone_of(src,hosts) == _zone_of(dst,hosts) and same_zone_policy == 'allow':
        return True,'assumed-intra-zone-allow'
    return False,'default-deny'


def build_reachability(data, same_zone_policy='allow'):
    """Produce all directly reachable service endpoints and a host-level binary matrix."""
    hosts = data['network']['hosts']
    nodes = ['INTERNET'] + [h['id'] for h in hosts]
    host_lookup = {h['id']: h for h in hosts}
    allowed = []
    matrix = {src:{dst:0 for dst in nodes} for src in nodes}
    for src in nodes:
        for dst in nodes:
            if src == dst:
                continue
            if dst == 'INTERNET':
                # External services are outside scope. The only declared destination
                # ports are those in explicitly allowed firewall rules.
                candidate_ports = sorted({p for r in data['network']['firewall_rules']
                                          if r['dst_zone']=='internet' for p in r['ports']})
            else:
                candidate_ports = sorted({svc['port'] for svc in host_lookup[dst]['services'] if svc['port'] > 0})
            for port in candidate_ports:
                can, basis = network_decision(data,src,dst,port,same_zone_policy)
                if can:
                    matrix[src][dst] = 1
                    allowed.append({'source':src,'destination':dst,'port':port,'basis':basis})
    return nodes, matrix, allowed


def analyze_data_flows(data,same_zone_policy='allow'):
    hosts = {h['id']: h for h in data['network']['hosts']}
    checked=[]
    for flow in data['network']['data_flows']:
        src = 'INTERNET' if flow['src'].startswith('ext-') else flow['src']
        dst = 'INTERNET' if flow['dst'].startswith('ext-') else flow['dst']
        service_type = SERVICE_BY_PROTOCOL.get(flow['protocol'].lower())
        if dst=='INTERNET':
            checked.append({'flow_id': flow['id'], 'src':flow['src'], 'dst':flow['dst'],
                            'protocol':flow['protocol'], 'dst_ports':'', 'status':'EXTERNAL_TARGET_NOT_MODELED', 'basis':''})
            continue
        matches = [s for s in hosts[dst]['services'] if s['name'].lower()==service_type and s['port']>0]
        if not matches:
            checked.append({'flow_id':flow['id'], 'src':flow['src'],'dst':flow['dst'],
                            'protocol':flow['protocol'], 'dst_ports':'','status':'MISSING_DECLARED_SERVICE', 'basis':''})
            continue
        results = [network_decision(data,src,dst,s['port'],same_zone_policy) for s in matches]
        ok = any(access for access,basis in results)
        checked.append({'flow_id':flow['id'], 'src':flow['src'],'dst':flow['dst'],
                        'protocol':flow['protocol'], 'dst_ports':','.join(str(s['port']) for s in matches),
                        'status':'REACHABLE' if ok else 'BLOCKED_BY_POLICY',
                        'basis':','.join(sorted({basis for allowed,basis in results if allowed})) if ok else ','.join(sorted({basis for allowed,basis in results}))})
    return checked


def build_graph(data, reachable):
    graph = nx.MultiDiGraph()
    for zone in data['network']['zones']:
        graph.add_node(f"zone:{zone['id']}", kind='trust_boundary', name=zone['id'], trusted=str(zone['trusted']))
    for host in data['network']['hosts']:
        hid = host['id']
        graph.add_node(f'host:{hid}',kind='process',name=host['name'],zone=host['zone'],criticality=str(host['criticality']))
        graph.add_edge(f'zone:{host["zone"]}',f'host:{hid}',kind='contains')
        for svc in host['services']:
            sid=f'service:{hid}:{svc["name"]}:{svc["port"]}'
            graph.add_node(sid,kind='service',name=svc['name'],port=str(svc['port']),product=svc['product'])
            graph.add_edge(f'host:{hid}',sid,kind='exposes-service')
        for j, asset in enumerate(host['data_assets']):
            aid=f'asset:{hid}:{j}'
            graph.add_node(aid,kind='data_store',name=asset,zone=host['zone'])
            graph.add_edge(f'host:{hid}',aid,kind='holds-data')
    for flow in data['network']['data_flows']:
        src=f'host:{flow["src"]}' if not flow['src'].startswith('ext-') else f'ext:{flow["src"]}'
        dst=f'host:{flow["dst"]}' if not flow['dst'].startswith('ext-') else f'ext:{flow["dst"]}'
        for endpoint,raw in ((src,flow['src']),(dst,flow['dst'])):
            if raw.startswith('ext-'):
                graph.add_node(endpoint, kind='external_entity',name=raw,zone='internet')
        graph.add_edge(src,dst,kind='declared-data-flow',flow_id=flow['id'],protocol=flow['protocol'],data=flow['data'])
    for trust in data['network']['trust_relations']:
        graph.add_edge('host:'+trust['from_host'],'host:'+trust['to_host'],kind='trust',relation=trust['id'],grant=trust['grants'],requires=trust.get('requires',''))
    for link in reachable:
        src='zone:internet' if link['source']=='INTERNET' else 'host:'+link['source']
        dst='zone:internet' if link['destination']=='INTERNET' else 'host:'+link['destination']
        graph.add_edge(src,dst,kind='port-reachable',port=str(link['port']),basis=link['basis'])
    return graph


def _write_csv(path, rows, fieldnames):
    with open(path,'w',encoding='utf-8',newline='') as fh:
        writer=csv.DictWriter(fh,fieldnames=fieldnames)
        writer.writeheader(); writer.writerows(rows)


def _draw_matrix(path,nodes,matrix,data):
    names={h['id']:h['name'] for h in data['network']['hosts']}
    labels=['Internet' if n=='INTERNET' else n for n in nodes]
    arr=[[matrix[src][dst] for dst in nodes] for src in nodes]
    fig,ax=plt.subplots(figsize=(14.5,13.5),dpi=160)
    ax.imshow(arr,cmap='Blues',vmin=0,vmax=1,interpolation='nearest',aspect='equal')
    ax.set_xticks(range(len(nodes)),labels,rotation=90,fontsize=8)
    ax.set_yticks(range(len(nodes)),labels,fontsize=8)
    ax.set_xlabel('Destination host (any declared remote listening service)',fontsize=10)
    ax.set_ylabel('Source host',fontsize=10)
    ax.set_title('Directed host reachability · 1 = at least one permitted service port',fontsize=13,pad=18)
    ax.set_xticks([i-.5 for i in range(1,len(nodes))],minor=True)
    ax.set_yticks([i-.5 for i in range(1,len(nodes))],minor=True)
    ax.grid(which='minor',color='#cbd5e1',linewidth=.35)
    ax.tick_params(which='minor',bottom=False,left=False)
    fig.tight_layout(); fig.savefig(path,bbox_inches='tight'); plt.close(fig)


def _write_assumptions(path, flow_checks, same_zone_policy):
    bad=[r for r in flow_checks if r['status']!='REACHABLE']
    with open(path,'w',encoding='utf-8') as fh:
        fh.write('# Task 1 — Modeling assumptions and data-quality observations\n\n')
        fh.write('## Assumptions\n\n')
        fh.write('1. `internet` is represented by one abstract endpoint `INTERNET`; remote external endpoints are not enumerated.\n')
        fh.write('2. Explicit firewall **deny** rules override explicit allows; unmatched inter-zone traffic is **denied by default**. The input gives no firewall priority ordering or default policy; these are modeling decisions, not proven facts.\n')
        fh.write(f'3. Unspecified intra-zone traffic follows the **{same_zone_policy}** policy (`--same-zone-policy {same_zone_policy}`). This is not stated in the JSON. Repeat the analysis with the opposite policy for sensitivity.\n')
        fh.write('4. A firewall rule permits an edge only if the destination has a declared **remote service** on that port. Port `0` denotes a local-only component (kernel, sudo, polkit) and creates no remote listener.\n')
        fh.write('5. Source/destination reachability is directional. Reverse connections and TCP response packets are not independent attack edges.\n')
        fh.write('6. `data_flows` describe intended functional communication, **not proof of reachability**. `trust_relations` describe credential-based privilege dependencies, **not firewall bypasses**.\n')
        fh.write('7. `ext-customer`, `ext-partner`, and `ext-employee` are separate external entities in the DFD, mapped to the abstract Internet endpoint for reachability.\n')
        fh.write('8. Host-level reachability means **at least one** declared listening service is allowed; it does NOT imply a vulnerability is exploitable or a goal is reachable.\n')
        fh.write('9. Level-0 is an intentionally manual **conceptual selection** of important business flows. Level-1 is automatically built from all hosts, data stores and declared data flows. Assets are visually grouped by host for legibility.\n')
        fh.write('10. No missing host services or firewall rules are silently inserted into `network.json`. Observed gaps remain flagged until justified.\n\n')
        fh.write('## Observed mismatches (nonfatal warnings)\n\n')
        if not bad:
            fh.write('No missing-service or blocked declared data flows under the current policy.\n')
        for r in bad:
            fh.write(f'- **{r["flow_id"]}** ({r["src"]} -> {r["dst"]}, {r["protocol"]}): `{r["status"]}`. Validate the corresponding listener/flow against the system owner.\n')
        fh.write('\n## Source discrepancy\n\n')
        fh.write('The slide summary describes the database zone as fully patched/a distractor, but the authoritative machine-readable input assigns CVEs to H20 and H21 (H22 alone has no listed CVEs). For analysis we use the host-level JSON.\n')
        fh.write('\n## Security note\n\n')
        fh.write('Level-1 diagrams show declared functional flows even when a service is missing in the host inventory; dashed red arrows denote such a mismatch, not a confirmed exploitable path.\n')


def _write_goals(path, data):
    hosts={h['id']:h for h in data['network']['hosts']}
    with open(path,'w',encoding='utf-8') as fh:
        fh.write('# Task 1 — Security goals and justification\n\n')
        fh.write('## Security objectives\n\n')
        fh.write('| Objective | Protected asset / scope | Why it matters | Validation metric |\n|---|---|---|---|\n')
        fh.write('| Confidentiality | Customer PII / payment tokens at H20; payroll / ledger at H21 | Regulatory, financial and customer-trust harm after disclosure | Maximum attack-path risk for G1/G3 and reachable exposure chains |\n')
        fh.write('| Integrity | Domain controller H13 and its administration relationships | Domain-level compromise can enable broad privilege abuse | Maximum attack-path risk for G2 and number of escalation paths |\n')
        fh.write('| Availability | Web shop H01, app backend H17, databases H20/H21, backups H18 | Business continuity and recoverability of retail workflows | Reachability/DoS threat exposure and surviving disruptive paths |\n')
        fh.write('| Accountability | Centralized logs on H19 and monitoring at H27 | Enables incident investigation; log compromise undermines evidence | STRIDE repudiation/tampering coverage and detection controls |\n')
        fh.write('| Least privilege / isolation | DMZ, corp, dev, server, DB, management zones | Limits lateral movement from Internet-facing systems and phished endpoints | Number of cross-boundary edges and feasible goal paths |\n\n')
        fh.write('## Attacker goals already specified in network.json\n\n')
        for goal in data['goals']:
            h=hosts[goal['host']]
            fh.write(f'- **{goal["id"]}: {goal["description"]}** — target {goal["host"]} ({h["name"]}); requires modeled privilege `{goal["privilege"]}`; violates {goal["property"]}. Its feasibility will be evaluated in Task 4 rather than assumed.\n')
        fh.write('\n## Entry scenarios\n\n')
        for scenario in data['attacker_scenarios']:
            fh.write(f'- **{scenario["id"]}: {scenario["name"]}** — entry {scenario.get("entry_zone",scenario.get("entry_host"))}, initial privilege `{scenario["initial_privilege"]}`.\n')


def export_task1(data, output_dir, same_zone_policy='allow'):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    nodes,matrix,reachable=build_reachability(data,same_zone_policy)
    checked=analyze_data_flows(data,same_zone_policy)
    _write_csv(out/'reachability_matrix.csv',[dict(source=src,**{dst:matrix[src][dst] for dst in nodes}) for src in nodes],['source']+nodes)
    _write_csv(out/'reachable_services.csv',reachable,['source','destination','port','basis'])
    _write_csv(out/'flow_checks.csv',checked,['flow_id','src','dst','protocol','dst_ports','status','basis'])
    _write_csv(out/'trust_relations.csv',[{'id':t['id'],'from_host':t['from_host'],'to_host':t['to_host'],'type':t['type'],'grants':t['grants'],'requires':t.get('requires','')} for t in data['network']['trust_relations']],['id','from_host','to_host','type','grants','requires'])
    inventory={'company':data['metadata'].get('name',''), 'zones':{z['id']:[h['id'] for h in data['network']['hosts'] if h['zone']==z['id']] for z in data['network']['zones']},'hosts':len(data['network']['hosts']),'services':sum(len(h['services']) for h in data['network']['hosts']),'cve_occurrences':sum(len(h['vulnerabilities']) for h in data['network']['hosts']),'distinct_cves':len({v['cve'] for h in data['network']['hosts'] for v in h['vulnerabilities']}),'misconfigurations':sum(len(h.get('misconfigurations',[])) for h in data['network']['hosts']),'firewall_rules':len(data['network']['firewall_rules']),'trust_relations':len(data['network']['trust_relations']),'data_flows':len(data['network']['data_flows']),'attacker_scenarios':len(data['attacker_scenarios']),'goals':len(data['goals']),'mitigations':len(data['mitigations']),'total_mitigation_cost':data['total_mitigation_cost'],'same_zone_policy':same_zone_policy,'reachable_service_edges':len(reachable),'reachable_host_pairs':sum(sum(row.values()) for row in matrix.values()),'flow_checks':dict(Counter(r['status'] for r in checked))}
    (out/'validation_report.json').write_text(json.dumps(inventory,indent=2)+'\n',encoding='utf-8')
    versions = {'python': sys.version.split()[0], 'networkx': nx.__version__, 'matplotlib': matplotlib.__version__}
    try:
        version_proc = subprocess.run(['dot','-V'],capture_output=True,text=True,timeout=5,check=False)
        versions['graphviz_dot'] = (version_proc.stderr or version_proc.stdout).strip()
    except (OSError,subprocess.TimeoutExpired):
        versions['graphviz_dot'] = 'not detected'
    (out/'runtime_versions.json').write_text(json.dumps(versions,indent=2)+'\n',encoding='utf-8')
    _write_assumptions(out/'assumptions.md',checked,same_zone_policy)
    _write_goals(out/'security_goals.md',data)
    graph=build_graph(data,reachable)
    nx.write_graphml(graph,out/'system_model.graphml')
    draw_level0(out/'dfd_level0_manual.png')
    draw_level1(data,checked,out/'dfd_level1_auto.png')
    _draw_matrix(out/'reachability_matrix.png',nodes,matrix,data)
    return inventory


def main(argv=None):
    parser=argparse.ArgumentParser(description='Task 1 — validate input and export network model / DFDs')
    parser.add_argument('--input',default='network.json',help='Path to input network.json')
    parser.add_argument('--output',default='output',help='Output directory')
    parser.add_argument('--same-zone-policy',choices=['allow','deny'],default='allow',help='Undeclared intra-zone policy; assumption, not fact')
    args=parser.parse_args(argv)
    try:
        data=load_network(args.input)
        inventory=export_task1(data,args.output,args.same_zone_policy)
    except (ModelValidationError,RuntimeError,ValueError) as exc:
        parser.exit(2,f'ERROR: {exc}\n')
    print('Task 1 completed.\n'+json.dumps(inventory,indent=2))
    print(f'Files saved to {Path(args.output).resolve()}')


if __name__=='__main__':
    main()
