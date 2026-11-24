"""Task 1 DFD diagrams: manual business-scope Level-0 and automated Level-1."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


def q(value):
    return json.dumps(str(value),ensure_ascii=False)


def _render(dot_source, path):
    if not shutil.which('dot'):
        raise RuntimeError("Graphviz 'dot' was not found. Install it with: sudo apt install graphviz")
    path = Path(path)
    result = subprocess.run(['dot','-Tpng','-Gdpi=145','-o',str(path)],input=dot_source,text=True,
                            capture_output=True,timeout=120,check=False)
    if result.returncode:
        raise RuntimeError(f"Graphviz failed: {result.stderr.strip()}")


def draw_level0(path):
    """Human-curated conceptual DFD from network.json flows (not an auto layout inventory)."""
    lines = [
        'digraph DFD0 {',
        'graph [rankdir=LR, bgcolor="white", fontname="DejaVu Sans", label="LEVEL 0  |  BUSINESS SYSTEM CONTEXT (MANUALLY DESIGNED)", labelloc=t, fontsize=19, pad=0.30, nodesep=0.35, ranksep=1.1, compound=true, splines=polyline];',
        'node [fontname="DejaVu Sans", fontsize=11, style="filled,rounded", shape=box, color="#64748b", penwidth=1.3, margin="0.14,0.09"];',
        'edge [fontname="DejaVu Sans", fontsize=9, color="#3b6387", fontcolor="#375270", arrowsize=.7, penwidth=1.5];',
        'subgraph cluster_internet { label="INTERNET | external / untrusted"; style="rounded,dashed"; color="#df995a"; bgcolor="#fff8ef"; ext_customer [label="Customer",shape=box,fillcolor="#ffedd5"]; ext_partner [label="Partner",shape=box,fillcolor="#ffedd5"]; ext_employee [label="Remote employee",shape=box,fillcolor="#ffedd5"]; }',
        'subgraph cluster_dmz { label="DMZ | untrusted"; style="rounded,dashed"; color="#df995a"; bgcolor="#fff8ef"; web [label="Web shop\nH01",fillcolor="#ffffff"]; ftp [label="Partner FTP\nH05",fillcolor="#ffffff"]; vpn [label="VPN gateway\nH04",fillcolor="#ffffff"]; }',
        'subgraph cluster_server { label="SERVER LAN | trusted"; style="rounded,dashed"; color="#90a9c8"; bgcolor="#f2f7fd"; app [label="Business application\nH17",fillcolor="#ffffff"]; backup [label="Backup service\nH18",fillcolor="#ffffff"]; log [label="Log server\nH19",fillcolor="#ffffff"]; }',
        'subgraph cluster_db { label="DATABASE ZONE | trusted"; style="rounded,dashed"; color="#90a9c8"; bgcolor="#f2f7fd"; db_customer [label="Customer PII / tokens\nH20",shape=cylinder,fillcolor="#d9eefa"]; db_finance [label="Ledger / payroll\nH21",shape=cylinder,fillcolor="#d9eefa"]; db_hr [label="HR records\nH22",shape=cylinder,fillcolor="#d9eefa"]; }',
        'subgraph cluster_mgmt { label="MGMT | trusted"; style="rounded,dashed"; color="#90a9c8"; bgcolor="#f2f7fd"; monitoring [label="Monitoring\nH27",fillcolor="#ffffff"]; }',
        'ext_customer -> web [label="F1  orders / HTTPS"];',
        'ext_partner -> ftp [label="F8  partner files / FTP"];',
        'ext_employee -> vpn [label="F9  VPN session / HTTPS"];',
        'web -> app [label="F2  order requests / HTTP"];',
        'app -> db_customer [label="F3  customer records / MySQL"];',
        'app -> db_finance [label="F4  invoices / PostgreSQL"];',
        'backup -> db_customer [label="F5  backups / SSH*",color="#b45353",style=dashed];',
        'backup -> db_finance [label="F6  backups / SSH*",color="#b45353",style=dashed];',
        'backup -> db_hr [label="F7  backups / SSH*",color="#b45353",style=dashed];',
        'log -> monitoring [label="F10  metrics / HTTP"];',
        'note [shape=note,fillcolor="#f1f5f9",color="#cbd5e1",fontsize=9,label="Solid = declared data flow with listener + policy match\\nDashed red = declared flow without listed SSH destination service (F5-F7)\\nSelected processes only. Corp/dev and other hosts appear in Level-1."];',
        '}',
    ]
    _render('\n'.join(lines),path)


def draw_level1(data,flow_checks,path):
    """Build Level-1 from all host/asset entities and all configured data flows."""
    zone_meta={z['id']:z for z in data['network']['zones']}
    all_flows={r['flow_id']:r for r in flow_checks}
    lines = [
        'digraph DFD1 {',
        'graph [rankdir=LR, bgcolor="white", fontname="DejaVu Sans", label="LEVEL 1  |  ALL HOSTS, DATA STORES AND DECLARED DATA FLOWS (AUTOMATED)", labelloc=t, fontsize=21, pad=.38, nodesep=.19, ranksep=.85, compound=true, newrank=true, splines=polyline];',
        'node [fontname="DejaVu Sans", fontsize=10, style="filled,rounded", shape=box, color="#8ba4ba", penwidth=1.0, margin="0.11,0.07"];',
        'edge [fontname="DejaVu Sans",fontsize=9,arrowsize=.65,color="#34699a",fontcolor="#35516b",penwidth=1.4];',
    ]
    for zid, zone in zone_meta.items():
        style='"rounded,dashed"'
        palette=('#f2f7fd','#7a9bbd') if zone['trusted'] else ('#fff8ee','#d6a064')
        lines.append(f'subgraph cluster_{zid.replace("-","_")} {{ label={q(zid.upper()+(" | TRUSTED" if zone["trusted"] else " | UNTRUSTED"))}; style={style}; color={q(palette[1])}; bgcolor={q(palette[0])}; penwidth=1.5;')
        if zid == 'internet':
            externals = sorted({ep for f in data['network']['data_flows'] for ep in (f['src'], f['dst']) if ep.startswith('ext-')})
            for ep in externals:
                lines.append(f'{q(ep)} [label={q(ep.replace("ext-","").capitalize())},shape=box,fillcolor="#ffead0",color="#cb9157"];')
        for host in [h for h in data['network']['hosts'] if h['zone']==zid]:
            label=f"{host['id']} · {host['name']}\n{host['role']}"
            lines.append(f'{q(host["id"])} [label={q(label)},fillcolor="white"];')
            if host['data_assets']:
                asset_id=f'store:{host["id"]}'
                # Each host's individual assets remain separate nodes in the GraphML model.
                asset_label='\n'.join(host['data_assets'])
                store_label="DATA STORES\n"+asset_label
                lines.append(f'{q(asset_id)} [label={q(store_label)},shape=cylinder,style="filled",fillcolor="#dbebf8",color="#7aacc9",fontsize=9];')
                lines.append(f'{q(host["id"])} -> {q(asset_id)} [style=dotted,color="#91a7b9",arrowhead=none,penwidth=1,constraint=false];')
        lines.append('}')
    for f in data['network']['data_flows']:
        observed=all_flows[f['id']]
        not_confirmed=observed['status']!='REACHABLE'
        color='#bd5959' if not_confirmed else '#34699a'
        style='dashed' if not_confirmed else 'solid'
        label=f"{f['id']} · {f['protocol']}\n{f['data']}"
        lines.append(f'{q(f["src"])} -> {q(f["dst"])} [label={q(label)}, color={q(color)},fontcolor={q(color)},style={style},penwidth=2];')
    lines.append('legend [shape=note,style=filled,fillcolor="#f1f5f9",color="#cbd5e1",label="BOX = process / host\nCYLINDER = data store (assets grouped by host)\nCLUSTER = trust boundary\nSOLID ARROW = declared flow with network and service match\nRED DASHED = declared flow missing service or access"];')
    lines.append('}')
    _render('\n'.join(lines),path)
