# HW3 — Automated Threat Modeling (Security Governance)

**Status:** Task 1 implemented. Tasks 2–5 have not yet been implemented, and no claims of attack-path feasibility or risk reduction are made at this stage.

This repository uses the professor's `network.json` without silently changing it. The goal is a reproducible, inspectable system model rather than a hand-crafted attack path.

## Setup (Ubuntu / WSL)

Use Python 3.8 or newer. `requirements.txt` allows the latest compatible library releases for that Python interpreter; the exact versions used for each generated run are recorded in `output/runtime_versions.json`.

```bash
sudo apt update
sudo apt install -y python3-venv graphviz
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run Task 1

```bash
python -m script.loader --input network.json --output output
```

Sensitivity analysis for intra-zone firewall policy:

```bash
python -m script.loader --input network.json --output output/strict --same-zone-policy deny
```

## Tests

```bash
python -m unittest discover -s test -v
```

## Task 1 generated files

- `dfd_level0_manual.png`: manually curated business-level Level-0 DFD, grounded in selected JSON data flows
- `dfd_level1_auto.png`: generated Level-1 DFD with trust-boundary clusters, all 27 hosts, per-host aggregated data stores, all 10 declared data flows
- `system_model.graphml`: complete machine-readable MultiDiGraph of zones, hosts, individual services, individual assets, flows, trusts and firewall-derived reachable service edges; open with Gephi or other GraphML tool
- `reachability_matrix.csv` / `.png`: 28×28 directed connectivity (Internet aggregate + 27 hosts)
- `reachable_services.csv`: source, destination, port and policy basis for each directly allowed declared service
- `flow_checks.csv`: sanity check of functional flows against declared listening services and firewall model
- `trust_relations.csv`: trust pre/post-condition material for later attack graph analysis
- `security_goals.md`: goals with confidentiality, integrity, availability and accountability rationales
- `assumptions.md`: assumptions, unknowns, source discrepancies, consistency warnings
- `validation_report.json`: counts and validation summary

## Modeling semantics (please read)

- `network.json` contains no physical cable/link topology and no explicit firewall default rule. **We do not invent physical links**: potential network links are derived from firewall rules and services.
- **Default assumption:** unmatched inter-zone communication is denied; intra-zone communication is allowed unless explicitly denied. Explicit deny wins. This is **an assumption**, adjustable with `--same-zone-policy`.
- A remote attack edge requires an allowed direction **and** a declared listening destination service. Ports `0` are strictly local-only.
- `data_flows` are intended business flows, not evidence that a port is actually open; missing declared SSH services on database hosts for backup flows F5–F7 are flagged, not hidden.
- Trust relations are separate from network reachability; later stages must check both access conditions and obtained privileges.
- A row/column `1` in the reachability matrix only means **some** destination service could be reached. It is **not** proof of compromise or exploitability.
- No automatic network.json corrections are made. Governance decisions and source uncertainties are in `output/assumptions.md`.

## Next tasks

2. `script/stride.py`: derive plausible STRIDE threats per DFD element; preserve traceability to host, flow and boundary.
3. `script/mapper.py`: connect CVE→CWE→CAPEC→ATT&CK; pin versions; report unmapped CVEs.
4. `script/ag.py`: pre/post privilege transitions, attack paths, per-path MTAO, likelihood, impact and risk.
5. `script/mitigate.py`: apply mitigations, evaluate 30% and 60% budget, greedy vs exact/near-optimal.

## Coursework requirements

The submission ultimately requires a **single PDF** with group contribution details (if applicable), a GitHub link, methodology/rationale per task **without code snippets**, and answers to the four governance questions. Cite data sources and tool/library versions and disclose use of generative AI tools. The assignment deadline listed in the PDF is **11 December 2026**.

**AI use disclosure example (adapt before submitting):** "A generative AI assistant was used to draft an initial Python implementation and documentation for the Task 1 network loader and DFD generator. The authors reviewed, tested, validated and took responsibility for the resulting software and interpretations."
