# HW3 Task 4 — Multi-step Attack Graph and Risk

**Purpose:** add Task 4 inside the **same** `HW3-Threat-Modeling/` project. This add-on adds `script/ag.py`, `test/test_ag.py` and this guide; it does not overwrite `network.json`, `loader.py`, `stride.py`, `mapper.py`, `requirements.txt` or previous results.

## 1. Run in WSL / VS Code

```bash
cd ~/projects/HW3-Threat-Modeling
source .venv/bin/activate
python -m script.ag --input network.json --output output
python -m unittest discover -s test -v
```

Expected: **45 passing tests**, provided the earlier 33 tests are installed. This module needs only existing NetworkX and Matplotlib dependencies, so it does **not** require an additional pip install. No Internet connection is needed to run it. Task 3's cached catalogues remain independent inputs; Task 4 does not assume every CVE has an ATT&CK mapping.

Run a sensitivity check on the database/OS privilege assumption:

```bash
python -m script.ag --input network.json --output output/strict_db --strict-db
```

Check a restrictive intra-zone firewall policy:

```bash
python -m script.ag --input network.json --output output/strict_zone --same-zone-policy deny
```

Control enumeration size explicitly:

```bash
python -m script.ag --max-hops 7 --max-paths 10000
```

`--max-paths` is **per scenario-goal pair**. The result will say `TRUNCATED` if the path cap is hit. Even without a cap hit, the enumeration is complete **only for simple privilege-state paths of at most `--max-hops` transitions**. Longer paths are **not** enumerated; do not present it as an exhaustive unbounded enumeration. The default bounds are 7 hops and 10,000 paths per pair.

## 2. Core model and assumptions

- **Graph model:** TVA-like directed **MultiDiGraph** (allows multiple attack mechanisms between the same privilege states). Nodes are `(host, privilege)` with `user` or `root`; external attacker `INTERNET:none`, and a separate `H04:vpn` network-session node. The VPN node is **not** an H04 OS shell.
- **Attack scenarios** are read from `attacker_scenarios`: `S1` at Internet with no host privilege, `S2` at `H10` with user privileges.
- **Goals** are the specified `(host, privilege)` targets in `goals`: `G1=H20:root`, `G2=H13:root`, `G3=H21:user`. Goal properties and criticality come from `network.json`.
- **Preconditions** for a remote CVE: a controlled source vantage; an actual declared listening service with the matching vulnerable service; source-to-target **directional** reachability by the Task 1 firewall rules; and the CVE-specific caveat in the graph edge. Local privilege escalations require a prior `user` foothold on the **same** host. `port: 0` never becomes a remotely accessible service.
- **Postconditions:** only the modeled `user`, `root`, or `vpn` effect. File disclosure, SSRF, and user enumeration are **not** automatically turned into remote shell access. Examples: Apache CVE-2021-41773 is not guaranteed RCE without CGI prerequisites; Exchange CVE-2021-26855 is SSRF, not a stand-alone shell; Pulse Secure CVE-2019-11510 can support a **conditional credential-reuse → VPN session** chain, not H04 shell.
- **Misconfiguration preconditions:** MC1 assumes factory printer password still works (user on printer only); MC2 assumes there is a guessable valid SSH password (user on jump host only). They are candidates, not confirmed attacks.
- **Trusts:** source compromise, source privilege, *and* reachable destination **listening** service are required. For example, T2 and T3 are not modeled as SSH shortcuts because the relevant database servers do not declare SSH listeners; T8 cannot ignore firewall segmentation. The script includes excluded relationships in a CSV.
- **Important simplification T9:** The fictional JSON explicitly declares `H17 → H20` DB credentials granting **user**. The default graph interprets that as generic host-level `user` consistent with the supplied simplified privilege vocabulary. **This is NOT generally valid for real systems**: MySQL accounts do not grant Linux shells. The `--strict-db` option removes this unproven equivalence; G1 then lacks a complete modeled path. This assumption needs explicit justification in the report and is important for Task 5.
- **CVE-specific preconditions are not evidenced fully in the JSON**. The graph is a conditional attack-opportunity graph, NOT proof of active exploitability. In particular, writable Samba shares, viable RCE configurations, vulnerable backdoor builds, user-controlled log input, valid credentials etc. have not been independently verified.

## 3. Risk methodology: transparent *illustrative* priors

Each modeled transition has a clearly documented educational **conditional** success prior `p` and **attempt duration** `t` in hours. These are *assumptions*, **not NVD/CVSS likelihoods, real-world exploit success rates, observed penetration-test durations, or validated empirical MTAO values.** The `EXPLOIT_PROFILES` in `script/ag.py` and edge table contain them.

For a path with steps `i=1..k` and target criticality `I` (integer 1–5), the heuristic is:

- **Single-pass path likelihood:** `L_path = ∏ p_i` (assume independent conditional successes; this independence may be false in practice).
- **Mean time to attack objective (MTAO):** `MTAO_path = Σ (t_i / p_i)` hours, using a geometric-retry approximation with independent repeated attempts and no defender reaction. This is a scenario metric, not a prediction.
- **Impact:** `I_path = criticality(target)` on 1–5 scale. This is a normalized business impact proxy.
- **Path risk:** `R_path = L_path × I_path`. Risk is 0–5 heuristic units, **not** a financial loss or a probability.
- **Scenario-goal risk:** `R_target = max_{paths to goal} R_path`, and paths are ranked by decreasing risk, then increasing MTAO.

**Interpretation warning:** A path containing more independent steps can have lower likelihood even if its worst vulnerability has a very high CVSS score. Conversely, one high-probability shortcut can dominate the goal risk. Task 5 should evaluate **path and goal risk**, not choose a patch solely by maximum CVSS.

## 4. Outputs

| File | Purpose |
|---|---|
| `output/attack_graph.graphml` | Attack multigraph for external graph tools |
| `output/attack_graph_edges.csv` | All transitions with mechanism, reference, pre/postconditions, prior and time |
| `output/attack_graph_exclusions.csv` | CVEs and trust shortcuts excluded with a reason |
| `output/attack_paths.csv` | One row per enumerated path with ordered states, mechanisms, likelihood, impact, MTAO, risk |
| `output/attack_goal_summary.csv` | Counts, maximum risk, minimum MTAO, calculation time and cap status for each of six scenario-goal combinations |
| `output/attack_graph_top3.png` | Full privilege-state graph with the top three ranked paths highlighted |
| `output/attack_top3_paths.png` | More readable three-path overview |
| `output/attack_summary.json` | Machine-readable summary of assumptions, formulas and limitations |

## 5. Example dry-run results for the provided network.json

With `same-zone-policy=allow`, 7-hop enumeration and default T9 host-user abstraction, the local demonstration found **56 nodes, 243 candidate edges and 6,598 simple attack paths of at most seven hops** (no per-pair cap hit). Counts per scenario/goal:

| Scenario | G1 — customer DB root | G2 — domain root | G3 — finance DB user |
|---|---:|---:|---:|
| S1 external | 75 | 906 | 0 |
| S2 phished H10 user | 853 | 4,764 | 0 |

**Never describe G3=0 as secure by proof**. The provided input lacks a supported user-privilege entry to H21. The original JSON contains a backup trust that is **not** executable over a declared H21 SSH service; new asset evidence or authorized changes could change the result.

In `--strict-db` sensitivity run, **G1 also falls to 0 modeled paths** because the default T9 database-credential-to-OS-user assumption is removed. This is why this assumption must be decided by the analyst rather than silently adopted.

The numbers above are *demonstration outputs*. Your own WSL output is authoritative for the report; always record invocation options, Python/NetworkX versions and model limitations.

## 6. What to write in the final PDF (no code snippets)

Discuss the selected graph model and why it allows parallel mechanisms; show the privilege state and pre/postcondition concept; justify the two entry scenarios, trust assumptions and evidence-based exclusions; document the independence and retry assumptions behind path likelihood and MTAO; present the goal risk (max over paths), path counts, runtime and top-three highlighted graph; address incomplete/unreachable goals; and explicitly compare the strict T9 sensitivity. State that these are conditional screening estimates, not measured incident probabilities.

Sources for validation of the effect categories (alongside the existing NVD catalog cache):

- https://httpd.apache.org/security/vulnerabilities_24.html (Apache HTTP Server; path traversal, CGI prerequisite)
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855 (Exchange SSRF)
- https://nvd.nist.gov/vuln/detail/CVE-2019-11510 (Pulse Secure arbitrary-file-read)
- https://nvd.nist.gov/vuln/detail/CVE-2012-2122 (MySQL authentication bypass)
- https://nvd.nist.gov/developers/vulnerabilities (NVD API source)

As required by your course, declare use of generative AI tools in the submitted report. Do not copy raw implementation code into the governance PDF.
