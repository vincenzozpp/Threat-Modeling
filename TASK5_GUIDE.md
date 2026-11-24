# HW3 — Task 5: Mitigation Selection

This is an **add-on to the same VS Code / WSL repository**, not a second project. It adds `script/mitigate.py` and `test/test_mitigate.py`, without overwriting existing code or `network.json`. It can be run offline using the Task 4 model.

## 1. Installation and execution (WSL terminal in VS Code)

Download `HW3_Task5_MITIGATE_Addon.zip` to Windows Downloads and then, from your existing project:

```bash
cd ~/projects/HW3-Threat-Modeling
unzip /mnt/c/Users/Vincenzo/Downloads/HW3_Task5_MITIGATE_Addon.zip -d .
source .venv/bin/activate
python -m script.mitigate --input network.json --output output/mitigations
python -m unittest discover -s test -v
```

Expect **58 successful unit tests** (45 from Tasks 1–4 + 13 Task 5), with the exact earlier add-ons and network file. The task uses the existing `networkx` and `matplotlib` packages; no extra pip install should be necessary.

Sensitivity check, which is important for the report:

```bash
python -m script.mitigate --input network.json --output output/mitigations_strict_db --strict-db
```

You can also examine any subset of interventions, without changing the original JSON:

```bash
python -m script.mitigate --input network.json --output output/mitigations_custom --select M07 M12 M14
```

Override the assumed intra-zone firewall policy if desired:

```bash
python -m script.mitigate --input network.json --output output/mitigations_deny --same-zone-policy deny
```

The optimizer fails with an explanatory error when a `--max-paths` cap is hit: it **cannot claim exact optimality using a silently truncated path inventory**. `--max-hops` defaults to 7 and is a hard modeling boundary.

## 2. What the script actually models

It reads all 18 mitigations from the unmodified `network.json` (total cost **€246,700**). `apply_mitigations()` returns a *copy* of the original network after the selected actions, together with an action audit; `mitigated_graph()` rebuilds its attack graph and updates EDR-conditioned likelihoods.

- **patch:** remove exactly the specified `(host, CVE)` instances from the modeled network. M04's *actual product migration to SFTP* would require more operational implementation; the script removes the specified CVE, not an invented new service.
- **block_flow:** add specific firewall `deny` rules. Task 1's `network_decision()` applies explicit denies before any allows. Preserves unrelated flows. M11 affects ports 8080/8090/443 from corp-lan to server-lan but not AD's 445/389.
- **remove_trust:** remove exactly the trust IDs listed in JSON. **M12 removes T6, T9 and T4**, even though its human-readable name focuses on admin credentials; document the discrepancy.
- **fix_misconfig:** remove MC1 or MC2 from the modeled host.
- **scale_time (M14):** JSON says `factor: 2`, `scope: all-hosts` and describes halving exploit success. To honor that, the model halves conditional success `p` for `remote-cve`, `local-cve`, and `credential-conditional` attack transitions. Attempt duration `t` is unchanged; each affected `t/p` contribution doubles, and path likelihood falls accordingly. Trust and password-misconfiguration probabilities are **not** halved. The textual name mentions servers, but the structured scope is all-hosts; this needs clarification before actual deployment.
- **detect_only (M18):** no reduction in path feasibility, likelihood, or risk. A network IDS may improve alerting and incident response, but those benefits are **not represented by this model**; it will not be selected by a purely risk-reduction objective.

`apply_mitigations()` deliberately leaves the original *mitigation catalogue* in the analytical copy for audit. It is not an updated deployable inventory: the original LOADER's patch-target validation would reject a post-patch document if reloaded as a fresh baseline. Use the original `network.json` as source of truth, and examine `mitigation_application_audit.json` for the modeled changes.

## 3. Budget, risk and optimization

Budgets are calculated from the JSON total (integer euro amounts, rounded down if necessary):

- 30% = **€74,010**
- 60% = **€148,020**

For each goal `g`, the modeled goal risk is the **maximum** risk over all paths from both attacker scenarios (S1 and S2), exactly as the homework's “maximum over paths” criterion requires:

```
R_goal(g) = max_{scenario, path to g} (product of step success priors × goal criticality)
Objective = R_goal(G1) + R_goal(G2) + R_goal(G3)
```

The objective is a **heuristic sum of per-goal maximum path risks**, not an expected euro loss, real probability of compromise, or sum over all paths. Because the original Task 4 does not define likelihood empirically, all conclusions are conditional on those priors and on the source graph.

- **Greedy:** start empty, repeatedly add the affordable control with the largest immediate *objective risk reduction per euro*, stopping if no action improves the objective. It can miss synergistic improvements when the current maximum-risk path remains.
- **Exact:** search the full binary decision space of **2^18 = 262,144 subsets**, filtering infeasible budgets. To make this fast, determine which individual controls remove each baseline path, then compute maximum path risk for every residual subset using a subset-max dynamic program. The EDR probability factor is handled separately. Choose lowest risk, breaking ties by lower cost and then deterministic mitigation IDs. Rebuild and re-enumerate the graph independently for every reported plan as a cross-check.

The monotone subset optimization relies on an explicit assumption: controls **only remove attack edges or decrease step-success probabilities**. The program checks that none creates a new modeled attack edge. If the model acquires controls that open new permissions or create new services, the fast exact-search method must be revised.

**“Exact” means exact under the *bounded model***: only simple paths with `max_hops=7` and non-truncated enumeration are included. Neither unlimited-length paths nor unknown real-world attack preconditions are solved here.

## 4. Demonstration results on the supplied JSON (default assumptions)

| Plan | Ceiling | Spent | Controls | Sum of max goal risks | Surviving modeled paths |
|---|---:|---:|---|---:|---:|
| Baseline | — | €0 | — | 1.7145 | 6,598 |
| Greedy 30% | €74,010 | €8,000 | M06, M07 | 0 | 0 |
| Exact 30% | €74,010 | €8,000 | M06, M07 | 0 | 0 |
| Greedy 60% | €148,020 | €8,000 | M06, M07 | 0 | 0 |
| Exact 60% | €148,020 | €8,000 | M06, M07 | 0 | 0 |

- M06 patches Struts CVE-2017-5638 on H17 (€5,000).
- M07 patches Zerologon CVE-2020-1472 on H13 (€3,000).
- Baseline per-goal risk: **G1 0.3645**, **G2 1.35**, **G3 0**. For the modeled G1 paths, M06 interrupts the identified way into H17; for modeled G2 paths, M07 interrupts privilege escalation/compromise of H13.
- The independent rebuilt graph has **191** attack edges after M06+M07 (baseline 243) and no enumerated paths to any of the three goals within seven hops.
- The most important **vulnerability across complete goal paths** is CVE-2020-1472, present in **6,158** baseline paths. M07 interrupts those 6,158 baseline paths, but also has the strongest modeled risk impact (reduction 1.35). The most frequently used **individual transition** can differ: `H10:user → H12:user` via MC1 appears in 1,395 paths. High path count alone does not imply high risk reduction, because many paths overlap and there may be alternate routes.
- Under `--strict-db`, G1 has no *supported* baseline path. The exact and greedy selections become **M07 alone (€3,000)** at both budgets. This is an especially important sensitivity: default T9 treats DB credentials as OS-user access, which real MySQL credentials do not generally grant.

**Do not write “100% security” or “all risks eliminated” in the report.** These results show **100% reduction of the narrowly modeled reach-the-goal risk objective**. The same Task 2 STRIDE enumeration still has about **38 candidate threats** after the exact 60% selection. G3 was never reachable in this abstract graph; risk zero is not evidence that the finance data is safe. Also, realistic DB privilege modeling might allow database-level exfiltration without OS root access.

## 5. Outputs generated in `output/mitigations/`

| Output | Governance use |
|---|---|
| `mitigation_summary.json` | Budget outcomes, goals, assumptions and method |
| `mitigation_plan.csv` | Before/after objective, costs, selected controls, paths |
| `mitigation_goal_comparison.csv` | Risk and path count **per scenario and goal**, including MTAO |
| `mitigation_selected_details.csv` | Names, types and costs of selected controls |
| `mitigation_marginals.csv` | Baseline paths interrupted by each single control and marginal risk reduction |
| `critical_transitions.csv` | Individually most widely used attack transition |
| `critical_references.csv` | Critical CVEs/misconfigurations/trusts across paths, counted once per path |
| `residual_stride_threats.csv` | Remaining candidate STRIDE threats after exact 60%; proposed treatments |
| `mitigation_application_audit.json` | Actual modeled changes for each budget strategy |
| `mitigation_risk_comparison.png` | Risk objective chart, before vs after |
| `attack_graph_exact_30pct.graphml`, `attack_graph_exact_60pct.graphml` | Rebuilt attack graphs after optimal control set |
| `attack_graph_custom.graphml` | Created only when you provide `--select` |

## 6. Residual risk and governance recommendations

The very low numerical objective is a warning about **model incompleteness**, not evidence that the network needs only two patches. Residual exposures may include:

1. **Information disclosure and spoofing:** exposed VPN/gateway authentication and stored credentials; treat by reducing (MFA, secrets rotation and session monitoring). The exact STRIDE survivors are in `residual_stride_threats.csv`.
2. **Tampering and repudiation:** plaintext application/partner flows and vulnerable log pipelines; reduce with authenticated encryption, immutability and off-host log protection.
3. **Denial of service:** rate limiting, upstream protection and an operational risk-transfer agreement (DDoS provider/insurance if appropriate).
4. **Local privilege escalation and lateral movement:** patch remaining exploited components, harden administrator credentials, segment management traffic; accept only well-supported exceptions with named risk owners and review dates.
5. **G3 finance database and G1 interpretation gap:** review actual PostgreSQL/MySQL permissions, service accounts and credentials; a database read privilege is not the same thing as Linux `user` or `root`.
6. **IDS M18:** do not call it useless. It contributes to visibility and detection, outside a static attack feasibility/max-risk calculation. Evaluate it with detection/response metrics in a separate decision criterion.

This task requires a **before/after table** and discussion of why *patch the highest CVSS first* may be suboptimal: the relevant quantity is whether a control breaks the high-risk *paths to business goals*, at acceptable cost. CVSS is vulnerability severity, not attack-chain centrality, reachable preconditions, or benefit-per-euro.

## 7. Suggested final-report wording (governance discussion, no source code)

> For mitigation selection, we minimized the sum of the maximum attack-path risks across the three specified business objectives. Two budget ceilings (€74,010 and €148,020) were evaluated with a risk-reduction-per-cost greedy baseline and an exact subset search over the 18 candidate mitigations. The numerical evaluation is conditional on seven-hop simple attack paths, the original privilege-state abstraction, and heuristic per-step success probabilities. Under the default assumptions, both procedures selected M06 and M07 for €8,000, reducing the modeled objective from 1.7145 to zero and interrupting all 6,598 enumerated paths. This does not establish the absence of real cyber risk: the STRIDE inventory retains residual candidates, actual CVE exploit preconditions remain unverified, and finance database access is under-modeled. In a strict database-privilege sensitivity run the initial G1 paths disappear without any mitigation, confirming that the model's T9 privilege assumption materially affects the outcome.

**For the homework submission**, cite the course's `network.json` and HW3 slides, the specific ATT&CK/CAPEC/NVD versions already recorded by Task 3, runtime versions, and declare the use of generative AI tools. Do not paste implementation code into the governance PDF.
