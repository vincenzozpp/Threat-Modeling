# Task 2 — STRIDE: how to run and interpret

This extension works with the **unchanged** Task 1 LOADER, `network.json`, and dependencies.

## Run from repository root

```bash
source .venv/bin/activate
python -m script.stride --input network.json --output output
python -m unittest discover -s test -v
```

To repeat under a stricter intra-zone firewall assumption:

```bash
python -m script.stride --input network.json --output output/strict --same-zone-policy deny
```

## Output files

- `output/stride_threat_table.csv` — deterministic threat IDs; DFD element, STRIDE type, property, description, trust boundary, scenario, feasibility/preconditions and input evidence.
- `output/stride_summary.json` — counts by category and feasibility class.
- `output/stride_filtered_observations.csv` — excluded or not-yet-supported paths, retained for auditability.
- `output/stride_support_checks.csv` — status of declared business data flows and trust relations.
- `output/stride_top5_discussion.md` — **draft** manual qualitative discussion of five high-priority candidates. Review and validate before citing in the report.

## Model rules (for report)

1. Input is validated with Task 1 `load_network`; reachability uses exactly the same configurable directional firewall semantics.
2. A remote CVE becomes a candidate only if its declared network service has a positive port and at least one source can reach that port. A vulnerable version or listening port alone does **not** prove exploitable configuration or successful privilege gain.
3. Direct exposure from `S1` (Internet) or `S2` (initial user control of H10) is distinguished from a **conditional lateral foothold**.
4. Local CVEs with port 0 **never** create remote exploit paths. A hypothetical local escalation is included only where a user foothold might conceivably be established, and is explicitly labelled as requiring an actual local session/code execution.
5. HTTP/FTP data flows are considered only when flow checks confirm service/port reachability. Interception also requires an adversary with on-path visibility/control; neither input scenario grants that by default.
6. Declared trust relations are treated as conditional authorizations, not unfiltered movement paths. A compatible, reachable destination service must exist. SSH keys/deploy keys are matched to SSH, runner tokens to HTTPS, database-config credentials to MySQL, and domain credentials to SMB in this first model; these are **modeling choices** and require application-owner validation.
7. Generic availability and audit-log integrity threats are conditional and do not claim a documented DoS CVE or existing failure of audit controls.
8. CVE effect classifications are **initial curated hypotheses**, not verified NVD/CWE mappings. Confirm impact/CWE prerequisites in Task 3 and attack-chain feasibility in Task 4. No risk scores are generated in Task 2.
9. Preserve source-data discrepancies: backup flows F5–F7 have no declared destination SSH services, and the script does not fill the gaps silently.
10. All STRIDE categories appear, but the purpose is *evidence-based* elicitation, not mechanically assigning every category to every process.

## Report quality checklist

- Use the `stride_threat_table.csv` columns requested by the professor.
- Justify which five threats you deem most important (the generated top-five draft is a starting point, **not** a result of quantitative risk scoring).
- Cite the original `network.json` and authoritative NVD/vendor/CVE sources for the CVE effects; attach the CVE/CWE mapping in Task 3.
- Explicitly discuss feasibility preconditions and distinguish reachability from exploitability.
- Explain how the alternative intra-zone firewall policy affects the candidate inventory.
- Include the required disclosure of generative-AI assistance in the final PDF.
