# Task 1 — Modeling assumptions and data-quality observations

## Assumptions

1. `internet` is represented by one abstract endpoint `INTERNET`; remote external endpoints are not enumerated.
2. Explicit firewall **deny** rules override explicit allows; unmatched inter-zone traffic is **denied by default**. The input gives no firewall priority ordering or default policy; these are modeling decisions, not proven facts.
3. Unspecified intra-zone traffic follows the **deny** policy (`--same-zone-policy deny`). This is not stated in the JSON. Repeat the analysis with the opposite policy for sensitivity.
4. A firewall rule permits an edge only if the destination has a declared **remote service** on that port. Port `0` denotes a local-only component (kernel, sudo, polkit) and creates no remote listener.
5. Source/destination reachability is directional. Reverse connections and TCP response packets are not independent attack edges.
6. `data_flows` describe intended functional communication, **not proof of reachability**. `trust_relations` describe credential-based privilege dependencies, **not firewall bypasses**.
7. `ext-customer`, `ext-partner`, and `ext-employee` are separate external entities in the DFD, mapped to the abstract Internet endpoint for reachability.
8. Host-level reachability means **at least one** declared listening service is allowed; it does NOT imply a vulnerability is exploitable or a goal is reachable.
9. Level-0 is an intentionally manual **conceptual selection** of important business flows. Level-1 is automatically built from all hosts, data stores and declared data flows. Assets are visually grouped by host for legibility.
10. No missing host services or firewall rules are silently inserted into `network.json`. Observed gaps remain flagged until justified.

## Observed mismatches (nonfatal warnings)

- **F5** (H18 -> H20, SSH): `MISSING_DECLARED_SERVICE`. Validate the corresponding listener/flow against the system owner.
- **F6** (H18 -> H21, SSH): `MISSING_DECLARED_SERVICE`. Validate the corresponding listener/flow against the system owner.
- **F7** (H18 -> H22, SSH): `MISSING_DECLARED_SERVICE`. Validate the corresponding listener/flow against the system owner.

## Source discrepancy

The slide summary describes the database zone as fully patched/a distractor, but the authoritative machine-readable input assigns CVEs to H20 and H21 (H22 alone has no listed CVEs). For analysis we use the host-level JSON.

## Security note

Level-1 diagrams show declared functional flows even when a service is missing in the host inventory; dashed red arrows denote such a mismatch, not a confirmed exploitable path.
