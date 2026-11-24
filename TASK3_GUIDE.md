# HW3 Task 3 — CVE → CWE → CAPEC → ATT&CK → tactic, and STRIDE tags

This add-on goes **inside the existing** `HW3-Threat-Modeling/` folder. It does not change `network.json`, `loader.py`, or `stride.py`.

## Prerequisites

Use the existing Python virtual environment and libraries. The existing `requirements.txt` already includes Matplotlib.

```bash
cd ~/projects/HW3-Threat-Modeling
source .venv/bin/activate
```

## 1. First run: acquire real catalogue data and generate mappings

```bash
python -m script.mapper --input network.json --output output
```

**Internet access is required on this first run.** The script downloads:

- MITRE **CAPEC 3.9**, source `https://capec.mitre.org/data/xml/capec_v3.9.xml`;
- MITRE **Enterprise ATT&CK 20.1** STIX 2.1 bundle, source `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json`;
- 22 original records through the **NVD CVE API 2.0**, `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`.

The NVD API imposes rate limits. Without a key, the script pauses between fresh requests; it prints progress, and previously downloaded records are reused on every later run. The first run may take several minutes because it retrieves 22 CVE records separately. If HTTP 403 or 429 occurs, check network access, retry later or request an NVD API key: `https://nvd.nist.gov/developers/request-an-api-key`.

**Do not interpret the printed mappings as verified exploitation.** CAPEC associations are generic vulnerability-class correspondences, and the final exploit feasibility is assessed in Task 4.

## 2. Offline reruns

After the downloads succeed, you can reproduce from the cached data without making HTTP requests:

```bash
python -m script.mapper --input network.json --output output --offline
```

Download directory (created automatically): `data/threat_libraries/`. All fetched files retain their original JSON/XML data and their SHA256 fingerprints are in `output/mapping_source_manifest.json`.

When you first share the GitHub repository, **preserve the source manifest** and, to guarantee exact NVD snapshot reproducibility, version or archive the downloaded input files, subject to repository size and dataset distribution terms. Simply running the API again later can return revised CWEs.

### Optional: NVD API key

```bash
python -m script.mapper --nvd-api-key YOUR_NVD_API_KEY
```

For safety, avoid including API keys in your Git commits, screenshots or the report. This argument may be visible in your shell history; a protected shell environment or secret store is preferable when possible.

## 3. Tests

```bash
python -m unittest discover -s test -v
```

Expected: **33 tests**, including **9 new Task 3 tests**. The Task 3 tests use tiny, *synthetic* local catalogues (not official NVD data), so they run quickly even without Internet. They test parsing, direct/parent links, handling missing mappings, revoked ATT&CK techniques, 22 unique CVEs versus 24 host occurrences, and generation of a heatmap and source manifest.

## 4. Generated `output/` files

| File | Purpose |
|---|---|
| `cve_attack_mapping.csv` | Full mapping rows, including explicit partial/unmapped rows, host and source URLs |
| `cve_unmapped.csv` | **Only CVEs without any complete chain**, with explanations |
| `misconfiguration_mapping.csv` | MC1 and MC2 separately, using manually proposed CAPEC-70 / CAPEC-49 |
| `attack_tactic_heatmap.png` | Counts of **distinct active techniques per tactic**, including zero-count tactics |
| `mapping_summary.json` | CVE coverage (per 22 distinct CVEs), occurrence count (24), tactic counts |
| `mapping_source_manifest.json` | URLs, version labels, SHA256 of each input catalogue and NVD snapshot |

`cve_attack_mapping.csv` can contain multiple rows for a single CVE: one CVE can have multiple CWEs, CAPEC patterns, ATT&CK techniques and tactics. Coverage is **the number of distinct CVEs with at least one complete mapped chain divided by 22**, not the number of table rows divided by 24.

## 5. Mapping semantics for the report

1. Use the **NVD weaknesses** field for CVE → CWE; ignore NVD-CWE-noinfo / NVD-CWE-Other as non-numeric.
2. Use each CAPEC pattern's **Related_Weaknesses** for CWE → CAPEC. Do not infer a pattern from mere similarity of names.
3. Use CAPEC's own ATTACK **Taxonomy_Mapping → Entry_ID** for CAPEC → ATT&CK. If CAPEC does not have a direct mapping, follow *nearest* CAPEC `ChildOf` parent as permitted by the CAPEC taxonomy; record the parent ID and hop count. CAPEC inheritance is **not** an ATT&CK taxonomy inheritance rule. Use `--no-inheritance` for a stricter sensitivity analysis.
4. Join ATT&CK IDs to *active, non-deprecated* techniques in Enterprise ATT&CK v20.1, reading tactics from STIX `kill_chain_phases`. Drop no CVE if its technique is retired: generate an explicit unmapped row.
5. Add a **primary STRIDE label** by ATT&CK tactic. This is a documented **classification heuristic**, NOT an official MITRE mapping. Examples: `credential-access` → Information Disclosure, `defense-evasion` → Repudiation, `execution` → Elevation of Privilege, `impact` → Tampering. A tactic could correspond to more than one STRIDE category in reality.
6. Treat non-CVE misconfigurations separately: default printer password (`MC1`) → CAPEC-70, and jump host SSH passwords with no lockout (`MC2`) → CAPEC-49. These are manual analytical analogies, with the actual ATT&CK references included *only* if they exist in CAPEC XML and the pinned STIX bundle. They are excluded from the CVE coverage denominator.

**Limitations to state clearly:** (a) a generic weakness association can over-generate plausible CAPEC/ATT&CK patterns; (b) a CAPEC→ATT&CK mapping does not establish that a specific CVE follows that attacker technique; (c) STRIDE labels are heuristic; (d) NVD metadata can evolve; (e) the evidence from Task 1 (service/zone reachability) and Task 4 (preconditions) must validate feasibility independently.

## 6. Troubleshooting

- `Task 3 FAILED: Could not download ...`: check WSL Internet/DNS, use VPN/proxy where appropriate, then retry. Cached files are retained.
- `Task 3 FAILED: Missing offline catalogue`: you used `--offline` before the first successful download.
- `Task 3 FAILED: ... CAPEC XML`: a wrong or corrupt XML file was copied; remove that one file and rerun.
- Want to compare without CAPEC inheritance? `python -m script.mapper --input network.json --output output/no_inheritance --offline --no-inheritance`.

## Sources for the bibliography

- NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
- MITRE CAPEC latest downloads (CAPEC v3.9): https://capec.mitre.org/data/downloads
- MITRE ATT&CK release archive: https://github.com/mitre-attack/attack-stix-data/blob/master/index.md
- MITRE ATT&CK version history: https://attack.mitre.org/resources/versions/

Document any generative AI usage as required by the professor.
