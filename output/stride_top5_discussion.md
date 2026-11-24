# Task 2 — Five high-priority threat hypotheses (manual analysis)

Priority is qualitative, driven by initial attack exposure, asset criticality and observed firewall permissions, **not** a computed path-risk ranking. None of the listed CVEs is assumed exploited.

| Threat | Candidate and why it deserves attention | What is established / what remains conditional |
|---|---|---|
| ST-003 (CVE-2019-11510) | The Internet-facing VPN has credentials as a stored asset. Possible compromise may have wide consequences for remote access. | direct-entry-reachable; exploit-conditional; Attacker reaches the service; affected configuration, CVE preconditions and exploit outcome require validation |
| ST-002 (CVE-2021-26855) | The public mail gateway can communicate with the AD controller using LDAP/SMB; this makes follow-on access worth analyzing. | direct-entry-reachable; exploit-conditional; Attacker reaches the service; affected configuration, CVE preconditions and exploit outcome require validation |
| ST-001 (CVE-2021-41773) | The public shopping front end has an Apache path-traversal CVE and an explicit direct firewall exception into the customer database. | direct-entry-reachable; exploit-conditional; Attacker reaches the service; affected configuration, CVE preconditions and exploit outcome require validation |
| ST-010 (CVE-2020-1472) | The phished HR workstation is allowed to reach the domain controller on SMB/Netlogon; the domain controller has criticality 5. | direct-entry-reachable; exploit-conditional; Attacker reaches the service; affected configuration, CVE preconditions and exploit outcome require validation |
| ST-024 (MC2) | The SSH jump host is reachable from the phished HR workstation, with password login and no lockout; it holds SSH keys. | direct-entry-reachable; authentication-conditional; A guessable valid password and enough attempts are required |

**Threat-model caveats.** Allowed ports and declared CVEs support plausible attack surfaces, not successful exploitation. For Zerologon, confirm the actual Netlogon RPC endpoint configuration; for Apache path traversal, confirm vulnerable configuration and any CGI prerequisites. The printer and VPN/jump-host credentials require separate authentication validation. The flow and trust-check exports enumerate unsubstantiated paths so they are not silently used later.

**STRIDE rules:** known authentication bypass/default-password/credential misuse → Spoofing; confidentiality exposure or clear-text traffic with on-path condition → Information Disclosure; manipulation of clear-text traffic → Tampering; log deletion after server compromise → Repudiation; service overload → Denial of Service; known remote/local code execution and privilege escalation → Elevation of Privilege. Labels are initial analyst hypotheses; no automated CVE-to-CWE assertion is made.
