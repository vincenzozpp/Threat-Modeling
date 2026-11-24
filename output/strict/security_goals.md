# Task 1 — Security goals and justification

## Security objectives

| Objective | Protected asset / scope | Why it matters | Validation metric |
|---|---|---|---|
| Confidentiality | Customer PII / payment tokens at H20; payroll / ledger at H21 | Regulatory, financial and customer-trust harm after disclosure | Maximum attack-path risk for G1/G3 and reachable exposure chains |
| Integrity | Domain controller H13 and its administration relationships | Domain-level compromise can enable broad privilege abuse | Maximum attack-path risk for G2 and number of escalation paths |
| Availability | Web shop H01, app backend H17, databases H20/H21, backups H18 | Business continuity and recoverability of retail workflows | Reachability/DoS threat exposure and surviving disruptive paths |
| Accountability | Centralized logs on H19 and monitoring at H27 | Enables incident investigation; log compromise undermines evidence | STRIDE repudiation/tampering coverage and detection controls |
| Least privilege / isolation | DMZ, corp, dev, server, DB, management zones | Limits lateral movement from Internet-facing systems and phished endpoints | Number of cross-boundary edges and feasible goal paths |

## Attacker goals already specified in network.json

- **G1: Exfiltrate customer PII** — target H20 (db-customers); requires modeled privilege `root`; violates confidentiality. Its feasibility will be evaluated in Task 4 rather than assumed.
- **G2: Take over the domain** — target H13 (dc01); requires modeled privilege `root`; violates integrity. Its feasibility will be evaluated in Task 4 rather than assumed.
- **G3: Read payroll and ledger** — target H21 (db-finance); requires modeled privilege `user`; violates confidentiality. Its feasibility will be evaluated in Task 4 rather than assumed.

## Entry scenarios

- **S1: External attacker** — entry internet, initial privilege `none`.
- **S2: Phished insider (HR workstation)** — entry H10, initial privilege `user`.
