# Day 22 — REPORT.md
## Risk Scoring Framework: Post-Incident Risk Assessment
**NovaCrest Capital Group | Threat Intelligence Track**
**Author:** V. Willis, CISSP
**Date:** 2026-06-22

---

## Summary

Ten confirmed findings from the Week 3 engagement were scored across
CVSS 3.1, DREAD, and a custom ATT&CK risk tier model. Three findings
scored P1 — Critical. All seven remaining findings scored P2 — High.
No findings are Low risk.

| Metric | Value |
|--------|-------|
| Total findings scored | 10 |
| P1 — Critical | 3 |
| P2 — High | 7 |
| Mean CVSS 3.1 score | **8.77** |
| Mean DREAD score | **8.27/10** |
| Highest unified risk | **RF-001 (0.97/1.0)** |
| Regulatory notifications | **3 required (1 overdue)** |
| Remediations complete | 4 |
| In progress | 5 |

---

## Key Outputs

- **Full risk register:** `reports/day22_risk_register.md` — all ten findings with
  scores, regulatory mapping, CVSS vectors, DREAD breakdown, and prioritized actions
- **Executive brief:** `reports/day22_executive_brief.md` — board/CISO-ready
  one-page summary with regulatory notification table
- **Machine-readable JSON:** `artifacts/risk_scores.json` — structured for
  GRC tool ingestion, Splunk lookup tables, or Sentinel enrichment tables

---

## CVSS 3.1 Highlights

The three critical-severity findings (CVSS ≥ 9.0) are:
- **RF-001** (10.0): GitHub credential exposure — network-reachable, no auth, full CIA
- **RF-007** (9.6): Confirmed exfil — authenticated, scope change (cloud), full C/I
- **RF-005** (9.3): SIEM gap — the "meta-vulnerability" enabling all other undetected activity

CVSS 3.1 captures the technical severity well for RF-001 and RF-002/003 but
underweights operational impact for RF-005 (a configuration gap, not a software
vulnerability). DREAD compensates — RF-005 DREAD score (9.2) appropriately
reflects the damage potential of operating undetected.

---

## DREAD Highlights

DREAD scores above 9.0 indicate techniques that are trivially reproducible
and exploitable by any attacker. Three findings hit this threshold:
- RF-001 (9.8): GitHub credentials — TruffleHog finds them automatically
- RF-005 (9.2): SIEM gap — permanently exploitable until fixed
- RF-007 (9.2): Data loss — post-facto; damage is done

The DREAD model is particularly useful for **prioritizing detection engineering**
work: high-DREAD, high-prevalence techniques (Kerberoasting, SUID abuse) should
receive detection rules regardless of current remediation status, because they
will appear again in future intrusions.

---

## ATT&CK Risk Tier Highlights

The custom tier model surfaces two findings that CVSS underweights because
they are not software vulnerabilities in the traditional sense:

- **RF-005** (Tier 1): The SIEM gap has no CVE, no patch — it's a configuration
  decision with enormous business impact (it enabled the entire undetected breach)
- **RF-001** (Tier 1): Credential exposure has detectability gap of 5 (external
  recon undetectable) combined with maximum business impact

The ATT&CK tier model is most valuable as a **detection investment guide**:
high-tier techniques with high prevalence (Kerberoasting T1558.003, log clearing
T1070.001) should have dedicated Sigma rules regardless of whether they were
exploited in a specific incident.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-22/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day22/* days/day-22/

git add days/day-22/

git commit -m "feat: Add Day 22 — Risk Scoring Framework (CVSS, DREAD, ATT&CK)

Track: Threat Intelligence | Tools: CVSS 3.1, DREAD, ATT&CK Navigator

Scored 10 confirmed findings from Week 3 NovaCrest engagement:
  RF-001 GitHub Credentials   CVSS 10.0 / DREAD 9.8 → P1 CRITICAL
  RF-007 Data Exfil (253 MB)  CVSS 9.6  / DREAD 9.2 → P1 CRITICAL
  RF-005 SIEM Coverage Gap    CVSS 9.3  / DREAD 9.2 → P1 CRITICAL
  RF-002 NOPASSWD sudo        CVSS 8.8  / DREAD 8.2 → P2 HIGH
  RF-003 SUID GTFOBins        CVSS 8.8  / DREAD 8.4 → P2 HIGH
  RF-004 Kerberoastable accts CVSS 8.5  / DREAD 7.6 → P2 HIGH
  RF-009 DLP S3 gap           CVSS 8.5  / DREAD 7.8 → P2 HIGH
  RF-008 Log cleared (649)    CVSS 8.2  / DREAD 8.2 → P2 HIGH
  RF-010 Domain fronting C2   CVSS 8.0  / DREAD 6.6 → P2 HIGH
  RF-006 TLS inspection off   CVSS 7.5  / DREAD 8.2 → P2 HIGH

Mean CVSS: 8.77 | Mean DREAD: 8.27 | 3 regulatory notifications required

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/risk_scorer.py           (CVSS+DREAD+ATT&CK tier calculator)
  scripts/risk_register_builder.py (markdown + executive brief generator)
  queries/risk_prioritization.spl  (Splunk risk dashboard + enrichment)
  queries/risk_prioritization.kql  (Sentinel risk register + tracker)
  reports/day22_risk_register.md   (full 10-finding risk register)
  reports/day22_executive_brief.md (board/CISO risk brief)
  artifacts/risk_scores.json       (GRC-ingestible risk register)"

git push origin main
```

---

*Day 22 — Risk Scoring Framework | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
