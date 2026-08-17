# Defensive Coverage Assessment Report
## Day 13 — MITRE ATT&CK Mapping: NovaCrest Capital Group vs APT29 Reference Profile

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-19 |
| **Report Type** | Defensive Coverage Benchmarking Assessment |
| **Classification** | Portfolio / Training Exercise |
| **Case ID** | NVC-IR-2025-004 (supporting assessment) |
| **Track** | Threat Intelligence |
| **Reference Profile** | APT29 / Cozy Bear (MITRE ATT&CK Group G0016) |
| **Distribution** | CISO, Detection Engineering, Board Risk Committee |

---

## ⚠️ Important Scope Clarification

**This report does not attribute the NovaCrest Capital Group incident to
APT29 or any specific named threat actor.** Day 11's attribution assessment
concluded — with high confidence — that current evidence does not support
attribution to any specific named group. APT29 is used exclusively as a
**defensive benchmarking reference** because its technique profile is one
of the most comprehensively documented in the public MITRE ATT&CK Groups
database, providing a rigorous standard against which to test detection
coverage completeness, independent of who actually conducted this specific
intrusion.

---

## Executive Summary

A structured defensive coverage assessment was conducted comparing NovaCrest
Capital Group's current detection engineering posture against the publicly
documented technique profile of APT29, a well-characterized threat actor
used here solely as a comprehensive benchmarking standard. Of 38 reference
techniques spanning all major ATT&CK tactics, NovaCrest currently has
**9 techniques fully covered (24%)**, 3 techniques with partial coverage
(8%), and **26 techniques representing complete detection gaps (68%)**.

This coverage percentage, while appearing low in isolation, reflects a
common and expected pattern for organizations early in their detection
engineering maturity journey: the 9 covered techniques were all developed
reactively during the direct incident investigation (Days 02, 04, and 06),
meaning current coverage is a byproduct of this specific incident rather
than the result of proactive, comprehensive detection engineering planning.

The gap analysis reveals the most significant weaknesses cluster in the
**Discovery** and **Lateral Movement** tactics — phases where, notably,
the Day 10 lateral movement hunt found no confirmed attacker activity, but
where the *absence of confirmed activity was determined through manual
hunting rather than automated detection*, precisely because no rules exist
for these techniques. This is a critical distinction: NovaCrest currently
relies on hunting to find what detection rules should be catching
automatically.

A risk-prioritized, 90-day phased roadmap has been developed, targeting
full remediation of the highest-priority 6 gaps within 30 days, an
additional 8 gaps within 60 days, and comprehensive coverage or explicit
risk acceptance for all remaining gaps by day 90.

---

## Methodology

```
Phase 1 — Reference Profile Construction (45 min)
  Source:  MITRE ATT&CK Groups database (G0016, public data)
  Output:  38-technique profile spanning 12 tactics

Phase 2 — Current Coverage Cataloging (30 min)
  Source:  Confirmed Sigma/KQL rules from Days 02, 04, 06 (9 rules)
  Output:  Complete current-state detection inventory

Phase 3 — Gap Analysis (60 min)
  Method:  Direct technique-ID cross-reference + related-technique
           partial-match assessment
  Output:  Covered / Partial / Gap classification for all 38 techniques

Phase 4 — Navigator Heat Map Generation (30 min)
  Output:  3-tier color-coded ATT&CK Navigator layer (green/amber/red)

Phase 5 — Risk-Based Prioritization (45 min)
  Framework: Exploitability × Business Impact, weighted against
             Implementation Effort
  Output:  Ranked gap list with priority scoring

Phase 6 — Roadmap Development (30 min)
  Output:  90-day phased detection engineering plan with milestones
```

---

## Coverage Analysis Results

```
TOTAL TECHNIQUES ASSESSED:  38

  ✅ COVERED:   9  (24%)
  🟡 PARTIAL:   3  (8%)
  ❌ GAP:      26  (68%)
```

### Covered Techniques (9)

| ID | Name | Tactic | Source Rule |
|----|------|--------|-------------|
| T1110.004 | Credential Stuffing | Credential Access | sigma_credential_stuffing.yml |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | kql_impossible_travel.kql |
| T1566.001 | Spearphishing Attachment | Initial Access | sigma_phishing_campaign.yml |
| T1583.001 | Acquire Infrastructure: Domains | Resource Dev | sigma_phishing_campaign.yml |
| T1071.004 | DNS C2 | Command & Control | sigma_c2_beacon_dns.yml |
| T1048.001 | Exfiltration Over DNS | Exfiltration | sigma_dns_tunneling.yml |
| T1053.005 | Scheduled Task | Persistence | sigma_scheduled_task_persistence.yml |
| T1547.001 | Registry Run Keys | Persistence | sigma_registry_run_key_persistence.yml |
| T1546.003 | WMI Event Subscription | Persistence | sigma_wmi_subscription_persistence.yml |

### Partial Coverage (3)

| ID | Name | Note |
|----|------|------|
| T1078 | Valid Accounts (general) | Rule targets Cloud sub-technique specifically; base technique partially covered |
| T1566.002 | Spearphishing Link | Existing rule catches some link-based indicators incidentally |
| T1055 | Process Injection | Day 08/12 forensic methodology (malfind) exists as capability, not yet an automated deployed rule |

### Coverage Gaps by Tactic — Where the Weaknesses Concentrate

| Tactic | Gap Count | Assessment |
|--------|:---------:|-----------|
| **Discovery** | 3 | No automated detection for system/domain/network reconnaissance |
| **Lateral Movement** | 3 | Day 10 relied entirely on manual hunting — zero automated rules |
| **Defense Evasion** | 4 | File deletion, token theft, name masquerading all undetected |
| **Credential Access** | 3 | Beyond LSASS (partial), password spray and cookie theft uncovered |
| **Persistence** | 2 | Account manipulation, account creation not covered |
| **Command & Control** | 3 | Web protocol C2, external proxy patterns uncovered |
| **Reconnaissance** | 2 | No detection for pre-intrusion scanning/identity gathering (expected — largely external to org visibility) |
| **Resource Development** | 2 | Limited visibility into attacker-side infrastructure prep (expected — external) |
| **Collection** | 2 | Email collection, archive utility usage uncovered |
| **Exfiltration** | 1 | Generic C2-channel exfiltration (beyond DNS-specific) uncovered |
| **Execution** | 1 | Windows Command Shell (cmd.exe) execution uncovered |

**Key observation:** Discovery and Lateral Movement together account for 6
of 26 gaps and represent the tactics where Day 10's investigation had to
rely entirely on manual, time-intensive hunting rather than automated
alerting. This is the most operationally urgent finding in this assessment.

---

## Risk-Prioritized Gap Remediation Plan

### Phase 1 — Days 1-30 (Highest Priority: High Exploitability + High Impact + Low Effort)

| Rank | Technique | Name | Priority Score |
|------|-----------|------|:---------------:|
| 1 | T1550.002 | Pass the Hash | 19 |
| 2 | T1539 | Steal Web Session Cookie | 18 |
| 3 | T1003.001 | LSASS Memory (automate existing capability) | 17 |
| 4 | T1098 | Account Manipulation | 16 |
| 5 | T1110.003 | Password Spraying | 16 |
| 6 | T1059.003 | Windows Command Shell | 14 |

**Rationale:** These six techniques combine high exploitability, high
business impact, and relatively low implementation effort — the classic
"quick win" quadrant. Notably, T1550.002 (Pass the Hash) and T1003.001
(LSASS Memory) directly relate to methodology already developed during
Days 10 and 12 of this very incident — converting manual hunt queries and
forensic techniques into automated, always-on detection rules represents
low marginal effort given the existing institutional knowledge.

### Phase 2 — Days 31-60 (Foundational Detection Engineering)

Focus shifts to techniques requiring new data source onboarding or more
significant engineering investment: T1021.001/T1021.006 (Remote Desktop/
WinRM), T1552.001 (Credentials in Files), T1550.001 (Application Access
Token), T1136 (Create Account), T1070.004 (File Deletion), T1041
(Generic C2 Exfiltration), T1069.002 (Domain Groups Discovery), T1018
(Remote System Discovery).

### Phase 3 — Days 61-90 (Comprehensive Coverage + Maturity)

Remaining lower-priority gaps, several of which (Reconnaissance and Resource
Development tactics) are inherently limited in organizational detection
capability since they largely occur outside the organization's visibility
boundary before any network contact occurs — these may ultimately be
addressed through threat intelligence subscription services rather than
internal detection engineering, and should be explicitly risk-accepted with
documented compensating controls (e.g., dark web monitoring per Day 09)
rather than pursued as internal SIEM rules.

---

## Success Metrics & Targets

| Metric | Day 13 Baseline | Day 30 Target | Day 60 Target | Day 90 Target |
|--------|:---------------:|:--------------:|:--------------:|:--------------:|
| Techniques covered | 9/38 (24%) | 15/38 (39%) | 23/38 (61%) | 35/38 (92%)* |
| Detection rules deployed | 8 | 14 | 22 | 33 |

*Full 100% is not targeted; 3 Reconnaissance/Resource-Development techniques
are explicitly planned for risk acceptance with compensating controls
(external threat intel monitoring) rather than internal detection rules,
since these tactics occur largely outside organizational network visibility.

---

## MITRE ATT&CK Technique Matrix — Gap Summary

| Tactic | Total in Profile | Covered | Partial | Gap |
|--------|:-----------------:|:-------:|:-------:|:---:|
| Reconnaissance | 2 | 0 | 0 | 2 |
| Resource Development | 3 | 1 | 0 | 2 |
| Initial Access | 4 | 2 | 1 | 1 |
| Execution | 2 | 0 | 0 | 2* |
| Persistence | 5 | 3 | 0 | 2 |
| Defense Evasion | 5 | 0 | 1 | 4 |
| Credential Access | 4 | 0 | 1 | 3 |
| Discovery | 3 | 0 | 0 | 3 |
| Lateral Movement | 3 | 0 | 0 | 3 |
| Collection | 2 | 0 | 0 | 2 |
| Command & Control | 4 | 1 | 0 | 3 |
| Exfiltration | 2 | 1 | 0 | 1 |

*Note: T1059.001 (PowerShell) benefits indirectly from other rules referencing PowerShell command patterns but has no dedicated standalone rule — counted here as a Phase 1 gap given its centrality to this incident.

---

## Recommendations

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0** | Present coverage findings to CISO and board risk committee | Threat Intel | 1 week |
| **P1** | Begin Phase 1 rule development (6 techniques) | Detection Eng | 30 days |
| **P1** | Automate Day 10/12 manual hunt methodology into standing rules | Detection Eng | 30 days |
| **P2** | Onboard additional data sources required for Phase 2 (RDP/WinRM logging) | IT / Detection Eng | 60 days |
| **P2** | Complete Phase 2 rule development | Detection Eng | 60 days |
| **P3** | Complete Phase 3 or formally risk-accept remaining gaps | Detection Eng / CISO | 90 days |
| **P3** | Re-run this full gap analysis at Day 90 to measure actual progress | Threat Intel | 90 days |
| **Ongoing** | Adopt this methodology as a recurring quarterly benchmarking exercise | Security Leadership | Recurring |

---

## Analyst Notes — On Using Reference Profiles Responsibly

This exercise demonstrates a discipline that is easy to get wrong: using a
well-documented threat actor's technique profile as a coverage benchmark
while explicitly avoiding the trap of implying attribution. It would have
been tempting, given the dramatic narrative built across Days 01–12, to
frame this report as "are we ready for APT29 specifically to attack us
again" — but that framing would misrepresent Day 11's honest conclusion
and potentially mislead the board about the actual, unresolved question of
who conducted this intrusion.

The correct framing, used throughout this report, is: APT29's profile is
comprehensive and well-vetted, making it a useful **yardstick**, not a
**suspect**. The coverage gaps identified here are valuable regardless of
who the actual NovaCrest attacker turns out to be, because sophisticated
threat actors across many different groups and motivations share substantial
technique overlap. A gap in Pass-the-Hash detection is a gap regardless of
whether the next attacker is a criminal syndicate, an access broker, or a
nation-state — closing it improves the organization's posture universally.

The most actionable finding in this report is the Discovery/Lateral
Movement gap cluster. Day 10's investigation succeeded only because an
analyst manually ran the right hunt queries at the right time. Converting
that manual capability into always-on automated detection is not a
theoretical improvement — it is the direct, evidence-based lesson this
specific incident already taught the organization.

---

## References

- [MITRE ATT&CK Groups — G0016 (APT29)](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [MITRE D3FEND — Defensive Technique Reference](https://d3fend.mitre.org/)
- [SANS — Detection Engineering Maturity Model](https://www.sans.org/white-papers/detection-engineering-maturity-model/)
- [Center for Threat-Informed Defense](https://ctid.mitre-engenuity.org/)

---

*Previous: [Day 12 ←](../day-12/REPORT.md) | Next: [Day 14 →](../day-14/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
