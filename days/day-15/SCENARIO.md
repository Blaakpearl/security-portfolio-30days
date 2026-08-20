# Day 15 — SCENARIO.md
## Week 3 Purple Team · Red-Side Reconnaissance Operation
**NovaCrest Capital Group | Authorized Adversary Simulation**
**Classification:** TLP:AMBER — Authorized Engagement Participants Only

---

## Engagement Background

NovaCrest Capital Group is a mid-size investment management firm headquartered in New York with regional offices in London and Singapore. The firm manages approximately $4.2B in assets across equity, fixed income, and alternative investment strategies. The security team has engaged this purple team exercise to assess their defensive posture against a realistic external threat actor prior to a planned SOC maturity review.

Week 3 opens the **adversary simulation track**. Rather than synthetic lab exercises, the red team now operates as a credible external threat actor — using the same tools, sources, and tradecraft an APT or financially-motivated actor would use in a real pre-exploitation phase. All activities are **authorized, documented, and bounded by the rules of engagement below.**

---

## Threat Actor Profile (Red Team Emulation Target)

The red team emulates a **financially-motivated threat actor** consistent with groups that target investment management firms:

```
Actor Type:       Financially-motivated threat actor / APT affiliate
Motivation:       Credential theft, trading data, wire transfer fraud
Sophistication:   Intermediate-Advanced (not nation-state 0-day; uses public tooling)
Prior Intel:      None — starts from zero knowledge, public sources only
Timeline:         Compressed (single operator, 2.5 hours)
Stealth Level:    High — avoids any active probing of target systems
Resources:        Open-source tools + commercial OSINT APIs (Shodan, Censys)
```

This profile is deliberately achievable — it represents what a motivated attacker with a few hundred dollars in OSINT subscriptions and an afternoon can accomplish. This is a more realistic threat model for most organizations than nation-state implant chains.

---

## Scenario Narrative

> *It is 08:00 UTC on June 15, 2026. A threat actor has selected NovaCrest Capital Group as a target based on publicly available information about the firm's AUM and recent executive announcements. The actor opens a fresh browser session from a VPS, loads their OSINT toolkit, and begins passive reconnaissance. They have no insider information, no prior relationship with NovaCrest, and no zero-day exploits. They have: an internet connection, a Shodan API key, a GitHub account, and time.*
>
> *Over the next 2.5 hours, the actor will systematically map NovaCrest's external infrastructure, identify exploitable exposures, and build a target package sufficient to launch a credential-based or spearphishing attack within 24 hours. They will not touch a single NovaCrest system directly. They will not trigger a single alert.*
>
> *The purple team's job is to find out what the actor found, understand why nothing flagged, and fix it before the next actor shows up.*

---

## Engagement Objectives

### Red Team Objectives
1. Map all externally-resolvable NovaCrest infrastructure using passive sources only
2. Identify exposed services with known vulnerabilities
3. Locate publicly accessible credentials, secrets, or sensitive data
4. Build an employee target list suitable for spearphishing campaign planning
5. Assess technology stack and software versions across web properties
6. Complete all objectives without generating a single confirmed detection

### Blue Team Objectives
1. Collect and preserve all log evidence generated during the recon window (08:00–10:30 UTC)
2. Conduct retrospective analysis: what log evidence exists per recon phase?
3. Identify which phases *could* have been caught with existing controls
4. Identify which phases required new tooling or sources to detect
5. Document the detection gap with root cause analysis
6. Produce a prioritized remediation plan

### Purple Team Objectives
1. Facilitate both red and blue team operations simultaneously
2. Maintain authoritative timeline of red team activities with timestamps
3. Map each red team activity to MITRE ATT&CK Reconnaissance sub-techniques
4. Broker findings between teams; ensure blue team has full red team activity log
5. Produce consolidated report comparing what was done vs. what was caught
6. Prioritize remediation by effort-to-impact ratio

---

## MITRE ATT&CK Coverage

This scenario covers the **Reconnaissance** tactic (TA0043) exclusively:

| Technique | Sub-Technique | Red Team Activity |
|-----------|---------------|-------------------|
| T1592 | Gather Victim Host Info | Shodan/Censys host enumeration |
| T1592.002 | Software | Web server fingerprinting (Apache, nginx, IIS versions) |
| T1592.003 | Firmware | Not applicable |
| T1592.004 | Client Configurations | Shodan API; service banner grabbing |
| T1589 | Gather Victim Identity Info | Email harvesting; LinkedIn scraping |
| T1589.001 | Credentials | GitHub secret scanning; leaked credentials |
| T1589.002 | Email Addresses | Hunter.io; email pattern generation; SMTP validation |
| T1589.003 | Employee Names | LinkedIn employee directory scraping |
| T1590 | Gather Victim Network Info | WHOIS; ASN lookup; netblock enumeration |
| T1590.001 | Domain Properties | WHOIS registrant data; registrar info |
| T1590.002 | DNS | Passive DNS; subdomain enumeration; zone transfer attempts |
| T1590.004 | Network Topology | IP range mapping; internal subnet discovery via DNS |
| T1590.005 | IP Addresses | Shodan/Censys IP resolution; reverse DNS |
| T1591 | Gather Victim Org Info | LinkedIn organizational mapping |
| T1591.002 | Business Relationships | Third-party mail relay detection (SendGrid, SES in SPF) |
| T1591.004 | Identify Roles | LinkedIn title scraping; org chart inference |
| T1596 | Search Open Technical Databases | Shodan; Censys; SecurityTrails |
| T1596.001 | DNS/Passive DNS | Censys passive DNS; SecurityTrails historical records |
| T1596.005 | Scan Databases | Shodan internet-wide scan results |
| T1597 | Search Closed Sources | Not applicable (no dark web in scope) |
| T1598 | Phishing for Information | Not applicable (Day 16) |
| T1593 | Search Open Websites/Domains | crt.sh CT logs; GitHub; LinkedIn |
| T1593.001 | Social Media | LinkedIn employee discovery |
| T1593.003 | Code Repositories | GitHub org scanning; hardcoded secret discovery |

---

## Rules of Engagement

### Authorized
- ✅ Querying public OSINT sources (crt.sh, Shodan, Censys, SecurityTrails, WHOIS, ARIN, GitHub)
- ✅ Passive DNS resolution and historical DNS lookups
- ✅ Certificate Transparency log searches
- ✅ LinkedIn public profile enumeration (non-automated; manual browsing equivalent)
- ✅ HTTP HEAD/GET requests to publicly-facing web servers (fingerprinting only)
- ✅ DNS A/MX/TXT record lookups
- ✅ DNS zone transfer *attempts* (AXFR requests; expected to be refused)
- ✅ SMTP connection and banner reading (no mail delivery, no commands after EHLO)
- ✅ Email pattern inference from publicly available names
- ✅ SMTP RCPT TO validation (≤ 10 attempts; no bulk sending)

### Not Authorized
- ❌ Active vulnerability scanning (Nessus, OpenVAS, Nikto)
- ❌ Directory brute-forcing against web servers (gobuster, dirbuster)
- ❌ Password spraying or credential stuffing
- ❌ Exploitation of any identified vulnerability
- ❌ Social engineering contacts (phone, email, LinkedIn direct message)
- ❌ Dark web searches or underground forum access
- ❌ Any activity that modifies, degrades, or disrupts NovaCrest systems
- ❌ Accessing any NovaCrest system that requires authentication
- ❌ DNS brute-force exceeding 5,000 permutations per domain

### Operational Security Requirements
- All red team activities must be logged with timestamps in the engagement log
- Red team must operate from designated VPS (IP range pre-disclosed to purple team)
- Purple team must be notified before each reconnaissance phase begins
- Blue team must not be given advance notice of red team activity timing
- Findings must be reported within 4 hours of operation completion

---

## Timeline & Phases

| Time (UTC) | Phase | Red Team Lead | Status |
|------------|-------|---------------|--------|
| 08:00 | Kick-off; briefing confirmation | Purple Team | ✅ Complete |
| 08:00–08:15 | Phase 1: Certificate Transparency | Red Team | ✅ Complete |
| 08:15–08:30 | Phase 2: Passive DNS | Red Team | ✅ Complete |
| 08:30–08:45 | Phase 3: WHOIS / ASN | Red Team | ✅ Complete |
| 08:45–09:00 | Phase 4: Shodan / Censys | Red Team | ✅ Complete |
| 09:00–09:15 | Phase 5: Subdomain Enumeration | Red Team | ✅ Complete |
| 09:15–09:30 | Phase 6: GitHub Scanning | Red Team | ✅ Complete |
| 09:30–09:45 | Phase 7: Email Harvesting | Red Team | ✅ Complete |
| 09:45–10:00 | Phase 8: Web Fingerprinting | Red Team | ✅ Complete |
| 10:00–10:10 | Phase 9: DNS Zone Transfer | Red Team | ✅ Complete |
| 10:10–10:30 | Phase 10: SMTP Banner Grabbing | Red Team | ✅ Complete |
| 10:30 | Red team debrief; findings handoff | Purple Team | ✅ Complete |
| 10:30–12:00 | Blue team gap analysis | Blue Team | ✅ Complete |
| 12:00 | Consolidated report published | Purple Team | ✅ Complete |

---

## Deliverables Checklist

| Deliverable | Owner | File | Status |
|-------------|-------|------|--------|
| Scenario document | Purple Team | SCENARIO.md | ✅ This document |
| Lab setup guide | Purple Team | LAB.md | ✅ See LAB.md |
| Red team recon report | Red Team | reports/day15_red_team_recon_report.md | ✅ Complete |
| Blue team gap analysis | Blue Team | reports/day15_blue_team_gap_analysis.md | ✅ Complete |
| Purple team findings | Purple Team | REPORT.md | ✅ See REPORT.md |
| Splunk detection queries | Blue Team | queries/splunk_recon_detection.spl | ✅ Complete |
| Sentinel detection queries | Blue Team | queries/sentinel_recon_detection.kql | ✅ Complete |
| OSINT recon simulator | Red Team | scripts/osint_reconnaissance_simulator.py | ✅ Complete |
| Findings analyzer | Purple Team | scripts/recon_findings_analyzer.py | ✅ Complete |

---

## Success Criteria

The engagement is considered successful if:

1. **Red Team:** All 10 reconnaissance phases executed within 2.5 hours; no confirmed detection during operation window
2. **Blue Team:** Retrospective log analysis identifies ≥ 3 detection opportunities; root cause documented for each missed detection
3. **Purple Team:** Consolidated report maps every red team activity to ATT&CK; remediation roadmap produced; at least one Priority 1 finding remediated before Day 16

---

*Day 15 Scenario | Week 3 Purple Team Adversary Simulation*
*NovaCrest Capital Group Engagement | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
