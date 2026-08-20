# Day 16 — SCENARIO.md
## Week 3 Purple Team · Initial Access Simulation
**NovaCrest Capital Group | Authorized Adversary Simulation**
**Classification:** TLP:AMBER — Authorized Engagement Participants Only

---

## Engagement Background

Day 15 reconnaissance produced a complete target package: 8 exposed credentials,
5 internet-facing vulnerable services, 340+ employee email addresses, and a mapped
organizational hierarchy. Day 16 simulates the **initial access phase** — the moment
the threat actor converts reconnaissance intelligence into a foothold.

Two parallel access paths are simulated, mirroring realistic adversary playbooks
against financial sector targets:

**Path A — Credential Exploitation**
Using AWS credentials and database passwords discovered in GitHub (Day 15), the red
team attempts direct infrastructure access without any phishing or social engineering.
This path requires zero victim interaction and zero exploit code.

**Path B — Spearphishing Simulation**
Using the organizational intelligence from Day 15 (names, titles, email patterns),
the red team crafts a targeted spearphishing email against NovaCrest's CTO. No
email is actually sent; instead, the red team produces the full email artifact and
the blue team assesses what email security controls would have intercepted it.

Both paths are **fully authorized and simulation-only**. No real credentials are
used against live systems. No emails are sent to real employees.

---

## Threat Actor Profile (Continued from Day 15)

```
Actor Type:       Financially-motivated / APT affiliate
Objective:        Establish persistent foothold; stage for lateral movement
Skill Level:      Intermediate (uses public tooling; no zero-days)
Prior Work:       Day 15 recon complete; target package ready
Tools:            AWS CLI, psql client, Python, email crafting tools
Timeline:         Same operator; 3-hour initial access window
```

---

## Scenario Narrative

> *It is 09:00 UTC on June 16, 2026. Twenty-five hours after completing
> reconnaissance, the threat actor opens their notes. The GitHub repository
> `novacrest/trading-api` is still public. The AWS key is still valid —
> no one rotated it. The PostgreSQL instance on 203.0.113.30:5432 is still
> listening. The CTO's email address is `j.smith@novacrest.com`.*
>
> *The actor launches two threads simultaneously. In terminal one: `aws
> configure` — paste in the key from GitHub, hit enter, and start
> enumerating S3 buckets. In terminal two: open a word processor and begin
> drafting an email that references the CTO's recent conference presentation
> (found on LinkedIn during Day 15). The actor has never been closer to the
> trading floor data than this.*
>
> *The blue team is watching. Or are they?*

---

## Objectives

### Red Team
1. **Path A — Credential Exploitation**
   - Simulate AWS credential use (enumerate IAM permissions, S3 buckets, EC2 instances)
   - Simulate PostgreSQL login attempt using exposed GitHub password
   - Simulate MySQL login attempt on 203.0.113.20:3306
   - Document what access each credential grants
   - Identify privilege escalation paths from initial access

2. **Path B — Spearphishing**
   - Craft a realistic spearphishing email targeting CTO John Smith
   - Embed a simulated malicious link (credential harvester)
   - Craft a second variant: malicious attachment (macro-enabled document)
   - Document email header construction and evasion techniques
   - Assess whether the email would pass SPF, DKIM, DMARC checks

### Blue Team
1. Determine whether AWS credential use triggers CloudTrail alerts
2. Determine whether database login attempts trigger authentication alerts
3. Assess email gateway controls against both phishing variants
4. Identify detection gaps and misconfigured controls
5. Propose remediation for each missed detection

### Purple Team
1. Facilitate and timestamp both access paths simultaneously
2. Map all activities to MITRE ATT&CK Initial Access and Execution techniques
3. Produce consolidated report with detection performance
4. Recommend defensive controls prioritized by effort vs. impact

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Sub-Technique | Activity |
|--------|-----------|---------------|----------|
| Initial Access | T1078 | T1078.004 Cloud Accounts | AWS credential use (GitHub-exposed key) |
| Initial Access | T1190 | — | Exploit Public-Facing Application (PostgreSQL) |
| Initial Access | T1566 | T1566.001 Spearphishing Attachment | Macro-enabled document email |
| Initial Access | T1566 | T1566.002 Spearphishing Link | Credential harvester link email |
| Credential Access | T1552 | T1552.001 Credentials in Files | GitHub-exposed passwords |
| Credential Access | T1552 | T1552.005 Cloud Instance Metadata | AWS IAM enumeration |
| Discovery | T1580 | — | Cloud Infrastructure Discovery (S3, EC2) |
| Discovery | T1087 | T1087.004 Cloud Account | IAM user/role enumeration |
| Discovery | T1619 | — | Cloud Storage Object Discovery (S3 listing) |
| Execution | T1059 | T1059.009 Cloud API | AWS CLI commands post-access |
| Defense Evasion | T1535 | — | Unused/unsupported cloud regions |
| Defense Evasion | T1036 | T1036.005 Match Legitimate Name | Phishing email spoofing legitimate sender |

---

## Rules of Engagement

### Authorized
- ✅ Simulating AWS CLI commands against a **lab/test AWS account** (not production)
- ✅ Simulating database connection attempts against **lab environment** (not production)
- ✅ Crafting phishing email artifacts (no actual delivery to real recipients)
- ✅ Analyzing email header construction and SPF/DKIM/DMARC evasion
- ✅ Documenting credential exploitation chains
- ✅ Simulating privilege escalation paths (documentation only)

### Not Authorized
- ❌ Using discovered credentials against live NovaCrest production systems
- ❌ Sending phishing emails to real NovaCrest employees
- ❌ Accessing any real AWS account that belongs to NovaCrest
- ❌ Exploiting vulnerabilities on production database servers
- ❌ Lateral movement beyond the initial access simulation
- ❌ Data exfiltration from any real system

### Simulation Boundary
All scripts in this day produce **simulated telemetry only**. AWS CLI output is
replicated from known response formats. Database connection sequences are logged
without live connections. Phishing emails are crafted artifacts — never sent.

---

## Timeline & Phases

| Time (UTC) | Phase | Path | Owner |
|------------|-------|------|-------|
| 09:00 | Kick-off; Day 15 handoff review | — | Purple Team |
| 09:00–09:30 | Path A: AWS credential enumeration | A | Red Team |
| 09:30–10:00 | Path A: Database login simulation | A | Red Team |
| 10:00–10:30 | Path A: Privilege escalation mapping | A | Red Team |
| 09:00–10:00 | Path B: Spearphishing email craft | B | Red Team |
| 10:00–10:30 | Path B: Email gateway assessment | B | Blue Team |
| 10:30–11:30 | Blue team: CloudTrail + DB log review | Both | Blue Team |
| 11:30–12:00 | Purple team debrief + report | Both | Purple Team |

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Environment setup for both paths |
| `REPORT.md` | Purple team consolidated findings |
| `scripts/credential_exploitation_simulator.py` | AWS + DB credential use simulation |
| `scripts/phishing_email_crafter.py` | Spearphishing artifact generator |
| `queries/splunk_initial_access_detection.spl` | Splunk detection queries |
| `queries/sentinel_initial_access_detection.kql` | Sentinel KQL queries |
| `reports/day16_red_team_initial_access.md` | Red team findings |
| `reports/day16_blue_team_gap_analysis.md` | Blue team detection review |

---

*Day 16 Scenario | Week 3 Purple Team Adversary Simulation*
*NovaCrest Capital Group Engagement | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
