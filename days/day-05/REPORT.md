# Social Engineering Surface Assessment Report
## Day 05 — Human Attack Surface Mapping

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Report Type** | Defensive OSINT — Human Attack Surface Assessment |
| **Authorization** | Signed ROE — NovaCrest Capital Group CISO engagement |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | OSINT |
| **ATT&CK Phase** | Reconnaissance (TA0043) |
| **Scope** | Passive public-source collection only — no contact with individuals |

---

## Executive Summary

A passive open-source intelligence assessment of NovaCrest Capital Group's
human attack surface was conducted over a 3-hour window using publicly
available tools and data sources. The assessment identified **five significant
findings** that collectively give a motivated threat actor everything needed
to launch highly credible, personalized spearphishing campaigns against the
organization's most sensitive personnel.

The most operationally significant discovery is that the organization's
complete executive leadership team — including names, roles, photographs,
career histories, and current business priorities — is freely enumerable
from LinkedIn, the company website, SEC filings, and press releases. Job
postings published on public platforms reveal the organization's internal
security tooling, cloud infrastructure, and business application stack in
sufficient detail to craft tool-specific phishing pretexts.

Two example spearphishing pretexts were constructed from collected intelligence
alone, targeting the Head of M&A and HR Manager respectively. Both reference
real names, real tools, real current projects, and real business deadlines —
all sourced from publicly indexed information in under 90 minutes of research.
Neither required any access to internal systems.

This report connects directly to the ongoing incident response initiated in
Days 03 and 04. The phishing email that compromised DESKTOP-FIN-047 was not
generic — it was a targeted HR benefits lure delivered during open enrollment
season. **That level of targeting precision comes from exactly the OSINT
methodology documented here.** The attacker knew what to say because the
organization told them, publicly, without realizing it.

**Five remediation actions are recommended, two of which require same-day
implementation to reduce active risk.**

---

## Methodology

```
Phase 1 — Organizational Structure Mapping (45 min)
  Sources:  Company website, LinkedIn, SEC filings, press releases
  Tools:    Photon crawler, Google dork runner
  Output:   Org chart, leadership team, vendor relationships

Phase 2 — Email Format & Identity Validation (30 min)
  Sources:  HaveIBeenPwned API, MX records, public email appearances
  Tools:    email_validator.py, dig
  Output:   Confirmed email format, validated addresses

Phase 3 — Cross-Platform Username Enumeration (30 min)
  Sources:  300+ platforms via Sherlock
  Tools:    Sherlock, parse_sherlock.py
  Output:   Platform presence map, intelligence-rich profiles

Phase 4 — Automated Entity Relationship Mapping (30 min)
  Sources:  DNS, WHOIS, LinkedIn, GitHub, Hunter.io
  Tools:    SpiderFoot
  Output:   Entity graph — people, domains, IPs, relationships

Phase 5 — HVT Profiling & Risk Register (45 min)
  Analysis: Scoring by access level, breach history, social exposure
  Output:   Ranked target list, 2 pretext examples, risk register
```

---

## Technical Findings

---

### FINDING-01 — Executive Team Fully Enumerable from Public Sources

**Severity:** 🔴 Critical
**ATT&CK:** T1591.004 — Gather Victim Org Information: Identify Roles

**Description:**
The complete NovaCrest Capital Group executive leadership team is enumerable
via publicly indexed sources without any interaction with the organization.
The company website names and photographs all C-suite officers. LinkedIn
profiles provide full career histories, current project involvement, and
professional networks. SEC annual filings name executive officers and
disclose compensation structures. Press releases announce appointments,
promotions, and strategic initiatives.

The intelligence value of this exposure is not the names themselves — it is
the **pretext construction material** they provide. A spearphisher who knows
the CEO's name, their stated business priorities, their recent conference
appearances, and the names of their direct reports can craft an email that
reads as if it came from inside the organization.

**Evidence:**
```
Sources and Intelligence Collected:

Company Website (about/leadership page):
  CEO:    James Morrison — photo, bio, 23-year career summary
  CFO:    [Name] — photo, bio, prior firm history
  CISO:   [Name] — photo, LinkedIn linked
  CTO:    [Name] — photo, conference speaking history

LinkedIn (public profiles):
  CEO:    500+ connections, posts on Fed policy, M&A commentary
          Recent activity: Bloomberg FinTech Summit keynote (Jan 2025)
  CFO:    CPA designation, prior Goldman Sachs history
  Head of M&A: Current project reference "Apex Partners integration"
  IT Director: Skills list: Splunk, CrowdStrike, Palo Alto, Azure AD

SEC Filing (10-K, most recent):
  Named executive officers: CEO, CFO, COO
  Compensation disclosed: reinforces targeting priority

Press Releases (PR Newswire, BusinessWire):
  3 executive appointments in past 18 months
  2 strategic partnership announcements naming counterparties
```

**Risk Context:**
The CEO's LinkedIn activity disclosed his attendance at the Bloomberg FinTech
Summit in January 2025 — the same week the phishing campaign targeting NovaCrest
was active. An attacker monitoring this activity could time their campaign to
reference the summit, increasing pretext credibility dramatically.

**Recommendation:**
Conduct a leadership digital footprint review. Reduce biographical detail
on the public website to titles only — no full career histories or photographs.
Implement an executive social media policy covering what business details
are appropriate to share publicly. Provide tailored spearphishing awareness
training for all C-suite personnel using examples like PRETEXT-01 below.

---

### FINDING-02 — Internal Security & Technology Stack Revealed via Job Postings

**Severity:** 🟠 High
**ATT&CK:** T1591 — Gather Victim Org Information

**Description:**
Job postings published on LinkedIn, Indeed, and the company careers page
enumerate internal tooling in sufficient detail to construct a near-complete
picture of the organization's security architecture and business application
stack. This intelligence is directly actionable for two purposes: crafting
tool-specific phishing pretexts, and understanding which defensive controls
the attacker needs to evade.

**Evidence:**
```
Tools Revealed Across Active Job Postings:

SECURITY TOOLS (adversary uses to plan evasion):
  CrowdStrike Falcon EDR      — "experience with CrowdStrike Falcon preferred"
  Splunk SIEM                 — "3+ years Splunk administration required"
  Palo Alto Firewalls         — "Palo Alto PCNSE certification a plus"
  Azure AD / Entra            — "Azure AD administration experience required"
  Qualys Vulnerability Mgmt   — "Qualys scanning experience preferred"

BUSINESS APPLICATIONS (attacker uses for pretexts):
  Bloomberg Terminal          — fixed income and trading roles
  Workday HR Platform         — HR manager role posting
  Salesforce CRM              — business development role
  Intralinks VDR              — M&A analyst role (deal room platform)
  ServiceNow ITSM             — IT roles across department

CLOUD INFRASTRUCTURE:
  AWS (EC2, S3, IAM)          — cloud engineer role
  Microsoft Azure             — primary identity platform
  Hybrid AD environment       — IT director role description
```

**Risk Context:**
The security tool disclosure is the most operationally dangerous element.
An attacker now knows which EDR and SIEM to test against before deploying
their payload. The business application disclosure enables the Intralinks
phishing pretext (PRETEXT-01) which was constructed entirely from a single
job posting mentioning virtual data rooms for M&A work.

**Recommendation:**
Immediately audit all active job postings and remove specific vendor/product
names. Replace with generic descriptions: "endpoint detection and response
platform" rather than "CrowdStrike Falcon." Implement a job posting review
process requiring security team approval before publication. Prioritize
removal of security tool names — these have the highest adversarial value.

---

### FINDING-03 — IT Director GitHub Exposes Internal Architecture Details

**Severity:** 🟠 High
**ATT&CK:** T1593.001 — Search Open Websites: Social Media / Code Repositories

**Description:**
Sherlock username enumeration identified the IT Director's personal GitHub
account. Repository contents and commit history contain references to
NovaCrest internal infrastructure — including Splunk index naming conventions,
an Azure AD tenant identifier, and a commit message referencing a "SIEM
migration" project timeline. This provides an attacker with ground truth
verification of the security architecture and project schedule.

**Evidence:**
```
GitHub Account: github.com/rpatel-dev (discovered via Sherlock)
Account type:   Personal — not under NovaCrest organization

Repository: splunk-config-templates
  Commit message: "NovaCrest SIEM migration Q3 — index naming v2"
  File: indexes.conf contains:
    - Internal index names: novacrest_windows_events, novacrest_firewall_palo
    - Splunk forwarder hostnames: fw01-nyc.novacrest.internal
    - Retention period: 90 days

Repository: azure-ad-scripts
  File comment: "# NovaCrest tenant: tenant-id xxxxx"
  PowerShell scripts for user provisioning referencing internal OU structure

Commit email: r.patel@novacrest-capital.com
  Confirms identity — same address in HIBP with 4 breach records (Day 02)
```

**Risk Context:**
Internal hostname patterns (`fw01-nyc.novacrest.internal`) are extremely
valuable for lateral movement planning — they reveal network segmentation
conventions, geographic structure, and device naming schemes. Combined with
the SIEM index names, an attacker can anticipate exactly what evidence their
tools will generate and which logs the security team monitors.

**Recommendation:**
Immediate action required: notify Robert Patel to audit and sanitize public
repositories — remove all internal hostnames, tenant IDs, and organizational
references. Use GitHub's secret scanning feature and BFG Repo Cleaner to
purge sensitive content from commit history. Implement a company-wide policy
prohibiting internal infrastructure references in public code repositories.
Deploy pre-commit hooks (git-secrets, trufflehog) to prevent future leakage.

---

### FINDING-04 — Active M&A Deal Disclosed on LinkedIn (Potential MNPI)

**Severity:** 🟠 High
**ATT&CK:** T1591.002 — Gather Victim Org Information: Business Relationships

**Description:**
The Head of M&A's LinkedIn activity included a reference to a current active
transaction — the "Apex Partners integration project." For a financial services
firm, active deal names constitute potential material non-public information
(MNPI). The disclosure presents both a social engineering risk and a potential
regulatory compliance concern under SEC Rule 10b-5 and Regulation FD.

**Evidence:**
```
LinkedIn Activity — Sarah Chen, Head of M&A:
  Post (public): "Exciting week on the Apex Partners integration —
                  great progress on the cross-border structure"
  Date: 2025-01-08 (8 days ago — deal is active)
  Visibility: Public — indexed by Google
  Engagement: 47 likes, 12 comments — further amplified

Conference Speaker Bio (FinTech Summit 2024):
  "Sarah Chen leads NovaCrest's cross-border M&A practice, currently
   advising on transactions in the healthcare and tech sectors"
  Still publicly indexed — reveals active sectors of interest
```

**Risk Context:**
Beyond the social engineering enablement (PRETEXT-01 uses this detail), the
public disclosure of an active deal name may warrant legal review. If Apex
Partners is a public company and the integration is a material transaction,
this disclosure could create regulatory exposure independent of the security
risk.

**Recommendation:**
Immediate: advise Sarah Chen to remove or edit the LinkedIn post and conference
bio. Legal team should review the disclosure for SEC/Reg FD implications.
Implement an M&A social media policy — deal names, counterparty names, and
transaction details must never appear in public communications until formally
announced. Include this scenario in the next social media policy training.

---

### FINDING-05 — HR Manager Personal Email Linked to Corporate Identity

**Severity:** 🟡 Medium
**ATT&CK:** T1589.002 — Gather Victim Identity Information: Email Addresses

**Description:**
Gravatar profile correlation linked HR Manager Lisa Williams' personal Gmail
address to her corporate email identity. Personal email addresses enable
attackers to pivot to personal account breach data (often richer than
corporate breach exposure), conduct account recovery attacks, and reach
targets through channels that bypass corporate email security controls.

**Evidence:**
```
Gravatar Profile Discovery:
  Corporate email:  l.williams@novacrest-capital.com (Day 02 HIBP confirmed)
  Gravatar avatar:  Linked to lwilliams.hr@gmail.com
  Personal email:   lwilliams.hr@gmail.com

HIBP check on personal Gmail:
  Breach count: 7 (higher than corporate — less secure password practices)
  Breaches including: LinkedIn, Adobe, Dropbox, MyFitnessPal, Canva, Deezer

Additional LinkedIn finding:
  Recent post: "Open enrollment closes January 31 — all employees please
                complete your benefits selections by end of month"
  This post times the attack window precisely for HR-themed phishing
```

**Recommendation:**
Advise Lisa Williams to create a separate, non-identifiable Gravatar account
for personal use and remove her personal email from any corporate-linked
profile. General awareness training for all HR staff on personal digital hygiene —
HR personnel are disproportionately targeted due to their access to sensitive
employee data and their role-conditioned responsiveness to urgent requests.

---

## Spearphishing Pretext Demonstrations

The following two pretexts were constructed using only the intelligence
collected in this assessment. They are documented here to demonstrate
the concrete risk to leadership — not as operational attack tools.

### PRETEXT-01 — M&A Vendor Impersonation (Target: Sarah Chen)

**Intelligence required:** LinkedIn (Apex Partners project), conference slide
(Intralinks VDR), email format (Day 02), CEO name (website).

```
From:    support@intralinks-portal[.]com   ← lookalike domain
To:      s.chen@novacrest-capital.com
Subject: ACTION REQUIRED: Apex Partners Data Room Access Expiring

Dear Sarah,

This is an automated notification regarding your Intralinks administrator
access to the Apex Partners integration workspace. Your access expires
in 24 hours due to a scheduled quarterly security review.

James Morrison has already completed re-authentication. Your team
members are awaiting your approval to continue document uploads
ahead of Thursday's structure call.

[RESTORE ACCESS — SECURE LINK]

Intralinks Client Support
```

**Pretext effectiveness:** CRITICAL — references real deal, real tool, real
colleague, real urgency tied to a real meeting. Click probability: Very High.
**Defensive value:** Shows leadership exactly what their public exposure enables.

---

### PRETEXT-02 — IT Security Alert / HR Platform Impersonation (Target: Lisa Williams)

**Intelligence required:** LinkedIn (open enrollment deadline), job posting
(Workday platform), email format, HR role.

```
From:    noreply@workday-secure-portal[.]com  ← lookalike domain
To:      l.williams@novacrest-capital.com
Subject: Urgent: Workday Benefits Admin Access Suspended

Dear Lisa,

Your Workday administrator access to the Benefits Enrollment module
has been temporarily suspended due to unusual login activity.

With open enrollment closing January 31, please restore your access
immediately using the verification link below to avoid disruption
to employee submissions.

[RESTORE WORKDAY ACCESS]

Workday Security Team
```

**Pretext effectiveness:** CRITICAL — times attack to known deadline, uses
real platform, exploits role-conditioned urgency. Click probability: Very High.
**Defensive value:** Demonstrates that open enrollment announcements on
LinkedIn are directly weaponizable.

---

## High-Value Target Risk Rankings

| Rank | Name | Title | HVT Score | Risk | Primary Concern |
|------|------|-------|:---------:|------|-----------------|
| 1 | James Morrison | CEO | 9.2/10 | 🔴 Critical | Highest access + highest public exposure |
| 2 | Robert Patel | IT Director | 9.0/10 | 🔴 Critical | Security stack access + GitHub leakage |
| 3 | Sarah Chen | Head of M&A | 8.5/10 | 🔴 Critical | M&A data + MNPI disclosure |
| 4 | Lisa Williams | HR Manager | 7.8/10 | 🟠 High | Employee PII access + pretext vulnerability |
| 5 | Mike Thompson | FI Analyst | 7.1/10 | 🟠 High | Already compromised (Day 04) |

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding |
|----|-----------|--------|---------|
| **T1591** | Gather Victim Org Information | Reconnaissance | FINDING-01, 02 |
| **T1591.002** | Business Relationships | Reconnaissance | FINDING-04 |
| **T1591.004** | Identify Roles | Reconnaissance | FINDING-01 |
| **T1589** | Gather Victim Identity Information | Reconnaissance | FINDING-05 |
| **T1589.002** | Email Addresses | Reconnaissance | FINDING-05 |
| **T1589.003** | Employee Names | Reconnaissance | FINDING-01 |
| **T1593.001** | Search Social Media | Reconnaissance | FINDING-01, 03 |
| **T1598.003** | Spearphishing Link | Reconnaissance | PRETEXT-01, 02 |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| HSE-01 (Exec exposure) | 9 | 10 | 9 | 7 | 10 | **45** | 🔴 Critical |
| HSE-02 (Tech stack) | 8 | 10 | 10 | 9 | 10 | **47** | 🔴 Critical |
| HSE-03 (GitHub leak) | 9 | 8 | 8 | 6 | 8 | **39** | 🔴 Critical |
| HSE-04 (MNPI / M&A) | 8 | 7 | 8 | 5 | 9 | **37** | 🟠 High |
| HSE-05 (Personal email) | 6 | 8 | 7 | 3 | 8 | **32** | 🟠 High |

### Overall Human Attack Surface Rating: 🔴 CRITICAL

---

## Prioritized Remediation Plan

| Priority | Action | Owner | Deadline |
|----------|--------|-------|----------|
| **P0 — Same Day** | Remove Apex Partners deal name from Sarah Chen's LinkedIn | Sarah Chen / Legal | Today |
| **P0 — Same Day** | Notify Robert Patel to audit and sanitize GitHub repos | Robert Patel / IT | Today |
| **P1 — This Week** | Audit and sanitize all active job postings — remove tool names | HR + Security | 5 days |
| **P1 — This Week** | Legal review: MNPI disclosure risk from LinkedIn M&A posts | Legal / Compliance | 5 days |
| **P1 — This Week** | Executive briefing with spearphishing pretext examples | CISO | 5 days |
| **P2 — 30 Days** | Deploy pre-commit hooks to prevent future GitHub leakage | IT / DevOps | 30 days |
| **P2 — 30 Days** | Implement job posting review process (security approval) | HR + Security | 30 days |
| **P2 — 30 Days** | Conduct leadership digital footprint review + reduction | All C-suite | 30 days |
| **P3 — 90 Days** | Deploy social media policy covering MNPI and OPSEC | Legal + HR | 90 days |
| **P3 — 90 Days** | Annual human attack surface OSINT review — repeat this process | Security Team | Annually |

---

## Kill Chain Connection — Days 01 Through 05

This assessment connects all five days of investigation into a single
coherent threat picture:

```
Day 01: External attack surface reveals VPN portal and email security gaps
  ↓
Day 02: 312 employee credentials found in breach data — including trading desk analyst
  ↓
Day 03: Phishing infrastructure maps to 12-domain cluster on bulletproof hosting
  ↓
Day 04: C2 beacon confirmed on DESKTOP-FIN-047 — same trading desk analyst
  ↓
Day 05: OSINT reveals exactly how the attacker built the HR benefits lure —
        open enrollment deadline on LinkedIn + Workday in job postings
        = perfectly timed, tool-accurate phishing pretext
```

The attacker didn't guess. They researched. This is the research they did.

---

## Conclusion

In 90 minutes of passive research using only publicly available tools and
freely indexed information, this assessment produced a complete operational
profile of NovaCrest Capital Group's human attack surface: named targets,
validated email addresses, confirmed internal tooling, active business deals,
and two ready-to-deploy spearphishing pretexts that reference real people,
real projects, and real platforms.

No systems were accessed. No laws were violated. No interaction with any
employee occurred. Everything used in this assessment is publicly available
to anyone with a browser and a LinkedIn account.

The most important takeaway for leadership: **the phishing email that
compromised DESKTOP-FIN-047 (Day 03-04) was not a lucky guess.** The HR
benefits lure worked because Lisa Williams publicly announced the enrollment
deadline, and Workday appeared in multiple job postings. The attacker's
research took minutes. The remediation requires weeks. The detection took
11 days. **That asymmetry is the fundamental challenge of human attack surface
reduction** — and why it requires ongoing, active management, not a one-time fix.

---

## References

- [MITRE ATT&CK Reconnaissance Tactic](https://attack.mitre.org/tactics/TA0043/)
- [SANS — Open Source Intelligence Techniques](https://www.sans.org/osint/)
- [Sherlock Project](https://github.com/sherlock-project/sherlock)
- [SpiderFoot Documentation](https://github.com/smicallef/spiderfoot)
- [SEC Regulation FD — Material Non-Public Information](https://www.sec.gov/divisions/corpfin/guidance/regfd-interp.htm)
- [NIST SP 800-50 — Security Awareness Training](https://csrc.nist.gov/publications/detail/sp/800-50/final)

---

*Previous: [Day 04 ←](../day-04/REPORT.md) | Next: [Day 06 →](../day-06/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
