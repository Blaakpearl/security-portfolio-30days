# Threat Intelligence Report
## Day 03 — Phishing Infrastructure Analysis: PHISH-FIN-2025-Q1

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-16 |
| **Report Type** | Tactical Threat Intelligence — Phishing Campaign Analysis |
| **TLP Classification** | TLP:WHITE — Shareable across sector |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | Threat Intelligence |
| **ATT&CK Phase** | Resource Development (TA0042) / Initial Access (TA0001) |
| **Campaign ID** | PHISH-FIN-2025-Q1 |

---

## Executive Summary

On January 16, 2025, a Microsoft 365 credential-harvesting phishing campaign
targeting NovaCrest Capital Group was detected after 14 emails were quarantined by
the email gateway. One employee clicked the phishing link but did not submit
credentials. Full infrastructure analysis of the phishing URL uncovered a
**12-domain adversary cluster** hosted on bulletproof infrastructure, a
reverse-proxy phishing kit capable of bypassing multi-factor authentication, and
campaign patterns consistent with prior attacks against six financial sector
organizations in Q4 2024.

The threat actor — tracked as **PHISH-FIN-2025-Q1** — registered infrastructure
11 days prior to first delivery, using privacy-protected registration via Namecheap
and bulletproof hosting through Flyservers S.A. (Seychelles, AS209588). Certificate
transparency pivoting revealed **8 additional phishing domains** targeting other
financial organizations, all sharing the same `microsoftonline-[org]` combosquatting
pattern and the same IP infrastructure block.

A full IOC package in STIX 2.1 format, two YARA detection rules, and one Sigma
email gateway rule are attached for immediate defensive deployment. The IOC list
is suitable for sector-wide sharing via FS-ISAC or equivalent information sharing
channels.

**No credential compromise confirmed at NovaCrest. Blocking action recommended
for all 12 domains and the 185.220.101.0/24 subnet.**

---

## Methodology

```
Phase 1 — Initial Triage (30 min)
  Trigger:    Email gateway quarantine alert — 14 messages
  Tool:       URLScan.io API
  Output:     Page screenshot, DOM source, network IOCs, hosting attribution

Phase 2 — Domain & Registration Profiling (30 min)
  Tools:      WHOIS, dig, crt.sh
  Output:     Registration timeline, DNS records, certificate transparency pivot

Phase 3 — Multi-Engine Analysis & Infrastructure Pivot (45 min)
  Tool:       VirusTotal API v3
  Output:     Detection coverage, IP resolutions, sibling domain cluster

Phase 4 — Detection Rule Development (45 min)
  Tools:      YARA, Sigma framework
  Output:     2 YARA rules (kit fingerprint + anti-analysis), 1 Sigma rule

Phase 5 — Intelligence Structuring & Dissemination (30 min)
  Tool:       STIX 2.1 Python library
  Output:     STIX bundle, IOC master list (TLP:WHITE)
```

---

## Campaign Overview

### Infrastructure Timeline

```
2025-01-05  14:32 UTC   microsoftonline-portal.com registered (Namecheap)
2025-01-05  ~16:00 UTC  DNS configured → Flyservers S.A. name servers
2025-01-05  ~18:00 UTC  Let's Encrypt wildcard certificate issued
                        CN: *.microsoftonline-portal.com
2025-01-06 — 2025-01-14 Infrastructure staging — 8 additional domains registered
                        following same combosquatting pattern
2025-01-14  ~09:00 UTC  Campaign delivery begins — financial sector orgs
2025-01-16  09:30 UTC   NovaCrest Capital Group targeted — 207 delivery attempts
2025-01-16  11:15 UTC   Email gateway quarantine rule fires (2-hour delay)
2025-01-16  11:22 UTC   Analyst investigation begins
2025-01-16  14:00 UTC   This report produced — IOC package ready for distribution
```

---

## Technical Findings

---

### FINDING-01 — Reverse-Proxy Phishing Kit with MFA Bypass Capability

**Severity:** 🔴 Critical
**CVSS v3.1 Score:** 9.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**ATT&CK:** T1056.003 — Input Capture: Web Portal Capture / T1539 — Steal Web Session Cookie

**Description:**
URLScan analysis and DOM inspection confirmed the phishing kit is a
**reverse-proxy credential harvester** — not a simple static HTML credential
capture page. The kit proxies all traffic between the victim and the legitimate
Microsoft 365 login service in real time, capturing credentials AND
authentication tokens (session cookies) as they pass through.

This architecture defeats standard MFA controls: when a victim completes
the MFA prompt (SMS, authenticator app, hardware key), the reverse proxy
captures the authenticated session cookie — granting the attacker a fully
authenticated session without needing the MFA factor themselves.

**Evidence:**
```
URLScan DOM Analysis:

  Kit Type:         Reverse proxy (Evilginx2-style architecture)
  Page Title:       "Sign in to your account" (mimics Microsoft)
  Credential Relay: POST /signin/v2/collect → attacker backend
  Session Capture:  esctx= and brcap= cookie parameters intercepted
  MFA Interception: otc= (one-time code) parameter relayed and captured

  Anti-Analysis Evasion (YARA detected):
    navigator.webdriver check   → serves benign content to Selenium/PhantomJS
    screen.width < 200 check    → detects low-resolution sandbox displays
    Mouse movement monitoring   → requires genuine human mouse events
    navigator.language check    → blocks non-English browser environments

  Network Requests (from URLScan):
    → legitimate login.microsoftonline.com (background legitimacy proxy)
    → cdn.microsoftonline-portal.com (kit CSS/JS assets)
    → log.microsoftonline-portal.com (credential exfiltration endpoint)
```

**Risk Context:**
The MFA-bypass capability is the critical differentiator here. Organizations
that believe MFA protects them from phishing are specifically targeted by
this kit design. A successful credential capture via this kit gives the
attacker a valid, fully authenticated M365 session — immediately usable for
email access, SharePoint file exfiltration, and Teams communication interception.

**Recommendation:**
Standard TOTP/SMS MFA does not protect against real-time phishing proxies.
Migrate high-value accounts to **FIDO2/WebAuthn hardware security keys**
(YubiKey, Windows Hello) — the only MFA form that cannot be intercepted by
a reverse proxy, as authentication is bound to the legitimate domain's TLS
certificate.

---

### FINDING-02 — Bulletproof Hosting Infrastructure: Flyservers S.A.

**Severity:** 🟠 High
**ATT&CK:** T1583.002 — Acquire Infrastructure: DNS Server / T1584.004 — Compromise Infrastructure: Server

**Description:**
The phishing infrastructure is hosted exclusively on **AS209588 — Flyservers S.A.**,
a hosting provider registered in the Seychelles with a documented history of
ignoring abuse reports and providing refuge for criminal infrastructure. Multiple
threat intelligence sources classify this ASN as a bulletproof hosting provider.

**Evidence:**
```
URLScan — Hosting Attribution:
  IP:       185.220.101.12
  ASN:      AS209588
  Org:      Flyservers S.A.
  Country:  Seychelles (SC)
  Server:   nginx/1.18.0

AbuseIPDB Score — 185.220.101.12:
  Abuse Confidence: 97%
  Reports (90 days): 412 reports from 156 distinct reporters
  Categories: Phishing, Web App Attack, SSH Brute Force

Threat Intel Cross-Reference:
  Same ASN hosted infrastructure for:
    - 3 BEC campaigns (Q3-Q4 2024) — financial sector
    - APT29-linked staging servers (2023)
    - Multiple ransomware C2 domains (2022-2024)

Name Server Analysis:
  ns1.flyservers.io / ns2.flyservers.io
  → Same provider controls DNS — no independent abuse reporting path
  → Rapid IP reassignment capability (< 15 min TTL observed)
```

**Recommendation:**
Block the full **185.220.101.0/24** subnet at perimeter firewall and web proxy.
While this may cause false positives for legitimate traffic using this range
(unlikely given its reputation), the risk-benefit strongly favors blocking.
Submit abuse report to Flyservers S.A. (expected: ignored) and simultaneously
report to the Seychelles CERT and ICANN for registrar action.

---

### FINDING-03 — Infrastructure Cluster: 12 Domains, 6 Target Organizations

**Severity:** 🟠 High
**ATT&CK:** T1583.001 — Acquire Infrastructure: Domains

**Description:**
VirusTotal IP pivot on 185.220.101.12, combined with certificate transparency
analysis of the `microsoftonline-portal.com` registration pattern, identified
**11 additional phishing domains** sharing the same infrastructure, registrar
pattern, and naming convention. Each domain is configured to target a specific
organization by incorporating that organization's name into the subdomain structure.

**Evidence:**
```
Domains sharing 185.220.101.0/24 infrastructure (all registered Jan 5-14, 2025):

Domain                                    Target Org           Status
microsoftonline-portal.com               NovaCrest Capital    ACTIVE
hrportal-login.microsoftonline-portal.com NovaCrest Capital   ACTIVE
ms-account-portal.net                    Generic financial    ACTIVE
secure-signin.ms-account-portal.com      Unknown org          ACTIVE
wellsfargo-benefits.ms-signin-portal.com Wells-type target    ACTIVE ← other org
healthcare-login.azure-portal-signin.com Healthcare sector    ACTIVE
jpmorgan-portal.microsoftonline-hub.com  JP Morgan-type       ACTIVE ← other org
[4 additional domains — full list in artifacts/related_domains.txt]

Certificate Transparency Findings:
  Wildcard certs covering all subdomains → enables instant new target creation
  Issuer: Let's Encrypt (auto-renewed — no manual intervention needed)
  Total domains on same cert SAN: 14
```

**Risk Context:**
The cluster scope indicates this is not a targeted attack on NovaCrest alone —
it is a **broad financial sector campaign** with infrastructure pre-positioned
to target multiple organizations simultaneously. The IOC list should be
distributed to all identified potential targets and shared via FS-ISAC.

**Recommendation:**
Immediately share the full IOC list and STIX bundle via appropriate sector ISAC
channels. Contact security teams at other identifiable target organizations
directly where contact information is known. Submit all domains to Google Safe
Browsing, Microsoft SmartScreen, and Netcraft phishing feeds for broad blocking.

---

### FINDING-04 — Combosquatting Domain Registration Pattern

**Severity:** 🟡 Medium
**ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name

**Description:**
All 12 identified domains follow a consistent combosquatting pattern: the
attacker appends a legitimate-sounding service descriptor to a near-Microsoft
domain name. This creates URLs that appear credible to non-technical recipients,
especially when combined with a valid Let's Encrypt certificate (green padlock).

**Evidence:**
```
Naming Pattern Analysis:

Formula: [target-org-name]-[service-descriptor].[fake-ms-domain].[tld]/[path]

Service descriptors observed:
  benefits, portal, signin, login, update, verify, secure, account

Fake MS domain bases observed:
  microsoftonline-portal.com
  ms-account-portal.net
  azure-portal-signin.com
  ms-signin-portal.com
  microsoftonline-hub.com

Example URLs constructed:
  novacrest-benefits.microsoftonline-portal.com/signin
  wellsfargo-benefits.ms-signin-portal.com/signin
  jpmorgan-portal.microsoftonline-hub.com/signin

Registrar: Namecheap (all 12 domains)
Privacy: WhoisGuard enabled (all 12 — identity concealed)
Registration method: Likely bulk registration via stolen/synthetic payment method
```

**Recommendation:**
Register defensive domains for your own organization following this naming
pattern (e.g., `novacrest-benefits.com`, `novacrest-login.com`) to prevent
future attacker registration. Implement a brand monitoring / domain alert
service (e.g., DomainTools Iris, Recorded Future) to notify on newly
registered domains containing your organization's name.

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Confidence |
|----|-----------|--------|---------|------------|
| **T1566.002** | Spearphishing Link | Initial Access | Email delivery vector | High |
| **T1583.001** | Acquire Infrastructure: Domains | Resource Development | FINDING-03, 04 | High |
| **T1583.002** | Acquire Infrastructure: DNS Server | Resource Development | FINDING-02 | High |
| **T1584.004** | Compromise Infrastructure: Server | Resource Development | Sending domain | Medium |
| **T1056.003** | Input Capture: Web Portal Capture | Collection | FINDING-01 | High |
| **T1539** | Steal Web Session Cookie | Credential Access | FINDING-01 (MFA bypass) | High |
| **T1036.005** | Masquerading: Match Legitimate Name | Defense Evasion | FINDING-04 | High |
| **T1114.003** | Email Forwarding Rule | Collection | Post-compromise risk | Low |
| **T1078.004** | Valid Accounts: Cloud Accounts | Initial Access | Post-credential-capture | Medium |

---

## Risk Assessment — DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **/50** | **Rating** |
|---------|:------:|:---------------:|:--------------:|:--------------:|:---------------:|:-------:|:----------:|
| FINDING-01 (MFA-bypass kit) | 10 | 8 | 8 | 8 | 6 | **40** | 🔴 Critical |
| FINDING-02 (Bulletproof hosting) | 7 | 9 | 7 | 9 | 8 | **40** | 🔴 Critical |
| FINDING-03 (12-domain cluster) | 8 | 8 | 8 | 10 | 8 | **42** | 🔴 Critical |
| FINDING-04 (Combosquatting) | 6 | 10 | 9 | 8 | 9 | **42** | 🔴 Critical |

### Overall Campaign Threat Rating: 🔴 CRITICAL

---

## Detection Rules Deployed

| Rule | File | Platform | Coverage |
|------|------|----------|---------|
| Phishing Kit HTML Fingerprint | `yara_phishing_kit.yar` | YARA (any) | T1056.003 |
| Phishing Kit Anti-Analysis Evasion | `yara_phishing_kit.yar` (rule 2) | YARA (any) | T1497 |
| M365 Phishing Email Delivery | `sigma_phishing_campaign.yml` | Sigma (any SIEM) | T1566.002 |

---

## IOC Summary

```
# DOMAINS (12 total — full list in artifacts/ioc_master_list.txt)
microsoftonline-portal[.]com
novacrest-benefits.microsoftonline-portal[.]com
ms-account-portal[.]net
secure-signin.ms-account-portal[.]com
[8 additional — see artifacts/ioc_master_list.txt]

# IP ADDRESSES / SUBNETS
185.220.101.12          ← Primary phishing host
185.220.101.0/24        ← Full bulletproof hosting block (recommended)

# ASN
AS209588 — Flyservers S.A. (Seychelles) — bulletproof hosting provider

# NAME SERVERS (block DNS resolution)
ns1.flyservers.io
ns2.flyservers.io

# EMAIL DETECTION PATTERNS
Subject contains: "Benefits Enrollment Update"
Link pattern: *microsoftonline-[word].com/signin*
Cert issuer: Let's Encrypt + new domain (< 30 days old)

# STIX 2.1 BUNDLE
File: artifacts/stix_bundle_day03.json
Objects: 12 (ThreatActor, Infrastructure, Indicators, Relationships)
```

---

## Dissemination Recommendations

| Channel | Action | Priority |
|---------|--------|----------|
| **FS-ISAC** | Share STIX bundle + TLP:WHITE IOC list | P1 — Today |
| **Email Gateway** | Deploy Sigma rule + block all 12 domains | P1 — Today |
| **Web Proxy / Firewall** | Block 185.220.101.0/24 subnet | P1 — Today |
| **DNS Sink-hole** | Add all 12 domains to internal sinkhole | P1 — Today |
| **Endpoint Security** | Deploy YARA rules to EDR for email attachment scanning | P2 — 24hrs |
| **Google Safe Browsing** | Submit all 12 domains via safebrowsing.google.com/safebrowsing/report_phish | P2 — 24hrs |
| **Microsoft SmartScreen** | Submit via microsoft.com/wdsi/report | P2 — 24hrs |
| **Netcraft** | Submit via netcraft.com/report | P2 — 24hrs |
| **Namecheap Abuse** | File abuse report — abuse@namecheap.com | P3 — 48hrs |
| **Let's Encrypt** | Request cert revocation via abuse@letsencrypt.org | P3 — 48hrs |

---

## Analyst Notes — Intelligence Gaps

The following questions remain unanswered and represent areas for continued
investigation:

1. **Sending domain attribution:** The phishing emails were delivered via a
   compromised legitimate domain — not the phishing domain itself. The compromised
   sender has not yet been identified.

2. **Kit origin:** The reverse-proxy kit shows similarities to open-source
   Evilginx2 but contains custom modifications. Source repository not yet
   identified — may indicate a custom-developed or purchased kit.

3. **Actor infrastructure beyond Flyservers:** Pivot analysis has not yet
   covered all name server and registrar combinations. Additional infrastructure
   may exist outside the identified cluster.

4. **Victim scope:** Without access to FS-ISAC private feeds, the full scope
   of organizations targeted by this campaign cannot be confirmed. Estimated
   6+ based on domain naming patterns.

---

## Conclusion

This investigation demonstrates the intelligence multiplier effect of full
infrastructure analysis: a single phishing URL yielded a 12-domain adversary
cluster, bulletproof hosting attribution, MFA-bypass capability assessment,
and a shareable STIX intelligence package — all within a three-hour analysis window.

The most operationally significant finding is the **reverse-proxy MFA bypass**
capability (FINDING-01). Organizations in the targeted sector that rely on
TOTP or SMS MFA as their primary phishing defense are not protected against
this kit. Migration to FIDO2 hardware keys for privileged and high-value
accounts is the only control that definitively defeats this attack pattern.

The STIX 2.1 bundle and TLP:WHITE IOC list should be shared immediately via
sector ISAC channels — the other 11 domains in the cluster represent active
threats to other financial sector organizations who may have no awareness of
this campaign.

---

## References

- [MITRE ATT&CK T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [STIX 2.1 Specification — OASIS](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [Evilginx2 — Reverse Proxy Phishing Framework](https://github.com/kgretzky/evilginx2)
- [AbuseIPDB — AS209588 Report](https://www.abuseipdb.com/asn/AS209588)
- [FS-ISAC Threat Intelligence Sharing](https://www.fsisac.com/)
- [FIDO2 / WebAuthn — Anti-Phishing MFA](https://fidoalliance.org/fido2/)

---

*Previous: [Day 02 ←](../day-02/REPORT.md) | Next: [Day 04 →](../day-04/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
