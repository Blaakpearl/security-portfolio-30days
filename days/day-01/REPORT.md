# External Attack Surface Assessment Report
## Day 01 — Recon & Footprinting

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-15 |
| **Assessment Type** | Passive External Reconnaissance / Attack Surface Analysis |
| **Classification** | Portfolio / Training Exercise |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | OSINT |
| **ATT&CK Phase** | Reconnaissance (TA0043) |

---

## Executive Summary

A passive external reconnaissance assessment of NovaCrest Capital Group's digital footprint
was conducted using open-source intelligence (OSINT) tools and publicly accessible databases.
The assessment identified **23 externally exposed services**, **47 subdomains**, and
**critical gaps in email authentication controls** that collectively present a significant
attack surface for a motivated threat actor.

The most severe findings include an externally accessible VPN portal running a version of
Palo Alto GlobalProtect associated with known CVEs, an absence of DMARC enforcement
allowing unrestricted domain spoofing, and multiple development and staging subdomains
inadvertently published in certificate transparency logs. No active scanning or direct
interaction with target systems was required to produce these findings — the intelligence
was gathered entirely from public sources, mirroring the capabilities of an APT-level
adversary in the pre-intrusion reconnaissance phase.

**Immediate action is recommended on three findings before further intrusion phases proceed.**

---

## Methodology

All reconnaissance was performed passively using publicly available tools and data sources.
No packets were sent to target infrastructure. Sources consulted:

```
┌──────────────────────┬──────────────────────────────────────────────────┐
│ Source               │ Data Collected                                   │
├──────────────────────┼──────────────────────────────────────────────────┤
│ Shodan.io            │ Exposed ports, services, banners, CVEs           │
│ Censys.io            │ Certificate & service enumeration                │
│ crt.sh               │ Certificate transparency log (all issued certs)  │
│ DNS (dig)            │ A, MX, TXT, NS, CNAME, SOA records               │
│ theHarvester         │ Emails, hostnames, employee names                │
│ Subfinder + Amass    │ Passive subdomain enumeration                    │
│ MXToolbox            │ SPF / DKIM / DMARC validation                    │
└──────────────────────┴──────────────────────────────────────────────────┘
```

---

## Technical Findings

---

### FINDING-01 — Unpatched VPN Portal (GlobalProtect) Exposed to Internet

**Severity:** 🔴 Critical  
**CVSS v3.1 Score:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)  
**ATT&CK:** T1596 (Search Open Technical Databases), T1190 (Exploit Public-Facing Application)

**Description:**  
Shodan enumeration identified a Palo Alto Networks GlobalProtect VPN portal at
`vpn.novacrest-capital.com` running version 9.1.3. This version is affected by
**CVE-2021-3064** (CVSS 9.8) — a buffer overflow allowing unauthenticated remote
code execution. The portal is publicly accessible on TCP/443 with no evidence of
network-level access controls.

**Evidence:**
```
Shodan Result:
  IP:       203.0.113.45
  Port:     443
  Service:  Palo Alto GlobalProtect
  Version:  9.1.3
  Banner:   PAN-OS 9.1.3 / GlobalProtect Gateway
  CVEs:     CVE-2021-3064 (9.8), CVE-2019-17440 (9.8)
  Last Seen: 2025-01-12

Certificate (crt.sh):
  CN: vpn.novacrest-capital.com
  Issued: 2024-08-15
  Issuer: DigiCert
```

**Risk Context:**  
An attacker exploiting CVE-2021-3064 gains unauthenticated RCE on the VPN gateway,
providing direct network adjacency to the internal corporate network — bypassing all
perimeter controls. This is a single-step path from the public internet to internal
infrastructure.

**Recommendation:**  
Upgrade GlobalProtect to 9.1.11+ or 10.x immediately. Implement IP allowlisting
to restrict VPN portal access to known corporate egress IPs and employee home
IP ranges via geo-restriction. Implement MFA on all VPN authentication flows.

---

### FINDING-02 — No DMARC Enforcement — Domain Spoofing Unrestricted

**Severity:** 🔴 Critical  
**CVSS v3.1 Score:** 8.6 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)  
**ATT&CK:** T1589.002 (Email Addresses), T1566.001 (Spearphishing Attachment — enabled)

**Description:**  
DNS analysis reveals that while an SPF record exists, DMARC is configured with
`p=none` — monitoring-only mode. This means emails sent from unauthorized senders
claiming to be `@novacrest-capital.com` will be **delivered to recipients without
any warning or rejection**, even if they fail SPF and DKIM checks.

**Evidence:**
```bash
$ dig TXT _dmarc.novacrest-capital.com +short
"v=DMARC1; p=none; rua=mailto:dmarc-reports@novacrest-capital.com"

$ dig TXT novacrest-capital.com +short | grep spf
"v=spf1 include:_spf.google.com include:spf.protection.outlook.com ~all"
# Note: ~all = softfail (not -all hardfail)
```

**Risk Context:**  
With `p=none` DMARC and `~all` SPF softfail, any attacker can send emails appearing
to originate from `ceo@novacrest-capital.com` or `hr@novacrest-capital.com`
to any recipient. Combined with the employee list discovered in Step 5 of the lab,
this enables highly credible Business Email Compromise (BEC) and spearphishing
campaigns with zero technical barriers.

**Recommendation:**  
1. Change SPF to `-all` (hardfail) immediately
2. Deploy DKIM signing for all outbound mail streams
3. Advance DMARC from `p=none` → `p=quarantine` (30-day transition) → `p=reject`
4. Set up DMARC aggregate reporting to `rua` address and review weekly

---

### FINDING-03 — Development & Staging Environments Exposed via Cert Transparency

**Severity:** 🟠 High  
**CVSS v3.1 Score:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)  
**ATT&CK:** T1596.003 (Certificate Logs), T1083 (File and Directory Discovery)

**Description:**  
Certificate transparency log analysis via crt.sh revealed 8 subdomain certificates
issued for non-production environments that are publicly indexed and potentially
accessible. Development environments frequently run older, unpatched software,
have weaker authentication controls, and may contain real production data copies.

**Evidence:**
```
Discovered via crt.sh (certificate transparency):

  dev.novacrest-capital.com        — issued 2024-11-03, DigiCert
  staging.novacrest-capital.com    — issued 2024-09-17, Let's Encrypt
  dev-api.novacrest-capital.com    — issued 2024-10-22, Let's Encrypt
  internal-docs.novacrest-capital.com  — issued 2024-07-08, DigiCert
  test-portal.novacrest-capital.com    — issued 2024-12-01, Let's Encrypt
  
Shodan confirms dev.novacrest-capital.com:
  Running: Apache 2.4.41 (Ubuntu) — EOL/unpatched
  Exposed: PHPMyAdmin at /phpmyadmin/ — no authentication wall
```

**Risk Context:**  
The PHPMyAdmin instance on `dev.novacrest-capital.com` represents a direct path to
database contents. If this development database contains any production data copies —
common in financial services — the exposure risk is severe.

**Recommendation:**  
Restrict all non-production environments behind VPN or IP allowlist immediately.
Audit whether development databases contain any production/real PII or financial data.
Implement a certificate transparency monitoring alert (e.g., Facebook CT Monitor,
Cert Spotter) to notify on any new certificate issuance for your domain.

---

### FINDING-04 — Email Address Naming Convention Identified

**Severity:** 🟡 Medium  
**ATT&CK:** T1589.002 (Gather Victim Identity — Email Addresses)

**Description:**  
theHarvester enumeration and LinkedIn correlation confirmed the organization uses a
`firstname.lastname@novacrest-capital.com` email naming convention across all
business units. 34 email addresses were recovered from public sources including
conference speaker listings, press releases, and SEC filing contacts.

**Evidence:**
```
Confirmed naming pattern: firstname.lastname@novacrest-capital.com

Sample recovered addresses (anonymized for report):
  j.morrison@novacrest-capital.com      — Chief Financial Officer
  s.chen@novacrest-capital.com          — Head of M&A
  r.patel@novacrest-capital.com         — IT Director
  [31 additional addresses in artifacts/emails_found.txt]
```

**Risk Context:**  
With confirmed email format and employee role data from LinkedIn, an attacker can
construct a targeted spearphishing campaign against high-value individuals with
personalized pretexts (CFO fraud, M&A deal spoofing, IT credential reset requests).

**Recommendation:**  
Implement email security training focused on spearphishing awareness for all
identified high-value individuals. Consider email address obfuscation for executives
in public-facing communications.

---

### FINDING-05 — Exposed OWA (Outlook Web Access) Portal

**Severity:** 🟡 Medium  
**CVSS v3.1 Score:** 6.5  
**ATT&CK:** T1590.001 (IP Addresses), T1078 (Valid Accounts — credential stuffing target)

**Description:**  
Shodan enumeration identified an Outlook Web Access portal at
`mail.novacrest-capital.com` running Exchange Server 2019 CU12. While this version
is within support lifecycle, public OWA portals are high-value credential stuffing
and password spray targets. No multi-factor authentication prompt was observed
in the banner/header analysis.

**Evidence:**
```
URL:     https://mail.novacrest-capital.com/owa
Server:  Microsoft-IIS/10.0
Version: Exchange 2019 CU12 (inferred from headers)
MFA:     Not detected in headers (requires manual verification)
Auth:    Forms-based authentication (Windows auth page observed)
```

**Recommendation:**  
Enforce MFA on all OWA access. Implement account lockout policies and alerting
for >5 failed authentication attempts per account per hour. Consider migrating to
Microsoft 365 with Conditional Access policies for stronger authentication controls.

---

## MITRE ATT&CK Technique Matrix

| Technique ID | Name | Tactic | Finding |
|---|---|---|---|
| **T1590** | Gather Victim Network Information | Reconnaissance | All findings |
| **T1590.001** | IP Addresses | Reconnaissance | FINDING-01, 05 |
| **T1591** | Gather Victim Org Information | Reconnaissance | FINDING-04 |
| **T1596** | Search Open Technical Databases | Reconnaissance | FINDING-01, 03 |
| **T1596.003** | Code Repositories (CT Logs) | Reconnaissance | FINDING-03 |
| **T1589** | Gather Victim Identity Information | Reconnaissance | FINDING-04 |
| **T1589.002** | Email Addresses | Reconnaissance | FINDING-04 |
| **T1598** | Phishing for Information | Reconnaissance | Enabled by FINDING-02 |
| **T1566.001** | Spearphishing Attachment | Initial Access | Enabled by FINDING-02, 04 |
| **T1190** | Exploit Public-Facing Application | Initial Access | FINDING-01 |
| **T1078** | Valid Accounts | Defense Evasion | FINDING-05 |

---

## Risk Assessment Summary

### DREAD Scoring

| Finding | Damage | Reproducibility | Exploitability | Affected Users | Discoverability | **Total /50** | **Rating** |
|---------|--------|-----------------|----------------|----------------|-----------------|---------------|------------|
| FINDING-01 (VPN RCE) | 10 | 9 | 9 | 10 | 9 | **47** | 🔴 Critical |
| FINDING-02 (No DMARC) | 9 | 10 | 10 | 10 | 8 | **47** | 🔴 Critical |
| FINDING-03 (Dev/Staging) | 8 | 8 | 7 | 6 | 9 | **38** | 🟠 High |
| FINDING-04 (Email List) | 6 | 8 | 9 | 7 | 9 | **39** | 🟠 High |
| FINDING-05 (OWA Portal) | 6 | 7 | 7 | 8 | 8 | **36** | 🟡 Medium |

### Overall Attack Surface Risk Rating: 🔴 HIGH

---

## Indicators of Compromise / Intelligence Artifacts

```
# High-Value Targets Identified
vpn.novacrest-capital.com       — GlobalProtect VPN (CVE-2021-3064 affected)
mail.novacrest-capital.com      — OWA Portal (credential stuffing target)
dev.novacrest-capital.com       — Exposed dev environment (PHPMyAdmin)
staging.novacrest-capital.com   — Staging environment (public cert)

# IP Addresses
203.0.113.45                    — Primary web/VPN IP (AS12345 — fictional)
203.0.113.46                    — Mail server IP

# CVEs Applicable
CVE-2021-3064                   — PAN-OS GlobalProtect RCE (CVSS 9.8)
CVE-2019-17440                  — PAN-OS auth bypass (CVSS 9.8)

# Email Naming Convention
firstname.lastname@novacrest-capital.com
```

---

## Prioritized Recommendations

| Priority | Action | Timeframe | Owner |
|----------|--------|-----------|-------|
| **P1 — Immediate** | Patch GlobalProtect to 9.1.11+ or upgrade to 10.x | 24 hours | IT Security |
| **P1 — Immediate** | Restrict VPN portal to allowlisted IPs + enforce MFA | 24 hours | Network Ops |
| **P1 — Immediate** | Change DMARC to `p=quarantine` as interim step | 48 hours | IT/Email Admin |
| **P2 — Short-term** | Change SPF from `~all` to `-all` after mail flow audit | 1 week | Email Admin |
| **P2 — Short-term** | Restrict dev/staging environments behind VPN | 1 week | DevOps |
| **P2 — Short-term** | Audit dev databases for production data presence | 1 week | IT Security |
| **P2 — Short-term** | Enforce MFA on OWA portal | 1 week | IT/M365 Admin |
| **P3 — Long-term** | Advance DMARC to `p=reject` after 30-day monitoring | 30 days | Email Admin |
| **P3 — Long-term** | Implement certificate transparency alerting (CertSpotter) | 30 days | IT Security |
| **P3 — Long-term** | Deploy executive email spearphishing training | 30 days | Security Awareness |

---

## Conclusion

This passive reconnaissance exercise demonstrates that a sophisticated threat actor
requires **no direct interaction with target systems** to build a comprehensive and
actionable intelligence picture of an organization's attack surface. The five findings
documented represent real, exploitable weaknesses that would serve as likely initial
access vectors in an actual intrusion campaign.

The combination of an unpatched internet-facing VPN portal (FINDING-01) and the
ability to send spoofed phishing emails that bypass all email authentication controls
(FINDING-02) represents the highest-priority attack path. These two findings alone
provide a realistic threat actor with both technical and social engineering initial
access vectors of the highest confidence.

**Remediation of P1 findings should begin within 24 hours of report delivery.**

---

## References

- [MITRE ATT&CK Reconnaissance Tactic](https://attack.mitre.org/tactics/TA0043/)
- [CVE-2021-3064 — Palo Alto GlobalProtect RCE](https://nvd.nist.gov/vuln/detail/CVE-2021-3064)
- [DMARC.org — Implementation Guide](https://dmarc.org/overview/)
- [Certificate Transparency — RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)
- [Shodan Documentation](https://help.shodan.io/)

---

*Previous: [SCENARIO.md](SCENARIO.md) | Next: [Day 02 →](../day-02/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
