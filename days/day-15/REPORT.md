# Day 15 — REPORT.md
## Purple Team Consolidated Findings: Red-Side Reconnaissance Operation
**NovaCrest Capital Group | Week 3 Adversary Simulation**
**Classification:** TLP:AMBER — Authorized Engagement Participants Only
**Author:** V. Willis, CISSP — Purple Team Lead
**Date:** 2026-06-15
**Version:** 1.0 Final

---

## 1. Executive Summary

On June 15, 2026 (08:00–10:30 UTC), the red team conducted a fully authorized 2.5-hour passive reconnaissance operation against NovaCrest Capital Group's external-facing infrastructure. The purple team observed, timestamped, and documented all red team activities, then coordinated a retrospective blue team review of detection coverage.

**The operation demonstrated that a motivated, intermediate-skill threat actor can build a complete exploitation-ready target package against NovaCrest in under three hours using only public, free or low-cost tools — without triggering a single real-time alert.**

Key outcomes:

| Metric | Result |
|--------|--------|
| Red team phases completed | 10 of 10 |
| Real-time alerts generated | 0 |
| Phases detectable with current tools | 3 (misconfigured) |
| Phases inherently undetectable | 7 |
| Exposed credentials discovered | 8 (in GitHub) |
| Internal IP addresses disclosed | 3 (via public DNS) |
| Employee targets identified | 340+ |
| Databases exposed to internet | 2 (MySQL, PostgreSQL) |
| Time to actionable exploitation | Est. 24–48 hours |

**Threat Level: CRITICAL.** The most immediately dangerous finding — AWS credentials hardcoded in a public GitHub repository — requires no exploitation skill. Rotate immediately.

---

## 2. Purple Team Methodology

The purple team maintained dual visibility across the engagement:

**Red Team Liaison** — Received advance notification of each phase start time; logged all activities with timestamps; confirmed scope compliance; flagged any ROE concerns in real time.

**Blue Team Liaison** — Monitored SIEM dashboards during the engagement window without knowledge of red team timing; documented what fired (nothing) and what log evidence was present.

**Timeline Reconciliation** — At 10:30 UTC, red team provided full activity log; blue team cross-referenced against log evidence; purple team documented the delta as detection gaps.

**ATT&CK Mapping** — Purple team mapped each activity to MITRE ATT&CK Reconnaissance sub-techniques (see Section 4).

---

## 3. Consolidated Findings by Phase

### Phase 1 — Certificate Transparency Queries
**Time:** 08:00–08:15 UTC  
**ATT&CK:** T1593.003 (Code Repositories), T1590.002 (DNS)  
**Finding:** 3 certificates enumerated; wildcard `*.novacrest.com` exposes all subdomain names  
**Detected:** No  
**Detectable:** No (external service)  
**Red Team Value:** Medium — confirmed subdomains in cert SANs before DNS brute-force  
**Remediation:** Use specific-domain certificates instead of wildcards; subscribe to CT monitoring

---

### Phase 2 — Passive DNS Reconnaissance
**Time:** 08:15–08:30 UTC  
**ATT&CK:** T1590.002 (DNS), T1590.004 (Network Topology)  
**Finding:** 10 subdomains resolved; 3 internal IPs (`10.0.x.x`) disclosed in public DNS  
**Detected:** No  
**Detectable:** No (external API queries)  
**Red Team Value:** High — full subdomain-to-IP mapping with no active probing  
**Remediation:** Split-horizon DNS; remove internal IPs from public DNS records

---

### Phase 3 — WHOIS & ASN Lookup
**Time:** 08:30–08:45 UTC  
**ATT&CK:** T1590.001 (Domain Properties), T1590.004 (Network Topology)  
**Finding:** 4 netblocks identified; registrant email `noc@novacrest.com` exposed  
**Detected:** No  
**Detectable:** No (public registry)  
**Red Team Value:** Medium — IP space confirmed; registrant contact for targeting  
**Remediation:** Enable WHOIS privacy; remove direct employee contacts from registrant fields

---

### Phase 4 — Shodan / Censys Internet Scanning
**Time:** 08:45–09:00 UTC  
**ATT&CK:** T1596.005 (Scan Databases)  
**Finding:** 5 exposed services; databases on 3306/5432 open to untrusted IPs; RDP on 3389 open  
**Detected:** No  
**Detectable:** No (red team queries Shodan's cached data; Shodan scanned NovaCrest previously)  
**Red Team Value:** Critical — exposed databases represent immediate exploitation path  
**Remediation:** Firewall 3306, 5432, 3389 from untrusted IPs (Priority 1)

---

### Phase 5 — Subdomain Enumeration
**Time:** 09:00–09:15 UTC  
**ATT&CK:** T1590.002 (DNS)  
**Finding:** 7 additional subdomains (including `dev`, `test`, `backup`, `staging`)  
**Detected:** No (threshold misconfigured — set at 100 NXDOMAIN; should be 20)  
**Detectable:** YES — bulk NXDOMAIN responses detectable with tuned threshold  
**Red Team Value:** Medium — dev/staging hosts expand attack surface  
**Remediation:** Tune NXDOMAIN alert from 100 → 20 per external IP per 5 minutes

---

### Phase 6 — GitHub Repository Scanning
**Time:** 09:15–09:30 UTC  
**ATT&CK:** T1589.001 (Credentials), T1593.003 (Code Repositories)  
**Finding:** 2 public repos; 8 hardcoded secrets (AWS keys, DB passwords, RSA private key)  
**Detected:** No  
**Detectable:** No (GitHub is public; searches leave no internal trace)  
**Red Team Value:** Critical — AWS credentials allow immediate cloud infrastructure compromise  
**Remediation:** Rotate all credentials immediately; enable GitHub Secret Scanning; implement pre-commit hooks; make internal repos private

---

### Phase 7 — Email Harvesting
**Time:** 09:30–09:45 UTC  
**ATT&CK:** T1589.002 (Email Addresses), T1589.003 (Employee Names), T1591.004 (Identify Roles)  
**Finding:** 340+ employee email addresses; org chart mapped; C-suite identified  
**Detected:** No (SMTP rejection alert not configured)  
**Detectable:** YES — SMTP validation attempts generate loggable rejection events  
**Red Team Value:** High — enables targeted spearphishing; BEC attack planning  
**Remediation:** Configure SMTP rejection threshold alert; disable VRFY/EXPN; implement SMTP rate limiting

---

### Phase 8 — Web Server Fingerprinting
**Time:** 09:45–10:00 UTC  
**ATT&CK:** T1592.002 (Software), T1592.004 (Client Configurations)  
**Finding:** Apache 2.4.41, nginx 1.18.0, IIS 10.0, PHP 7.4.3 (EOL), ASP.NET 4.0; 15+ known CVEs  
**Detected:** No  
**Detectable:** No (indistinguishable from normal HTTP traffic)  
**Red Team Value:** High — known-exploitable software versions; RCE paths identified  
**Remediation:** Remove version strings from HTTP headers; patch or upgrade flagged software

---

### Phase 9 — DNS Zone Transfer Attempts
**Time:** 10:00–10:10 UTC  
**ATT&CK:** T1590.002 (DNS)  
**Finding:** Both NS servers refused AXFR (correct behavior)  
**Detected:** No (AXFR alert rule not deployed in SIEM)  
**Detectable:** YES — AXFR queries are unambiguous; extremely low false-positive rate  
**Red Team Value:** Low — blocked; no zone data obtained  
**Remediation:** Add AXFR detection rule to SIEM (30 minutes; high-value, near-zero false positives)

---

### Phase 10 — SMTP Banner Grabbing
**Time:** 10:10–10:30 UTC  
**ATT&CK:** T1592.004 (Client Configurations)  
**Finding:** Postfix 3.4.8 and Sendmail 8.15.1 version disclosed; both have known CVEs including RCE  
**Detected:** No (external SMTP connections not alerted on)  
**Detectable:** YES — external connections to TCP:25 without mail delivery detectable via SMTP session logging  
**Red Team Value:** High — Sendmail 8.15.1 has RCE vulnerability (CVE-2021-3438)  
**Remediation:** Remove version from SMTP banner; patch Sendmail; configure SMTP session logging

---

## 4. MITRE ATT&CK Heat Map

```
RECONNAISSANCE (TA0043)
═══════════════════════════════════════════════════════════════
T1589 — Gather Victim Identity Information
  T1589.001 Credentials                    ■■■■■  CRITICAL (GitHub secrets)
  T1589.002 Email Addresses                ■■■■░  HIGH (340+ harvested)
  T1589.003 Employee Names                 ■■■░░  MEDIUM (LinkedIn scraping)

T1590 — Gather Victim Network Information
  T1590.001 Domain Properties              ■■░░░  LOW (WHOIS data)
  T1590.002 DNS                            ■■■■░  HIGH (subdomain enum + zone xfer)
  T1590.004 Network Topology               ■■■░░  MEDIUM (netblock mapping)
  T1590.005 IP Addresses                   ■■■░░  MEDIUM (Shodan resolution)

T1591 — Gather Victim Organization Info
  T1591.002 Business Relationships         ■■░░░  LOW (SPF reveals SendGrid)
  T1591.004 Identify Roles                 ■■■░░  MEDIUM (org chart mapped)

T1592 — Gather Victim Host Information
  T1592.002 Software                       ■■■■░  HIGH (version disclosures)
  T1592.004 Client Configurations          ■■■░░  MEDIUM (HTTP headers, banners)

T1593 — Search Open Websites/Domains
  T1593.001 Social Media                   ■■■░░  MEDIUM (LinkedIn)
  T1593.003 Code Repositories              ■■■■■  CRITICAL (GitHub secrets)

T1596 — Search Open Technical Databases
  T1596.001 DNS/Passive DNS                ■■■░░  MEDIUM (Censys/SecurityTrails)
  T1596.005 Scan Databases                 ■■■■░  HIGH (Shodan exposure)

Legend: ■ = Technique exercised/exposed   ░ = Partial coverage
        ■■■■■ = Critical finding   ■■■■░ = High   ■■■░░ = Medium
```

---

## 5. Detection Performance Summary

### What Fired (Real-Time)
**Nothing.** Zero alerts during the 2.5-hour operation window.

### What Could Have Fired (With Existing Infrastructure)

| Phase | Existing Log Source | Why It Didn't Fire | Fix Effort |
|---|---|---|---|
| Subdomain Enumeration | DNS server query log | NXDOMAIN threshold set at 100 (should be 20) | 2 hours |
| Email Harvesting | SMTP rejection log | No alert rule configured | 4 hours |
| DNS Zone Transfer | DNS server query log | AXFR rule not in SIEM ruleset | 30 min |
| SMTP Banner Grabbing | Firewall egress log | No alert for external port 25 connections | 4 hours |

**4 of 10 phases** were detectable with existing tooling. All 4 failed due to **configuration gaps, not capability gaps.** No new tooling is required to address these.

### What Cannot Be Detected (Structural Gaps)

| Phase | Reason |
|---|---|
| CT Log Queries | External service; no internal log trail |
| Passive DNS | External API calls from red team IP; no visibility |
| WHOIS Lookups | Public registry; inherently unmonitorable |
| Shodan/Censys Searches | External service; targets already scanned by Shodan |
| GitHub Scanning | Public platform; searches leave no trace |
| Web Fingerprinting | Indistinguishable from legitimate HTTP traffic |

For these 6 phases, the only effective countermeasure is **exposure reduction** — removing or obscuring the data that makes reconnaissance valuable. Detection is structurally impossible.

---

## 6. Risk Register

| Finding | Severity | Exploitability | Recommended Action | Owner |
|---------|----------|---------------|-------------------|-------|
| AWS credentials in GitHub | Critical | Immediate (no skill required) | Rotate now; audit commit history | Engineering |
| PostgreSQL (5432) public | Critical | High (default creds likely) | Firewall from untrusted IPs today | Infrastructure |
| MySQL (3306) public | Critical | High | Firewall from untrusted IPs today | Infrastructure |
| RDP (3389) public | Critical | High (brute-force target) | VPN-gate or firewall today | Infrastructure |
| Sendmail 8.15.1 RCE (CVE-2021-3438) | High | Moderate (requires net access) | Patch or upgrade mail server | Infrastructure |
| 340+ employees targeted | High | Moderate (spearphishing skill) | Security awareness training | Security |
| Internal IPs in public DNS | High | Low (aids lateral movement) | Split-horizon DNS | Infrastructure |
| PHP 7.4.3 EOL | High | Moderate | Upgrade PHP | Engineering |
| WordPress 5.8 outdated | High | Moderate | Upgrade WordPress | Engineering |
| Apache 2.4.41 unpatched | High | Moderate | Patch Apache | Infrastructure |
| Wildcard cert (*.novacrest.com) | Medium | Low (enables subdomain mapping) | Use specific certs | Security |
| HTTP version disclosure | Medium | Low (aids targeting) | Remove Server headers | Engineering |
| SMTP version disclosure | Medium | Low (aids targeting) | Remove banner version | Infrastructure |
| Weak DMARC policy | Medium | Moderate (enables spoofing) | Set p=reject | Security |

---

## 7. Remediation Roadmap

### Immediate (Before Day 16)

```
1. Rotate GitHub-exposed credentials
   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY  → Revoke in AWS IAM; generate new
   DB_PASSWORD                               → Change in all environments
   API_TOKEN                                 → Revoke at API provider
   RSA PRIVATE KEY                           → Generate new keypair; deploy

2. Firewall exposed databases and RDP
   iptables -A INPUT -p tcp --dport 3306 -s ! 10.0.0.0/8 -j DROP
   iptables -A INPUT -p tcp --dport 5432 -s ! 10.0.0.0/8 -j DROP
   iptables -A INPUT -p tcp --dport 3389 -s ! 10.0.0.0/8 -j DROP

3. Deploy AXFR alert rule (30 minutes)
   Add Query 10 from splunk_recon_detection.spl to SIEM
   Threshold: any AXFR from non-DNS-server IP = immediate alert
```

### This Week

```
4. Tune NXDOMAIN alert threshold
   Current: 100 per IP per 5 minutes
   Target: 20 per IP per 5 minutes (external sources only)

5. Enable SMTP rejection rate alert
   Threshold: >20 rejections from single IP in 10 minutes

6. Enable SMTP session logging (not just connection logging)
   Allows detection of banner-grab pattern (connect + EHLO + disconnect)

7. Make internal GitHub repos private
   novacrest/internal-tools → private immediately
   novacrest/trading-api → private + audit for more secrets

8. Enable GitHub Advanced Security
   → Secret scanning (free for public repos)
   → Configure pre-commit hooks (detect-secrets)

9. Strip HTTP version headers
   Apache: ServerTokens Prod (add to httpd.conf)
   nginx: server_tokens off (add to nginx.conf)
   Remove X-Powered-By, X-AspNet-Version headers

10. Remove SMTP banner version string
    Postfix: smtpd_banner = $myhostname ESMTP (edit /etc/postfix/main.cf)
```

### This Month

```
11. Patch or upgrade flagged software
    Apache 2.4.41 → 2.4.62 (current)
    nginx 1.18.0 → 1.26.x (current)
    PHP 7.4.3 → 8.3.x (7.4 is EOL)
    WordPress 5.8 → 6.x current
    Sendmail 8.15.1 → remove/replace with Postfix or upgrade
    Postfix 3.4.8 → 3.8.x (current)

12. Implement split-horizon DNS
    Internal queries → return RFC1918 IPs
    External queries → return only public IPs for internet-facing services
    Remove internal.novacrest.com, staging.novacrest.com from external DNS

13. Subscribe to CT log monitoring
    Google Certificate Transparency Monitor (free)
    Alerts on unexpected certificate issuance for novacrest.com

14. Conduct Shodan self-assessment
    shodan search "org:NovaCrest Capital" → review your own exposure
    Schedule quarterly recurring self-assessment

15. Strengthen DMARC policy
    Current: p=quarantine
    Target: p=reject (blocks spoofed emails entirely)
    Timeline: Test p=quarantine for 30 days → migrate to p=reject
```

### This Quarter

```
16. Deploy egress proxy with TLS inspection
    Visibility into outbound API calls (Shodan, Censys queries from internal network)
    Note: Only catches recon FROM inside; external recon remains invisible

17. Implement CASB for GitHub/SaaS monitoring
    Cloud Access Security Broker: monitors employee GitHub activity
    Alerts on public repo creation or secret patterns in commits

18. Employee security awareness training
    340+ employees are phishing targets
    Quarterly simulation recommended; focus on spearphishing indicators

19. External attack surface management (EASM) tool
    Continuous automated external scanning of your own infrastructure
    Tools: Censys ASM, Mandiant ASM, CrowdStrike Falcon Surface
    Fills the gap of knowing what adversaries see before they do
```

---

## 8. Key Takeaways for Purple Team Practice

**Takeaway 1: Passive reconnaissance is structurally undetectable.**
Six of ten reconnaissance phases left zero log evidence inside NovaCrest's environment. This is not a detection failure — it's an architectural reality. Defenders must accept this and focus energy on exposure reduction rather than chasing phantom detection of external OSINT queries.

**Takeaway 2: Configuration gaps are more common than capability gaps.**
Four detectable phases weren't caught because of misconfigured thresholds (NXDOMAIN at 100, not 20) and missing alert rules (no AXFR detection, no SMTP rejection rate). The infrastructure exists. The rules don't. This is the most actionable finding from blue team retrospectives: what could have fired with existing tools?

**Takeaway 3: GitHub is a crown jewel exposure vector that organizations consistently underweight.**
Hardcoded credentials in public repositories represent the highest-impact, lowest-skill exploitation path discovered in the operation. The AWS key can be used immediately with `aws configure` — no vulnerability exploitation, no lateral movement required. The detection countermeasure (GitHub Secret Scanning) is free for public repositories and takes 15 minutes to enable. The risk-to-remediation ratio is as favorable as it gets.

**Takeaway 4: The best reconnaissance countermeasure is having less to find.**
For every phase that's undetectable, there's usually a corresponding surface reduction action: strip HTTP headers, remove version from SMTP banners, use specific certificates instead of wildcards, remove internal IPs from public DNS, close database ports. These don't detect reconnaissance — they make reconnaissance less useful.

**Takeaway 5: 24 hours is a realistic time-to-exploitation estimate.**
With exposed credentials, public database ports, and a 340-person spearphishing target list, a motivated actor does not need zero-day exploits or significant skill to achieve initial access against NovaCrest. The reconnaissance phase is complete. Day 16 will demonstrate the initial access phase that logically follows.

---

## 9. Engagement Sign-Off

| Role | Name | Sign-Off |
|------|------|---------|
| Purple Team Lead | V. Willis, CISSP | ✅ Approved |
| Red Team Lead | [Engagement Operator] | ✅ Confirmed activities as documented |
| Blue Team Lead | [SOC Analyst] | ✅ Confirmed log review complete |
| Engagement Sponsor | [NovaCrest CISO] | ⏳ Pending review |

---

## 10. Day 16 Preview

**Next Session:** Initial Access — Credential Exploitation & Spearphishing Simulation

Building on Day 15's reconnaissance findings, Day 16 will simulate two parallel initial access paths:

- **Path A:** Credential exploitation — using GitHub-exposed AWS credentials to access cloud infrastructure; attempting database login with exposed credentials
- **Path B:** Spearphishing simulation — crafting a targeted email to the CTO (John Smith, `j.smith@novacrest.com`) leveraging org chart intelligence; analyzing what email security controls would detect or block delivery

Blue team will configure email gateway defenses and measure detection against both paths.

---

*Day 15 — Purple Team Consolidated Report*
*Week 3 Red-Side Reconnaissance Operation | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
