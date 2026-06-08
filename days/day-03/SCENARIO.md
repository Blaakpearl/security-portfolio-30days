# Day 03 — Phishing Infrastructure Analysis
### Track: Threat Intelligence | Difficulty: Intermediate | Phase: Reconnaissance / Initial Access

---

## 🎯 Threat Brief

It's 11:15 on a Wednesday. Your organization's email gateway quarantined 14 messages
in the past 2 hours — all sharing a common trait: they impersonate your firm's
HR department with a subject line of **"Urgent: Benefits Enrollment Update Required."**

The emails contain a link to a convincing replica of your Microsoft 365 login portal.
One employee in the Accounts Payable department clicked the link before the gateway
rule fired. She stopped short of entering credentials when she noticed the URL looked
"a bit off" — and called the IT helpdesk immediately.

You caught a break. But the campaign is almost certainly still live and targeting
other firms in your sector. Your job is to **tear apart the infrastructure** — map
every domain, IP, hosting provider, and certificate associated with this phishing
kit — and produce an intelligence product that can be shared sector-wide so other
organizations can block the same infrastructure before they're hit.

This is the work of a **Threat Intelligence Analyst**: turning a single phishing URL
into a complete adversary infrastructure map.

---

## 🕵️ Threat Actor Profile

| Attribute | Details |
|-----------|---------|
| **Actor Type** | Financially motivated cybercriminal group |
| **Motivation** | Credential harvesting → BEC / wire fraud / account takeover |
| **Sophistication** | Medium-High — custom phishing kit, bulletproof hosting, anti-analysis |
| **Sector Targeting** | Financial services, healthcare, professional services |
| **Campaign Age** | Infrastructure registered 11 days ago — active campaign |
| **Prior Activity** | Infrastructure patterns match campaigns hitting 6 orgs in Q4 2024 |
| **TTPs** | T1566, T1583, T1584, T1056.003, T1539, T1114 |
| **Kit Features** | Real-time credential relay, MFA token interception (Evilginx-style) |

---

## 🏢 Incident Context

```
Trigger Event:    14 phishing emails quarantined by email gateway
Delivery Vector:  Spearphishing link (T1566.002) via compromised sending domain
Lure Theme:       HR benefits enrollment — Microsoft 365 credential harvester
Target:           NovaCrest Capital Group employees (207 attempted deliveries)
One Click:        Accounts Payable employee — no credentials entered
Gateway Rule:     Triggered on URL pattern match — 2hr delay from first delivery
Phishing URL:     hxxps://novacrest-benefits[.]microsoftonline-portal[.]com/signin
Kit Type:         Reverse proxy credential harvester (intercepts MFA tokens)
```

---

## 🔍 What Phishing Infrastructure Analysis Reveals

Most analysts stop at blocking the URL. A skilled threat intelligence analyst goes
much further — using a single indicator to map the **entire adversary operation:**

```
┌─────────────────────────────────────────────────────────────────────┐
│  SINGLE PHISHING URL                                                 │
│  hxxps://novacrest-benefits.microsoftonline-portal.com/signin        │
│                          │                                           │
│          ┌───────────────┼───────────────────┐                      │
│          ▼               ▼                   ▼                       │
│   Domain Analysis    IP / Hosting        Certificate                 │
│   • Registrar        • ASN / Provider    • Issued date               │
│   • Registration     • Shared hosting    • Common names              │
│   • DNS history      • Abuse history     • Cert transparency         │
│   • Typosquatting    • BGP routing       • Wildcard scope            │
│          │               │                   │                       │
│          └───────────────┼───────────────────┘                      │
│                          ▼                                           │
│              PIVOT — Find related infrastructure                     │
│              • Same registrar + same IP range                        │
│              • Same SSL cert fingerprint                             │
│              • Same phishing kit HTML fingerprint                   │
│              • Same hosting ASN with similar domain patterns        │
│                          │                                           │
│                          ▼                                           │
│              INFRASTRUCTURE CLUSTER MAP                              │
│              • 12 related phishing domains                           │
│              • 3 C2 IP addresses                                     │
│              • 2 bulletproof hosting providers                       │
│              • Campaign targeting 6+ organizations                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Detection Challenge

Modern phishing infrastructure is purpose-built to evade analysis:

- **Bulletproof hosting** — providers that ignore abuse reports; hosted in
  jurisdictions with limited law enforcement cooperation
- **Domain generation** — attackers register many look-alike domains (typosquatting,
  combosquatting) so blocking one has minimal impact
- **Certificate legitimacy** — free Let's Encrypt certificates make phishing sites
  appear "secure" to users (the padlock means nothing for trust)
- **Anti-sandbox techniques** — phishing kits detect automated analysis environments
  and serve benign content; human mouse movement required
- **Short TTL infrastructure** — phishing pages rotate IPs and domains rapidly;
  feeds go stale within 24–48 hours of a campaign

**The analyst's edge:** pivoting through passive sources (URLScan, Shodan, crt.sh,
VirusTotal) creates a wider net than any single blocking rule.

---

## 📚 Learning Objectives

1. Analyze a phishing URL using URLScan.io and extract full page metadata, IOCs, and screenshot evidence
2. Perform passive DNS analysis and WHOIS attribution to profile the threat actor's infrastructure choices
3. Use VirusTotal to pivot from a single URL to related domains, IPs, and file hashes
4. Query certificate transparency logs to discover the full scope of a phishing campaign
5. Detonate a phishing URL in a sandbox (Any.run) and analyze network behavior and credential relay mechanics
6. Structure findings as a STIX 2.1 threat intelligence object suitable for sharing via TAXII
7. Produce a sector-wide advisory IOC list in multiple formats (CSV, STIX, plain text)

---

## ✅ Success Criteria

- [ ] Extract and document all IOCs from the phishing URL (domain, IP, registrar, cert)
- [ ] Pivot from the initial domain to discover at least 3 related infrastructure items
- [ ] Identify the hosting provider / ASN and document its bulletproof-hosting reputation
- [ ] Produce a YARA rule targeting the phishing kit's HTML fingerprint
- [ ] Export IOCs in STIX 2.1 JSON format
- [ ] Write one Sigma rule for email gateway detection of this campaign
- [ ] Complete the infrastructure cluster map diagram in `artifacts/`

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1566.002** | Phishing: Spearphishing Link | Initial Access | Delivery vector |
| **T1583.001** | Acquire Infrastructure: Domains | Resource Development | Attacker registered phishing domain |
| **T1583.002** | Acquire Infrastructure: DNS Server | Resource Development | Custom DNS configuration |
| **T1584.004** | Compromise Infrastructure: Server | Resource Development | Compromised sending domain |
| **T1056.003** | Input Capture: Web Portal Capture | Collection | Credential harvesting page |
| **T1539** | Steal Web Session Cookie | Credential Access | Reverse proxy MFA bypass |
| **T1114.003** | Email Collection: Email Forwarding Rule | Collection | Post-compromise step |
| **T1036.005** | Masquerading: Match Legitimate Name | Defense Evasion | Domain typosquatting |

---

*Next: [LAB.md](LAB.md) — Step-by-step phishing infrastructure analysis guide*
