# Day 01 — Recon & Footprinting
### Track: OSINT | Difficulty: Intermediate | Phase: Pre-Intrusion Reconnaissance

---

## 🎯 Threat Brief

A Fortune 500 financial services firm — **NovaCrest Capital Group** (fictional) — has been
flagged by their threat intelligence feed. Indicators suggest a nation-state-aligned threat
actor has begun systematic passive reconnaissance of their external attack surface in the
weeks preceding a targeted intrusion campaign against the financial sector.

Your role: **act as the attacker's reconnaissance analyst** to map exactly what they can
see — before they use it against you. The intelligence you gather will directly feed the
firm's attack surface reduction program.

---

## 🕵️ Threat Actor Profile

| Attribute         | Details                                                                 |
|-------------------|-------------------------------------------------------------------------|
| **Actor Type**    | Nation-state aligned / Advanced Persistent Threat                      |
| **Motivation**    | Financial intelligence theft, market manipulation data, M&A strategy   |
| **Sophistication**| High — APT-level OPSEC, patient multi-phase approach                   |
| **Sector Target** | Financial services, investment banking, hedge funds                     |
| **Known TTPs**    | T1590, T1591, T1596, T1589 — passive recon before spearphishing        |
| **Dwell Patience**| Recon phase observed lasting 30–90 days before first intrusion attempt |

---

## 🏢 Target Environment — NovaCrest Capital Group

```
Organization:     NovaCrest Capital Group (fictional stand-in: use your own test domain)
Industry:         Financial Services / Investment Banking
Employee Count:   ~2,400 globally
Headquarters:     New York, NY
Key Offices:      London, Singapore, Dubai
Public Presence:  Corporate website, LinkedIn, press releases, SEC filings
Tech Stack:       Microsoft 365, Azure AD, Cisco edge, Palo Alto firewalls (inferred)
```

**Assets at risk:**
- Customer PII and financial account data
- M&A deal intelligence (pre-announcement)
- Proprietary trading algorithms
- Executive communications

---

## 🔍 Reconnaissance Scope — What the Attacker Wants to Map

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER 1 — Network Infrastructure                                 │
│  • IP ranges & ASN ownership                                     │
│  • Exposed ports & services (Shodan)                            │
│  • SSL/TLS certificates (cert transparency logs)                │
│  • DNS records (A, MX, TXT, CNAME, SPF, DMARC)                │
├─────────────────────────────────────────────────────────────────┤
│  TIER 2 — Technology Fingerprinting                              │
│  • Web tech stack (headers, CMS, CDN)                           │
│  • Remote access portals (VPN, Citrix, RDP, OWA)              │
│  • Cloud services (AWS S3, Azure blobs, GCP buckets)           │
│  • Email security posture (SPF/DKIM/DMARC gaps)               │
├─────────────────────────────────────────────────────────────────┤
│  TIER 3 — Human Intelligence Surface                             │
│  • Employee names, roles, LinkedIn profiles                     │
│  • Email address format discovery                               │
│  • Third-party vendor relationships                             │
│  • Job postings (reveals internal tech stack)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Detection Challenge

This reconnaissance phase is **entirely passive** — no active scanning, no packets
sent to the target. The attacker uses:

- **Publicly indexed data** (Shodan, Censys cache previously-scanned results)
- **Certificate transparency logs** (public by design)
- **DNS records** (public by design)
- **Social media & OSINT** (no interaction with target systems)

**Result:** Traditional security monitoring (firewall logs, IDS/IPS, EDR) generates
**zero alerts** during this phase. The only defensive countermeasure is proactive
attack surface reduction — you must know your exposure before the attacker does.

---

## 📚 Learning Objectives

1. Perform a complete passive external recon using Shodan, Censys, and certificate transparency
2. Enumerate DNS infrastructure and identify security misconfigurations
3. Map exposed services and remote access portals that represent high-value entry points
4. Assess email security posture via SPF/DKIM/DMARC record analysis
5. Identify technology stack through passive fingerprinting
6. Produce a professional attack surface report with risk-rated findings

---

## ✅ Success Criteria

- [ ] Identify at least 3 exposed services or open ports on the target's IP range
- [ ] Map SSL/TLS certificate relationships to discover subdomains
- [ ] Confirm presence or absence of SPF, DKIM, DMARC records
- [ ] Identify at least 1 remote access portal (VPN/OWA/Citrix/RDP)
- [ ] Document technology stack indicators from passive sources
- [ ] Produce a risk-rated asset inventory with at least 5 entries
- [ ] Export findings as IOC list and save to `artifacts/`

---

## 🧪 Lab Environment Note

> **Ethics & Legality:** This lab uses **publicly available tools against publicly
> accessible data only**. For practice, use your own domain, a purpose-built
> practice target such as `scanme.nmap.org`, or intentionally vulnerable ranges.
> **Never run reconnaissance against organizations without explicit written authorization.**
>
> Real-world application of these skills requires a signed Rules of Engagement (ROE) document.

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| **T1590** | Gather Victim Network Information | Reconnaissance | IP ranges, ASN, topology |
| **T1590.001** | IP Addresses | Reconnaissance | Shodan/Censys IP enumeration |
| **T1590.004** | Network Topology | Reconnaissance | AS path, BGP route mapping |
| **T1591** | Gather Victim Org Information | Reconnaissance | LinkedIn, website, filings |
| **T1596** | Search Open Technical Databases | Reconnaissance | Shodan, Censys, crt.sh |
| **T1596.003** | Code Repositories | Reconnaissance | GitHub secrets scanning |
| **T1589** | Gather Victim Identity Information | Reconnaissance | Email formats, employee names |
| **T1589.002** | Email Addresses | Reconnaissance | Hunter.io, LinkedIn |

---

*Next: [LAB.md](LAB.md) — Step-by-step hands-on lab guide*
