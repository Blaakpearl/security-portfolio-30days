# Day 28 — OSINT Investigation Report
## FIN-NC-001: Infrastructure Mapping & Campaign Analysis
**NovaCrest Capital Group | Threat Intelligence**
**Classification:** TLP:AMBER — Attorney-Client Privileged
**Author:** V. Willis, CISSP
**Date:** 2026-06-28
**Distribution:** CISO, Legal Counsel, FBI Cyber Division Liaison

---

## 1. Investigation Summary

Passive OSINT investigation pivoting from C2 IP `198.51.100.99` has produced
a complete infrastructure map for FIN-NC-001, corroborating four confirmed
victim campaigns between March and June 2026. The investigation identifies a
highly consistent operational playbook with measurable timing signatures that
can serve as early warning indicators for the actor's next campaign.

| Finding | Detail |
|---------|--------|
| Infrastructure nodes mapped | 6 domains + 2 C2 IPs |
| Confirmed prior victims | 4 (NovaCrest + 3) |
| Potential 5th victim | Unconfirmed — `capitalupdates.org` domain (April 2026) |
| Campaign cadence | ~50 days between victims |
| Infrastructure prep lead time | 8 days (domain reg → phishing delivery) |
| OPSEC rating | 5.8/10 — Moderate-Advanced |
| Key OPSEC weakness | Static C2 IP maintained 3+ months; predictable naming |
| Total ransom demanded (4 victims) | $12M USD equivalent |
| Ransom paid | 1 of 4 victims (US Hedge Fund, May 2026) |

---

## 2. Infrastructure Map

### C2 Cluster (198.51.100.0/24 | AS209588)

```
AS209588 — Flyservers S.A.
├── Registered: Panama (company); physically hosted Netherlands
├── Known abuse-resistant bulletproof hosting
├── 23 prior abuse reports on file
├── FS-ISAC TLP:WHITE advisory (April 2026)
│
├── 198.51.100.99 [PRIMARY C2]
│   ├── JARM: 1dd28f00...15c (Sliver C2)
│   ├── Ports: 443, 80, 8443, 22
│   ├── TLS CN: trading-updates.novacrest-secure.com
│   ├── Server: nginx/1.24.0 (consistent across campaigns)
│   └── Domains resolved here (historical):
│       ├── trading-updates.novacrest-secure.com (Jun 2026 → NovaCrest)
│       ├── updates-cdn.financialdata.net (Apr 2026 → EU Asset Mgr)
│       ├── telemetry.marketsync.io (May 2026 → US Hedge Fund)
│       └── secure-trading-api.financedocs.net (Mar 2026 → UK PE)
│
└── 198.51.100.101 [SECONDARY C2 — discovered via ASN pivot]
    ├── JARM: 1dd28f00...15c (same — second Sliver instance)
    ├── Ports: 443, 8080
    ├── TLS CN: api-gateway.fintradeops.com
    └── Status: Currently active
```

### Domain Naming Pattern

Every FIN-NC-001 phishing domain follows the same formula:

```
[finance/trading theme] + [-] + [action/service term] + [.com/.net/.org]

Examples:
  trading-updates.novacrest-secure.com    ← Finance + action + typosquat
  updates-cdn.financialdata.net           ← Action + finance
  telemetry.marketsync.io                 ← Action + finance
  secure-trading-api.financedocs.net      ← Finance + action + finance
  portfolio-sync.capitalupdates.org       ← Finance + action + finance
```

This naming pattern is fingerprint-quality — no legitimate financial services
firm uses this exact vocabulary combination in their actual domain names.
Adding this pattern to the domain registration monitoring watchlist (Query O-3)
provides 6+ days of warning before the next phishing campaign.

---

## 3. Certificate Transparency Analysis

Every domain in the FIN-NC-001 cluster used Let's Encrypt for TLS certificates.
This is a meaningful OPSEC choice: Let's Encrypt leaves no financial paper trail,
is fully automated, and is free. But it creates a detection opportunity.

**Key timing finding:** Across all four campaigns, certificates were issued
**2 days after domain registration** and **6 days before phishing delivery**.
This is a clockwork preparation sequence:

```
Day 0:  Domain registered (Namecheap or GoDaddy; privacy-protected)
Day 2:  Let's Encrypt cert issued (automated; certbot/acme.sh)
Day 6:  Cloudflare DNS propagated; infrastructure validated
Day 8:  Phishing campaign launched against target
Day 13: Ransomware deployed (Day 8 + 5-day dwell)
```

The cert issuance → phishing window is consistent enough to be a predictive
signal: a new Let's Encrypt cert for a finance-themed domain resolving to
AS209588 should be treated as an imminent attack preparation indicator.

---

## 4. Campaign Timeline & Pattern Analysis

### Four-Victim Timeline

| Date | Victim | Event |
|------|--------|-------|
| Mar 8, 2026 | UK Private Equity | Domain `financedocs.net` registered |
| Mar 14, 2026 | UK Private Equity | Phishing delivered — ESG Summit lure |
| Mar 19, 2026 | UK Private Equity | Ransomware deployed; $2.1M demanded |
| Mar 22, 2026 | UK Private Equity | Deadline expired; did not pay |
| Apr 3, 2026 | EU Asset Manager | Phishing delivered — Q1 Summit lure |
| Apr 5, 2026 | UK PE | **Data published** on leak site |
| Apr 8, 2026 | EU Asset Manager | Ransomware deployed; $2.6M demanded |
| Apr 11, 2026 | EU Asset Manager | Deadline expired; did not pay |
| Apr 25, 2026 | Potential 5th | Domain `capitalupdates.org` registered |
| May 2, 2026 | US Hedge Fund | Phishing delivered — Private Credit Forum lure |
| May 7, 2026 | US Hedge Fund | Ransomware deployed; $3.1M demanded |
| May 10, 2026 | US Hedge Fund | Deadline; **paid** (negotiated -35%) |
| May 12, 2026 | US Hedge Fund | Leak site entry removed (payment confirmed) |
| Jun 8, 2026 | NovaCrest | Domain `novacrest-secure.com` registered |
| Jun 14, 2026 | NovaCrest | Phishing delivered — FinTech Summit lure |
| Jun 19, 2026 | NovaCrest | Ransomware deployed; $4.2M demanded |
| Jun 22, 2026 | NovaCrest | **Deadline** (this report date) |

### Escalating Victim Profile

```
Campaign 1: $2.1B AUM → $2.1M demanded
Campaign 2: $2.6B AUM → $2.6M demanded
Campaign 3: $3.1B AUM → $3.1M demanded
Campaign 4: $4.2B AUM → $4.2M demanded

Formula: Ransom ≈ 0.1% of target AUM (consistent across all 4 victims)
Trend: AUM target increasing by ~$0.5-1.1B per campaign
Next predicted: $5–6B AUM target → $5-6M demanded
```

---

## 5. Actor OPSEC Assessment

### Strengths (What They Do Well)

- **Bulletproof hosting:** AS209588 is genuinely abuse-resistant; IP maintained for 3+ months without takedown
- **Privacy protection:** All domains use WHOIS privacy; registrant identity completely hidden
- **Cloudflare DNS:** Hides origin IP from passive DNS; adds CDN layer
- **Tor leak site:** High-availability hidden service; professionally maintained
- **Let's Encrypt automation:** No financial trail; no certificate authority that can revoke based on abuse report alone

### Weaknesses (What They Expose)

- **Static C2 IP** (3+ months): Sophisticated actors rotate IPs every 4-6 weeks. The same IP being used across 4 victim campaigns is a significant detection signal — and now it's in FS-ISAC.
- **Domain naming pattern**: The finance + action formula is consistent enough to fingerprint. A threat intel system watching CT logs for this pattern would flag every new domain within hours of registration.
- **Unchanged JARM fingerprint**: Same Sliver instance (or same Sliver configuration) across all campaigns. A JARM rotation would require only 5 minutes of work and would invalidate detection rule DET-002.
- **Conference lure pattern**: Every phishing lure references a specific financial sector conference. An attacker with better OPSEC would vary the pretext.
- **6-day infrastructure prep window**: This is consistent enough to be a predictive signal. A monitored CT log would give sector defenders 6 days of warning.

---

## 6. Dark Web Findings

### Leak Site (`ncrypt3k4j7mxbwz.onion`)

- **First observed:** February 20, 2026 — predates first known victim by 3 weeks
- **Victim count:** 4 pages (3 with published data; NovaCrest pending)
- **Site quality:** Professional; consistent formatting; English only; no grammar errors
- **Group branding:** "ncrypt" — distinctive; consistent with binary name and extension

### Victim Policy

The actor's behavior across four victims reveals a clear policy:

1. Victims who **don't engage**: Data published on deadline
2. Victims who **negotiate and pay**: Leak site entry removed (US Hedge Fund paid, data was removed within hours)
3. Victims who **negotiate but don't pay**: Data published at deadline

This policy is actually rational and consistently applied — the US Hedge Fund received exactly what was promised when they paid. This legitimizes the threat of publication for NovaCrest, as the actor has demonstrated follow-through.

---

## 7. Next Campaign Prediction

Based on the 50-day average campaign spacing:

```
Last phishing: June 14, 2026 (NovaCrest)
Next estimated: ~August 3, 2026 (±2 weeks)
Infrastructure prep: ~July 26, 2026 (watch CT logs from this date)
Next target profile: US or EU financial services, $5-6B AUM
Expected lure: Q3 investment conference or fund performance review
Expected ransom: ~$5-6M USD in Monero
```

### Early Warning Checklist (Share with FS-ISAC)

```
Watch for (July 26 onward):
  □ New domain registered: [finance/trading term]-[action/service].[tld]
  □ At Namecheap or GoDaddy with privacy protection
  □ Let's Encrypt cert within 2 days of registration
  □ Domain resolves to AS209588 (198.51.100.0/24 range)
  □ nginx/1.24.0 banner on port 443
  □ Sliver JARM: 1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c
```

---

## 8. Recommendations

1. **Immediate:** Submit this domain list + JARM + ASN to FS-ISAC for sector-wide blocking before the next campaign
2. **Immediate:** Notify FBI Cyber Division — this report is suitable as an investigative lead
3. **This week:** Configure CT log monitoring for the naming pattern (see Query O-3/O-4)
4. **This month:** Build JARM-based detection into NGFW ruleset — any external host with Sliver JARM should be blocked
5. **Ongoing:** Monitor Ransomwatch for NovaCrest leak site status (data publication = regulatory trigger)
6. **Sector:** Prepare FS-ISAC TLP:WHITE advisory using redacted IOC set — other firms need 6+ days warning

---

*Day 28 — OSINT Investigation Report | FIN-NC-001*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
