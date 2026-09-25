# Day 28 — SCENARIO.md
## OSINT Investigation Report: FIN-NC-001 Infrastructure & Personnel
**NovaCrest Capital Group | Threat Intelligence**
**Classification:** TLP:AMBER — Authorized Analyst Use Only
**Track:** OSINT
**Tools:** Maltego · i2 Analyst's Notebook · Shodan · SpiderFoot · OSINT Framework

---

## Investigation Brief

The Day 26 actor profile attributed the NovaCrest breach to **FIN-NC-001**
with 78% confidence. That profile was built from IOC pivoting and TTP
correlation against known groups. Day 28 goes deeper: a structured OSINT
investigation to map the actor's **external infrastructure**, identify
**operational patterns** visible in public data, and produce a network graph
suitable for law enforcement and executive briefing.

This is an all-source open intelligence investigation — no active probing,
no exploitation, no unauthorized access. Every data point comes from publicly
available sources or authorized threat intelligence feeds. The investigation
covers three threads:

**Thread 1 — Infrastructure Mapping**
Pivot from C2 IP (198.51.100.99) through ASN, hosting, co-hosted domains,
certificate transparency, passive DNS, and historical Shodan data to map
the full FIN-NC-001 operational infrastructure visible in public data.

**Thread 2 — Campaign Pattern Analysis**
Correlate the three prior victim incidents (confirmed in Day 26 via ransom
email pivot) to identify the actor's operational timeline, target selection
cadence, geographic clustering, and infrastructure rotation patterns.

**Thread 3 — Dark Web Presence**
Document the FIN-NC-001 leak site (`ncrypt3k4j7mxbwz.onion`), ransomware
group positioning, victim publication pattern, and negotiation infrastructure
visible in public dark web monitoring.

---

## Legal & Ethical Framework

```
AUTHORIZED:
  ✅ Public domain WHOIS, RDAP, ASN records
  ✅ Certificate Transparency logs (crt.sh, Censys, Google CT)
  ✅ Passive DNS records (VirusTotal, DNSDB, Farsight PDNS)
  ✅ Shodan/Censys host fingerprinting (passive — no active probing)
  ✅ Public social media and forum posts
  ✅ Dark web monitoring via commercial feeds (DarkOwl, Recorded Future)
  ✅ Ransomwatch — public ransomware group monitoring
  ✅ Public court records and law enforcement press releases
  ✅ Academic and security researcher publications

NOT AUTHORIZED:
  ❌ Active port scanning or probing of actor infrastructure
  ❌ Attempting to access actor systems
  ❌ Social engineering of threat actor personas
  ❌ Accessing private communications without legal process
  ❌ Accessing the leak site directly (legal gray area — coordinate with counsel)

LEGAL COORDINATION:
  → All findings provided to FBI Cyber Division (Case NCA-2026-06)
  → Attorney-client privilege applies to this investigation document
  → Do NOT share with parties outside authorized distribution list
```

---

## OSINT Toolkit

| Tool | Purpose | Access |
|------|---------|--------|
| Maltego CE/Pro | Link analysis graph, transform-based pivoting | Licensed |
| i2 Analyst's Notebook | Law enforcement-grade link chart | Licensed |
| Shodan | Internet-facing host fingerprinting | API key |
| Censys | Certificate transparency + host data | API key |
| crt.sh | Certificate transparency log search | Public |
| DNSDB (Farsight) | Passive DNS historical records | API key |
| VirusTotal Graph | IOC relationship visualization | Licensed |
| SpiderFoot | Automated OSINT enumeration framework | Open source |
| Ransomwatch | Ransomware group leak site monitoring | Public GitHub |
| WHOIS / RDAP | Domain and IP registration records | Public |
| Wayback Machine | Historical web content | Public |

---

## Investigation Objectives

1. Map the full C2 infrastructure cluster linked to 198.51.100.99
2. Identify additional victim domains linked to the phishing infrastructure
3. Establish timeline of actor infrastructure creation vs. victim targeting
4. Characterize actor OPSEC (what do they expose vs. conceal?)
5. Document leak site activity and victim negotiation pattern
6. Produce a link analysis chart suitable for law enforcement briefing
7. Identify any OPSEC failures that might support further attribution

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Maltego, SpiderFoot, Shodan walkthrough |
| `REPORT.md` | Investigation findings summary |
| `scripts/infrastructure_mapper.py` | Automated infrastructure pivot tool |
| `scripts/campaign_tracker.py` | Multi-victim campaign timeline builder |
| `queries/osint_hunt.spl` | Splunk SPL: passive DNS + cert transparency queries |
| `queries/osint_hunt.kql` | Sentinel KQL: threat intel enrichment queries |
| `reports/day28_investigation_report.md` | Full OSINT investigation report |
| `reports/day28_executive_brief.md` | Non-technical executive brief |
| `artifacts/infrastructure_graph.json` | Link analysis graph data (Maltego/i2 compatible) |

---

*Day 28 Scenario | OSINT Investigation Report*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
