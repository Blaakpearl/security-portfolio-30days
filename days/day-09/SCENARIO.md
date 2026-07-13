# Day 09 — Dark Web Intelligence
### Track: Threat Intelligence | Difficulty: Intermediate | Phase: Intelligence Collection

---

## 🎯 Threat Brief

It is Day 14 of the NovaCrest Capital Group incident. Forensic analysis of
DESKTOP-FIN-047 is producing results. But a parallel question has been
sitting unanswered since Day 02: **what are threat actors saying about
NovaCrest on criminal forums, and has any exfiltrated data already appeared
for sale?**

At 06:45 this morning, your commercial dark web monitoring platform fires
an alert. A post on a well-known criminal forum — indexed by the monitoring
service through its automated crawling infrastructure — mentions NovaCrest
Capital Group by name. The post was made 18 hours ago. It claims to offer
"internal financial records and employee credentials" for sale.

You cannot confirm the post is genuine. Threat actors frequently make false
claims to build reputation, extort organizations, or generate noise. But you
also cannot dismiss it. If the data from the 11-day DNS tunnel exfiltration
(confirmed at ~126KB in Day 04) is now being monetized, the incident scope
just expanded dramatically.

**Your mission:** validate the claim, assess the threat actor's credibility,
determine what data may be at risk, and produce a finished intelligence brief
for the CISO and legal team within 4 hours — before market open.

---

## 🔍 Dark Web Intelligence: What It Is and Is Not

Dark web intelligence (DARKINT) is a legitimate, widely practised component
of corporate threat intelligence programs. It is fundamentally **passive
monitoring** — observing what threat actors post publicly on criminal forums
and marketplaces, using the same automated collection tools that security
vendors use to build their threat feeds.

```
WHAT DARK WEB INTELLIGENCE IS:
  ✅ Automated monitoring of indexed criminal forum content
  ✅ Commercial platform APIs (Flare, Recorded Future, Intel 471)
  ✅ Validating whether your organization's data appears in breach dumps
  ✅ Threat actor profiling from public post histories
  ✅ Early warning before public data leak announcements
  ✅ Intelligence to support law enforcement referrals

WHAT DARK WEB INTELLIGENCE IS NOT:
  ❌ Purchasing stolen data (illegal)
  ❌ Communicating with threat actors on criminal forums (illegal / dangerous)
  ❌ Accessing criminal marketplaces directly for non-authorized research
  ❌ Downloading malware or exploit tools from criminal repositories
  ❌ Participating in criminal forums under any pretense
```

All collection in this lab uses **commercial monitoring platforms and their
APIs** — Flare.io, Recorded Future, and similar services that provide
authorized, legally obtained access to indexed dark web content. This is
identical to how enterprise security teams operate.

---

## 🏢 Incident Context

```
Alert Source:   Commercial dark web monitoring platform (Flare.io)
Alert Type:     Keyword match — "NovaCrest Capital Group"
Forum:          [Indexed by monitoring platform — not accessed directly]
Post Date:      2025-01-16 12:47 UTC (18 hours before alert)
Claimed Data:   "Internal financial records, employee credentials, Q1 projections"
Asking Price:   "$35,000 USD in Monero"
Threat Actor:   Handle "fin_broker_01" — first post on this forum
Credibility:    UNVERIFIED — requires full assessment
Context:        Aligns with 126KB DNS exfil confirmed in Day 04
```

---

## 🔬 The Intelligence Assessment Framework

```
┌────────────────────────────────────────────────────────────────────┐
│  COLLECTION                                                         │
│    Commercial platform API → indexed forum content                  │
│    Keyword monitoring → organization name, domain, executives      │
│    Breach data monitoring → email domain in dump databases         │
│                                                                     │
│  PROCESSING                                                         │
│    Threat actor profiling → post history, reputation score         │
│    Data validation → sample verification against known assets      │
│    Cross-reference → correlate with known IOCs from Days 01–08     │
│                                                                     │
│  ANALYSIS                                                           │
│    Credibility scoring → is the claim plausible and substantiated? │
│    Impact assessment → what data at risk, business consequences     │
│    Attribution confidence → does actor profile match our attacker? │
│                                                                     │
│  DISSEMINATION                                                      │
│    Finished intelligence brief → CISO, Legal, Board if warranted   │
│    Law enforcement package → FBI IC3, Secret Service if applicable │
│    Sector sharing → FS-ISAC if threat affects broader sector       │
└────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Learning Objectives

1. Understand how commercial dark web monitoring platforms index and alert on content
2. Use the Flare.io API to query for organizational mentions in monitored sources
3. Profile a threat actor from observable post history and behavioral patterns
4. Apply a structured credibility scoring framework to unverified claims
5. Validate breach data claims by cross-referencing against known exfiltrated data
6. Produce a finished intelligence brief in standard format with confidence levels
7. Prepare a law enforcement referral package appropriate for FBI IC3 submission

---

## ✅ Success Criteria

- [ ] Commercial monitoring platform query executed for organization keywords
- [ ] Threat actor profile built from observable indicators
- [ ] Credibility score calculated and documented with evidence
- [ ] Data validation assessment completed — claimed vs confirmed exfil scope
- [ ] Finished intelligence brief produced — under 800 words, executive-ready
- [ ] Confidence levels assigned to all key assessments
- [ ] Law enforcement referral package outlined

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1597** | Search Closed Sources | Reconnaissance | Forum monitoring (defender perspective) |
| **T1597.001** | Threat Intel Vendors | Reconnaissance | Commercial platform data |
| **T1589** | Gather Victim Identity Info | Reconnaissance | Credential data claimed in post |
| **T1567** | Exfiltration to Web Service | Exfiltration | Data posted to criminal forum |
| **T1486** | Data Encrypted for Impact | Impact | Ransomware threat (secondary) |

---

*Next: [LAB.md](LAB.md) — Step-by-step dark web intelligence lab guide*
