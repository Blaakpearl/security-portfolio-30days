# Attribution Intelligence Report
## Day 11 — Geographic & Infrastructure Attribution: NovaCrest Capital Group Intrusion

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-18 |
| **Report Type** | Attribution Intelligence Assessment |
| **Classification** | TLP:AMBER |
| **Case ID** | NVC-IR-2025-004 |
| **Track** | OSINT / Threat Intelligence |
| **Confidence Standard** | ICD 203 (Intelligence Community Directive) |
| **ATT&CK Phase** | Resource Development (TA0042) |

---

## Executive Summary

This report presents a disciplined attribution assessment of the threat
actor behind the NovaCrest Capital Group intrusion, built exclusively from
technical evidence collected across Days 01 through 10. Consistent with
intelligence community best practice, this assessment explicitly states
confidence levels for every judgment and documents alternative hypotheses
rather than presenting a single confident conclusion.

**The central finding is a negative one, and it is the most important
judgment in this report: current evidence does not support attribution to
any specific named threat actor group.** All observed tactics, techniques,
and procedures are documented in public frameworks and used across numerous
unrelated threat actors. No unique signature — linguistic, infrastructural,
or behavioral — meets the evidentiary threshold for named attribution.

What the evidence does support, with moderate-to-high confidence, is a
profile: a financially motivated actor or small group operating with
above-average but not elite technical sophistication, using cost-sensitive
bulletproof hosting infrastructure, and directly monetizing their access
through dark web forum sales rather than pursuing long-term strategic
intelligence collection. This profile is more consistent with an independent
criminal operation or initial access broker than a nation-state sponsored
campaign, though the latter cannot be entirely excluded.

This report should be read as a **profile assessment**, not a **named
attribution**. Any communication of these findings to the board, media, or
regulators should preserve this distinction carefully — overclaiming
attribution creates legal, reputational, and strategic risk disproportionate
to the intelligence value gained.

---

## Methodology

```
Phase 1 — Infrastructure Cluster Mapping (45 min)
  Consolidated Days 01, 03, 04, 09 infrastructure into unified cluster
  Confirmed single-ASN, single-registrar, single-subnet cohesion

Phase 2 — Hosting Provider Pattern Analysis (30 min)
  Assessed Flyservers S.A. selection against criminal vs nation-state
  infrastructure preference patterns documented in public threat intel

Phase 3 — Operational Timing Analysis (45 min)
  Analyzed 12 timestamped events across the incident lifecycle
  Applied heavy methodological caveats to timing-based inference

Phase 4 — TTP Comparison (45 min)
  Compared 13 confirmed techniques against 3 reference actor profiles
  Explicitly rejected TTP-overlap-as-attribution reasoning

Phase 5 — Structured Assessment (45 min)
  Applied ICD 203 confidence language standards
  Documented 3 alternative hypotheses with supporting/contradicting evidence
```

---

## Infrastructure Attribution Findings

---

### FINDING-01 — Single Cohesive Operator Infrastructure (HIGH Confidence)

**ATT&CK:** T1583, T1583.001, T1584

**Description:**
All identified infrastructure across the entire incident — the phishing
hosting IP, the C2 server IP, the credential stuffing source IP, and all
associated domains — resolves to a single Autonomous System (AS209588,
Flyservers S.A., Seychelles) and a single /24 subnet
(185.220.101.0/24). All 12 phishing domains and the C2 domain share a
consistent registrar (Namecheap) and privacy protection service
(WhoisGuard). Registration timestamps cluster within a single 6-hour
window on January 5, 2025.

**Evidence:**
```
Subnet clustering:
  185.220.101.12  — Phishing hosting (Day 03)
  185.220.101.33  — C2 server (Day 04)
  185.220.101.47  — Credential stuffing source (Day 02)
  All within 185.220.101.0/24

ASN concentration: 100% of identified IPs under AS209588

Registrar consistency: 100% of domains (13 total) via Namecheap + WhoisGuard

Temporal clustering: All infrastructure registered within a single
  6-hour window (14:32-20:00 UTC, January 5, 2025)
```

**Judgment:** This pattern of infrastructure cohesion is a **HIGH confidence**
indicator that a single operator or tightly coordinated small team is
responsible for the full intrusion lifecycle — reconnaissance-adjacent
credential stuffing, phishing delivery, and C2 operations. This is a
statement about operational unity, not identity.

---

### FINDING-02 — Financially-Motivated Actor Profile More Likely Than Nation-State (MODERATE Confidence)

**ATT&CK:** T1583.002, T1584.004

**Description:**
Comparative analysis of the attacker's infrastructure and monetization
choices against documented patterns for financially-motivated criminal
actors versus nation-state operations shows stronger alignment with the
criminal profile across 4 of 4 assessed behavioral indicators.

**Evidence:**
```
Criminal Pattern Indicators (4/4 present):
  ✅ Cost-sensitive bulletproof hosting (vs. compromised legitimate infra)
  ✅ Disposable, rapidly-rotated domain infrastructure (12 domains, 1 week)
  ✅ Commodity or lightly-modified tooling (Day 08 — CS-like but modified)
  ✅ Direct monetization via dark web sale (Day 09 confirmed)

Nation-State Pattern Indicators (0/2 present):
  ❌ Compromised legitimate infrastructure (not observed — used dedicated
     bulletproof hosting instead)
  ❌ Long-term infrastructure investment (infra built same-day as campaign,
     suggesting rapid disposable-use design)
```

**Judgment:** **MODERATE confidence** that this activity reflects an
independent or small-group financially motivated actor rather than a
nation-state sponsored operation. This judgment rests on behavioral pattern
comparison, not definitive technical proof, and should be presented with
appropriate hedging in any external communication.

---

### FINDING-03 — Operational Timing Provides Weak, Non-Determinative Signal (LOW-MODERATE Confidence)

**ATT&CK:** N/A (behavioral analysis)

**Description:**
Analysis of 12 timestamped attacker actions shows activity concentrated
between 09:00 and 23:00 UTC. When restricted to likely human-driven events
(excluding automated beacon and scheduled task activity), the pattern is
loosely consistent with an actor operating in a UTC+2 to UTC+5 time zone
range under a standard working-hours assumption — a broad band covering
Eastern Europe, the Middle East, and Western/Central Asia.

**Evidence:**
```
Human-driven event timestamps (n=7):
  14:32 UTC — Phishing domain registered
  16:00 UTC — C2 domain registered
  18:00 UTC — Certificate issued
  09:00 UTC — Phishing delivered
  22:14 UTC — CEO account accessed (Ukraine geography — see caveat below)
  23:47 UTC — Credential stuffing attempt
  12:47 UTC — Forum data sale post

Distribution spans nearly the full 24-hour UTC clock — this is itself
a caution flag against strong time zone inference from a small sample.
```

**Critical Caveat:**
This is explicitly the **weakest evidentiary basis** in this assessment. The
sample size (7 events) is statistically insufficient for confident inference.
A sophisticated actor may deliberately operate during atypical hours
specifically to defeat this type of analysis. The Ukrainian geolocation of
the CEO account access (Day 02) should NOT be conflated with the attacker's
true location — that access could represent VPN/proxy infrastructure entirely
unrelated to the operator's actual location, and using it as a standalone
attribution data point would be a significant analytical error.

**Judgment:** **LOW-MODERATE confidence.** This finding should be treated
as a weak supporting data point only, never as a standalone basis for
geographic attribution, and must always be presented alongside these caveats.

---

### FINDING-04 — TTP Overlap Confirms Category, Not Identity (HIGH Confidence in This Limitation)

**ATT&CK:** All 13 confirmed incident techniques

**Description:**
Comparison of the 13 confirmed MITRE ATT&CK techniques from this incident
against three reference behavioral profiles showed the highest overlap
(62%, 8 of 13 techniques) with a composite "Generic Financially-Motivated
Criminal Cluster" profile — not a named group, but an aggregate pattern
observed across many unattributed financially motivated intrusion sets.

**Evidence:**
```
TTP Overlap Results:
  Generic Financially-Motivated Criminal Cluster:  62% overlap (8/13 techniques)
  Illustrative APT-style DNS C2 pattern:            46% overlap (6/13 techniques)
  Commodity Ransomware Precursor Pattern:           38% overlap (5/13 techniques)

Highest-overlap techniques matched:
  T1566.001 (Spearphishing), T1078.004 (Cloud Accounts),
  T1071.004 (DNS C2), T1048.001 (DNS Exfil), T1053.005 (Scheduled Task),
  T1547.001 (Registry Run Keys), T1003.001 (LSASS Memory), T1027 (Obfuscation)
```

**Critical Interpretation:**
Every one of these 8 overlapping techniques is publicly documented,
available in open-source and commercial penetration testing frameworks,
and used by dozens to hundreds of unrelated threat actors across the
global threat landscape. **TTP overlap with a category is fundamentally
different from attribution to a specific actor or group.** This finding
should never be reported externally as "matches known APT group X" without
substantially stronger corroborating evidence than technique overlap alone
— a mistake common in lower-quality commercial threat intelligence reporting.

**Judgment:** **HIGH confidence** that this incident falls within a broadly
documented criminal TTP category. **NOT sufficient confidence** for
attribution to any specific named actor or group.

---

## Alternative Hypotheses

Per intelligence community best practice, three competing hypotheses were
evaluated rather than pursuing a single narrative:

### H1 — Independent Financially-Motivated Criminal Actor
**Assessment: MOST LIKELY based on available evidence**

Supporting: Bulletproof hosting cost-sensitivity, direct dark web
monetization, 62% TTP overlap with criminal pattern.
Contradicting: Custom malware development effort somewhat exceeds
typical low-tier commodity criminal tooling investment.

### H2 — Initial Access Broker (IAB) Preparing Hand-off
**Assessment: PLAUSIBLE — cannot be excluded**

Supporting: Dark web sale of access/data is a well-documented IAB
business model; multi-layered persistence suggests preparation for
a follow-on actor.
Contradicting: No confirmed second-stage actor activity observed to date;
the same actor appears to have conducted both intrusion and monetization
directly, which is somewhat atypical of the pure-IAB model.

### H3 — Nation-State Actor Using Criminal Infrastructure as False Flag
**Assessment: POSSIBLE BUT NOT SUPPORTED — low confidence**

Supporting: Custom malware development shows above-commodity investment;
financial sector targeting could align with strategic collection interests.
Contradicting: Unsubtle, direct public monetization via forum sale is
atypical of nation-state operational security discipline; no evidence
of selective, intelligence-driven document targeting was observed.

---

## What This Assessment Explicitly Does NOT Support

In the interest of analytical honesty, this report explicitly states the
boundaries of what the evidence permits:

- ❌ Attribution to any specific named APT group or criminal syndicate
- ❌ Nation-of-origin determination beyond broad regional speculation
- ❌ Identification of any individual operator
- ❌ Definitive confirmation of financial vs. nation-state motivation
  (moderate confidence only, not high confidence)
- ❌ Confirmation that the Ukrainian CEO-account login geolocation
  reflects the attacker's true physical location

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Attribution Relevance |
|----|-----------|--------|----------------------|
| **T1583** | Acquire Infrastructure | Resource Development | Cluster cohesion (Finding-01) |
| **T1583.001** | Domains | Resource Development | Registrar pattern (Finding-01) |
| **T1584** | Compromise Infrastructure | Resource Development | Provider selection (Finding-02) |
| **T1584.004** | Compromise Infrastructure: Server | Resource Development | Bulletproof hosting choice |

---

## Confidence Language Reference (ICD 203)

| Level | Definition Applied in This Report |
|-------|-----------------------------------|
| **HIGH** | Strong evidentiary basis; judgment well-supported by multiple independent, high-quality indicators |
| **MODERATE** | Credibly sourced evidence exists but is not corroborated sufficiently for high confidence, or admits reasonable alternative explanations |
| **LOW** | Scant, questionable, or single-source evidence; judgment should be treated as speculative |

---

## Recommendations

| Priority | Action | Owner |
|----------|--------|-------|
| **P1** | Do not communicate named-actor attribution to board, media, or regulators | CISO / Comms |
| **P1** | Use profile language ("financially motivated criminal actor") in all external communication | Legal / Comms |
| **P2** | Share full technical evidence (without attribution claims) via FS-ISAC | Threat Intel |
| **P2** | Preserve infrastructure evidence for potential future correlation as new intelligence emerges | Threat Intel |
| **P3** | Revisit this assessment if new evidence emerges (e.g., second-stage actor activity, DNS payload decode results from Day 04) | Threat Intel |

---

## Analyst Notes — On Attribution Discipline

Attribution work carries a unique professional hazard: the temptation to
produce a confident, headline-worthy conclusion ("This was APT29" or "This
was a Russian state actor") is strong, particularly under pressure from
leadership who want a clear answer. Resisting that temptation is the actual
skill being demonstrated in this exercise.

Every judgment in this report is graded by confidence level, and the
single highest-confidence judgment is a negative one: **we cannot name
this actor.** That is not an analytical failure — it is the correct and
honest conclusion given the evidence. Commercial threat intelligence vendors
frequently overclaim attribution because confident narratives sell reports.
A disciplined analyst's job is the opposite: to give leadership an accurate
picture of what is known, what is inferred, and what remains genuinely
uncertain, so that business decisions are made on solid ground rather than
a comforting but unsupported story.

The profile assessment — financially motivated, moderately sophisticated,
operating from a single cohesive infrastructure base — is genuinely useful
for defensive planning even without a named actor. It tells the security
team what kind of adversary they are likely facing for follow-up activity
and informs realistic expectations about the attacker's likely next moves
(further monetization attempts, opportunistic targeting of other victims
via the same infrastructure) rather than assuming nation-state-level
persistence and resourcing that may not be warranted.

---

## References

- [Intelligence Community Directive 203 — Analytic Standards](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [SANS — Cyber Threat Intelligence Attribution](https://www.sans.org/white-papers/attribution-cyber-threats/)
- [Rid & Buchanan — Attributing Cyber Attacks (Journal of Strategic Studies)](https://www.tandfonline.com/doi/full/10.1080/01402390.2014.977382)

---

*Previous: [Day 10 ←](../day-10/REPORT.md) | Next: [Day 12 →](../day-12/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
