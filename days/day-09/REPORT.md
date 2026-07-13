# Dark Web Intelligence Report
## Day 09 — Threat Actor Assessment: NovaCrest Data Sale Claim

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-17 |
| **Report Type** | Dark Web Intelligence — Threat Actor & Data Claim Assessment |
| **Classification** | TLP:RED — Named Organization — Restricted Distribution |
| **Target (Fictional)** | NovaCrest Capital Group |
| **Track** | Threat Intelligence |
| **Case ID** | NVC-IR-2025-004 |
| **ATT&CK Phase** | Exfiltration (TA0010) / Impact (TA0040) |
| **Distribution** | CISO, Legal Counsel, CEO, Board Risk Committee |

---

## Executive Summary

A commercial dark web monitoring alert identified a post on a criminal forum —
indexed by Flare.io's automated collection infrastructure — in which a threat
actor using the handle **fin_broker_01** claims to be selling data exfiltrated
from NovaCrest Capital Group, including employee credentials, Q4 financial
projections, and internal strategy documents, for $35,000 in Monero.

A structured four-phase assessment was conducted: platform monitoring, actor
profiling, data claim validation, and cross-reference against all known incident
IOCs from Days 01–08. The assessment produced a **credibility score of 23/100**
for the actor — placing the claim in the Low-to-Medium tier. However, several
data points in the post align with confirmed incident details, preventing outright
dismissal.

**Key finding:** The "300+ employee credentials" claim most likely refers to
the publicly circulating COMBOLIST-FIN-2025-Q1 dataset identified in Day 02
rather than freshly exfiltrated data. The actor may be repackaging known public
breach data alongside claimed fresh access — a common tactic used by low-reputation
forum actors to inflate the apparent value of their offering.

The most critical unknown remains the **content of the 126KB DNS tunnel
exfiltration** confirmed in Day 04. Until those payloads are decoded, it is not
possible to definitively confirm or refute whether financial documents were among
the exfiltrated data. Decoding the captured DNS TXT records is the highest
investigative priority this report generates.

No engagement with the threat actor is recommended. A law enforcement referral
to FBI IC3 has been prepared.

---

## Methodology

```
Phase 1 — Collection (30 min)
  Platform:  Flare.io commercial monitoring API
  Sources:   Indexed criminal forum content, paste sites, breach databases
  Scope:     30-day lookback on "NovaCrest Capital Group" keyword
  Output:    2 alerts — forum post + paste site partial credential sample

Phase 2 — Actor Profiling (45 min)
  Sources:   Actor post history, reputation metadata, writing analysis
  Framework: Credibility scoring — positive/negative factor weighting
  Output:    Actor profile, credibility score 23/100 (Low)

Phase 3 — Data Validation (45 min)
  Sources:   Confirmed exfil data (Day 04), LSASS finding (Day 08),
             COMBOLIST cross-reference (Day 02), HIBP domain check
  Output:    Per-claim validation verdicts with confidence levels

Phase 4 — Cross-Reference & Dissemination (30 min)
  Sources:   All IOCs from Days 01–08
  Output:    Timeline correlation, finished intelligence brief, LE referral
```

---

## Technical Findings

---

### FINDING-01 — Actor fin_broker_01: Low Credibility, High Suspicion

**Severity:** 🟠 High (concern level — not actor capability)
**ATT&CK:** T1567 — Exfiltration to Web Service (claimed)

**Description:**
The threat actor `fin_broker_01` is a newly created forum account with a
credibility score of 23/100 — placing it in the bottom quartile of actor
reliability for this platform. The account was created January 3, 2025 —
13 days before the monitoring alert — with only 3 posts, zero verified
transaction history, and no publicly posted data sample despite offering one.

Despite the low credibility score, the actor's knowledge of NovaCrest as a
specific target — combined with timeline alignment to the confirmed intrusion —
prevents dismissal. The possibility that this actor is the same individual
who operated the phishing campaign and C2 infrastructure cannot be excluded
based on available intelligence.

**Evidence:**
```
Actor Profile Summary:
  Handle:             fin_broker_01
  Account created:    2025-01-03  (13 days before alert)
  Post count:         3
  Reputation score:   12/100  (platform assigned)
  Verified sales:     0
  Escrow history:     0 transactions
  Credibility score:  23/100 (Blaakpearl assessment framework)

Credibility Factors (negative):
  ❌ New account (< 30 days)           -20
  ❌ Zero transaction history           -15
  ❌ No public sample posted            -20
  ❌ High price with no proof           -15
  ❌ Low reputation score (< 20)        -10
  ❌ Vague data description             -10

Credibility Factors (positive):
  ✅ Data matches known exfil scope     +25
     (credentials + financial docs consistent with confirmed exfil)

Post History Analysis:
  Jan 03: Vague introduction ("access to corporate networks")
  Jan 10: Second post ("US financial firm data") — no target named
  Jan 16: Named NovaCrest specifically — same day as incident detection
          Price: $35,000 XMR | Contact: PM only | Sample: offered, not posted

Writing Pattern:
  Native/near-native English grammar
  Basic operational security (Monero only, PM only, no IRC/Telegram given)
  No technical specifics in any post — cannot verify claimed access
  Moderate urgency pressure ("no time wasters")
```

**Behavioral Red Flags:**
The post appearing on January 16 — the same day the IR team detected and
contained the incident — raises two competing interpretations. Either the
actor monitored for detection signals and posted immediately to monetize
before remediation closed their access, or the timing is coincidental.
Neither interpretation can be excluded with current intelligence.

**Recommendation:**
Continue passive monitoring. Do not engage. The actor's next action will
provide intelligence: if they post a verified sample with genuine internal
data, credibility upgrades to Medium. If they disappear without posting a
sample after the sale window passes, this confirms a false claim or exit
fraud attempt.

---

### FINDING-02 — "300+ Credentials" Claim Likely References COMBOLIST-FIN-2025-Q1

**Severity:** 🟡 Medium
**ATT&CK:** T1589 — Gather Victim Identity Information

**Description:**
The actor's claimed credential count — "300+ employees" — matches almost
exactly the 312 NovaCrest accounts confirmed in the COMBOLIST-FIN-2025-Q1
breach compilation identified in Day 02. This compilation was publicly
available on criminal forums for at least 48 hours before the actor's post.
Threat actors routinely aggregate publicly available breach data and present
it as fresh access to inflate their forum reputation and justify higher prices.

**Evidence:**
```
Actor claim:        "300+ employee credentials"
COMBOLIST count:    312 @novacrest-capital.com accounts (confirmed Day 02)
Post date:          2025-01-16 12:47 UTC
COMBOLIST upload:   2025-01-14 ~14:00 UTC (publicly available 48+ hrs prior)

Comparison of data types:
  COMBOLIST data:   Email addresses + hashed passwords (various algorithms)
  Actor claims:     "email:hash pairs" (format matches COMBOLIST format)
  New exfil data:   Unknown content — pending DNS payload decode

Statistical note:
  Probability of "300+ credential" count matching 312 exactly by coincidence
  if the data were genuinely fresh exfil: Very low — actual exfil would
  produce a different count. The near-exact match to publicly available
  data is the strongest evidence of repackaging.
```

**Recommendation:**
This finding reduces the incident severity for the credential component —
the 312 accounts identified in Day 02 were already being rotated as a
precautionary measure. No new accounts require rotation based solely on
this actor's claim. However, the DNS payload decode remains critical to
determine whether additional fresh credentials were also exfiltrated.

---

### FINDING-03 — Financial Document Claim: Unverified but Plausible

**Severity:** 🟠 High (business risk if genuine)
**ATT&CK:** T1567 — Exfiltration to Web Service

**Description:**
The actor's claim of "Q4 financial projections" and "internal strategy docs"
cannot be confirmed or refuted with current intelligence. The confirmed 126KB
DNS tunnel exfiltration is volumetrically consistent with containing documents
(3–15 files at 8–40KB average). The Fixed Income analyst's role provides
access to trading models and market data but not typically to board-level
Q4 financial projections — however, the CEO's M365 session during the
impossible travel event (Day 02) could have provided access to higher-value
documents if the session was active long enough.

**Evidence:**
```
Exfiltration Volume Assessment:
  Confirmed exfil:  ~126KB via DNS TXT tunneling (Day 04)
  Document analysis:
    Small Excel file (trading model):  15–50KB  ← FITS
    PowerPoint deck (Q4 projections):  200–800KB ← TOO LARGE for 126KB
    Word document (strategy memo):     50–150KB  ← BORDERLINE
    Text/CSV data (credentials):       5–30KB   ← FITS

CEO Session Assessment (Day 02):
  Unauthorized session from Ukraine: 2025-01-15 22:14 UTC
  Session duration: Unknown — M365 audit log review pending
  SharePoint/OneDrive access: Audit log review pending
  If CEO accessed board documents: HIGH risk of financial data exposure

Timeline gap:
  CEO session (Jan 15) → Actor post (Jan 16 12:47)
  Gap: ~15 hours — consistent with downloading, staging, and listing
```

**Recommendation:**
The M365 audit log review for the CEO's unauthorized session is the
highest-priority validation action. If SharePoint or OneDrive document
access occurred during the Ukrainian session, the financial document claim
credibility immediately upgrades to HIGH. Pull audit logs within 24 hours.

---

### FINDING-04 — Timeline Correlation: Single Operator Hypothesis

**Severity:** 🟡 Medium (analytical finding — not confirmed)
**ATT&CK:** Attribution assessment — MODERATE confidence

**Description:**
Timeline analysis produces a sequence consistent with a single-operator
campaign: forum account created (Jan 3), attack infrastructure registered
(Jan 5), phishing delivered and C2 established (Jan 14), detection occurs
(Jan 16 02:17), actor posts data for sale (Jan 16 12:47 — 10 hours after
detection). The 10-hour gap between detection/containment and the forum
post is consistent with an operator who detected the network isolation
of DESKTOP-FIN-047 and immediately moved to monetize collected data
before remediation was complete.

**Evidence:**
```
Chronological Sequence:
  2025-01-03  fin_broker_01 account created on criminal forum
  2025-01-05  Phishing domain + C2 domain registered (same day)
  2025-01-14  Phishing delivered, DESKTOP-FIN-047 compromised, C2 active
  2025-01-14  DNS exfiltration begins (Day 04 confirmed)
  2025-01-15  CEO account accessed from Ukraine (Day 02)
  2025-01-16 02:17  DESKTOP-FIN-047 isolation detected by IR
  2025-01-16 03:30  FIN-047 isolated from network
  2025-01-16 12:47  Forum post: "NovaCrest data for sale"

10-hour gap analysis:
  Possible interpretation A: Operator detected isolation, immediately listed
  Possible interpretation B: Post was pre-scheduled before detection occurred
  Possible interpretation C: Different actor, coincidental timing

Assessment: Interpretation A is most operationally consistent but cannot
be confirmed without additional technical attribution evidence.
```

---

## MITRE ATT&CK Technique Matrix

| ID | Technique | Tactic | Finding | Confidence |
|----|-----------|--------|---------|------------|
| **T1597** | Search Closed Sources | Reconnaissance | Monitoring methodology | High |
| **T1567** | Exfiltration to Web Service | Exfiltration | Forum data listing | Medium |
| **T1589** | Gather Victim Identity Info | Reconnaissance | FINDING-02 (credential claim) | High |
| **T1486** | Data Encrypted for Impact | Impact | Ransom pricing pattern | Low |

---

## Risk Assessment

| Finding | Business Impact | Probability | Risk Rating |
|---------|----------------|-------------|-------------|
| FINDING-01 (Actor claim) | High if genuine | Low-Medium | 🟠 High (monitor) |
| FINDING-02 (Old breach repackaged) | Low (already mitigated) | High | 🟡 Medium |
| FINDING-03 (Financial docs) | Critical if genuine | Unknown | 🔴 Critical (pending) |
| FINDING-04 (Single operator) | Attribution value | Medium | 🟡 Medium |

---

## Confidence Assessment Summary

| Key Judgment | Confidence | Rationale |
|-------------|------------|-----------|
| Actor credibility LOW | **HIGH** | Scoring framework — objective negative factors |
| Credential claim = old COMBOLIST | **MEDIUM-HIGH** | Near-exact count match |
| Financial docs exfiltrated | **LOW** | Volume plausible, no direct confirmation |
| Same actor as phishing campaign | **LOW-MEDIUM** | Timeline circumstantial only |
| Genuine fresh exfil occurred | **MEDIUM** | DNS exfil confirmed — content unknown |

---

## Recommended Actions

### Immediate (0–4 hours — before market open)

| Priority | Action | Owner |
|----------|--------|-------|
| **P0** | Pull M365 audit logs for CEO's Jan 15 Ukrainian session | SOC / Azure Admin |
| **P0** | Legal assessment — does this constitute reportable breach? | Legal Counsel |
| **P0** | Preserve all monitoring platform evidence for LE referral | IR Team |
| **P0** | Do NOT engage threat actor — no contact, no sample request | All |

### Short Term (24–48 hours)

| Priority | Action | Owner |
|----------|--------|-------|
| **P1** | Decode all 3,160 captured DNS TXT exfil queries from Day 04 | Forensics |
| **P1** | Submit FBI IC3 report (ic3.gov) — attach evidence package | Legal / CISO |
| **P1** | Notify FS-ISAC — sector-wide threat actor awareness | Threat Intel |
| **P2** | Continue 24/7 dark web monitoring for follow-up posts | Threat Intel |

### Ongoing Monitoring Keywords

```
Primary:    "NovaCrest Capital Group" | "novacrest-capital.com"
Secondary:  "fin_broker_01" | "NovaCrest" | "Fixed Income trading data"
Financial:  "novacrest credentials" | "novacrest financial"
```

---

## Analyst Notes — On Dark Web Intelligence Methodology

Dark web intelligence is frequently misunderstood as a high-risk, exotic
discipline requiring direct access to criminal infrastructure. In practice,
enterprise-grade dark web intelligence is a structured API workflow:
commercial platforms (Flare, Recorded Future, Intel 471) maintain their own
monitoring infrastructure, index criminal forum content, and expose it through
clean REST APIs. The analyst never touches criminal infrastructure directly.

The discipline's real skill is not collection — it is assessment. Any monitoring
platform can flag a keyword match. The analytical work is determining: **Is this
claim credible? Does it match confirmed incident data? What is the risk to the
organization if it is genuine? What actions should leadership take given
uncertainty?**

This case illustrates the challenge well. A low-credibility actor has made a
claim that partially matches confirmed incident data. The appropriate response
is not alarm (the claim may be false) and not dismissal (it may be genuine).
It is structured validation, prioritized investigation (CEO audit logs, DNS
decode), and proportionate escalation — exactly what this report delivers.

The 126KB DNS payload decode is the pivotal finding this analysis is waiting
on. That investigation should begin immediately.

---

## References

- [Flare.io — Dark Web Monitoring Platform](https://flare.io)
- [Recorded Future — Intelligence Cloud](https://www.recordedfuture.com)
- [FBI IC3 — Internet Crime Complaint Center](https://www.ic3.gov)
- [FS-ISAC — Financial Services ISAC](https://www.fsisac.com)
- [MITRE ATT&CK T1597 — Search Closed Sources](https://attack.mitre.org/techniques/T1597/)
- [TLP Protocol — Traffic Light Protocol](https://www.cisa.gov/tlp)
- [NIST SP 800-61 — Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

*Previous: [Day 08 ←](../day-08/REPORT.md) | Next: [Day 10 →](../day-10/SCENARIO.md)*

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
