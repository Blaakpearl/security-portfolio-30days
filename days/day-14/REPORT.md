# Finished Intelligence Product
## Week 2 Capstone: NovaCrest Capital Group Intrusion — Comprehensive Assessment

---

| Field | Details |
|-------|---------|
| **Analyst** | Blaakpearl |
| **Report Date** | 2025-01-20 |
| **Report Type** | Finished Intelligence Product — Full Synthesis |
| **Classification** | TLP:AMBER (see Appendix for TLP:RED and TLP:WHITE variants) |
| **Case ID** | NVC-IR-2025-004 |
| **Track** | Full Stack |
| **Reporting Period** | Days 08–13 (January 17–19, 2025) |
| **Distribution** | CISO, Board Risk Committee, Legal Counsel |

---

## BOTTOM LINE UP FRONT

NovaCrest Capital Group's Fixed Income analyst workstation was compromised
by a custom C2 dropper that successfully extracted domain credentials from
system memory — this is now confirmed through direct forensic evidence, not
merely suspected. Comprehensive hunting found no confirmed spread beyond
this single workstation, though one critical question about a privileged
service account's exposure remains unresolved and requires immediate
attention. A dark web claim to be selling NovaCrest data carries low-to-moderate
credibility and likely repackages previously known breach data rather than
representing an entirely new compromise. No specific threat actor can be
named with the evidence available, and the organization's automated
detection capability currently covers roughly one-quarter of the technique
set a sophisticated adversary would be expected to use — a gap that this
same incident directly demonstrates the cost of, and for which a 90-day
remediation roadmap now exists.

---

## Key Judgments

1. **[HIGH CONFIDENCE]** The malware deployed against DESKTOP-FIN-047
   successfully extracted domain credentials from LSASS memory. This is
   confirmed via live memory forensics (Day 12), not merely suspected from
   sandbox behavior (Day 08). *Business impact: all accounts authenticated
   to the affected host during the compromise window must be treated as
   compromised — credential rotation is already underway.*

2. **[MODERATE-HIGH CONFIDENCE]** No confirmed lateral movement occurred
   beyond the single compromised workstation, based on comprehensive
   hunting across three distinct techniques. *Business impact: incident
   scope can reasonably be bounded to one workstation, pending resolution
   of Judgment 3.*

3. **[MODERATE CONFIDENCE ON RISK / LOW CONFIDENCE ON TIMING]** An
   unresolved risk exists: a privileged Backup Operators service account
   has a historical session on the compromised host. If this authentication
   occurred during the compromise window, credential exposure extends to
   domain-wide impact. *Business impact: this is the single highest-priority
   unresolved question in the entire investigation.*

4. **[MODERATE CONFIDENCE]** A criminal forum data-sale claim is assessed
   as low-to-moderate credibility; the specific credential count claimed
   matches previously known public breach data almost exactly, suggesting
   repackaging rather than exclusively fresh exfiltration. *Business
   impact: reduces but does not eliminate concern about further data
   exposure; the financial document claim remains genuinely unresolved.*

5. **[HIGH CONFIDENCE — NO ATTRIBUTION / MODERATE CONFIDENCE — PROFILE]**
   Current evidence does not support attribution to any specific named
   threat actor group. The actor's profile is more consistent with an
   independent, financially motivated operation than a nation-state
   campaign. *Business impact: external communications should use profile
   language, never named-actor attribution.*

6. **[HIGH CONFIDENCE]** NovaCrest's current automated detection coverage
   against a comprehensive reference threat profile is approximately 24%,
   with the most significant gaps in Discovery and Lateral Movement —
   precisely the techniques that required manual hunting during this
   incident. *Business impact: a 90-day phased roadmap exists and should
   be resourced immediately.*

---

## Detailed Analysis

### 1. Malware & Confirmed Credential Compromise (Days 08, 12)

Static and dynamic analysis of the dropper (`updater.exe`) identified a
custom-built or heavily modified C2 tool that evaded all 72 antivirus
engines checked on VirusTotal at time of analysis. Behavioral analysis in
an isolated sandbox suggested process hollowing into `svchost.exe`, DNS-based
command and control, multi-layered persistence, and an attempt to access
LSASS credential material.

Memory forensics on the actual production system (Day 12) subsequently
confirmed every one of these sandbox-suggested behaviors as having actually
occurred on the real, compromised host — including the critical
distinction that LSASS access was not merely attempted but **succeeded**,
evidenced by recovered metadata for a dump file that had been deleted from
disk as an anti-forensic measure but persisted in memory's file record
cache. This upgrade from "sandbox capability" to "confirmed production
outcome" is the most consequential finding of the two-week investigation
period and directly drove the credential rotation scope already underway.

### 2. Lateral Movement Assessment (Day 10)

A structured, hypothesis-driven hunt covering Pass-the-Hash, Pass-the-Ticket,
and DCOM/WMI-based lateral movement techniques found no evidence that the
compromised account's credentials were used to authenticate to any system
outside the established 30-day behavioral baseline. This negative finding
is methodologically significant — it was reached through disciplined,
documented technique-by-technique hunting rather than an absence of
investigation, and it meaningfully bounds the probable scope of the incident.

However, the investigation surfaced a separate and more consequential
finding: Active Directory path analysis revealed that a service account
with Backup Operators privilege — a group membership that grants file
system access equivalent to Domain Admin on all domain-joined systems,
including domain controllers — has a recorded historical authentication
session on the compromised workstation. Whether this session occurred
during the actual 11-day compromise window remains unconfirmed at the time
of this report and represents the single most important open question
carried forward from Week 2.

### 3. Dark Web Data Sale Claim (Day 09)

A commercial dark web monitoring platform identified a forum post from an
actor using the handle `fin_broker_01`, claiming to sell NovaCrest
credentials and financial documents for $35,000 in Monero. Structured
credibility assessment scored this actor at 23 out of 100 — a new forum
account with zero verified transaction history and no publicly posted data
sample despite an 18-hour window in which to provide one.

Critically, cross-referencing the claimed "300+ employee credentials"
against previously confirmed intelligence revealed this figure matches,
almost exactly, the 312-account count from a publicly circulating breach
compilation identified earlier in the investigation (Week 1, Day 02) — data
that predates this specific intrusion by an unrelated third-party breach.
This strongly suggests the actor is repackaging known, already-public
breach data rather than exclusively offering newly exfiltrated material,
though it does not rule out that some additional fresh data may also be
included in the offering. The claim regarding internal financial documents
remains genuinely unresolved and is directly tied to an outstanding action
(decoding the DNS exfiltration payloads captured during Week 1).

### 4. Attribution Assessment (Day 11)

A disciplined attribution analysis — deliberately avoiding the common
pitfall of overclaiming a named actor for narrative convenience — concluded
with high confidence that current evidence does not meet the threshold for
attributing this intrusion to any specific named threat actor group. All
observed techniques are documented in public frameworks and used across
numerous unrelated actors; no unique linguistic, infrastructural, or
behavioral signature was identified that would support named attribution.

What the evidence does support, with moderate confidence, is a general
actor profile: financially motivated rather than nation-state sponsored,
based on the actor's selection of cost-sensitive bulletproof hosting
infrastructure, rapid disposable domain registration patterns, and direct
attempted monetization via the dark web forum sale described above. This
profile assessment is useful for defensive planning even in the absence of
named attribution.

### 5. Defensive Coverage Assessment (Day 13)

A structured benchmarking exercise compared NovaCrest's current detection
engineering posture against a comprehensive, publicly documented threat
actor technique profile (used strictly as a defensive yardstick, consistent
with the Day 11 conclusion that no attribution claim is being made). The
assessment found that only 24% of the 38 benchmarked techniques currently
have deployed detection coverage, with the remaining gaps concentrated most
heavily in the Discovery and Lateral Movement tactics.

This finding carries particular weight because it is directly, empirically
demonstrated by this very incident: Day 10's lateral movement investigation
succeeded only because an analyst manually executed the correct hunt
queries — no automated detection rule exists for any of the three lateral
movement techniques investigated. A risk-prioritized, 90-day phased
roadmap has been developed to close the highest-value gaps first,
beginning with automating the exact hunt methodology this incident already
proved necessary.

---

## Consolidated Indicators of Compromise

```
IP ADDRESSES:
  185.220.101.12, 185.220.101.33, 185.220.101.47, 91.108.4.11

DOMAINS (defanged):
  microsoftonline-portal[.]com
  updates.cdn-telemetry-svc[.]net
  ms-account-portal[.]net

HOSTING INFRASTRUCTURE:
  AS209588 — Flyservers S.A. (Seychelles) — recommend perimeter block

FILE HASH (SHA-256):
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  (updater.exe — confirmed custom C2 dropper)

FILE PATHS:
  C:\Users\Public\Libraries\updater.exe
  C:\Windows\Temp\~tmp4891.dll  (deleted from disk, recovered from memory)

YARA RULES AVAILABLE: 3 (exact hash, behavioral signature, DNS beacon pattern)

DARK WEB ACTOR: fin_broker_01 (credibility 23/100 — low)
```

Full consolidated IOC package (Week 1 + Week 2, all formats) is available
in `artifacts/ioc_merge/`.

---

## MITRE ATT&CK Technique Summary — Week 2 Confirmations

| ID | Technique | Confidence | Note |
|----|-----------|:----------:|------|
| T1055.012 | Process Hollowing | HIGH | Confirmed live (upgraded from sandbox-only) |
| T1003.001 | LSASS Memory | HIGH | Confirmed SUCCESSFUL (upgraded from "attempted") |
| T1071.004 | DNS C2 | HIGH | Confirmed via network state in memory |
| T1550.002 | Pass the Hash | N/A — NOT OBSERVED | Negative finding, high confidence |
| T1550.003 | Pass the Ticket | N/A — NOT OBSERVED | Negative finding, high confidence |
| T1078.003 | Valid Accounts: Local Accounts | MODERATE (risk) | svc_backup exposure — unresolved timing |
| T1567 | Exfiltration to Web Service | LOW-MODERATE | Dark web sale claim — credibility assessed |

---

## Outstanding Actions — Consolidated Tracker

| ID | Priority | Description | Owner | Status |
|----|:--------:|-------------|-------|--------|
| ACT-001 | 🔴 P0 | Confirm svc_backup authentication timing on FIN-047 | IR/AD Team | OPEN |
| ACT-002 | 🔴 P0 | Decode DNS TXT exfiltration payloads (resolves financial doc claim) | Forensics | OPEN |
| ACT-003 | 🔴 P0 | Pull M365 audit logs for CEO's Ukrainian session | SOC/Azure Admin | OPEN |
| ACT-004 | 🟠 P1 | Submit FBI IC3 report with evidence package | Legal/CISO | OPEN |
| ACT-005 | 🟠 P1 | Begin Phase 1 detection engineering (6 gaps) | Detection Eng | OPEN |
| ACT-006 | 🟠 P1 | Submit malware sample to community intel platforms | Threat Intel | OPEN |
| ACT-008 | 🟠 P1 | Present coverage findings to CISO/board | Threat Intel | OPEN |
| ACT-007 | 🟡 P2 | Static analysis of memory-extracted injected code | Forensics | OPEN |
| ACT-009 | 🟡 P2 | Continue dark web monitoring for follow-up activity | Threat Intel | ONGOING |

**The single most urgent unresolved item across the entire two-week
investigation is ACT-001 — the svc_backup authentication timing question.
Its resolution determines whether this incident's scope remains bounded to
one workstation or must be treated as a full domain compromise.**

---

## Confidence Assessment Summary Table

| Assessment Area | Confidence Level | Basis |
|-----------------|:-----------------:|-------|
| LSASS credential access occurred | HIGH | Direct memory forensic evidence |
| Lateral movement did NOT occur (with caveat) | MODERATE-HIGH | Three independent negative hunt results |
| svc_backup risk timing | LOW (on resolution) | Requires event log cross-reference not yet performed |
| Dark web claim partially repackaged data | MODERATE | Statistical count match to known breach |
| No named actor attribution | HIGH | No unique signature meets evidentiary threshold |
| Financially motivated actor profile | MODERATE | Infrastructure/monetization pattern analysis |
| 24% detection coverage figure | HIGH | Direct rule-to-technique cross-reference |

---

## Recommendations — Prioritized

| Priority | Recommendation | Timeframe |
|----------|-----------------|-----------|
| **Immediate** | Resolve ACT-001 (svc_backup timing) — this gates all other scope decisions | 2 hours |
| **Immediate** | Do not communicate named-actor attribution externally | Ongoing |
| **This week** | Complete DNS payload decode and M365 audit log review (ACT-002, ACT-003) | 48 hours |
| **This week** | Submit FBI IC3 report and malware samples to community platforms | 72 hours |
| **This month** | Begin Phase 1 of the 90-day detection engineering roadmap | 30 days |
| **This quarter** | Present full findings and roadmap to board; establish quarterly re-benchmarking | 90 days |

---

## Appendix — TLP Dissemination Package

Three properly classified variants of this intelligence have been produced
for different audiences (full text in `artifacts/tlp_variants/`):

- **TLP:RED** — Full technical detail, named organization, restricted to
  CISO/CEO/Legal/Board only
- **TLP:AMBER** — Sector-sharing variant for FS-ISAC and trusted partners,
  organization named, IOCs and TTPs included, no internal personnel detail
- **TLP:WHITE** — Public-safe general awareness advisory, no organization
  name, defensive recommendations only

---

## Analyst Notes — On Finished Intelligence as a Discipline

The six individual reports produced across Days 08 through 13 each
contained rigorous technical analysis. None of them, individually, would
serve a CISO well as a briefing document — each is written from the
investigative chronology of its specific analytical task, uses
domain-specific terminology, and buries its most important conclusion
somewhere in the middle of a technical narrative.

This capstone's actual work product is not new investigation — it is
**synthesis discipline**. The Key Judgments section above took the six
most consequential findings from six days of work and restated them in
under 400 words, each with an explicit confidence level and business
impact statement. That is the actual skill being demonstrated: not doing
more analysis, but recognizing which findings matter most to a
decision-maker and stating them with appropriate calibrated confidence,
stripped of investigative narrative that a technical reader needs but an
executive reader does not.

The TLP variant exercise makes a related point concrete: the same
underlying facts require substantially different framing, detail level,
and organizational naming depending on audience. An analyst who sends the
same document to the board, to FS-ISAC, and to a public advisory feed
without adjusting classification and content is not practicing
intelligence dissemination — they are simply broadcasting. The discipline
is in the tailoring.

---

## References

- [Intelligence Community Directive 203 — Analytic Standards](https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf)
- [FS-ISAC — Traffic Light Protocol Guidance](https://www.fsisac.com/)
- [CISA — Traffic Light Protocol (TLP) Definitions](https://www.cisa.gov/tlp)
- [SANS — Intelligence-Driven Incident Response](https://www.sans.org/white-papers/intelligence-driven-incident-response/)

---

*Previous: [Day 13 ←](../day-13/REPORT.md) | Week 3 Begins: [Day 15 →](../day-15/SCENARIO.md)*

---

## Week 2 Complete — Portfolio Summary

```
Days 08–14: Deep Forensics, Intelligence & Defensive Assessment
  Tracks covered:      Forensics, Threat Intel, Threat Hunting, OSINT, Full Stack
  New confirmations:   Process hollowing (live), LSASS success (live), 
                        no lateral movement (3-technique negative)
  New unresolved risk: svc_backup privileged session timing
  Attribution:         Explicitly NOT claimed — profile only
  Detection maturity:  24% coverage measured, 90-day roadmap built
  Finished product:    Full BLUF intelligence report + 3 TLP variants
  Key lesson:          Confidence-graded synthesis, not raw findings,
                        is what makes intelligence actionable
```

---
*Report generated as part of the [Blaakpearl 30-Day Security Portfolio](../../README.md)*
