# Day 14 — Week 2 Capstone: Finished Intelligence Product
### Track: Full Stack | Difficulty: Advanced | Phase: Intelligence Synthesis & Dissemination

---

## 🎯 Threat Brief

Week 2 is complete. Six days of deep technical work — malware triage, dark
web monitoring, lateral movement hunting, attribution analysis, memory
forensics, and defensive coverage mapping — have produced an enormous volume
of evidence, findings, and recommendations. But raw findings scattered
across six separate reports do not constitute actionable intelligence.

Today's exercise is the discipline that separates a security analyst from
a **threat intelligence professional**: taking six days of disparate
technical outputs and synthesizing them into a single, finished intelligence
product — one document that a CISO, a board member, an insurer, a
regulator, or a peer organization's security team could read cover to cover
and understand exactly what happened, what it means, and what to do next.

**Your mission:** produce the complete Week 2 finished intelligence
product, following the same disciplined structure used by professional
threat intelligence teams: Key Judgments, Detailed Analysis, Confidence
Levels, and a structured Traffic Light Protocol (TLP) dissemination package
appropriate for sharing with FS-ISAC and law enforcement.

---

## 📚 What "Finished Intelligence" Means

```
┌────────────────────────────────────────────────────────────────────┐
│  RAW INFORMATION (what Days 08-13 individually produced)             │
│    • A malware sample's static and dynamic analysis                  │
│    • A dark web forum post and an actor credibility score            │
│    • A negative lateral movement hunt with one critical caveat       │
│    • An attribution assessment explicitly avoiding named attribution │
│    • A memory forensics report confirming prior sandbox findings     │
│    • A defensive coverage gap map and 90-day roadmap                 │
│                                                                      │
│  FINISHED INTELLIGENCE (what Day 14 must produce)                    │
│    A single product that:                                            │
│    • Leads with Key Judgments — the "so what" for decision-makers    │
│    • Synthesizes all six days into one coherent narrative            │
│    • Assigns explicit confidence levels to every major claim         │
│    • Distinguishes fact from assessment from recommendation          │
│    • Is structured for the audience's decision-making needs, not     │
│      the analyst's investigative chronology                          │
│    • Includes a properly classified (TLP) dissemination package      │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Week 2 Thread Summary

```
DAY 08 — MALWARE TRIAGE
  Finding: updater.exe confirmed custom C2 dropper, 0/72 AV detection,
           process hollowing into svchost.exe, LSASS access attempted,
           3 YARA rules produced

DAY 09 — DARK WEB INTELLIGENCE
  Finding: Actor "fin_broker_01" claims data sale, credibility 23/100,
           "300+ credentials" claim likely repackaged public breach data,
           financial document claim unverified

DAY 10 — LATERAL MOVEMENT DETECTION
  Finding: No confirmed PtH/PtT/DCOM/WMI lateral movement, BUT critical
           unresolved risk — svc_backup (Backup Operators) session timing
           requires confirmation

DAY 11 — GEO-IP & ATTRIBUTION
  Finding: High confidence NO specific actor can be named; moderate
           confidence in financially-motivated profile; 3 alternative
           hypotheses documented

DAY 12 — MEMORY FORENSICS
  Finding: Process injection CONFIRMED live (not just sandbox), LSASS
           dump CONFIRMED SUCCESSFUL (upgraded from "attempted"), C2
           connection directly linked to injected process

DAY 13 — MITRE ATT&CK MAPPING
  Finding: 24% detection coverage against APT29 reference profile,
           Discovery/Lateral Movement biggest gaps, 90-day roadmap built
```

---

## 🎯 Capstone Objectives

```
┌──────────────────────────────────────────────────────────────────┐
│  DELIVERABLE 1: Key Judgments Summary                              │
│  5-7 bullet points, confidence-graded, that any executive reads   │
│  first and understands the entire incident's implications          │
│                                                                     │
│  DELIVERABLE 2: Finished Intelligence Report                        │
│  Full synthesis of Days 08-13 in professional IC-style format      │
│  BLUF (Bottom Line Up Front) structure throughout                   │
│                                                                     │
│  DELIVERABLE 3: Consolidated IOC & TTP Package                     │
│  Merge Week 1 and Week 2 IOCs into master reference                │
│  STIX 2.1 bundle update with all new indicators                    │
│                                                                     │
│  DELIVERABLE 4: TLP Dissemination Package                          │
│  Properly classified versions for: internal (TLP:RED),             │
│  FS-ISAC sharing (TLP:AMBER), public advisory (TLP:WHITE)           │
│                                                                     │
│  DELIVERABLE 5: Outstanding Actions Tracker                          │
│  Every unresolved item from Days 08-13 consolidated into a single  │
│  tracked action list with owners and deadlines                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📚 Learning Objectives

1. Synthesize six days of independent technical investigations into one coherent narrative
2. Apply Bottom Line Up Front (BLUF) and Key Judgments structuring to technical findings
3. Consolidate and deduplicate IOCs and TTPs across an entire investigation phase
4. Produce properly TLP-classified variants of the same intelligence for different audiences
5. Build a unified outstanding-actions tracker from findings scattered across multiple reports
6. Understand the professional distinction between an investigation report and finished intelligence

---

## ✅ Success Criteria

- [ ] Key Judgments summary produced — confidence-graded, under 10 bullet points
- [ ] Full finished intelligence report synthesizing all 6 days
- [ ] Consolidated IOC list merging Week 1 (Day 07) and Week 2 findings
- [ ] Three TLP-classified variants produced (RED/AMBER/WHITE)
- [ ] Outstanding actions tracker consolidating unresolved items from Days 09, 10, 13
- [ ] Report readable end-to-end by a non-technical executive audience

---

## 🔗 MITRE ATT&CK Mapping — Week 2 Technique Additions

| Phase | New Techniques This Week | Day Source |
|-------|---------------------------|------------|
| **Defense Evasion** | T1055.012 (confirmed live), T1140 | Days 08, 12 |
| **Credential Access** | T1003.001 (confirmed successful) | Days 08, 12 |
| **Discovery** | T1082, T1016 | Day 08 |
| **Persistence** | T1547.001, T1546.003 (live-confirmed) | Day 12 |
| **Exfiltration** | T1567 (dark web sale — attempted monetization) | Day 09 |

---

*Next: [LAB.md](LAB.md) — Week 2 capstone synthesis lab guide*
