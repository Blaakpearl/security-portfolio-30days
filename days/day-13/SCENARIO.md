# Day 13 — MITRE ATT&CK Mapping
### Track: Threat Intelligence | Difficulty: Advanced | Phase: Defensive Coverage Assessment

---

## 🎯 Threat Brief

It is Day 19 of the NovaCrest Capital Group incident, and the technical
investigation is substantively complete. The CISO has asked for something
different today: **not another finding, but a structured defensive posture
assessment.** With 12 days of investigation behind you, and Day 11's honest
conclusion that the specific actor cannot be named, leadership wants to
know a more actionable question: **"Regardless of who did this, are we
prepared for the next attack that uses similar techniques — or a more
sophisticated one?"**

Today's exercise takes a documented, publicly known threat actor group —
**APT29 (also tracked as Cozy Bear / Midnight Blizzard)** — not because
evidence attributes this incident to them (Day 11 explicitly does not
support that conclusion), but because APT29 is one of the most thoroughly
documented threat actor profiles in the public MITRE ATT&CK Groups database,
making it an excellent reference standard for a defensive coverage exercise.

**Your mission:** map APT29's full publicly documented technique set against
NovaCrest's actual detection capability (established through Days 01–12),
identify every coverage gap, and produce a prioritized 90-day detection
engineering roadmap.

---

## 📖 Why Use a Reference Threat Actor for This Exercise

```
┌────────────────────────────────────────────────────────────────────┐
│  THIS IS NOT AN ATTRIBUTION CLAIM                                    │
│                                                                      │
│  Day 11 concluded — correctly — that current evidence does not      │
│  support attribution to any named group. Using APT29's public        │
│  ATT&CK profile here is a DEFENSIVE BENCHMARKING exercise, not a     │
│  revision of that conclusion.                                        │
│                                                                      │
│  WHY THIS IS STANDARD PRACTICE                                       │
│  Security teams regularly benchmark their detection coverage against │
│  well-documented threat actor profiles — not because they believe    │
│  that specific actor is targeting them, but because:                 │
│    • The technique set is comprehensive and publicly vetted          │
│    • It represents a credible "sophisticated adversary" baseline     │
│    • It provides a structured way to test coverage completeness      │
│      beyond just the techniques observed in THIS incident            │
│    • Many techniques APT29 uses overlap with what LOWER-              │
│      sophistication actors also use — testing against a thorough     │
│      profile catches gaps relevant to many possible future threats   │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🏢 Assessment Context

```
Reference profile:  APT29 (Cozy Bear / Midnight Blizzard / NOBELIUM)
Source:             MITRE ATT&CK Groups database (attack.mitre.org/groups/G0016)
Purpose:            Defensive coverage benchmarking — NOT attribution
Organization:       NovaCrest Capital Group
Current detection:  8 Sigma/KQL rules deployed across Days 02, 04, 06
                     (confirmed from Day 07 capstone coverage gap analysis)
Assessment scope:   Enterprise ATT&CK matrix, all tactics
Output:             ATT&CK Navigator heat map + 90-day detection roadmap
```

---

## 🔬 The Coverage Assessment Methodology

```
┌────────────────────────────────────────────────────────────────────┐
│  STEP 1: BUILD THE REFERENCE PROFILE                                 │
│    Enumerate APT29's full publicly documented technique list from    │
│    the MITRE ATT&CK Groups database                                  │
│                                                                      │
│  STEP 2: BUILD THE CURRENT DEFENSIVE POSTURE                         │
│    Enumerate every detection rule NovaCrest currently has deployed   │
│    (from Days 02, 04, 06 — 8 rules total per Day 07 analysis)       │
│                                                                      │
│  STEP 3: GAP ANALYSIS                                                │
│    Cross-reference: which APT29 techniques have detection coverage?  │
│    Which do not? Categorize by tactic and severity                   │
│                                                                      │
│  STEP 4: ATT&CK NAVIGATOR HEAT MAP                                    │
│    Generate a three-color layer: covered / partial / gap             │
│                                                                      │
│  STEP 5: PRIORITIZED ROADMAP                                          │
│    Rank gaps by exploitability and business impact; build a 90-day  │
│    phased detection engineering plan                                 │
└────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Learning Objectives

1. Extract and structure a threat actor's technique profile from MITRE ATT&CK Groups data
2. Build a defensive coverage matrix cross-referencing rules against techniques
3. Generate a three-tier ATT&CK Navigator heat map (covered/partial/gap)
4. Apply a risk-based prioritization framework to detection engineering backlogs
5. Produce a phased 90-day roadmap balancing quick wins against foundational work
6. Communicate defensive posture to leadership using visual and narrative tools

---

## ✅ Success Criteria

- [ ] APT29 reference technique profile documented (minimum 20 techniques)
- [ ] Current NovaCrest detection coverage fully cataloged
- [ ] Gap analysis completed — covered / partial / gap classification for every technique
- [ ] ATT&CK Navigator layer generated showing three-tier heat map
- [ ] Gaps prioritized using a documented risk framework
- [ ] 90-day roadmap produced with phased milestones
- [ ] Executive summary suitable for CISO/board presentation

---

## 🔗 MITRE ATT&CK Mapping — This Exercise Covers the Full Matrix

This day intentionally spans all 14 enterprise ATT&CK tactics rather than
a narrow technique set, as the goal is comprehensive coverage assessment:

```
TA0043 Reconnaissance      TA0042 Resource Development   TA0001 Initial Access
TA0002 Execution           TA0003 Persistence            TA0004 Privilege Escalation
TA0005 Defense Evasion     TA0006 Credential Access       TA0007 Discovery
TA0008 Lateral Movement    TA0009 Collection              TA0011 Command & Control
TA0010 Exfiltration        TA0040 Impact
```

---

*Next: [LAB.md](LAB.md) — Step-by-step ATT&CK mapping and gap analysis lab guide*
