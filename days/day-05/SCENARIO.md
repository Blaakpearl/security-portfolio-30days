# Day 05 — Social Engineering Surface Mapping
### Track: OSINT | Difficulty: Intermediate | Phase: Reconnaissance / Pre-Engagement

---

## 🎯 Threat Brief

Your security team has been engaged by NovaCrest Capital Group's CISO to
conduct a **pre-authorized red team assessment**. Before any technical testing
begins, you are tasked with the reconnaissance phase: mapping the organization's
**human attack surface** — the people, roles, relationships, and publicly
available personal information that a social engineer or spearphisher would
exploit to craft convincing pretexts.

This is reconnaissance as defense — understanding your exposure through the
attacker's eyes so the organization can reduce it. A signed Rules of Engagement
(ROE) document authorizes all collection activity in this lab.

The intelligence gathered today directly answers what every CISO should be
asking: *"If an attacker spent two hours on LinkedIn and Google, what would
they know about us — and how would they use it?"*

The Day 03 and Day 04 findings show this threat actor is sophisticated and
patient. Day 05 answers: **who did they target, why that person, and what did
they already know before the phishing email landed?**

---

## 🕵️ Threat Actor Perspective

| Attribute | Details |
|-----------|---------|
| **Goal** | Identify high-value targets and build convincing phishing pretexts |
| **Tools** | LinkedIn, Google dorking, Sherlock, SpiderFoot, public breach data |
| **Time Investment** | 2–4 hours passive research per target organization |
| **Cost** | Zero — entirely free, publicly available sources |
| **Detection Risk** | Near zero — no contact with target systems |
| **Output** | Targeted spearphish referencing real names, roles, projects, vendors |

---

## 🏢 Assessment Context — NovaCrest Capital Group

```
Authorization:     Signed ROE — NovaCrest Capital Group CISO engagement
Scope:             Public-facing information only — no contact with individuals
Collection:        Passive OSINT — no interaction with target employees
Objective:         Map human attack surface and produce risk-rated findings
Deliverable:       Attack surface report + social engineering risk register
Note:              NovaCrest is fictional — techniques demonstrated against
                   public methodology, not real private individuals
```

> ⚠️ **Ethics Reminder:** All OSINT in this lab is passive and authorized.
> Real-world application requires written engagement authorization. Never apply
> these techniques against individuals or organizations without explicit consent.
> This lab demonstrates *defensive awareness* — knowing your exposure so you
> can reduce it.

---

## 🔍 The Human Attack Surface — Three Layers

```
┌───────────────────────────────────────────────────────────────────┐
│  LAYER 1 — ORGANIZATIONAL STRUCTURE                                │
│    • C-suite and leadership team (website, press releases)         │
│    • Departmental hierarchy (org chart inference)                  │
│    • Key vendor and partner relationships                          │
│    • Recent hires, departures, promotions                          │
│                                                                    │
│  LAYER 2 — INDIVIDUAL DIGITAL FOOTPRINT                           │
│    • Professional profiles (LinkedIn, GitHub, conference bios)    │
│    • Publications, presentations, media appearances               │
│    • Cross-platform username correlation                           │
│    • Personal details volunteered publicly                         │
│                                                                    │
│  LAYER 3 — PRETEXT CONSTRUCTION MATERIAL                          │
│    • Current projects (job postings, press releases, news)        │
│    • Internal tools/vendors revealed in job ads                   │
│    • Recent business events (M&A, expansions, new hires)         │
│    • Industry conferences and shared events                        │
└───────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Why This Matters

The Day 03 phishing email — *"Urgent: Benefits Enrollment Update Required"* —
worked because it was timely and plausible. But a truly targeted spearphish
is far more dangerous:

> *"Hi Sarah — I'm following up on the Apex Partners integration project.
> Mike Chen mentioned you're the right contact for the vendor access portal.
> Could you review the attached onboarding document before Thursday's call?"*

Every detail — Sarah's name, Mike Chen, Apex Partners, the integration project,
Thursday's call — can come from 90 minutes of LinkedIn and Google research.
The technical payload is the easy part. The social engineering pretext is
where attacks succeed or fail. **Defensive OSINT reveals this gap before
attackers exploit it.**

---

## 📚 Learning Objectives

1. Use Sherlock to perform cross-platform username enumeration across 300+ sites
2. Use SpiderFoot to automate multi-source OSINT collection for a target org
3. Apply Google dorking to extract employee information from public sources
4. Infer organizational structure and internal projects from job postings
5. Identify high-value targets (HVTs) by role criticality and breach exposure
6. Construct example spearphishing pretexts to demonstrate exposure risk
7. Produce a human attack surface risk register with remediation guidance

---

## ✅ Success Criteria

- [ ] Identify organizational hierarchy from public sources (minimum 5 roles)
- [ ] Enumerate email naming convention and validate format
- [ ] Discover internal tools/vendors from job postings (minimum 3)
- [ ] Run Sherlock against 3 sample usernames — document cross-platform presence
- [ ] SpiderFoot scan producing structured entity relationship data
- [ ] Build 2 example spearphishing pretexts demonstrating exposure risk
- [ ] Produce risk-rated human attack surface register with 5+ entries
- [ ] Document 3 specific remediation recommendations

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1591** | Gather Victim Org Information | Reconnaissance | Org structure mapping |
| **T1591.002** | Business Relationships | Reconnaissance | Vendor/partner discovery |
| **T1591.004** | Identify Roles | Reconnaissance | Key personnel identification |
| **T1589** | Gather Victim Identity Information | Reconnaissance | Employee enumeration |
| **T1589.002** | Email Addresses | Reconnaissance | Format validation |
| **T1589.003** | Employee Names | Reconnaissance | LinkedIn / public sources |
| **T1593** | Search Open Websites/Domains | Reconnaissance | LinkedIn, website, news |
| **T1593.001** | Social Media | Reconnaissance | LinkedIn, Twitter, GitHub |
| **T1598.003** | Spearphishing Link | Reconnaissance | Targeted pretext construction |

---

*Next: [LAB.md](LAB.md) — Step-by-step social engineering surface mapping guide*
