# Day 07 — Week 1 Capstone: Full Kill Chain Synthesis
### Track: Full Stack | Difficulty: Advanced | Phase: All Phases

---

## 🎯 Threat Brief

Day 7 is not a new scenario. It is the moment where six days of investigation
converge into a single coherent picture.

Over the past week you worked six separate threads — external recon, credential
exposure, phishing infrastructure, C2 beaconing, social engineering surface
mapping, and endpoint persistence detection. Each was a discrete investigation
with its own tools, findings, and reports. Today you step back and ask the
question that matters to the CISO, the board, and the incident responders:

**What actually happened? When? To whom? By whom? And what do we do about it?**

This is the capstone deliverable. You will synthesize all Week 1 findings into:

1. A **complete kill chain narrative** mapping attacker actions from first
   domain registration through confirmed persistence on the endpoint
2. A **unified IOC master list** drawing from all six prior investigations
3. A **MITRE ATT&CK Navigator layer** exporting all confirmed technique
   coverage as a JSON file importable at attack.mitre.org/navigator
4. A **defensive coverage gap heatmap** showing which ATT&CK techniques
   lack detection rules
5. An **executive incident brief** — the 2-page document that goes to the
   CISO and legal team to initiate formal incident response

---

## 🧩 Week 1 Thread Summary

```
DAY 01 — EXTERNAL ATTACK SURFACE
  Finding: VPN portal (GlobalProtect 9.1.3, CVE-2021-3064), DMARC p=none,
           47 subdomains including dev/staging environments
  IOCs:    203.0.113.45, vpn.novacrest-capital.com, cert transparency pivots

DAY 02 — CREDENTIAL EXPOSURE HUNT
  Finding: 312 accounts in COMBOLIST-FIN-2025-Q1, CEO impossible travel,
           credential stuffing attempt (94 attempts, 23 accounts, MTTD: 48hrs)
  IOCs:    185.220.101.47, j.morrison@novacrest-capital.com (possible compromise)

DAY 03 — PHISHING INFRASTRUCTURE
  Finding: 12-domain adversary cluster, Flyservers AS209588 bulletproof hosting,
           reverse-proxy MFA-bypass kit, STIX 2.1 bundle generated
  IOCs:    microsoftonline-portal.com, 185.220.101.12, PHISH-FIN-2025-Q1 actor

DAY 04 — C2 BEACON & DNS TUNNEL
  Finding: DESKTOP-FIN-047 beaconing at 60.3s (CV=0.0018), 11-day dwell,
           126KB DNS exfiltration via TXT records, infrastructure overlap
  IOCs:    updates.cdn-telemetry-svc.net, 185.220.101.33, MTTD: 11 days

DAY 05 — SOCIAL ENGINEERING SURFACE
  Finding: Full executive enumeration, tech stack in job postings, M&A deal
           disclosed (MNPI risk), HR Manager pretext demonstrated
  IOCs:    5 risk register findings, 2 demonstrated spearphishing pretexts

DAY 06 — ENDPOINT PERSISTENCE HUNT
  Finding: 3 persistence mechanisms detectable in lab, 4 production detection
           gaps confirmed, WMI subscription most dangerous — no automated alert
  Output:  3 Sigma rules, MTTD scores, purple team gap analysis
```

---

## 🎯 Capstone Objectives

```
┌──────────────────────────────────────────────────────────────────┐
│  DELIVERABLE 1: Complete Kill Chain Timeline                      │
│  Connect all 7 days into a single chronological attack narrative │
│  Format: Markdown table with timestamps, phases, ATT&CK IDs     │
│                                                                   │
│  DELIVERABLE 2: Unified IOC Master List                          │
│  All IOCs from Days 01–06 in a single deduplicated file         │
│  Formats: Plain text (defanged), CSV, STIX 2.1 JSON             │
│                                                                   │
│  DELIVERABLE 3: ATT&CK Navigator Layer Export                    │
│  All confirmed techniques → JSON layer file                      │
│  Importable at attack.mitre.org/navigator                        │
│                                                                   │
│  DELIVERABLE 4: Detection Coverage Gap Map                       │
│  Which ATT&CK techniques have Sigma rules?                       │
│  Which are blind spots? Priority order for remediation           │
│                                                                   │
│  DELIVERABLE 5: Executive Incident Brief                         │
│  2-page non-technical summary for CISO + Legal                   │
│  What happened, business impact, what we are doing               │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📚 Learning Objectives

1. Synthesize multi-day investigation threads into a coherent incident narrative
2. Build a complete ATT&CK technique inventory from six separate hunt outputs
3. Generate an ATT&CK Navigator layer JSON programmatically in Python
4. Produce a unified IOC master list in multiple formats including STIX 2.1
5. Map detection coverage: confirmed detections vs confirmed blind spots
6. Write an executive incident brief suitable for CISO and legal counsel
7. Understand the difference between technical findings and business impact framing

---

## ✅ Success Criteria

- [ ] Kill chain timeline covers all 7 ATT&CK tactics present in Week 1
- [ ] IOC master list contains all unique indicators from Days 01–06
- [ ] ATT&CK Navigator JSON file imports successfully at attack.mitre.org/navigator
- [ ] Coverage gap map identifies at least 3 techniques without detection rules
- [ ] Executive brief is under 600 words and contains no unexplained jargon
- [ ] All artifacts committed to `days/day-07/artifacts/` on GitHub

---

## 🔗 MITRE ATT&CK Mapping — All Week 1 Techniques

| Phase | Techniques | Day Source |
|-------|-----------|------------|
| **Reconnaissance** | T1590, T1591, T1596, T1589, T1593 | Days 01, 05 |
| **Resource Development** | T1583, T1584, T1587 | Day 03 |
| **Initial Access** | T1566.001, T1566.002, T1078 | Days 02, 03 |
| **Execution** | T1059.001, T1059.003 | Days 04, 06 |
| **Persistence** | T1053.005, T1547.001, T1546.003 | Day 06 |
| **Defense Evasion** | T1036.005, T1112, T1027 | Days 03, 06 |
| **Credential Access** | T1110.003, T1110.004, T1539 | Days 02, 03 |
| **Command & Control** | T1071.004, T1573.002, T1008 | Day 04 |
| **Exfiltration** | T1048.001, T1041 | Day 04 |

---

*Next: [LAB.md](LAB.md) — Capstone synthesis lab guide*
