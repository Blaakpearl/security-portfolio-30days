# Day 21 — REPORT.md
## Week 3 Capstone: Full Purple Team APT Lifecycle Engagement
**NovaCrest Capital Group | Week 3 Complete**
**Track:** Full Stack Purple Team
**Author:** V. Willis, CISSP
**Date:** 2026-06-21

---

## Final Score: 32/40 (80%)

| Phase | Technique(s) | MTTD | Score |
|-------|-------------|------|-------|
| P1 Reconnaissance | T1592, T1589, T1593 | — | 0/5 (expected miss) |
| P2 Initial Access | T1566.001, T1059.001 | **8 min** ✅ | 5/5 |
| P3 Exec & Persist | T1053.005, T1547.001 | **14 min** ✅ | 5/5 |
| P4 Priv Escalation | T1548.002, T1134.001, T1558.003 | **6 min** ✅ | 5/5 |
| P5 Defense Evasion | T1070.001, T1562.001 | **3 min** ✅ | 5/5 |
| P6 Lateral Movement | T1021.002, T1550.002, T1047 | **23 min** ⚠️ | 2/5 |
| P7 C2 | T1071.001, T1090.004, T1573.002 | **17 min** ✅ | 5/5 |
| P8 Exfil + Staging | T1560.001, T1041, T1567.002 | **11 min** ✅ | 5/5 |
| **Total** | | **Mean: 12.3 min** | **32/40** |

---

## Week 3 Arc: What Changed

Days 15–16 began with zero real-time detection capability — 11 logged
activities during initial access, no alerts, C2 established undetected.
Day 21 closed with 80% SLA compliance and a 12.3-minute mean MTTD.

The detection stack built during Days 17–20 (privesc hunt queries, Zeek exfil
detection, C2 Sigma rules, TLS inspection deployment) all fired correctly in
the capstone. The two gaps that remain — lateral movement EQL tuning and run
key Sigma import — are 30–45 minute fixes, not architecture problems.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-21/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day21/* days/day-21/

git add days/day-21/

git commit -m "feat: Add Day 21 — Week 3 Capstone: Full Purple Team APT Lifecycle

Track: Full Stack Purple Team | Tools: Cobalt Strike, Elastic, ATT&CK Nav
MITRE ATT&CK: Full kill chain (8 phases — T1592 through T1567.002)

Exercise: NCA-PURPLE-2026-06-21 | Score: 32/40 (80%) | Mean MTTD: 12.3 min
  P1 Recon          → 0/5  (passive; undetectable — expected)
  P2 Initial Access → 5/5  ✅ MTTD 8 min  (Sliver JA3 + CS ML)
  P3 Exec/Persist   → 5/5  ✅ MTTD 14 min (Event 4698 EQL rule)
  P4 Priv Escalation→ 5/5  ✅ MTTD 6 min  (3 signals in <3 min)
  P5 Def Evasion    → 5/5  ✅ MTTD 3 min  (Event 1102 fastest)
  P6 Lateral Move   → 2/5  ⚠️ MTTD 23 min (SLA miss — EQL maxspan fix needed)
  P7 C2             → 5/5  ✅ MTTD 17 min (TLS inspect now enabled)
  P8 Exfil          → 5/5  ✅ MTTD 11 min (Zeek + Zscaler DLP BLOCKED)

Week 3 trajectory: 0% real-time detection (Day 15) → 80% SLA (Day 21)
Remaining gaps: 6 of 7 close with <4 hours engineering effort (roadmap)

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/engagement_tracker.py       (MTTD dashboard + scorecard engine)
  scripts/attck_navigator_exporter.py (ATT&CK Navigator JSON generator)
  queries/elastic_killchain.eql       (8 EQL rules, one per phase)
  queries/splunk_killchain.spl        (SPL dashboard + SLA scorecard)
  reports/day21_engagement_report.md  (full phase-by-phase analysis)
  reports/day21_improvement_roadmap.md (9-item prioritized roadmap)
  artifacts/attck_navigator_layer.json (color-coded Navigator layer)"

git push origin main
```

---

## Week 3 Complete

| Day | Topic | Track |
|-----|-------|-------|
| Day 15 | Red Team Recon Op | Purple |
| Day 16 | Initial Access Simulation | Purple |
| Day 17 | Privilege Escalation Hunt | TH + Purple |
| Day 18 | Data Exfiltration Patterns | TH |
| Day 19 | Log Forensics & SIEM | Forensics |
| Day 20 | Purple Team C2 Exercise | Purple |
| **Day 21** | **Week 3 Capstone — Full Stack** | **Purple** |

**Week 4 begins Monday: Days 22–28**
Next: Day 22 — Risk Scoring Framework (Threat Intelligence track)

---

*Day 21 — Week 3 Capstone | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
