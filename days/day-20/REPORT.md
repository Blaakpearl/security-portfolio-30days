# Day 20 — REPORT.md
## Purple Team: C2 Beaconing Detection Exercise
**NovaCrest Capital Group | Week 3 Capstone Prep**
**Track:** Purple Teaming
**Author:** V. Willis, CISSP
**Date:** 2026-06-20

---

## Summary

| Metric | Result |
|--------|--------|
| Variants deployed | 4 |
| Detected within SLA | 2 (V1, V2) |
| Detected outside SLA | 1 (V3 — late; TLS inspection not active) |
| Not detected | 1 (V4 — Havoc + DoH; new framework + no DoH blocking) |
| Exercise score | 7/12 points |
| Sigma rules written | 7 rules (14 with tuning variants) |
| Critical gaps identified | 2: TLS inspection disabled; DoH not blocked |
| Time to close both gaps | < 4 hours (configuration only; no new tools) |

---

## ATT&CK Coverage

| Technique | Detected | Method |
|-----------|----------|--------|
| T1071.001 HTTPS C2 | ✅ V1, ✅ V2, ⚠️ V3 late, ❌ V4 | JA3, timing |
| T1573.002 Asymmetric Encryption | ✅ V1 | JA3 / cert analysis |
| T1090.004 Domain Fronting | ⚠️ Late | Zscaler TLS inspection (post-fix) |
| T1008 Fallback Channels (DoH) | ❌ Missed | DoH blocking not enabled |
| T1001.001 Jitter Obfuscation | ✅ V2 | Beacon timing CV analysis |
| T1071.004 DNS Application Protocol | ❌ Missed | No DoH monitoring |
| T1102 Web Service (CDN abuse) | ⚠️ Partial | Domain fronting detection |

---

## The Two Critical Gaps

**Gap 1: TLS Inspection Disabled**
Domain fronting (V3) is structurally invisible without TLS inspection.
The fix is a Zscaler configuration change — no new tools, no procurement.
Enable SSL inspection for uncategorized and newly-registered domains.

**Gap 2: DoH Blocking Disabled**
DNS-over-HTTPS bypasses all DNS monitoring. Havoc C2 (V4) used this as
its primary exfil and communication channel. Enable Zscaler DNS Security
to block DoH to external resolvers. Exception: internal browser DoH can
be disabled via Group Policy.

Both gaps can be closed in an afternoon with existing Zscaler licensing.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-20/{scripts,queries,reports,rules}
cp -r /path/to/outputs/day20/* days/day-20/

git add days/day-20/

git commit -m "feat: Add Day 20 — Purple Team C2 Detection Exercise

Track: Purple Teaming | Tools: Sliver C2, Havoc, Zeek, Zscaler, EDR, Sigma
MITRE ATT&CK: T1071.001, T1573.002, T1090.004, T1008, T1001.001

Exercise: 4-variant C2 beaconing exercise with 30-min detection SLA
Score: 7/12 (V1 ✅ T+3:22 / V2 ✅ T+12:44 / V3 ⚠️ late / V4 ❌ missed)

Variants:
  V1 Sliver baseline      → JA3 fingerprint caught in 3:22
  V2 Sliver + jitter      → Beacon timing CV=0.31 caught in 12:44
  V3 Domain fronting      → Missed SLA; TLS inspection disabled
  V4 Havoc + DoH fallback → Not detected; Havoc JARM unknown; DoH unblocked

Critical gaps:
  TLS inspection: disabled (domain fronting invisible without it)
  DoH blocking: disabled (Havoc DoH fallback undetected)
  Both gaps close with Zscaler config change (<4 hours)

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/c2_beacon_simulator.py  (4-variant beacon telemetry generator)
  scripts/beacon_timing_analyzer.py (IAT CV statistical beacon detection)
  rules/sigma_c2_detection.yml    (7 Sigma rules; JA3, timing, fronting, DoH)
  queries/zeek_c2_detection.spl   (SPL: JA3, timing, fronting, DoH, SLA)
  queries/zeek_c2_detection.kql   (KQL: all variants + SLA scorecard)
  reports/day20_exercise_report.md (full SLA scorecard + detection analysis)
  reports/day20_sigma_tuning.md   (FP analysis + tuning guide per rule)"

git push origin main
```

---

*Day 20 — Purple Team C2 Detection Exercise*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
