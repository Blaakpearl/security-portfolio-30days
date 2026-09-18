# Day 26 — REPORT.md
## Threat Intelligence: FIN-NC-001 Actor Profiling
**NovaCrest Capital Group | Threat Intelligence Track**
**Author:** V. Willis, CISSP
**Date:** 2026-06-26

---

## Summary

| Attribute | Value |
|-----------|-------|
| Actor designation | FIN-NC-001 |
| Attribution | GOLD MYSTIC / LockBit affiliate |
| Confidence | 78% — Medium-High (Admiralty B2) |
| Prior victims confirmed | 3 (via ransom email pivot) |
| ATT&CK techniques documented | 29 across 14 tactics |
| IOCs for sharing | 5 (IP, hash, email, domain, IAM key) |
| STIX bundle objects | 14 (threat-actor, malware, indicators, COAs, report) |
| Recommended sharing | FS-ISAC TLP:AMBER within 24 hours |

---

## The Attribution Chain

The ransom email (`ncrypt-support@protonmail.com`) was the pivotal IOC.
Threat intel pivoting confirmed it has been active since March 2026 with
three confirmed prior victims — all financial services firms, all charged
3–5% of AUM in Monero, all targeted via conference-themed spearphishing.
That pattern, combined with the LockBit 3.0 builder binary (confirmed via
Ghidra code diff) and bulletproof VPS infrastructure on AS209588, puts
attribution squarely in the GOLD MYSTIC cluster at medium-high confidence.

The 78% (not higher) reflects an important caveat: the LockBit 3.0 builder
kit leaked publicly in 2022. Any actor could have downloaded it and built
the same binary. Attribution relies on the *combination* of factors (hosting
pattern + tooling + victim selection + ransom formula + email reuse), not
any single artifact.

---

## Intelligence Value for the Sector

The most actionable output of Day 26 is the STIX 2.1 bundle ready for
FS-ISAC sharing. When NovaCrest submits these IOCs — particularly the C2 IP
and ransom email — other financial sector firms can immediately block and
hunt. The three prior victims in the actor's history suggest at least two
other organizations could have used this intelligence to prevent being
targeted at all.

This is the purpose of structured threat intelligence: one organization's
breach becomes another's prevention.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-26/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day26/* days/day-26/

git add days/day-26/

git commit -m "feat: Add Day 26 — Threat Actor Profiling (FIN-NC-001 / GOLD MYSTIC)

Track: Threat Intelligence | Tools: OpenCTI, STIX 2.1, TAXII, VirusTotal
MITRE ATT&CK: 29 techniques documented across 14 tactics

Attribution: FIN-NC-001 → GOLD MYSTIC/LockBit affiliate (78% confidence, Admiralty B2)
  - 3 prior financial sector victims confirmed via ransom email pivot
  - LockBit 3.0 builder variant confirmed via Ghidra code diff
  - AS209588 (Flyservers NL) bulletproof hosting — consistent with group profile
  - Ransom = 3-5% AUM in Monero (consistent formula across all 4 known victims)
  - 5-day dwell time within GOLD MYSTIC 3-14 day range

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/actor_profiler.py        (IOC enrichment + ATT&CK correlation + next-move)
  scripts/stix_builder.py          (STIX 2.1 bundle generator — 14 objects)
  queries/cti_hunt.spl             (IOC feed matching + TTP hunt — 8 queries)
  queries/cti_hunt.kql             (Sentinel KQL — IOC matching + actor playbook)
  reports/day26_actor_profile.md   (full FIN-NC-001 profile + attribution chain)
  artifacts/fin_nc_001_stix_bundle.json (production STIX 2.1 bundle for FS-ISAC)"

git push origin main
```

---

*Day 26 — Threat Actor Profiling | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
