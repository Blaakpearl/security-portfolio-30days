# Day 23 — REPORT.md
## Mobile Device OSINT: Threat Intelligence from Mobile Artifacts
**NovaCrest Capital Group | OSINT Track**
**Author:** V. Willis, CISSP
**Date:** 2026-06-23

---

## Summary

Mobile OSINT analysis produced four categories of findings across the
NovaCrest employee footprint. The most significant discovery: a single
Instagram photo from the FinTech Summit (March 22, 2026) with intact GPS
metadata directly enabled the attacker to craft the spearphishing lure
used on June 14. The mobile device was also confirmed as the initial
phishing delivery channel via MDM check-in correlation.

| Category | Key Finding | Severity |
|----------|------------|---------|
| EXIF/GPS | 4/5 public photos geotagged; conference photo enabled spearphish lure | Critical |
| Social footprint | GitHub repo reveals Bloomberg API key patterns; 5 platforms identified | Critical |
| Breach exposure | Personal email in Collection #1 dump (cracked passwords) | Critical |
| MDM compliance | iPhone 14 with no screen lock and iOS 16.7.4 (Bloomberg enrolled) | Critical |
| Phishing correlation | MDM check-in at 08:47 UTC confirms iPhone was phishing delivery channel | High |

---

## The Mobile → Breach Chain

```
March 22, 2026
  └── j.henderson posts conference photo at Javits Center
      GPS: 40.761429, -73.977355 (intact in Instagram EXIF)
      Caption: "Great session at #FinTechSummit2026 @javitscenter"

Attacker OSINT (pre-June 14)
  └── Finds photo → confirms FinTech Summit attendance
  └── Finds GitHub repo jhenderson85/bloomberg-api-tools
  └── Finds jhenderson@novacrest.com in LinkedIn EXIF UserComment
  └── Constructs lure: "Q3 Investment Strategy — FinTech Summit Follow-up"

June 14, 2026 — 08:47 UTC
  └── Phishing email delivered to corporate inbox
  └── Opened on iPhone (MDM check-in confirms mobile read)
  └── Mobile email app renders tracking pixel — attacker confirms open

June 14, 2026 — 09:12 UTC
  └── j.henderson opens attachment on WS-FIN-04
  └── Macros enabled → Sliver implant deployed
  └── Breach begins
```

**Lesson:** The attacker did not need to break anything to know what lure
would work. One public Instagram photo provided the entire context.

---

## Recommendations Priority

1. **EXIF stripping policy** (immediate) — Camera location services off via MDM
2. **MDM-003 (s.chen)** (immediate) — Force iOS update; enforce screen lock
3. **TikTok restriction** (immediate) — MDM block on supervised devices
4. **GitHub audit** (this week) — Scan all public repos for key patterns
5. **Employee awareness** (this month) — "Your phone is an OSINT source" module
6. **BYOD Intune policy** (this quarter) — App Protection Policies for data isolation

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-23/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day23/* days/day-23/

git add days/day-23/

git commit -m "feat: Add Day 23 — Mobile Device OSINT

Track: OSINT | Tools: ExifTool, CellHawk, MDM (Jamf Pro), Sherlock

Key findings:
  - 4/5 public employee photos contain GPS metadata
  - FinTech Summit photo (GPS + hashtag) enabled spearphishing lure
  - MDM check-in confirms iPhone was phishing delivery channel at 08:47 UTC
  - GitHub repo reveals Bloomberg API key naming conventions
  - iPhone 14 (s.chen): iOS 16.7.4 + NO SCREEN LOCK + Bloomberg installed
  - Personal email in Collection #1 breach (cracked passwords)

MITRE ATT&CK: T1430, T1592.002, T1589.002, T1593.001, T1598.002, T1636

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/exif_analyzer.py          (EXIF extractor + GPS mapper + risk assessor)
  scripts/mobile_osint_profiler.py  (phone OSINT + social + breach + MDM audit)
  queries/mdm_audit.spl             (Jamf compliance + incident correlation)
  queries/mdm_audit.kql             (Sentinel MDM audit + compliance scorecard)
  reports/day23_mobile_osint_report.md  (full findings per category)
  reports/day23_mdm_hardening_checklist.md (Jamf policy + BYOD guide)
  artifacts/exif_findings.json      (structured EXIF analysis results)"

git push origin main
```

---

*Day 23 — Mobile Device OSINT | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
