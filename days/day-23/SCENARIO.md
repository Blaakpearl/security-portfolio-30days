# Day 23 — SCENARIO.md
## Mobile Device OSINT: Threat Intelligence from Mobile Artifacts
**NovaCrest Capital Group | Threat Intelligence Track**
**Classification:** TLP:AMBER — Authorized Analyst Use Only
**Track:** OSINT
**Tools:** ExifTool · CellHawk · MDM Audit · Maltego · Sherlock

---

## Scenario Context

During forensic review of the NovaCrest breach (Case NCA-2026-06), the IR team
identified that the spearphishing email delivered to `j.henderson` was opened
on both her corporate Windows workstation **and** her personal iPhone. MDM logs
show the device accessed corporate email at 08:47 UTC on June 14 — 25 minutes
before the macro was executed on WS-FIN-04.

The question now shifts to mobile: did the attacker also compromise or profile
the mobile device? Were photos or documents shared from the device that could
have aided reconnaissance? Is there OSINT-available mobile footprint from
`j.henderson` or other NovaCrest employees that the attacker could have
leveraged — and that the security team should now understand and reduce?

This day covers **mobile OSINT methodology** across three dimensions:

1. **EXIF / image metadata analysis** — photos shared publicly from corporate
   devices that embed GPS coordinates, device model, and timestamps
2. **Mobile identity footprinting** — phone number OSINT, app footprint, and
   social account enumeration linked to the device
3. **MDM audit** — reviewing corporate MDM enrollment, device posture, and
   app inventory for security gaps on managed mobile devices

---

## Threat Intelligence Objectives

### Objective 1 — Attacker Mobile Reconnaissance Surface
Assess what OSINT an attacker could have harvested about NovaCrest employees
via mobile-sourced intelligence: geotagged photos, app profiles, mobile-linked
social accounts, and device identifiers exposed in public data.

### Objective 2 — j.henderson Mobile Device Security Posture
Review the MDM enrollment record for `j.henderson`'s corporate iPhone:
- Device model and OS version (is it patched?)
- Managed apps inventory (any shadow IT or risky apps?)
- MDM compliance status (screen lock, encryption, jailbreak detection)
- Last check-in time and location data (if enabled)

### Objective 3 — Org-Wide Mobile Attack Surface Reduction
Identify systemic mobile security gaps across the NovaCrest employee fleet
that the attacker could have exploited or that remain open exposure.

---

## Target Profile

**Primary subject:** Jennifer Henderson (`j.henderson@novacrest.com`)
- Title: Senior Financial Analyst, NovaCrest Capital Group
- Corporate device: iPhone 15 Pro (MDM-enrolled, managed by Jamf Pro)
- Personal device: iPhone 14 (personal; not MDM-enrolled — BYOD gap)
- LinkedIn: `linkedin.com/in/jhenderson-finance` (public profile)
- Public Instagram: `@jhenderson_nyc` (personal, public, 847 followers)
- Confirmed phishing target — opened email at 08:47 UTC June 14

**OSINT scope for this exercise:**
```
Permitted:   Public social media profiles (LinkedIn, Instagram, Twitter/X)
             Public photo metadata (images posted publicly by subject)
             Public domain and app store records
             Passive reconnaissance only — no active probing of personal accounts
             MDM audit of corporate-enrolled device (authorized)

Not in scope: Personal financial records, location tracking, private messages
             Active exploitation of any accounts or devices
```

---

## MITRE ATT&CK & Mobile Techniques

| Technique | Name | Attacker Use | Defender Mitigation |
|-----------|------|-------------|---------------------|
| T1592.002 | Gather Victim Host Info (Hardware) | Device model via EXIF | Strip EXIF on upload |
| T1589.001 | Gather Victim Identity (Credentials) | Email from EXIF; linked accounts | Reduce public exposure |
| T1589.002 | Gather Victim Identity (Email) | Email addresses from app stores, OSINT | Employee awareness |
| T1593.001 | Search Open Websites (Social Media) | LinkedIn, Instagram footprint | Profile review policy |
| T1598.002 | Phishing for Info (Spearphishing via Service) | Mobile-targeted phishing via SMS | MDM + user training |
| T1430 | Location Tracking | GPS from geotagged photos | MDM GPS policy |
| T1636 | Protected User Data (Calendar) | Calendar invites expose schedule | MDM app permissions |
| T1481 | Web Service (for C2 via mobile) | Mobile-targeted C2 delivery | App vetting; MDM |

---

## Exercise Structure

```
PART 1 — EXIF Metadata Analysis (simulated photo set)
  ↓ ExifTool: extract GPS, device, timestamp from public photos
  ↓ Map geolocations; identify device model and OS fingerprint
  ↓ Assess: what would an attacker learn from this data?

PART 2 — Mobile Identity Footprinting
  ↓ Phone number OSINT: carrier, registration history
  ↓ App store search: apps registered to corporate email
  ↓ Sherlock / social account enumeration by username
  ↓ LinkedIn: job history, connections, employer data

PART 3 — MDM Posture Audit (Jamf Pro)
  ↓ Device compliance status (OS version, screen lock, encryption)
  ↓ App inventory: managed vs. unmanaged apps
  ↓ MDM policy gaps: what isn't controlled?
  ↓ BYOD exposure: personal devices accessing corporate data

PART 4 — Findings & Remediation
  ↓ Threat model: what could attacker do with this data?
  ↓ OSINT reduction recommendations per finding
  ↓ MDM policy hardening checklist
```

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | ExifTool setup, phone OSINT tools, MDM audit commands |
| `REPORT.md` | Summary of mobile OSINT findings and MDM gaps |
| `scripts/exif_analyzer.py` | Batch EXIF metadata extractor + GPS mapper |
| `scripts/mobile_osint_profiler.py` | Mobile identity footprinting pipeline |
| `queries/mdm_audit.spl` | Splunk SPL: Jamf Pro MDM compliance queries |
| `queries/mdm_audit.kql` | Sentinel KQL: MDM audit equivalents |
| `reports/day23_mobile_osint_report.md` | Full mobile OSINT findings |
| `reports/day23_mdm_hardening_checklist.md` | MDM policy hardening guide |
| `artifacts/exif_findings.json` | Extracted metadata findings |

---

*Day 23 Scenario | Mobile Device OSINT*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
