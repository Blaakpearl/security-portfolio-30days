# Day 23 — Mobile OSINT Report
## Mobile Device Intelligence & MDM Audit
**NovaCrest Capital Group | Threat Intelligence**
**Classification:** TLP:AMBER — Restricted Distribution
**Author:** V. Willis, CISSP
**Date:** 2026-06-23

---

## Executive Summary

Mobile OSINT analysis of the NovaCrest employee footprint revealed
significant intelligence exposure through public social media profiles,
intact EXIF metadata on public photos, and corporate email confirmed in
breach databases. MDM audit of the enrolled device fleet identified three
compliance failures — one critical (no screen lock on a Bloomberg-enrolled
device). The MDM check-in log for `j.henderson`'s iPhone correlates
directly to the phishing email open time, confirming mobile was the initial
delivery channel.

| Finding Category | Count | Highest Severity |
|-----------------|-------|-----------------|
| EXIF/GPS exposure | 4 of 5 photos geotagged | Critical |
| Social media footprint | 5 platforms identified | Critical (GitHub + Instagram) |
| Breach database exposure | 2 emails compromised | Critical (personal email) |
| MDM compliance gaps | 2 of 3 devices non-compliant | Critical (no screen lock) |
| Device-phishing correlation | Confirmed | High |

---

## Part 1 — EXIF Metadata Findings

### Photo Set Analysis (5 Public Images)

**4 of 5 photos contained GPS coordinates.** Instagram only strips EXIF on
web uploads — the Instagram app sometimes preserves GPS in Stories and
downloads. LinkedIn strips EXIF on all profile photos but not on posts.

| Photo | Platform | GPS | Device | Risk |
|-------|----------|-----|--------|------|
| Instagram lunch photo (May 14) | Instagram | ✅ 40.748817, -73.985428 | iPhone 15 Pro, iOS 17.2.1 | Critical |
| LinkedIn profile photo | LinkedIn | ❌ Stripped | Adobe PS only | Medium |
| FinTech Summit photo (Mar 22) | Instagram | ✅ 40.761429, -73.977355 | iPhone 15 Pro, iOS 17.2.0 | Critical |
| M. Torres LinkedIn photo | LinkedIn | ✅ 40.706005, -74.008827 | Samsung Galaxy S24 | Critical |
| Team photo (NovaCrest Twitter) | Twitter/X | ✅ 40.748540, -73.983992 | iPhone 14, iOS **16.7.4** | Critical |

### Critical Findings

**Finding 1 — FinTech Summit Photo (Most Significant)**

The Instagram photo from March 22, 2026 was taken at the Javits Center
(GPS confirmed: 40.761429, -73.977355) and tagged `#FinTechSummit2026`.
This single data point gave the attacker everything needed to craft the
spearphishing lure used on June 14:

```
Attacker's kill chain from this single photo:
  1. Photo taken at Javits Center → j.henderson attended FinTech Summit 2026
  2. #FinTechSummit2026 → public agenda and speaker list available
  3. Lure: "Q3 Investment Strategy" from a fake conference follow-up sender
  4. j.henderson recognized the context → opened attachment
```

**Finding 2 — Corporate Office Location Confirmed**

Three photos cluster within 200 meters of the NovaCrest office building
(Grand Central area). An attacker can identify the physical office
location, employee arrival/departure patterns, and building security
posture — all from public Instagram posts.

**Finding 3 — Outdated iOS on Official Twitter Post**

The team photo posted from the NovaCrest official Twitter account was
taken on an iPhone 14 running iOS 16.7.4 — two major versions behind
the then-current iOS 17.4. This indicates an unmanaged personal device
was used to post corporate content, and the device owner (`s.chen`) has
a significantly outdated OS with multiple known CVEs.

**Finding 4 — Employee Email in LinkedIn Metadata**

`j.henderson`'s LinkedIn profile photo had the corporate email address
(`jhenderson@novacrest.com`) embedded in the EXIF `UserComment` field.
Adobe Photoshop preserves this field during export. This confirms the
email address for phishing targeting without any additional effort.

---

## Part 2 — Mobile Identity Footprint

### Platform Presence (j.henderson)

| Platform | Username | Followers | Risk | Key Intel |
|----------|----------|-----------|------|-----------|
| LinkedIn | jhenderson-finance | 847 conn | High | Full career history; org chart mapping |
| Instagram | jhenderson_nyc | 847 | **Critical** | 47 geotagged photos; routine visible |
| Twitter/X | jhenderson_finance | 312 | High | Conference attendance; employer confirmed |
| **GitHub** | jhenderson85 | — | **Critical** | bloomberg-api-tools repo; key naming patterns |
| Strava | jhenderson_nyc | — | High | Home location inferred from run start points |

### GitHub Finding (Critical)

The `jhenderson85/bloomberg-api-tools` public repository contains comments
referencing `novacrest-prod` in API configuration examples. While no actual
key was committed (the incident key came from a different repo), the repository
reveals:
- j.henderson has direct Bloomberg API integration access
- The production environment name is `novacrest-prod`
- Python SDK usage patterns (enables crafting targeted exploitation code)
- The attacker almost certainly found this repository during Day 15 recon

### Strava — Home Location Inference

Strava activity start/end points cluster in the Upper West Side, allowing
inference of approximate home location within 3–4 blocks. This is a
frequently overlooked OSINT source — most users don't consider fitness
apps as a security risk.

---

## Part 3 — Breach Database Exposure

| Email | Breaches | Severity | Risk |
|-------|---------|----------|------|
| `jhenderson@novacrest.com` | LinkedIn 2021 | Medium | Phone number and name confirmed |
| `jhenderson85@gmail.com` | Adobe 2013 + Collection #1 2019 | **Critical** | Password hashes from 2013 may still be in use for password reuse |

**Critical finding:** The personal Gmail address (`jhenderson85@gmail.com`) appeared
in the Collection #1 dump (2019) which contains cracked plaintext passwords.
If j.henderson reused this password for any corporate system — VPN, SSO portal,
personal cloud services that sync to corporate device — the attacker had a second
potential access path beyond the phishing macro.

---

## Part 4 — MDM Device Compliance Audit

### Fleet Summary (Enrolled Devices)

| Device | Owner | Model | iOS | Screen Lock | Supervised | Risk |
|--------|-------|-------|-----|-------------|------------|------|
| MDM-001 | j.henderson | iPhone 15 Pro | 17.4.1 | ✅ | ✅ | Low |
| MDM-002 | m.torres | Galaxy S24 | Android 14 | ✅ | ❌ BYOD | Medium |
| MDM-003 | **s.chen** | iPhone 14 | **16.7.4** | **❌ NONE** | ✅ | **Critical** |

### MDM-003 — Critical Finding (s.chen)

- **iOS 16.7.4** — 17.5 is current. Two major versions behind. CVE-2023-42916
  (WebKit zero-click) and CVE-2024-23222 (JavaScriptCore) both unpatched on this
  device. Both were exploited in the wild.
- **No screen lock** — the device is completely unprotected if lost or stolen.
  Bloomberg Professional app is installed. All NovaCrest client data accessible
  without authentication.
- **TikTok installed** — ByteDance data sharing concerns; US government contractors
  are prohibited; many enterprises follow the same policy. Data on the device
  (including contacts with corporate emails) is at risk.

### MDM-001 — j.henderson Device Correlation

MDM check-in log shows last contact at `2026-06-14T08:47:00Z` — exactly when
the phishing email was opened. The device was within range of the NovaCrest
office cell towers (confirmed from MDM location data). This confirms:

1. The phishing email was first opened on the iPhone at 08:47 UTC
2. j.henderson commuted to the office after reading the email
3. At 09:12:34 UTC, she opened the attachment on WS-FIN-04 and enabled macros

**The mobile device was the initial delivery channel.** The iOS Mail app
rendered the phishing email with image loading enabled (external image pixel
confirmed in NGFW logs), which also pre-seeded the attacker's open tracking.

---

## Recommendations

### Immediate (This Week)

1. **MDM-003 (s.chen):** Force iOS update to 17.5 via MDM policy; enforce screen
   lock via Jamf compliance policy — device access blocked until compliant
2. **TikTok:** Deploy MDM restriction to block TikTok on all supervised devices
3. **EXIF stripping:** Enable automatic EXIF strip on all corporate social media
   posting tools; add to social media policy
4. **GitHub audit:** Scan all public GitHub repos associated with corporate emails
   for credential references, key naming patterns, and internal system names

### This Month

5. **Strava/fitness apps:** Add to the OSINT awareness training module — employees
   should understand that fitness app routes expose home location
6. **Personal email breach:** Notify j.henderson to change all passwords associated
   with the compromised personal Gmail; verify no password reuse on corporate systems
7. **Bloomberg MDM app:** Review Bloomberg Professional app MDM configuration;
   ensure data cannot be accessed without corporate authentication
8. **BYOD policy tightening:** Unsupervised BYOD (MDM-002, m.torres) should not
   have personal cloud storage apps — Google Drive Personal is a data exfil channel
   that MDM cannot block on unsupervised enrollment

### MDM Policy Hardening

See `reports/day23_mdm_hardening_checklist.md` for full policy checklist.

---

*Day 23 — Mobile OSINT Report | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
