# Day 23 — MDM Hardening Checklist
## Mobile Device Management Policy Guide
**NovaCrest Capital Group | Security Operations**
**Author:** V. Willis, CISSP

---

## Jamf Pro Policy Hardening

### Device Compliance — Enforce via Jamf Smart Groups

```
COMPLIANCE POLICY: NovaCrest-Mobile-Baseline

Requirements (ALL must be met for compliant status):
  ☐ iOS version ≥ current-1 (within one major version of latest)
  ☐ Screen lock / passcode: REQUIRED
  ☐ Device encryption: REQUIRED
  ☐ Jailbreak detected: BLOCK (remove access if detected)
  ☐ MDM check-in within past 7 days
  ☐ CrowdStrike Falcon mobile agent: INSTALLED and reporting

Enforcement (non-compliant devices):
  → Block corporate email (Exchange ActiveSync policy)
  → Block VPN access (certificate-based; revoke cert)
  → Notify user and manager via automated email
  → Auto-resolve when device comes back into compliance
```

### Jamf Configuration Profile Settings

```
# Screen Lock (Passcode Policy)
Require passcode: YES
Minimum passcode length: 6 (prefer alphanumeric, 8+)
Maximum passcode age (days): 365
Maximum failed attempts: 10 (then wipe)
Auto-lock: 2 minutes

# OS Updates
Minimum iOS version: 17.4 (update quarterly)
Defer major updates: 30 days (testing window)
Force update deadline: 30 days from release

# App Management
Block jailbroken devices: YES
Allow voice dialing when locked: NO
Allow screenshots: YES (needed for Bloomberg)
Allow app installation from unknown sources: NO

# Data Protection
Force encrypted backup: YES
Allow iCloud backup of corporate apps: NO
  (Microsoft Intune App Protection Policy instead)
Allow AirDrop to unmanaged devices: NO

# Network
Require VPN for corporate resources: YES (Zscaler always-on)
Allow joining open Wi-Fi networks: NO (corporate networks only)
  (or: require VPN if on untrusted Wi-Fi)
```

### Restricted Apps (Jamf Restrictions Profile)

```
BLOCK these apps on supervised corporate devices:
  com.zhiliaoapp.musically   # TikTok / Douyin
  com.ss.iphone.ugc.Ame      # TikTok alt bundle IDs
  ph.telegra.Telegraph       # Telegram
  group.im.vector            # Element (Matrix)
  com.hammerandchisel.discord # Discord (if not approved)

ALLOW (managed allowlist — only approved apps):
  com.microsoft.Office.Outlook
  com.microsoft.Teams
  com.okta.mobile.auth
  com.crowdstrike.falcon.falconformdm
  com.zscaler.zscalertwo
  com.bloomberg.terminal     # Bloomberg Professional
```

### Managed App Distribution

```
Jamf App Catalog → Push to all enrolled devices:
  REQUIRED (compliance failure if not installed):
    - CrowdStrike Falcon for Mobile (MDM-managed)
    - Zscaler App (always-on VPN)
    - Okta Verify (MFA)
    - Microsoft Authenticator

  AVAILABLE (self-service):
    - Microsoft Office suite
    - Bloomberg Professional
    - Cisco Webex (backup comms)
```

---

## iOS EXIF & Privacy Settings

### MDM-Enforced Privacy Restrictions

```
# Location Services
Location Services: Restrict per-app
  Photos app: NEVER (prevents GPS tagging)
  Camera app: NEVER (prevents GPS tagging on photos)
  Approved apps only: WHILE USING

# Deploy via Jamf Configuration Profile:
PayloadType: com.apple.applicationaccess
AllowLocationServices: false  # For Camera specifically
  — OR —
Use MDM restrictions to set:
  forceLocationServicesEnabled: false for Camera
```

### Employee Communication — EXIF Policy

```
Distribute to all employees:
  "NovaCrest Mobile Photo Policy" (email/Teams)

Key points to communicate:
  1. NEVER post work-related photos from your corporate iPhone to
     personal social media — GPS metadata may be attached
  2. Before posting any photo to Instagram/LinkedIn/Twitter from
     your personal phone: Settings → Privacy → Location Services →
     Camera → NEVER
  3. LinkedIn strips GPS on profile photos but NOT on post images
  4. Instagram strips GPS on web uploads but MAY preserve it on
     Stories and app-direct shares
  5. If you post from the official NovaCrest social accounts, use
     the designated media workstation (not personal devices)
```

---

## BYOD Policy Tightening

### Current Gap

BYOD devices enrolled via Jamf are "unsupervised" — MDM can:
- ✅ Push managed apps (Outlook, Teams, Okta)
- ✅ Remote wipe managed apps only (not full device)
- ✅ Require passcode
- ❌ Cannot block personal apps
- ❌ Cannot enforce EXIF stripping
- ❌ Cannot block personal cloud storage

### Recommended BYOD Requirements

```
BYOD ENROLLMENT REQUIREMENTS:
  1. Managed apps only receive corporate data
     → Microsoft Intune App Protection Policies on Outlook/Teams
     → Corporate data cannot be copy/pasted to unmanaged apps
  
  2. Conditional Access (Azure AD):
     → Require MDM compliance = compliant OR
     → Require Intune App Protection Policy registration
     → Non-enrolled personal devices: no corporate access
  
  3. BYOD data classification:
     → EMAIL: Managed by Intune; no copy to personal apps
     → SHAREPOINT: Managed access only; no download to personal storage
     → BLOOMBERG: Corporate device only; no BYOD access
  
  4. BYOD personal cloud apps:
     → Cannot be blocked on personal device
     → MITIGATION: Intune prevents corporate data copy to Google Drive
     → Communicate policy: "Do not manually save corporate files to
       personal cloud storage"
```

---

## Incident Response — Mobile Device Procedures

### When a Corporate iPhone Is Reported Lost/Stolen

```
IMMEDIATE (within 30 minutes):
  1. Jamf Pro → Device Management → Lost Mode ON
     → Displays: "This device belongs to NovaCrest Capital Group.
                  If found, call +1-212-555-0100"
     → Plays sound and locks display
  
  2. Revoke all OAuth tokens (Azure AD → User → Revoke sessions)
  
  3. If data at risk: Jamf → Remote Wipe → Wipe Device
     → CAUTION: Full wipe; cannot be undone
     → Confirm with device owner before wiping

WITHIN 4 HOURS:
  4. Export last-known GPS location from Jamf before wipe
  5. Document last MDM check-in time and apps installed
  6. File police report if theft suspected
  7. Notify CISO if Bloomberg or client data was installed
```

### When Jailbreak Is Detected by MDM

```
IMMEDIATE:
  1. MDM auto-revokes email access (configure in compliance policy)
  2. Alert fires to SOC: "Jailbroken device detected — [owner]"
  3. SOC contacts device owner within 1 business hour
  
INVESTIGATION:
  4. Was it intentional? (user side-loading) or exploit? (zero-day)
  5. Review MDM logs for any policy bypass attempts
  6. Check CrowdStrike Falcon mobile agent telemetry
  7. If exploit: does employee need a replacement device?
  
RESOLUTION:
  8. Restore device from scratch (not from backup — backup may be infected)
  9. Re-enroll in MDM only after clean restore confirmed
```

---

## Awareness Training Additions

Add to quarterly security awareness training:

```
MODULE: "Your Phone is an OSINT Source"

Topics:
  1. What EXIF metadata is (5 min)
     - Demo: ExifTool output from a geotagged photo
     - Show: GPS coordinates on Google Maps
  
  2. How attackers use your social media (5 min)
     - Conference photos → spearphishing lure
     - Strava routes → home location inference
     - LinkedIn connections → org chart mapping
  
  3. What to do (5 min)
     - Camera: Settings → Privacy → Location → Camera → Never
     - Before posting: check for location icon in Photos
     - LinkedIn: Review what's public on your profile
     - Strava: Enable privacy zones around home and work
  
  4. MDM and your corporate phone (5 min)
     - What Jamf can and can't see on your device
     - Why compliance matters (Bloomberg access, email access)
     - How to update iOS on your corporate device
```

---

*Day 23 — MDM Hardening Checklist | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
