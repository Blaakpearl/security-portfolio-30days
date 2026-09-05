# Day 23 — LAB.md
## Mobile Device OSINT Lab Guide
**NovaCrest Capital Group | OSINT Track**

---

## Part 1: EXIF Metadata Analysis with ExifTool

### Install ExifTool
```bash
# Ubuntu / Debian
sudo apt-get install -y libimage-exiftool-perl

# macOS
brew install exiftool

# Verify
exiftool -ver   # Should return version number (e.g. 12.65)
```

### Basic EXIF Extraction
```bash
# Extract all metadata from a single image
exiftool photo.jpg

# Extract GPS coordinates only
exiftool -GPSLatitude -GPSLongitude -GPSAltitude photo.jpg

# Batch process a directory of images
exiftool -r -csv ./photos/ > exif_results.csv

# Extract key fields for OSINT: GPS, device, timestamp, software
exiftool -GPSLatitude -GPSLongitude -GPSAltitude \
         -Make -Model -Software \
         -DateTimeOriginal -CreateDate \
         -ImageDescription -UserComment \
         -csv ./photos/ > osint_extract.csv

# Convert GPS to decimal degrees (easier to map)
exiftool -GPSLatitude -GPSLongitude -n photo.jpg
# -n flag returns numeric values; without it: "40 deg 44' 54.36" N"
```

### Detecting Stripped vs. Intact Metadata
```bash
# Check if metadata was stripped (common on Instagram web upload)
exiftool -All photo.jpg | grep -c "GPS"    # 0 = stripped; >0 = intact

# Check for metadata inconsistencies (creation vs. modification time)
exiftool -DateTimeOriginal -FileModifyDate -CreateDate photo.jpg
# If FileModifyDate << DateTimeOriginal → possible evidence tampering

# Find photos with GPS in a large set
exiftool -if '$GPSLatitude' -filename -GPSLatitude -GPSLongitude ./photos/
```

### GPS to Usable Format
```bash
# Convert EXIF GPS to decimal degrees for Google Maps
python3 - << 'EOF'
import subprocess, re

def dms_to_decimal(dms_str):
    """Convert '40 deg 44\' 54.36" N' to decimal degrees."""
    parts = re.findall(r'[\d.]+', dms_str)
    d, m, s = float(parts[0]), float(parts[1]), float(parts[2])
    decimal = d + m/60 + s/3600
    if 'S' in dms_str or 'W' in dms_str:
        decimal = -decimal
    return round(decimal, 6)

# Example (from simulated j.henderson Instagram photo EXIF)
lat_raw = "40 deg 44' 54.36\" N"
lon_raw = "73 deg 59' 18.12\" W"
lat = dms_to_decimal(lat_raw)
lon = dms_to_decimal(lon_raw)
print(f"GPS: {lat}, {lon}")
print(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")
EOF
```

### Run the EXIF Analyzer Script
```bash
# Demo mode (simulated j.henderson photo set)
python3 scripts/exif_analyzer.py --demo --verbose

# Live mode (point at a directory of actual images)
python3 scripts/exif_analyzer.py --input ./photos/ --output artifacts/exif_findings.json
```

---

## Part 2: Mobile Identity Footprinting

### Phone Number OSINT
```bash
# Tool: PhoneInfoga (open source phone number OSINT)
pip install phoneinfoga --break-system-packages

# Basic scan
phoneinfoga scan -n "+12125550134"   # j.henderson corporate number

# Output: carrier, region, line type (mobile/VoIP), OSINT sources

# Alternative: NumVerify API (free tier)
curl "https://apilayer.net/api/validate?access_key=YOUR_KEY&number=12125550134"
```

### Social Account Enumeration (Sherlock)
```bash
# Install Sherlock
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock && pip install -r requirements.txt --break-system-packages

# Search for username across 400+ platforms
python3 sherlock jhenderson_nyc
python3 sherlock jhendersonfinance
python3 sherlock jhenderson_finance

# Outputs: list of platforms where username exists + profile URL
# Relevant for building attacker's recon picture of the target
```

### LinkedIn Footprinting (Manual + OSINT tools)
```bash
# LinkedIn company employee search (passive)
# In browser: site:linkedin.com "NovaCrest Capital" "Senior Financial Analyst"

# Extract LinkedIn data with li-scraper (legal for public profiles)
# pip install linkedin-api (requires valid LinkedIn account)
# Scope: name, title, connections, job history, education, public posts

# Key intel for attacker:
#   - Job title and team → spearphishing lure customization
#   - Connections → identify other targets for lateral spearphishing
#   - Recent activity (liked posts, shared articles) → trust signals for lure
#   - Work history → previous employers for credential reuse research
```

### App Store Footprinting
```bash
# Search iTunes/App Store for apps registered to corporate email
# (Attacker technique: find developer accounts, beta invites, personal projects)
# No command-line tool; use web search:
#   site:apps.apple.com "jhenderson@novacrest.com"
#   "novacrest" site:play.google.com

# Check Have I Been Pwned for corporate email exposure
curl "https://haveibeenpwned.com/api/v3/breachedaccount/jhenderson%40novacrest.com" \
     -H "hibp-api-key: YOUR_KEY"
```

---

## Part 3: MDM Posture Audit (Jamf Pro)

### Jamf Pro API — Device Compliance Check
```bash
# Jamf Pro REST API authentication
JAMF_URL="https://novacrest.jamfcloud.com"
JAMF_USER="api_svc_osint"
JAMF_PASS="[REDACTED]"

# Get auth token
TOKEN=$(curl -s -u "$JAMF_USER:$JAMF_PASS" \
    "$JAMF_URL/api/v1/auth/token" \
    -X POST | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# List all enrolled devices
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/json" \
     "$JAMF_URL/api/v1/computers-preview" | python3 -m json.tool

# Get specific device by serial number
SERIAL="DNPXQ2XYZABC"   # j.henderson iPhone
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/json" \
     "$JAMF_URL/api/v1/mobile-devices?filter=serialNumber==$SERIAL" \
     | python3 -m json.tool
```

### Key MDM Compliance Fields to Audit
```bash
# For each enrolled device, check:
#   osVersion          — is the device on the latest iOS?
#   isSupervised       — supervised = more control available
#   isEncrypted        — data at rest encrypted?
#   passcodePresent    — screen lock enabled?
#   isJailbroken       — MDM jailbreak detection result
#   lastContactTime    — when did device last check in?
#   managedApps        — inventory of all managed applications
#   certificates       — corporate cert installed?
#   restrictions       — what is MDM policy restricting?

# Jamf API: get compliance details for j.henderson device
curl -s -H "Authorization: Bearer $TOKEN" \
     -H "Accept: application/json" \
     "$JAMF_URL/api/v1/mobile-devices/12345/detail" \
     | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('OS Version:', d.get('general', {}).get('osVersion'))
print('Encrypted:', d.get('security', {}).get('dataProtected'))
print('Passcode:', d.get('security', {}).get('passcodePresent'))
print('Jailbroken:', d.get('security', {}).get('jailbreakDetected'))
print('Last Check-in:', d.get('general', {}).get('lastContactTime'))
"
```

### MDM Non-Compliance Report
```bash
# Find all devices NOT on latest iOS (17.4 as of Jun 2026)
curl -s -H "Authorization: Bearer $TOKEN" \
     "$JAMF_URL/api/v1/mobile-devices" | python3 -c "
import sys, json
devices = json.load(sys.stdin).get('results', [])
outdated = [d for d in devices if d.get('osVersion','') < '17.4']
print(f'Outdated devices: {len(outdated)} / {len(devices)}')
for d in outdated:
    print(f'  {d[\"serialNumber\"]} — iOS {d[\"osVersion\"]} — {d.get(\"username\")}')
"

# Find devices without screen lock
# Find devices that haven't checked in for > 30 days (possibly lost/stolen)
# Run: python3 scripts/mobile_osint_profiler.py --mode mdm-audit --demo
```

### Run the Full Mobile OSINT Profiler
```bash
python3 scripts/mobile_osint_profiler.py --demo --subject jhenderson --verbose
```

---

## Part 4: CellHawk (Cell Tower OSINT)

CellHawk is a commercial intelligence platform for cell tower and carrier OSINT.
In a lab context, the relevant capability is understanding what cell tower data
can reveal about a target's location patterns — relevant for physical security
assessment and for understanding attacker recon potential.

```
WHAT CELLHAWK REVEALS (from carrier data / tower records):
  - Approximate location history (tower-level, ~500m accuracy)
  - Carrier name, account type, registration date
  - Device type (handset category from IMSI)
  - Roaming history (international travel)
  - Call pattern analysis (frequency, duration — not content)

LEGAL CAVEAT:
  - Cell tower records require legal process (warrant or subpoena) in most jurisdictions
  - OSINT use case: understand the surface area, not perform warrantless tracking
  - For NovaCrest: this data was obtained via legal hold in the IR process

DEMO: Use simulated cell tower records in mobile_osint_profiler.py
```

---

*Day 23 Lab Guide | Mobile Device OSINT*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
