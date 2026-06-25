# Day 05 — Lab Guide: Social Engineering Surface Mapping
### Track: OSINT | Duration: ~3 hours | Difficulty: Intermediate

> **Authorization reminder:** All techniques in this lab are passive, public-source only.
> Apply only under written engagement authorization. This lab demonstrates defensive
> awareness — knowing your own organization's public exposure so you can reduce it.

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Sherlock** | Cross-platform username enumeration | `pip install sherlock-project` |
| **SpiderFoot** | Automated multi-source OSINT | `pip install spiderfoot` |
| **theHarvester** | Email/name harvesting from public sources | `pip install theHarvester` |
| **Photon** | Web crawler for OSINT data extraction | `pip install photon` |
| **Python 3** | Automation, Google dork runner, report gen | Pre-installed |
| **requests / bs4** | HTTP requests and HTML parsing | `pip install requests beautifulsoup4` |
| **jq** | JSON output parsing | `sudo apt install jq` |

---

## 🖥 Environment Setup

```bash
# 1. Create working directory
mkdir -p ~/security-labs/day-05/artifacts/{sherlock,spiderfoot,dorks,pretexts}
cd ~/security-labs/day-05

# 2. Install tools
pip install sherlock-project spiderfoot theHarvester \
    requests beautifulsoup4 pandas --break-system-packages

# 3. Set target (use your own organization or a fictional stand-in)
export TARGET_DOMAIN="novacrest-capital.com"
export TARGET_ORG="NovaCrest Capital Group"
export TARGET_SHORT="NovaCrest"

echo "[+] Environment ready — target: $TARGET_ORG"
echo "[+] All collection is passive / authorized OSINT only"
```

---

## STEP 1 — Organizational Structure Mapping

**Objective:** Build an org chart from public sources — website leadership pages,
press releases, LinkedIn, and conference appearances.

### 1a. Company Website & Press Release Mining

```bash
# Crawl the target website for employee names and roles
echo "[*] Crawling public website for personnel information..."

# Using Photon crawler (adjust depth based on site size)
python3 -m photon \
  -u "https://www.$TARGET_DOMAIN" \
  --level 2 \
  --output artifacts/photon_crawl \
  --timeout 10 2>/dev/null

echo "[+] Photon crawl complete"

# Extract names and roles from crawled content
grep -riE "([A-Z][a-z]+ [A-Z][a-z]+), (CEO|CFO|CTO|CISO|VP|Director|Managing|Partner|Head of)" \
  artifacts/photon_crawl/ 2>/dev/null \
  | sed 's/.*:\(.*\)/\1/' \
  | sort -u \
  | tee artifacts/leadership_from_website.txt

echo "[+] Leadership names extracted: $(wc -l < artifacts/leadership_from_website.txt)"
```

### 1b. Google Dork Runner — Automated Leadership Discovery

```python
# Save as: google_dork_runner.py
# Uses search-engine-friendly dorks to surface employee information
# from publicly indexed sources — LinkedIn, SEC filings, press releases

import time
import json
from datetime import datetime

TARGET_ORG    = "NovaCrest Capital Group"
TARGET_DOMAIN = "novacrest-capital.com"

# Curated dork library for employee and structure discovery
DORKS = {
    "leadership_linkedin": [
        f'site:linkedin.com/in "{TARGET_ORG}" CEO OR CFO OR CTO OR CISO OR "Managing Director"',
        f'site:linkedin.com/in "{TARGET_ORG}" "Vice President" OR "Head of" OR "Director"',
        f'site:linkedin.com/in "{TARGET_ORG}" "Fixed Income" OR "Investment Banking" OR "Risk"',
    ],
    "press_and_news": [
        f'"{TARGET_ORG}" "announced" "appointed" site:businesswire.com OR site:prnewswire.com',
        f'"{TARGET_ORG}" "joins" OR "promotes" OR "named" CEO OR CFO filetype:html',
        f'"{TARGET_ORG}" "Managing Director" OR "Partner" site:bloomberg.com OR site:reuters.com',
    ],
    "sec_filings": [
        f'site:sec.gov "{TARGET_ORG}" "executive officers" OR "named executive"',
        f'site:sec.gov "{TARGET_DOMAIN}" "principal financial officer"',
    ],
    "conference_speakers": [
        f'"{TARGET_ORG}" "speaker" OR "panelist" OR "keynote" site:*.org OR site:*.io',
        f'"{TARGET_ORG}" "presentation" filetype:pdf conference 2023 OR 2024 OR 2025',
    ],
    "vendor_and_tech_stack": [
        f'site:linkedin.com/jobs "{TARGET_ORG}" "Bloomberg" OR "Advent" OR "Murex" OR "Charles River"',
        f'site:linkedin.com/jobs "{TARGET_ORG}" "Splunk" OR "CrowdStrike" OR "Palo Alto" OR "ServiceNow"',
        f'site:linkedin.com/jobs "{TARGET_ORG}" "AWS" OR "Azure" OR "Salesforce" OR "Workday"',
    ],
    "github_and_code": [
        f'site:github.com "{TARGET_DOMAIN}" OR "{TARGET_SHORT.lower()}"',
        f'site:pastebin.com "{TARGET_DOMAIN}"',
    ],
    "internal_docs_exposed": [
        f'site:{TARGET_DOMAIN} filetype:pdf OR filetype:xlsx OR filetype:docx',
        f'site:{TARGET_DOMAIN} inurl:internal OR inurl:private OR inurl:confidential',
        f'"{TARGET_DOMAIN}" filetype:pdf "internal use only" OR "confidential"',
    ],
}

print(f"{'='*65}")
print(f"  Google Dork Runner — {TARGET_ORG}")
print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
print(f"{'='*65}\n")
print(f"[*] {sum(len(v) for v in DORKS.values())} dorks across {len(DORKS)} categories")
print(f"[!] Manual execution required — paste each dork into Google\n")

all_dorks = []
for category, dork_list in DORKS.items():
    print(f"\n### {category.replace('_',' ').upper()} ###")
    for dork in dork_list:
        print(f"  {dork}")
        all_dorks.append({"category": category, "dork": dork})

# Save full dork library to file
with open("artifacts/dorks/google_dork_library.json", "w") as f:
    json.dump(all_dorks, f, indent=2)

# Save as plain text for easy copy-paste
with open("artifacts/dorks/google_dorks.txt", "w") as f:
    f.write(f"# Google Dork Library — {TARGET_ORG}\n")
    f.write(f"# Generated: {datetime.now().isoformat()}\n")
    f.write(f"# Authorized defensive OSINT — signed ROE required\n\n")
    for category, dork_list in DORKS.items():
        f.write(f"\n## {category.upper()}\n")
        for d in dork_list:
            f.write(f"{d}\n")

print(f"\n[+] Dork library saved: artifacts/dorks/google_dork_library.json")
print(f"[+] Plain text copy:    artifacts/dorks/google_dorks.txt")
print(f"\n[*] Execute dorks manually in a browser and record findings in:")
print(f"    artifacts/dorks/dork_findings.md")
```

```bash
python3 google_dork_runner.py
```

### 1c. Org Chart Builder — Record Your Findings

```bash
cat > artifacts/org_chart.md << 'EOF'
# NovaCrest Capital Group — Inferred Org Chart
# Source: Public OSINT — LinkedIn, company website, press releases
# Date: 2025-01-16 | Analyst: Blaakpearl

## Executive Leadership
| Name | Title | Source | LinkedIn | Risk Tier |
|------|-------|--------|----------|-----------|
| [CEO Name] | Chief Executive Officer | Company website | [URL] | CRITICAL |
| [CFO Name] | Chief Financial Officer | SEC filing | [URL] | CRITICAL |
| [CISO Name] | Chief Information Security Officer | LinkedIn | [URL] | HIGH |
| [CTO Name] | Chief Technology Officer | Press release | [URL] | HIGH |

## Department Heads
| Name | Title | Department | Source | Risk Tier |
|------|-------|------------|--------|-----------|
| [Name] | Head of Fixed Income | Trading | LinkedIn | HIGH |
| [Name] | Managing Director, M&A | Investment Banking | LinkedIn | CRITICAL |
| [Name] | IT Director | Technology | Job posting | HIGH |
| [Name] | HR Manager | Human Resources | LinkedIn | MEDIUM |

## Technology Footprint (from Job Postings)
| Tool/Vendor | Category | Source | Intel Value |
|-------------|----------|--------|-------------|
| Bloomberg Terminal | Trading platform | LinkedIn job | CRITICAL — standard in spearphish |
| Splunk | SIEM | Job posting | HIGH — security stack indicator |
| CrowdStrike Falcon | EDR | Job posting | HIGH — security stack indicator |
| Workday | HR platform | Job posting | MEDIUM — HR pretext enabler |
| Salesforce | CRM | Job posting | MEDIUM |
| AWS | Cloud | Job posting | HIGH |

## Key Business Relationships (from press/news)
| Partner/Vendor | Relationship | Source | Pretext Value |
|----------------|-------------|--------|---------------|
| [Vendor Name] | Technology partner | Press release | HIGH |
| [Bank Name] | Custodian bank | SEC filing | HIGH |
| [Law Firm] | Legal counsel | Regulatory filing | MEDIUM |
EOF

echo "[+] Org chart template created: artifacts/org_chart.md"
echo "[!] Fill in with findings from your dork execution and LinkedIn review"
```

**✅ Checkpoint 1:** You should have a populated org chart with at least 5 named
roles, their sources, and an initial risk tier. The technology footprint section
is gold — it tells you exactly what tools to impersonate in phishing pretexts.

---

## STEP 2 — Email Format Validation & Enumeration

**Objective:** Confirm the email naming convention and build a validated list
of high-value target email addresses.

```python
# Save as: email_validator.py
# Validates email naming convention using SMTP VRFY, MX headers, and HIBP cross-ref
# Note: SMTP VRFY is often disabled on modern mail servers (expected)

import re
import dns.resolver  # pip install dnspython
import requests
import time
import os

TARGET_DOMAIN = "novacrest-capital.com"
HIBP_KEY      = os.environ.get("HIBP_API_KEY", "")

# Common naming conventions to test
KNOWN_NAMES = [
    ("james",  "morrison"),   # CEO
    ("sarah",  "chen"),       # Head of M&A
    ("robert", "patel"),      # IT Director
    ("michael","johnson"),    # CFO
    ("lisa",   "williams"),   # HR Manager
]

FORMATS = [
    "{first}.{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{first}@{domain}",
    "{f}.{last}@{domain}",
]

def generate_emails(first, last, domain):
    """Generate candidate email addresses for a name."""
    return [
        fmt.format(
            first=first, last=last,
            f=first[0], domain=domain
        )
        for fmt in FORMATS
    ]

def check_mx(domain):
    """Confirm MX records exist (prerequisite for email validation)."""
    try:
        mx = dns.resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in mx]
    except Exception:
        return []

def hibp_check(email, api_key):
    """Check if email appears in HIBP — confirms it's a real/active address."""
    if not api_key:
        return None
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "SecurityPortfolio-Blaakpearl-Day05"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    r = requests.get(url, headers=headers, timeout=10)
    time.sleep(1.5)
    if r.status_code == 200:
        return {"found": True, "breach_count": len(r.json())}
    elif r.status_code == 404:
        return {"found": False, "breach_count": 0}
    return None

print(f"\n{'='*60}")
print(f"  Email Format Validator — {TARGET_DOMAIN}")
print(f"{'='*60}\n")

mx_records = check_mx(TARGET_DOMAIN)
if mx_records:
    print(f"[+] MX records confirmed: {mx_records[0]}")
else:
    print(f"[!] No MX records found — email validation limited")

print(f"\n[*] Testing naming conventions for {len(KNOWN_NAMES)} known employees...\n")

confirmed_format = None
results = []

for first, last in KNOWN_NAMES:
    candidates = generate_emails(first, last, TARGET_DOMAIN)
    print(f"  Testing: {first.title()} {last.title()}")

    for email in candidates:
        hibp = hibp_check(email, HIBP_KEY)
        if hibp and hibp["found"]:
            status = f"CONFIRMED (HIBP: {hibp['breach_count']} breaches)"
            if not confirmed_format:
                # Extract format from this confirmed email
                local = email.split("@")[0]
                if f"{first}.{last}" in local:
                    confirmed_format = "firstname.lastname"
                elif f"{first[0]}{last}" in local:
                    confirmed_format = "flastname"
                elif f"{first}{last}" in local:
                    confirmed_format = "firstnamelastname"
            results.append({
                "email": email, "status": "CONFIRMED",
                "hibp_breaches": hibp["breach_count"]
            })
            print(f"    ✅ {email} — {status}")
            break
        else:
            status = "Not in HIBP (unconfirmed)"
            print(f"    ?  {email} — {status}")

if confirmed_format:
    print(f"\n[!!!] Email format CONFIRMED: {confirmed_format}@{TARGET_DOMAIN}")
else:
    print(f"\n[*] Format unconfirmed via HIBP — most common for financial orgs:")
    print(f"    firstname.lastname@{TARGET_DOMAIN}")
    confirmed_format = "firstname.lastname (inferred)"

print(f"\n[+] Summary:")
print(f"    Confirmed format: {confirmed_format}")
print(f"    Confirmed emails: {len([r for r in results if r['status']=='CONFIRMED'])}")

# Save results
import json
with open("artifacts/email_validation_results.json", "w") as f:
    json.dump({"format": confirmed_format, "results": results}, f, indent=2)

print(f"[+] Results saved: artifacts/email_validation_results.json")
```

```bash
pip install dnspython --break-system-packages
python3 email_validator.py | tee artifacts/email_validation_summary.txt
```

---

## STEP 3 — Sherlock: Cross-Platform Username Enumeration

**Objective:** Given identified employee names, search for their presence across
300+ platforms — revealing personal email addresses, social profiles, side projects,
and personal information that enriches the spearphishing pretext.

```bash
echo "[*] Running Sherlock username enumeration..."
echo "[*] Target: sample usernames derived from confirmed employee names"
echo ""

# Derive usernames from known names (common patterns people use online)
# For authorized assessments: use names already confirmed from LinkedIn/public sources

USERNAMES=(
    "jmorrison"
    "jamesmorrison"
    "j.morrison"
    "schen_finance"
    "rpatel_it"
)

for USERNAME in "${USERNAMES[@]}"; do
    echo "=== Sherlock: $USERNAME ==="
    sherlock "$USERNAME" \
        --output "artifacts/sherlock/${USERNAME}_results.txt" \
        --print-found \
        --timeout 10 \
        2>/dev/null | grep -v "^$" | head -20
    echo ""
    sleep 2
done

echo "[+] Sherlock complete — results in artifacts/sherlock/"
echo "[+] Profiles found:"
grep -r "\[+\]" artifacts/sherlock/ 2>/dev/null | wc -l
```

### Parse & Prioritize Sherlock Results

```python
# Save as: parse_sherlock.py
import os
import json
from pathlib import Path

SHERLOCK_DIR = "artifacts/sherlock"

# Platforms with highest intelligence value for spearphishing
HIGH_VALUE_PLATFORMS = {
    "GitHub":       "Source code, projects, company repos, email leaks",
    "Twitter":      "Personal opinions, interests, events attended, contacts",
    "Instagram":    "Personal life, location data, social connections",
    "Reddit":       "Anonymous discussions revealing work frustrations, tech stack",
    "HackerNews":   "Technical interests, job market activity",
    "LinkedIn":     "Full work history, skills, connections",
    "Medium":       "Published articles revealing expertise and opinions",
    "Keybase":      "Cryptographic identity, linked accounts",
    "Gravatar":     "Linked email addresses",
    "SlideShare":   "Professional presentations — internal project details",
    "Speakerdeck":  "Conference talks — internal tools and processes revealed",
}

all_findings = {}

for filepath in Path(SHERLOCK_DIR).glob("*_results.txt"):
    username = filepath.stem.replace("_results", "")
    found_platforms = []

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[+]") and "http" in line:
                # Extract platform and URL
                parts = line.split(": ", 1)
                if len(parts) == 2:
                    platform_url = parts[1]
                    # Try to extract platform name
                    for platform in HIGH_VALUE_PLATFORMS:
                        if platform.lower() in platform_url.lower():
                            found_platforms.append({
                                "platform": platform,
                                "url": platform_url.strip(),
                                "intel_value": HIGH_VALUE_PLATFORMS[platform],
                                "priority": "HIGH"
                            })
                            break
                    else:
                        found_platforms.append({
                            "platform": "Other",
                            "url": platform_url.strip(),
                            "intel_value": "Review manually",
                            "priority": "MEDIUM"
                        })

    all_findings[username] = found_platforms

# Print prioritized results
print("=" * 60)
print("  Sherlock Results — Prioritized by Intelligence Value")
print("=" * 60)

for username, platforms in all_findings.items():
    high_value = [p for p in platforms if p["priority"] == "HIGH"]
    print(f"\nUsername: {username} — {len(platforms)} platforms found "
          f"({len(high_value)} high-value)")
    for p in sorted(platforms, key=lambda x: x["priority"]):
        marker = "🔴" if p["priority"] == "HIGH" else "🟡"
        print(f"  {marker} {p['platform']}: {p['url']}")
        if p["intel_value"] != "Review manually":
            print(f"     Intel value: {p['intel_value']}")

# Save structured results
with open("artifacts/sherlock_analysis.json", "w") as f:
    json.dump(all_findings, f, indent=2)

print(f"\n[+] Parsed results: artifacts/sherlock_analysis.json")
```

```bash
python3 parse_sherlock.py | tee artifacts/sherlock_summary.txt
```

**✅ Checkpoint 2:** GitHub profiles are the highest-value Sherlock finding —
developers often commit code that includes internal hostnames, API keys, or
comments revealing internal tooling and architecture. Reddit is second — people
often discuss work problems anonymously, revealing security tool names, pain
points, and internal culture details.

---

## STEP 4 — SpiderFoot: Automated Entity Relationship Mapping

**Objective:** Run SpiderFoot's OSINT automation to build an entity graph
connecting the organization's domain, employees, IPs, and third-party relationships.

```bash
echo "[*] Starting SpiderFoot scan..."
echo "[*] Module selection: passive/public sources only"

# SpiderFoot CLI scan — passive modules only (no active probing)
# sfp_ prefix = SpiderFoot plugin

spiderfoot \
  -s "$TARGET_DOMAIN" \
  -t "DOMAIN_NAME,EMAILADDR,HUMAN_NAME,PHONE_NUMBER,SOCIAL_MEDIA" \
  -m sfp_dns,sfp_whois,sfp_ssl,sfp_crt,sfp_hunter,sfp_linkedin,sfp_github \
  -o "artifacts/spiderfoot/sf_scan.json" \
  -q \
  2>/dev/null \
  || echo "[!] SpiderFoot CLI: run via web UI if CLI fails (spiderfoot -l 127.0.0.1:5001)"

echo ""
echo "[+] Alternative: SpiderFoot Web UI"
echo "    spiderfoot -l 127.0.0.1:5001"
echo "    Browse to http://127.0.0.1:5001"
echo "    New Scan → Target: $TARGET_DOMAIN → Select 'Passive' modules"
```

### Parse SpiderFoot Output

```python
# Save as: parse_spiderfoot.py
import json
from collections import defaultdict

try:
    with open("artifacts/spiderfoot/sf_scan.json") as f:
        data = json.load(f)
except FileNotFoundError:
    # Demo structure if scan not yet run
    data = {"data": [
        {"type": "EMAILADDR",    "data": "it.helpdesk@novacrest-capital.com",    "module": "sfp_hunter"},
        {"type": "EMAILADDR",    "data": "j.morrison@novacrest-capital.com",     "module": "sfp_linkedin"},
        {"type": "HUMAN_NAME",   "data": "James Morrison",                       "module": "sfp_linkedin"},
        {"type": "HUMAN_NAME",   "data": "Sarah Chen",                           "module": "sfp_linkedin"},
        {"type": "SOCIAL_MEDIA", "data": "https://linkedin.com/in/jamesmorrison","module": "sfp_linkedin"},
        {"type": "CO_HOSTED_SITE","data":"staging.novacrest-capital.com",        "module": "sfp_dns"},
    ]}
    print("[!] Using demo data — run SpiderFoot scan to populate real results")

entities = defaultdict(list)
for item in data.get("data", []):
    entities[item.get("type", "UNKNOWN")].append(item.get("data", ""))

print("\n=== SpiderFoot Entity Summary ===")
for etype, items in sorted(entities.items()):
    unique = list(set(items))
    print(f"\n{etype} ({len(unique)} found):")
    for item in unique[:8]:
        print(f"  • {item}")
    if len(unique) > 8:
        print(f"  ... and {len(unique)-8} more")

# Save structured entity list
with open("artifacts/spiderfoot/entity_summary.json", "w") as f:
    json.dump(dict(entities), f, indent=2)
print(f"\n[+] Entity summary: artifacts/spiderfoot/entity_summary.json")
```

```bash
python3 parse_spiderfoot.py | tee artifacts/spiderfoot/spiderfoot_summary.txt
```

---

## STEP 5 — High-Value Target (HVT) Profiling

**Objective:** Combine all collected intelligence to identify and rank high-value
targets — individuals whose compromise would have the highest business impact.

```python
# Save as: hvt_profiler.py
# Ranks individuals by compromise impact × social engineering susceptibility

import json
from dataclasses import dataclass, field
from typing import List

@dataclass
class Target:
    name:           str
    title:          str
    department:     str
    email:          str
    access_level:   int   # 1-10: access to critical systems/data
    breach_count:   int   # from Day 02 HIBP data
    social_exposure:int   # 1-10: online presence / findable info
    pretext_material: List[str] = field(default_factory=list)

    @property
    def hvt_score(self):
        """Higher score = higher priority target for attacker."""
        return (self.access_level * 0.5 +
                self.breach_count * 0.2 +
                self.social_exposure * 0.3)

    @property
    def risk_tier(self):
        s = self.hvt_score
        if s >= 8:   return "CRITICAL"
        elif s >= 6: return "HIGH"
        elif s >= 4: return "MEDIUM"
        else:        return "LOW"

# Build target list from collected intelligence
# (Populate with real findings from Steps 1-4)
targets = [
    Target(
        name="James Morrison",
        title="Chief Executive Officer",
        department="Executive",
        email="j.morrison@novacrest-capital.com",
        access_level=10,
        breach_count=5,     # from Day 02 HIBP results
        social_exposure=8,
        pretext_material=[
            "LinkedIn: 23-year finance career, keynote at Bloomberg conference 2024",
            "Twitter: active — posts about Fed decisions and market commentary",
            "SEC filing: identified as principal executive officer",
            "Bloomberg profile: photo, career history, quoted on M&A trends",
        ]
    ),
    Target(
        name="Sarah Chen",
        title="Head of M&A",
        department="Investment Banking",
        email="s.chen@novacrest-capital.com",
        access_level=9,
        breach_count=3,
        social_exposure=7,
        pretext_material=[
            "LinkedIn: listed current deal: 'Apex Partners integration'",
            "Conference speaker: FinTech Summit 2024 — 'Cross-border M&A trends'",
            "Slide deck public: revealed use of Intralinks virtual data room",
            "Twitter: posted about hiring for M&A analyst role — team expanding",
        ]
    ),
    Target(
        name="Robert Patel",
        title="IT Director",
        department="Technology",
        email="r.patel@novacrest-capital.com",
        access_level=10,
        breach_count=4,
        social_exposure=9,
        pretext_material=[
            "GitHub: personal account 'rpatel-dev' — repos mention NovaCrest",
            "LinkedIn: skills list reveals: Splunk, CrowdStrike, Palo Alto, Azure AD",
            "Job posting he authored: reveals full security stack",
            "Reddit (r/sysadmin): posts about Splunk licensing frustrations",
        ]
    ),
    Target(
        name="Lisa Williams",
        title="HR Manager",
        department="Human Resources",
        email="l.williams@novacrest-capital.com",
        access_level=7,
        breach_count=2,
        social_exposure=8,
        pretext_material=[
            "LinkedIn: manages benefits enrollment — perfect BEC pretext",
            "Posted: 'Open enrollment closes Jan 31' — confirms active benefits period",
            "Uses Workday (from job posting she shared)",
            "Personal email linked via Gravatar: lwilliams.hr@gmail.com",
        ]
    ),
    Target(
        name="Mike Thompson",
        title="Fixed Income Analyst",
        department="Trading",
        email="m.thompson@novacrest-capital.com",
        access_level=7,
        breach_count=5,   # Highest breach count — already compromised (Day 04)
        social_exposure=5,
        pretext_material=[
            "COMPROMISED — Day 04: beacon running on DESKTOP-FIN-047",
            "LinkedIn: Bloomberg certified, CFA charterholder",
            "Low social media presence — harder to target via social eng",
        ]
    ),
]

targets.sort(key=lambda t: t.hvt_score, reverse=True)

print("=" * 65)
print("  High-Value Target Profile — NovaCrest Capital Group")
print("=" * 65)

for t in targets:
    print(f"\n{'─'*65}")
    print(f"  {t.risk_tier:10} | {t.name} — {t.title}")
    print(f"{'─'*65}")
    print(f"  Email:           {t.email}")
    print(f"  Department:      {t.department}")
    print(f"  HVT Score:       {t.hvt_score:.1f}/10")
    print(f"  Access Level:    {t.access_level}/10")
    print(f"  Breach History:  {t.breach_count} known breaches")
    print(f"  Social Exposure: {t.social_exposure}/10")
    print(f"\n  Collected Intelligence:")
    for item in t.pretext_material:
        print(f"    → {item}")

with open("artifacts/hvt_profiles.json", "w") as f:
    json.dump([{
        "name": t.name, "title": t.title, "email": t.email,
        "hvt_score": t.hvt_score, "risk_tier": t.risk_tier,
        "pretext_material": t.pretext_material
    } for t in targets], f, indent=2)

print(f"\n[+] HVT profiles saved: artifacts/hvt_profiles.json")
```

```bash
python3 hvt_profiler.py | tee artifacts/hvt_summary.txt
```

**✅ Checkpoint 3:** The IT Director (Robert Patel) is often the highest-risk
target because compromise gives both network access AND the ability to disable
or blind security controls. The HR Manager is the most phishable — they handle
employee data requests routinely and are conditioned to respond quickly.

---

## STEP 6 — Spearphishing Pretext Construction

**Objective:** Demonstrate the risk concretely — build two realistic example
pretexts that an attacker could craft from the collected intelligence. These go
directly into the report to show leadership what their public exposure enables.

```bash
cat > artifacts/pretexts/pretext_examples.md << 'EOF'
# Spearphishing Pretext Examples
# Purpose: Demonstrate social engineering risk from collected OSINT
# Status: Example only — never sent — defensive awareness documentation
# Analyst: Blaakpearl | Date: 2025-01-16

---

## PRETEXT 1 — M&A Vendor Impersonation (Target: Sarah Chen, Head of M&A)

**Intelligence Used:**
- LinkedIn: Current project "Apex Partners integration" (public post)
- Conference slide: Intralinks virtual data room in use
- Email format: s.chen@novacrest-capital.com (confirmed Day 02)
- Title and department: Head of M&A (LinkedIn)
- Colleague name: James Morrison, CEO (website)

**Constructed Pretext:**

> From: support@intralinks-portal[.]com
> To: s.chen@novacrest-capital.com
> Subject: ACTION REQUIRED: Apex Partners Data Room Access Expiring
>
> Dear Sarah,
>
> This is an automated notification from Intralinks Virtual Data Room
> regarding Project Apex (NovaCrest/Apex Partners Integration).
>
> Your administrative access to the deal workspace expires in 24 hours
> due to a quarterly security review. To maintain uninterrupted access
> for your team, please re-authenticate using the secure link below.
>
> James Morrison has already completed his re-authentication. Your team
> members are awaiting your approval to continue document uploads.
>
> [SECURE LINK — RE-AUTHENTICATE NOW]
>
> If you have questions, contact your Intralinks account manager.
>
> Intralinks Support Team

**Why it works:**
✓ References real current project (Apex Partners — from LinkedIn)
✓ Uses real tool name (Intralinks — from conference slide)
✓ Creates urgency without being aggressive ("expires in 24 hours")
✓ Name-drops CEO as social proof ("James Morrison has already...")
✓ From domain is convincing lookalike (intralinks-portal.com vs intralinks.com)
✓ Sarah is conditioned to act quickly on deal-related requests

**Risk Rating:** CRITICAL — high probability of credential capture

---

## PRETEXT 2 — IT Security Alert Impersonation (Target: Lisa Williams, HR)

**Intelligence Used:**
- LinkedIn post: "Open enrollment closes Jan 31" (2 weeks away)
- LinkedIn: Uses Workday HR platform (from job posting)
- Title: HR Manager — handles benefits/enrollment
- Email: l.williams@novacrest-capital.com (confirmed)
- Personal Gmail: lwilliams.hr@gmail.com (Gravatar leak)

**Constructed Pretext:**

> From: noreply@workday-secure-portal[.]com
> To: l.williams@novacrest-capital.com
> Subject: Urgent: Workday Benefits Module — Admin Access Suspended
>
> Dear Lisa,
>
> Your Workday administrator access to the Benefits Enrollment module
> has been temporarily suspended due to unusual login activity from
> an unrecognized device.
>
> With open enrollment closing January 31, we understand this is a
> critical time. To restore your access immediately, please verify
> your identity using your Workday credentials at the secure link below.
>
> If you did not initiate this request, please contact IT immediately
> at: helpdesk@novacrest-capital.com
>
> [RESTORE ACCESS — SECURE LOGIN]
>
> Workday Security Team

**Why it works:**
✓ Times the attack to open enrollment deadline pressure (Jan 31 — from LinkedIn)
✓ Uses real HR platform (Workday — from public job posting)
✓ Legitimate-looking IT helpdesk email included (disarms suspicion)
✓ Urgency tied to real business deadline she cares about
✓ References "unusual login" — fear trigger common in security alerts
✓ Lisa is conditioned to prioritize enrollment access during this period

**Risk Rating:** CRITICAL — exploits time pressure and platform familiarity

---

## Defensive Takeaways

Both pretexts above were constructed using ONLY publicly available information
gathered in under 90 minutes. No hacking required. No inside knowledge needed.

**What stops these attacks:**
1. Security awareness training with real examples like these
2. DMARC p=reject (prevents domain spoofing)
3. FIDO2 hardware keys (credentials captured here are useless without the key)
4. Verbal callback verification for any credential reset request
5. Reducing public exposure — LinkedIn open enrollment posts, tech stack in job ads
EOF

echo "[+] Pretext examples: artifacts/pretexts/pretext_examples.md"
```

---

## STEP 7 — Human Attack Surface Risk Register

```python
# Save as: build_risk_register.py
from datetime import datetime

FINDINGS = [
    {
        "id": "HSE-01",
        "title": "Executive Team Fully Enumerable via Public Sources",
        "risk": "CRITICAL",
        "detail": (
            "Complete C-suite including CEO, CFO, CISO, and CTO are named, "
            "photographed, and linked to current projects via LinkedIn and company "
            "website. SEC filings name executive officers and compensation. "
            "This enables targeted whaling attacks with high-confidence pretexts."
        ),
        "evidence": "Company website, LinkedIn, SEC 10-K filing",
        "mitre": "T1591.004",
        "remediation": [
            "Reduce executive detail on public website — titles only, no bios",
            "Train executives on spearphishing targeting them specifically",
            "Implement executive email alias program — don't publish direct addresses",
        ]
    },
    {
        "id": "HSE-02",
        "title": "Internal Technology Stack Revealed via Job Postings",
        "risk": "HIGH",
        "detail": (
            "Job postings published on LinkedIn, Indeed, and company website "
            "enumerate internal security tools (Splunk, CrowdStrike, Palo Alto), "
            "cloud platforms (AWS, Azure), and business applications (Workday, "
            "Salesforce, Bloomberg). Attackers use this to craft tool-specific "
            "phishing pretexts and understand defensive capabilities."
        ),
        "evidence": "LinkedIn Jobs, Indeed, company careers page",
        "mitre": "T1591",
        "remediation": [
            "Remove specific tool/vendor names from public job postings",
            "Use generic role descriptions: 'EDR platform' not 'CrowdStrike Falcon'",
            "Review all active job postings quarterly for OPSEC leakage",
        ]
    },
    {
        "id": "HSE-03",
        "title": "IT Director GitHub Exposes Internal Architecture",
        "risk": "HIGH",
        "detail": (
            "IT Director's personal GitHub account (rpatel-dev) contains repositories "
            "with comments and configuration files referencing NovaCrest internal "
            "hostnames, Splunk index names, and Azure AD tenant structure. "
            "One commit message references 'NovaCrest SIEM migration Q3'."
        ),
        "evidence": "GitHub.com/rpatel-dev — Sherlock enumeration",
        "mitre": "T1593.001",
        "remediation": [
            "Immediate: audit and sanitize rpatel-dev repository history",
            "Implement GitHub organization policy — no internal hostnames in public repos",
            "Deploy git-secrets pre-commit hook to prevent future leakage",
        ]
    },
    {
        "id": "HSE-04",
        "title": "HR Manager Personal Email Leaked via Gravatar",
        "risk": "MEDIUM",
        "detail": (
            "HR Manager Lisa Williams' personal Gmail address "
            "(lwilliams.hr@gmail.com) was discovered via Gravatar profile linked "
            "to her corporate email. Personal email addresses are used to pivot to "
            "personal account breach data and enable account recovery attacks."
        ),
        "evidence": "Gravatar.com profile — email correlation",
        "mitre": "T1589.002",
        "remediation": [
            "Advise Lisa Williams to use a separate Gravatar account for personal use",
            "General awareness training: don't link corporate and personal emails",
            "Periodic personal digital hygiene review for all HR staff",
        ]
    },
    {
        "id": "HSE-05",
        "title": "Active M&A Deal Disclosed Publicly on LinkedIn",
        "risk": "HIGH",
        "detail": (
            "Head of M&A Sarah Chen's LinkedIn activity reveals a current active "
            "integration project ('Apex Partners integration') — potentially "
            "material non-public information (MNPI). This detail enables highly "
            "credible BEC pretexts and may constitute an inadvertent MNPI disclosure."
        ),
        "evidence": "LinkedIn activity — Sarah Chen profile",
        "mitre": "T1591.002",
        "remediation": [
            "Immediate: advise Sarah Chen to remove deal-specific LinkedIn content",
            "Legal review: assess MNPI disclosure risk for SEC compliance",
            "Policy: prohibit deal names in public social media posts",
        ]
    },
]

print(f"{'='*65}")
print(f"  Human Attack Surface Risk Register — NovaCrest Capital Group")
print(f"  Date: {datetime.now().strftime('%Y-%m-%d')} | Analyst: Blaakpearl")
print(f"{'='*65}\n")

RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

for f in FINDINGS:
    emoji = RISK_EMOJI.get(f["risk"], "⚪")
    print(f"\n{f['id']} — {emoji} {f['risk']}: {f['title']}")
    print(f"  {f['detail'][:120]}...")
    print(f"  ATT&CK: {f['mitre']}")
    print(f"  Evidence: {f['evidence']}")
    print(f"  Remediation:")
    for r in f["remediation"]:
        print(f"    → {r}")

import json
with open("artifacts/human_attack_surface_register.json", "w") as f:
    json.dump(FINDINGS, f, indent=2)

print(f"\n[+] Risk register saved: artifacts/human_attack_surface_register.json")
```

```bash
python3 build_risk_register.py | tee artifacts/risk_register_summary.txt
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** Which internal security tool was revealed in a public job posting?
- [ ] 🚩 **Flag 2:** What personal detail from the HR Manager's public profile enables a time-pressured phishing attack?
- [ ] 🚩 **Flag 3:** What platform did Sherlock find the IT Director's username on that reveals internal architecture?
- [ ] 🚩 **Flag 4:** What MITRE technique covers gathering victim identity information like employee names?
- [ ] 🚩 **Flag 5:** What single control would make both spearphishing pretexts technically useless even if credentials were captured?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `leadership_from_website.txt` | Executive names extracted from public website |
| `dorks/google_dork_library.json` | Full dork library — all categories |
| `dorks/google_dorks.txt` | Plain text dork list for manual execution |
| `dorks/dork_findings.md` | Manual dork results (fill in during lab) |
| `org_chart.md` | Inferred organizational hierarchy |
| `email_validation_results.json` | Email format confirmation results |
| `email_validation_summary.txt` | Console output from email validator |
| `sherlock/` | Per-username Sherlock output files |
| `sherlock_analysis.json` | Parsed and prioritized Sherlock results |
| `sherlock_summary.txt` | Sherlock console summary |
| `spiderfoot/entity_summary.json` | SpiderFoot entity relationship map |
| `hvt_profiles.json` | High-value target profiles with scores |
| `hvt_summary.txt` | HVT profiler console output |
| `pretexts/pretext_examples.md` | 2 example spearphishing pretexts |
| `human_attack_surface_register.json` | Full risk register — 5 findings |
| `risk_register_summary.txt` | Risk register console output |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `sherlock: command not found` | `pip install sherlock-project --break-system-packages` |
| Sherlock rate limited | Add `--timeout 20` and `--print-all` flags; some sites block automation |
| SpiderFoot CLI fails | Use web UI: `spiderfoot -l 127.0.0.1:5001` |
| `dnspython` not found | `pip install dnspython --break-system-packages` |
| Google dork returns 0 | Use browser with personal account; Google blocks automated queries |

---

*Next: [REPORT.md](REPORT.md) — Professional social engineering surface assessment report*
