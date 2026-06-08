# Day 03 — Lab Guide: Phishing Infrastructure Analysis
### Track: Threat Intelligence | Duration: ~3 hours | Difficulty: Intermediate

---

## 🛠 Tools Required

| Tool | Purpose | Install / Access |
|------|---------|-----------------|
| **URLScan.io** | Phishing URL analysis & screenshot capture | urlscan.io (free account) |
| **VirusTotal API** | Multi-engine URL/domain/IP/file analysis + pivoting | virustotal.com (free API key) |
| **Any.run** | Interactive malware sandbox for URL detonation | app.any.run (free tier) |
| **crt.sh** | Certificate transparency log pivoting | Browser / curl |
| **whois / dig** | Domain registration & DNS record lookup | Pre-installed / `sudo apt install whois` |
| **Python 3** | API automation, IOC extraction, STIX generation | Pre-installed |
| **stix2 library** | Generate STIX 2.1 threat intelligence objects | `pip install stix2` |
| **jq** | JSON parsing | `sudo apt install jq` |
| **Shodan CLI** | Infrastructure scanning pivot | `pip install shodan` |

---

## 🖥 Environment Setup

```bash
# 1. Create working directory
mkdir -p ~/security-labs/day-03/artifacts
cd ~/security-labs/day-03

# 2. Set API keys
export VT_API_KEY="your-virustotal-api-key"
export URLSCAN_API_KEY="your-urlscan-api-key"

# 3. Install Python dependencies
pip install requests stix2 python-dateutil --break-system-packages

# 4. Set the phishing indicator (DEFANGED — safe to store, never click)
# Defanged = hxxps, [.] notation — must be re-fanged before API queries
export PHISH_DOMAIN="microsoftonline-portal.com"
export PHISH_URL="hxxps://novacrest-benefits.microsoftonline-portal[.]com/signin"
export PHISH_URL_FANGED="https://novacrest-benefits.microsoftonline-portal.com/signin"

echo "[+] Environment ready"
echo "[+] Target domain: $PHISH_DOMAIN"
```

> ⚠️ **Safety Rule:** Always store phishing URLs in **defanged** format (hxxps, [.])
> in notes, reports, and artifacts. Only re-fang when passing to analysis APIs.
> Never open phishing URLs in a standard browser — use sandboxes only.

---

## 📋 Pre-Lab Checklist

- [ ] VirusTotal API key obtained (virustotal.com → profile → API key)
- [ ] URLScan.io API key obtained (urlscan.io → settings → API key)
- [ ] Any.run account created (app.any.run — free tier sufficient)
- [ ] Python 3 + `stix2` + `requests` installed
- [ ] Working directory set at `~/security-labs/day-03/`
- [ ] `whois` installed (`sudo apt install whois`)

---

## STEP 1 — URLScan.io: Initial Phishing URL Analysis

**Objective:** Submit the phishing URL to URLScan for automated analysis — captures
page screenshot, DOM content, network requests, cookies, and resource hashes without
you visiting the page directly.

### 1a. Submit URL via API

```python
# Save as: urlscan_submit.py
import requests, json, time, os

API_KEY  = os.environ.get("URLSCAN_API_KEY")
HEADERS  = {"API-Key": API_KEY, "Content-Type": "application/json"}
SCAN_URL = "https://urlscan.io/api/v1/scan/"

payload = {
    "url":        "https://novacrest-benefits.microsoftonline-portal.com/signin",
    "visibility": "unlisted",   # don't make public — OPSEC
    "tags":       ["phishing", "day03-lab", "financial-sector"]
}

print("[*] Submitting URL to URLScan.io...")
r = requests.post(SCAN_URL, headers=HEADERS, json=payload)
data = r.json()

scan_uuid = data.get("uuid")
result_url = data.get("result")

print(f"[+] Scan submitted — UUID: {scan_uuid}")
print(f"[+] Results will be at: {result_url}")
print("[*] Waiting 30 seconds for scan to complete...")
time.sleep(30)

# Fetch results
result = requests.get(
    f"https://urlscan.io/api/v1/result/{scan_uuid}/",
    headers=HEADERS
).json()

# Save full result
with open("artifacts/urlscan_result.json", "w") as f:
    json.dump(result, f, indent=2)

# Extract key fields
page   = result.get("page",   {})
lists  = result.get("lists",  {})
stats  = result.get("stats",  {})
meta   = result.get("meta",   {})
task   = result.get("task",   {})

print("\n=== URLScan Results ===")
print(f"Final URL:       {page.get('url')}")
print(f"IP Address:      {page.get('ip')}")
print(f"ASN:             {page.get('asn')} — {page.get('asnname')}")
print(f"Country:         {page.get('country')}")
print(f"Server:          {page.get('server')}")
print(f"Title:           {page.get('title')}")
print(f"Screenshot:      https://urlscan.io/screenshots/{scan_uuid}.png")

print(f"\nDomains contacted:  {len(lists.get('domains', []))}")
print(f"IPs contacted:      {len(lists.get('ips', []))}")
print(f"URLs loaded:        {len(lists.get('urls', []))}")

print("\n=== Domains Contacted ===")
for d in lists.get("domains", [])[:10]:
    print(f"  {d}")

print("\n=== IPs Contacted ===")
for ip in lists.get("ips", [])[:10]:
    print(f"  {ip}")

# Extract resource hashes (JS files, etc.)
print("\n=== Resource Hashes (SHA-256) ===")
for h in lists.get("hashes", [])[:5]:
    print(f"  {h}")
```

```bash
python3 urlscan_submit.py | tee artifacts/urlscan_summary.txt
```

**Expected Output:**
```
[+] Scan submitted — UUID: a1b2c3d4-...
[+] Results at: https://urlscan.io/result/a1b2c3d4-.../

=== URLScan Results ===
Final URL:       https://novacrest-benefits.microsoftonline-portal.com/signin
IP Address:      185.220.101.12
ASN:             AS209588 — Flyservers S.A.
Country:         Seychelles
Server:          nginx/1.18.0
Title:           Sign in to your account - Microsoft

Domains contacted:  4
IPs contacted:      2
URLs loaded:        23

=== Domains Contacted ===
  novacrest-benefits.microsoftonline-portal.com
  microsoftonline-portal.com
  cdn.microsoftonline-portal.com
  login.microsoftonline.com  ← legitimate MS domain (used as background iframe)
```

**✅ Checkpoint 1:** Note the IP, ASN, and hosting country.
Flyservers S.A. (Seychelles) is a known bulletproof hosting provider.
Save the screenshot URL — this is your visual evidence for the report.

---

### 1b. Download Screenshot Evidence

```bash
# Download page screenshot (visual evidence)
SCAN_UUID=$(python3 -c "import json; d=json.load(open('artifacts/urlscan_result.json')); print(d['task']['uuid'])")

curl -s "https://urlscan.io/screenshots/${SCAN_UUID}.png" \
  -o artifacts/phishing_page_screenshot.png

echo "[+] Screenshot saved: artifacts/phishing_page_screenshot.png"

# Download DOM content for YARA rule development
curl -s "https://urlscan.io/dom/${SCAN_UUID}/" \
  -o artifacts/phishing_page_dom.html

echo "[+] DOM saved: artifacts/phishing_page_dom.html"
wc -l artifacts/phishing_page_dom.html
```

**✅ Checkpoint 2:** You now have a screenshot of the phishing page and its full
HTML source — both are key evidence artifacts and feed into YARA rule creation in Step 5.

---

## STEP 2 — WHOIS & DNS: Domain Registration Profiling

**Objective:** Profile the attacker's domain registration patterns — registrar choice,
registration date, name servers, and passive DNS history.

### 2a. WHOIS Registration Analysis

```bash
echo "[*] WHOIS analysis for $PHISH_DOMAIN"
whois $PHISH_DOMAIN | tee artifacts/whois_phish_domain.txt

# Extract key fields
echo ""
echo "=== Key Registration Fields ==="
grep -iE "registrar:|created:|updated:|expiry|registrant|name server|status" \
  artifacts/whois_phish_domain.txt | head -20
```

**Expected Output:**
```
Registrar:          Namecheap, Inc.
Registrar IANA ID:  1068
Domain Status:      clientTransferProhibited
Created Date:       2025-01-05T14:32:11Z   ← 11 days ago
Updated Date:       2025-01-05T14:32:11Z
Expiry Date:        2026-01-05T14:32:11Z
Name Server:        ns1.flyservers.io      ← same provider as hosting
Name Server:        ns2.flyservers.io
Registrant:         [REDACTED — privacy protection]
```

**Analysis Notes:**
- Domain created **11 days ago** — brand new, zero reputation history
- Privacy-protected registrant — standard for criminal infrastructure
- Name servers match hosting provider (Flyservers) — tight infrastructure integration

### 2b. DNS Enumeration

```bash
echo "[*] DNS enumeration for $PHISH_DOMAIN"

echo "=== A Records ===" && dig A $PHISH_DOMAIN +short
echo "=== All Subdomains via brute DNS ==="
for sub in www mail cdn login portal signin benefits update secure account; do
    result=$(dig A ${sub}.${PHISH_DOMAIN} +short 2>/dev/null)
    [ ! -z "$result" ] && echo "  ${sub}.${PHISH_DOMAIN} → $result"
done

echo ""
echo "=== MX Records ===" && dig MX $PHISH_DOMAIN +short
echo "=== TXT Records ===" && dig TXT $PHISH_DOMAIN +short

# Save all DNS
{
  echo "# DNS Records — $PHISH_DOMAIN — $(date)"
  echo "## A"; dig A $PHISH_DOMAIN +short
  echo "## MX"; dig MX $PHISH_DOMAIN +short
  echo "## TXT"; dig TXT $PHISH_DOMAIN +short
  echo "## NS"; dig NS $PHISH_DOMAIN +short
} > artifacts/dns_phish_domain.txt

echo "[+] DNS records saved"
```

---

## STEP 3 — VirusTotal: Multi-Engine Analysis & Pivoting

**Objective:** Query VirusTotal for detection coverage, then use its relationship
graph to pivot from the phishing domain to related IPs, files, and sibling domains.

### 3a. Domain Analysis

```python
# Save as: vt_analysis.py
import requests, json, time, os

API_KEY = os.environ.get("VT_API_KEY")
HEADERS = {"x-apikey": API_KEY}
BASE    = "https://www.virustotal.com/api/v3"

DOMAIN  = "microsoftonline-portal.com"
PHISH_URL = "https://novacrest-benefits.microsoftonline-portal.com/signin"

def vt_get(endpoint):
    r = requests.get(f"{BASE}/{endpoint}", headers=HEADERS)
    time.sleep(15)  # Free tier: 4 lookups/min
    return r.json()

def vt_post(endpoint, data):
    r = requests.post(f"{BASE}/{endpoint}", headers=HEADERS, data=data)
    time.sleep(15)
    return r.json()

print("[*] VirusTotal Analysis Pipeline")
print("=" * 50)

# --- Domain Report ---
print(f"\n[1/4] Domain: {DOMAIN}")
domain_data = vt_get(f"domains/{DOMAIN}")
attrs = domain_data.get("data", {}).get("attributes", {})
stats = attrs.get("last_analysis_stats", {})

print(f"  Malicious:    {stats.get('malicious', 0)}")
print(f"  Suspicious:   {stats.get('suspicious', 0)}")
print(f"  Harmless:     {stats.get('harmless', 0)}")
print(f"  Undetected:   {stats.get('undetected', 0)}")
print(f"  Categories:   {attrs.get('categories', {})}")
print(f"  Reputation:   {attrs.get('reputation', 0)}")
print(f"  Creation:     {attrs.get('creation_date', 'N/A')}")

with open("artifacts/vt_domain.json", "w") as f:
    json.dump(domain_data, f, indent=2)

# --- URL Report ---
import base64
url_id = base64.urlsafe_b64encode(PHISH_URL.encode()).decode().rstrip("=")
print(f"\n[2/4] URL Analysis...")
url_data = vt_get(f"urls/{url_id}")
url_attrs = url_data.get("data", {}).get("attributes", {})
url_stats = url_attrs.get("last_analysis_stats", {})

print(f"  Malicious:  {url_stats.get('malicious', 0)}")
print(f"  Final URL:  {url_attrs.get('last_final_url', 'N/A')}")
print(f"  Title:      {url_attrs.get('title', 'N/A')}")

with open("artifacts/vt_url.json", "w") as f:
    json.dump(url_data, f, indent=2)

# --- IP Resolutions ---
print(f"\n[3/4] Domain Resolutions (IPs hosting this domain)...")
resolutions = vt_get(f"domains/{DOMAIN}/resolutions?limit=10")
ips_found = []
for item in resolutions.get("data", []):
    ip = item.get("attributes", {}).get("ip_address")
    date = item.get("attributes", {}).get("date")
    if ip:
        ips_found.append(ip)
        print(f"  {ip}  (resolved: {date})")

with open("artifacts/vt_resolutions.json", "w") as f:
    json.dump(resolutions, f, indent=2)

# --- Related Domains (Pivot!) ---
print(f"\n[4/4] Sibling domains on same IP (pivot)...")
if ips_found:
    pivot_ip = ips_found[0]
    ip_data = vt_get(f"ip_addresses/{pivot_ip}/resolutions?limit=20")
    print(f"  Pivoting on IP: {pivot_ip}")
    siblings = []
    for item in ip_data.get("data", []):
        hostname = item.get("attributes", {}).get("host_name", "")
        if hostname and hostname != DOMAIN:
            siblings.append(hostname)
            print(f"  Related domain: {hostname}")

    with open("artifacts/vt_pivot_siblings.json", "w") as f:
        json.dump(ip_data, f, indent=2)

    # Save sibling domains for IOC list
    with open("artifacts/related_domains.txt", "w") as f:
        f.write(f"# Domains sharing IP {pivot_ip}\n")
        for s in siblings:
            f.write(f"{s}\n")

print(f"\n[+] VT analysis complete — results in artifacts/")
```

```bash
python3 vt_analysis.py | tee artifacts/vt_summary.txt
```

**✅ Checkpoint 3:** The sibling domain pivot is the intelligence gold —
finding other phishing domains on the same IP expands your blocking scope
from 1 domain to potentially 10+. Each one is a campaign targeting another org.

---

## STEP 4 — Certificate Transparency Pivot

**Objective:** Use SSL/TLS certificate issuance records to find every domain
the attacker registered as part of this campaign infrastructure.

```bash
echo "[*] Certificate transparency pivot on $PHISH_DOMAIN"

# Find all certs issued to this domain and subdomains
curl -s "https://crt.sh/?q=%25.${PHISH_DOMAIN}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | tee artifacts/cert_transparency_phish.txt

echo ""
echo "[+] Domains found in cert transparency: $(wc -l < artifacts/cert_transparency_phish.txt)"

# Now search for the registrant pattern — look for similar newly registered domains
# that share the same "microsoftonline-*" combosquatting pattern
echo ""
echo "[*] Hunting for related combosquatting domains..."
for pattern in "microsoftonline-" "microsoft-online-" "ms-signin-" "azure-login-" "office365-login-"; do
    echo "  Pattern: ${pattern}*.com"
    # Via crt.sh wildcard search
    curl -s "https://crt.sh/?q=%25${pattern}%25&output=json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null \
      | grep -v "^$" \
      | sort -u \
      | head -5 \
      | sed 's/^/    /'
    sleep 2
done | tee -a artifacts/combosquatting_domains.txt

echo "[+] Combosquatting pivot complete"
```

**✅ Checkpoint 4:** Every domain matching the `microsoftonline-*` typosquatting
pattern that you find is almost certainly part of the same threat actor's
infrastructure cluster. Each one targets a different organization.

---

## STEP 5 — YARA Rule: Phishing Kit HTML Fingerprinting

**Objective:** Write a YARA rule that detects this specific phishing kit based on
unique strings in the HTML source — enabling proactive scanning of email attachments,
web proxies, and threat intel feeds.

```bash
# First, analyze the DOM we captured in Step 1b
echo "[*] Analyzing phishing page DOM for unique fingerprints..."

# Look for unique strings in the HTML that identify this kit
echo ""
echo "=== Unique Kit Identifiers ==="
grep -iE "kit_version|phish_id|relay_url|collector|session_token" \
  artifacts/phishing_page_dom.html 2>/dev/null | head -10

# Look for the credential relay endpoint
grep -iE "action=|fetch\(|xhr\.|post.*signin" \
  artifacts/phishing_page_dom.html 2>/dev/null | head -5

# Look for anti-analysis techniques
grep -iE "webdriver|phantom|selenium|headless|bot_check" \
  artifacts/phishing_page_dom.html 2>/dev/null | head -5
```

```bash
# Generate the YARA rule based on observed HTML patterns
cat > artifacts/yara_phishing_kit.yar << 'YARAEOF'
/*
    YARA Rule: Phishing Kit — Microsoft 365 Credential Harvester
    Author:    Blaakpearl
    Date:      2025-01-16
    Track:     Threat Intelligence — Day 03
    Reference: URLScan UUID a1b2c3d4 / VT analysis
    
    Detects the HTML structure of a Microsoft 365 phishing kit observed in
    COMBOLIST-FIN-2025-Q1 campaign targeting financial sector organizations.
    Kit uses reverse-proxy architecture to relay credentials and MFA tokens.
    
    ATT&CK: T1566.002, T1056.003, T1539
*/

rule Phishing_M365_CredentialHarvester_FinSector_2025 {
    meta:
        description     = "Detects Microsoft 365 credential harvesting phishing kit — financial sector campaign Jan 2025"
        author          = "Blaakpearl"
        date            = "2025-01-16"
        version         = "1.0"
        hash_sample     = "d41d8cd98f00b204e9800998ecf8427e"
        mitre_attack    = "T1566.002, T1056.003, T1539"
        tlp             = "TLP:WHITE — shareable"
        reference       = "Day 03 — Phishing Infrastructure Analysis"
        
    strings:
        /* Core phishing kit page title mimicking Microsoft */
        $title_ms       = "Sign in to your account" nocase ascii wide

        /* Fake Microsoft branding elements */
        $ms_logo        = "microsoft-logo" nocase ascii
        $ms_form        = "ms-form-container" nocase ascii

        /* Credential relay endpoint pattern */
        $relay_path     = "/signin/v2/collect" nocase ascii
        $relay_post     = "loginResponse" nocase ascii

        /* Kit-specific session token format */
        $session_fmt    = "canary=" nocase ascii
        $flow_token     = "flowToken" nocase ascii

        /* Anti-analysis bot detection */
        $bot_check      = "navigator.webdriver" ascii
        $mouse_check    = "mousemove" ascii

        /* Reverse proxy MFA intercept marker */
        $mfa_relay      = "otc" ascii  /* one-time code relay parameter */
        $cookie_steal   = "esctx=" ascii

        /* Suspicious hosting patterns */
        $cdn_fake       = "cdn.microsoftonline-portal" nocase ascii
        $domain_typo    = /microsoftonline-[a-z]{4,15}\.(com|net|org)/ nocase

    condition:
        /* Must have Microsoft impersonation + credential collection */
        (
            ($title_ms or $ms_logo or $ms_form) and
            ($relay_path or $relay_post or $session_fmt)
        )
        and
        /* Plus either anti-analysis OR MFA relay indicators */
        (
            ($bot_check and $mouse_check) or
            ($mfa_relay and $cookie_steal) or
            $domain_typo or
            $cdn_fake
        )
        and
        /* Exclude legitimate Microsoft domains */
        not (
            filename matches /login\.microsoftonline\.com/ or
            filename matches /microsoft\.com/
        )
}

rule Phishing_M365_Kit_AntiAnalysis {
    meta:
        description = "Detects anti-analysis evasion in M365 phishing kits"
        author      = "Blaakpearl"
        date        = "2025-01-16"
        
    strings:
        $wdcheck    = "if(navigator.webdriver)" ascii
        $vpncheck   = "datacenter" nocase ascii
        $proxycheck = "isProxy" nocase ascii
        $screenres  = "screen.width < 200" ascii  /* sandboxes often have small screens */
        $langcheck  = "navigator.language" ascii

    condition:
        3 of them
}
YARAEOF

echo "[+] YARA rules saved to artifacts/yara_phishing_kit.yar"
```

---

## STEP 6 — Sigma Rule: Email Gateway Detection

```bash
cat > artifacts/sigma_phishing_campaign.yml << 'SIGMAEOF'
title: Phishing Campaign — Microsoft 365 Credential Harvester Link Delivery
id: f3e1d842-7a2b-4c9f-b881-5d6e3a7f0c42
status: experimental
description: |
    Detects delivery of phishing emails impersonating Microsoft 365 login
    as observed in COMBOLIST-FIN-2025-Q1 campaign targeting financial sector.
    Campaign uses combosquatting domains with "microsoftonline-[org]" pattern.
    Sender domain is typically a compromised legitimate domain (not the phish domain).

author: Blaakpearl
date: 2025/01/16

references:
    - https://attack.mitre.org/techniques/T1566/002/
    - https://urlscan.io/result/a1b2c3d4

tags:
    - attack.initial_access
    - attack.t1566.002
    - attack.resource_development
    - attack.t1583.001

logsource:
    category: email
    product: microsoft365

detection:
    # Link in body matching combosquatting pattern
    link_pattern:
        body|contains:
            - 'microsoftonline-portal.com'
            - 'microsoft-online-signin'
            - 'ms-account-verify'
            - 'office365-update'
            - 'azure-login-portal'
            - 'microsoftonline-benefits'

    # Subject line lures matching campaign theme
    subject_lure:
        subject|contains:
            - 'Benefits Enrollment'
            - 'Account Verification Required'
            - 'Unusual Sign-in Activity'
            - 'Password Expiring'
            - 'Security Alert'

    # Sender domain anomaly (not microsoft.com but looks like it)
    sender_spoof:
        sender_domain|contains:
            - 'microsoft-'
            - '-microsoft'
            - 'microsoftonline-'
            - 'ms-security'
            - 'azure-notify'
        sender_domain|not_contains:
            - 'microsoft.com'
            - 'office.com'
            - 'live.com'
            - 'outlook.com'

    condition: link_pattern or (subject_lure and sender_spoof)

falsepositives:
    - Internal IT security awareness phishing simulations (check change calendar)
    - Legitimate third-party Microsoft reseller communications

level: high

fields:
    - sender
    - subject
    - body_links
    - recipient
    - x-originating-ip

response:
    - Quarantine message and all copies
    - Extract all URLs from message body
    - Submit URL to URLScan and VirusTotal
    - Notify recipient's manager if credentials may have been entered
    - Block sending domain at email gateway
    - Search mail logs for all recipients — notify anyone who received and clicked
SIGMAEOF

echo "[+] Sigma rule saved to artifacts/sigma_phishing_campaign.yml"
```

---

## STEP 7 — STIX 2.1: Structured Threat Intelligence Export

**Objective:** Structure all findings as STIX 2.1 objects — the standard format
for sharing threat intelligence via TAXII feeds, ISACs, and threat intel platforms.

```python
# Save as: generate_stix.py
from stix2 import (
    Indicator, ThreatActor, Infrastructure, DomainName,
    IPv4Address, Relationship, Bundle, Report,
    ExternalReference, KillChainPhase
)
from datetime import datetime, timezone
import json

NOW = datetime.now(timezone.utc)

# --- Threat Actor ---
actor = ThreatActor(
    name="PHISH-FIN-2025-Q1",
    description=(
        "Financially motivated threat actor targeting financial sector organizations "
        "with Microsoft 365 credential harvesting phishing campaigns. Uses combosquatting "
        "domains and bulletproof hosting via Flyservers S.A. (Seychelles). Observed "
        "deploying reverse-proxy MFA-bypass phishing kits."
    ),
    threat_actor_types=["criminal"],
    sophistication="intermediate",
    resource_level="individual",
    primary_motivation="financial-gain",
    aliases=["COMBOLIST-FIN-2025-Q1-OPERATOR"],
    first_seen="2025-01-05T00:00:00Z",
    labels=["phishing", "credential-harvester", "financial-sector"],
    external_references=[
        ExternalReference(
            source_name="URLScan",
            url="https://urlscan.io/result/a1b2c3d4",
            description="URLScan analysis of primary phishing URL"
        )
    ]
)

# --- Infrastructure Objects ---
phish_domain = DomainName(value="microsoftonline-portal.com")
phish_ip     = IPv4Address(value="185.220.101.12")

related_domains = [
    DomainName(value=d) for d in [
        "novacrest-benefits.microsoftonline-portal.com",
        "hrportal-login.microsoftonline-portal.com",
        "secure-signin.ms-account-portal.com",
    ]
]

infra = Infrastructure(
    name="PHISH-FIN-2025-Q1 Hosting Infrastructure",
    description=(
        "Bulletproof hosting cluster via Flyservers S.A. (AS209588, Seychelles). "
        "IP range 185.220.101.0/24 hosts multiple phishing domains targeting "
        "financial sector orgs across North America and Europe."
    ),
    infrastructure_types=["hosting-malware"],
    labels=["bulletproof-hosting", "phishing-infrastructure"]
)

# --- Indicators ---
indicator_domain = Indicator(
    name="Phishing Domain — microsoftonline-portal.com",
    description="Primary phishing domain used in COMBOLIST-FIN-2025-Q1 campaign",
    pattern="[domain-name:value = 'microsoftonline-portal.com']",
    pattern_type="stix",
    valid_from=NOW,
    kill_chain_phases=[
        KillChainPhase(kill_chain_name="mitre-attack", phase_name="initial-access")
    ],
    labels=["malicious-activity", "phishing"],
    confidence=85
)

indicator_ip = Indicator(
    name="Phishing Infrastructure IP — 185.220.101.12",
    description="IP hosting phishing pages on Flyservers S.A. bulletproof hosting",
    pattern="[ipv4-addr:value = '185.220.101.12']",
    pattern_type="stix",
    valid_from=NOW,
    labels=["malicious-activity", "phishing-infrastructure"],
    confidence=90
)

indicator_url = Indicator(
    name="Phishing URL — M365 Credential Harvester",
    description="Phishing URL harvesting Microsoft 365 credentials from financial sector employees",
    pattern=(
        "[url:value = 'https://novacrest-benefits.microsoftonline-portal.com/signin']"
    ),
    pattern_type="stix",
    valid_from=NOW,
    kill_chain_phases=[
        KillChainPhase(kill_chain_name="mitre-attack", phase_name="initial-access")
    ],
    labels=["malicious-activity", "phishing"],
    confidence=95
)

# --- Relationships ---
rel_actor_infra = Relationship(
    relationship_type="uses",
    source_ref=actor.id,
    target_ref=infra.id,
    description="Threat actor uses Flyservers bulletproof hosting for phishing infrastructure"
)

rel_indicator_actor = Relationship(
    relationship_type="indicates",
    source_ref=indicator_domain.id,
    target_ref=actor.id
)

rel_infra_ip = Relationship(
    relationship_type="consists-of",
    source_ref=infra.id,
    target_ref=phish_ip.id
)

# --- Bundle everything ---
bundle = Bundle(objects=[
    actor, phish_domain, phish_ip, infra,
    indicator_domain, indicator_ip, indicator_url,
    rel_actor_infra, rel_indicator_actor, rel_infra_ip,
    *related_domains
])

# Save STIX bundle
with open("artifacts/stix_bundle_day03.json", "w") as f:
    f.write(bundle.serialize(pretty=True))

print("[+] STIX 2.1 bundle saved: artifacts/stix_bundle_day03.json")
print(f"    Objects: {len(bundle.objects)}")
print(f"    Indicators: 3")
print(f"    Relationships: 3")
print(f"    Threat Actor: 1 (PHISH-FIN-2025-Q1)")
```

```bash
python3 generate_stix.py
```

---

## STEP 8 — Compile Master IOC List

```bash
echo "[*] Building master IOC list..."

cat > artifacts/ioc_master_list.txt << 'IOCEOF'
# =================================================================
# IOC Master List — Phishing Campaign: PHISH-FIN-2025-Q1
# Analyst: Blaakpearl | Date: 2025-01-16 | TLP: WHITE
# =================================================================

# DOMAINS (Defanged)
microsoftonline-portal[.]com
novacrest-benefits.microsoftonline-portal[.]com
hrportal-login.microsoftonline-portal[.]com
secure-signin.ms-account-portal[.]com
cdn.microsoftonline-portal[.]com

# IP ADDRESSES
185.220.101.12
185.220.101.0/24   # Full subnet — bulletproof hosting block

# URLS (Defanged)
hxxps://novacrest-benefits.microsoftonline-portal[.]com/signin
hxxps://hrportal-login.microsoftonline-portal[.]com/signin

# HOSTING INFRASTRUCTURE
ASN: AS209588 — Flyservers S.A. (Seychelles) — bulletproof hosting
Name Servers: ns1.flyservers.io / ns2.flyservers.io

# EMAIL INDICATORS
Subject: "Urgent: Benefits Enrollment Update Required"
Subject: "Account Verification Required"
Sender pattern: *@[compromised-legitimate-domain].com
Link pattern: microsoftonline-[word].com/signin

# CERTIFICATE
Issuer: Let's Encrypt
Validity: 90 days (auto-renewed — infrastructure likely maintained)
Common Name: *.microsoftonline-portal.com

# FILE HASHES (Phishing Kit Resources — from URLScan)
# [Populate from artifacts/urlscan_result.json → lists.hashes]
IOCEOF

echo "[+] IOC master list: artifacts/ioc_master_list.txt"
echo ""
echo "=== Final Artifact Summary ==="
ls -lah artifacts/
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What ASN hosts the phishing infrastructure, and in what country?
- [ ] 🚩 **Flag 2:** How many sibling domains did the VirusTotal IP pivot reveal?
- [ ] 🚩 **Flag 3:** What anti-analysis technique did the phishing kit use to detect sandboxes?
- [ ] 🚩 **Flag 4:** What MITRE ATT&CK technique describes the reverse-proxy MFA token theft?
- [ ] 🚩 **Flag 5:** What STIX 2.1 object type represents the phishing domain indicator?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `urlscan_result.json` | Full URLScan analysis output |
| `urlscan_summary.txt` | Parsed key fields from URLScan |
| `phishing_page_screenshot.png` | Visual evidence of phishing page |
| `phishing_page_dom.html` | Full HTML source of phishing page |
| `whois_phish_domain.txt` | WHOIS registration data |
| `dns_phish_domain.txt` | DNS record enumeration |
| `vt_domain.json` | VirusTotal domain analysis |
| `vt_url.json` | VirusTotal URL analysis |
| `vt_pivot_siblings.json` | Sibling domains from IP pivot |
| `related_domains.txt` | All related domains discovered |
| `cert_transparency_phish.txt` | Certificate transparency results |
| `combosquatting_domains.txt` | Related typosquatting patterns |
| `yara_phishing_kit.yar` | YARA detection rules (2 rules) |
| `sigma_phishing_campaign.yml` | Sigma email gateway detection rule |
| `stix_bundle_day03.json` | STIX 2.1 threat intelligence bundle |
| `ioc_master_list.txt` | Consolidated IOC list (TLP:WHITE) |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| URLScan 400 error | Check API key header is `API-Key` (not `Authorization`) |
| VirusTotal 204 no content | URL not yet in VT DB — submit manually first, wait 5 min |
| `stix2` import error | `pip install stix2 --break-system-packages` |
| crt.sh times out | Add `-m 30` to curl command; retry — site intermittently slow |
| YARA rule syntax error | Test with `yara -r yara_phishing_kit.yar test_file.html` |

---

*Next: [REPORT.md](REPORT.md) — Professional threat intelligence report*
