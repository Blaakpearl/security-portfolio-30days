# Day 01 — Lab Guide: Recon & Footprinting
### Track: OSINT | Duration: ~2.5 hours | Difficulty: Intermediate

---

## 🛠 Tools Required

| Tool | Purpose | Install / Access |
|------|---------|-----------------|
| **Shodan CLI** | Internet-wide port/service scanning database | `pip install shodan` + free API key at shodan.io |
| **Amass** | Subdomain enumeration & DNS mapping | `sudo apt install amass` or brew |
| **theHarvester** | Email, hostname, IP harvesting | Pre-installed on Kali / `pip install theHarvester` |
| **crt.sh** | Certificate transparency log search | Browser or `curl` (no install needed) |
| **DNSrecon** | DNS enumeration & zone walking | Pre-installed on Kali / `pip install dnsrecon` |
| **MXToolbox** | Email security record validation | Browser: mxtoolbox.com (free) |
| **Subfinder** | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **curl / jq** | API queries & JSON parsing | Pre-installed on most systems |

---

## 🖥 Environment Setup

```bash
# 1. Create your working directory
mkdir -p ~/security-labs/day-01/artifacts
cd ~/security-labs/day-01

# 2. Set your target domain (USE YOUR OWN or an authorized test domain)
export TARGET="yourdomain.com"
# Example practice target: export TARGET="scanme.nmap.org"

# 3. Install Python tools if not present
pip install shodan theHarvester --break-system-packages

# 4. Set up Shodan (free account at shodan.io → get API key)
shodan init YOUR_SHODAN_API_KEY

# 5. Verify tools
shodan info
amass version
subfinder -version
echo "Environment ready for $TARGET"
```

---

## 📋 Pre-Lab Checklist

- [ ] Working directory created at `~/security-labs/day-01/`
- [ ] `TARGET` environment variable set
- [ ] Shodan API key configured
- [ ] Kali Linux or Ubuntu VM running (recommended)
- [ ] VPN active if desired for OPSEC practice
- [ ] Written authorization if testing against real org (not your own domain)

---

## STEP 1 — DNS Enumeration & Infrastructure Mapping

**Objective:** Map the target's DNS infrastructure — subdomains, mail servers, IP addresses,
and any DNS misconfigurations.

### 1a. Basic DNS Record Enumeration

```bash
# Gather all standard DNS record types
echo "=== A Records ===" && dig A $TARGET +short
echo "=== MX Records ===" && dig MX $TARGET +short
echo "=== NS Records ===" && dig NS $TARGET +short
echo "=== TXT Records ===" && dig TXT $TARGET +short
echo "=== CNAME Records ===" && dig CNAME www.$TARGET +short

# Save to file
{
  echo "# DNS Records — $TARGET — $(date)"
  echo "## A Records"; dig A $TARGET +short
  echo "## MX Records"; dig MX $TARGET +short
  echo "## NS Records"; dig NS $TARGET +short
  echo "## TXT Records"; dig TXT $TARGET +short
} > artifacts/dns_records.txt

echo "[+] DNS records saved to artifacts/dns_records.txt"
```

**Expected Output:**
```
=== A Records ===
203.0.113.45
=== MX Records ===
10 mail.yourdomain.com.
=== NS Records ===
ns1.yourdomain.com.
ns2.yourdomain.com.
=== TXT Records ===
"v=spf1 include:_spf.google.com ~all"
```

**✅ Checkpoint 1:** You should see at least one A record and one MX record.
If TXT contains `v=spf1` — note it for the email security analysis in Step 4.

---

### 1b. Zone Transfer Attempt (Tests for Misconfiguration)

```bash
# Attempt DNS zone transfer — should FAIL on properly configured domains
# A successful transfer reveals ALL DNS records — major misconfiguration
for NS in $(dig NS $TARGET +short); do
  echo "[*] Attempting zone transfer from $NS"
  dig AXFR $TARGET @$NS
done
```

**Expected Output (secure):**
```
; Transfer failed.
```

**⚠️ If zone transfer SUCCEEDS:** This is a Critical finding — document it immediately.
A successful AXFR exposes your entire DNS infrastructure to any requestor.

---

### 1c. Subdomain Enumeration with Subfinder + Amass

```bash
# Passive subdomain enumeration (no direct contact with target)
echo "[*] Running Subfinder (passive)..."
subfinder -d $TARGET -silent -o artifacts/subdomains_subfinder.txt
echo "[+] Subfinder found: $(wc -l < artifacts/subdomains_subfinder.txt) subdomains"

# Amass passive mode
echo "[*] Running Amass (passive)..."
amass enum --passive -d $TARGET -o artifacts/subdomains_amass.txt
echo "[+] Amass found: $(wc -l < artifacts/subdomains_amass.txt) subdomains"

# Combine and deduplicate
cat artifacts/subdomains_subfinder.txt artifacts/subdomains_amass.txt \
  | sort -u > artifacts/subdomains_all.txt
echo "[+] Total unique subdomains: $(wc -l < artifacts/subdomains_all.txt)"
```

**✅ Checkpoint 2:** Your combined subdomain list should be populated.
Look for high-value targets: `vpn.`, `remote.`, `mail.`, `owa.`, `citrix.`, `admin.`, `portal.`

---

## STEP 2 — Certificate Transparency Recon

**Objective:** Use SSL/TLS certificate logs to discover subdomains that may not appear
in DNS enumeration — including internal hostnames accidentally exposed via public certs.

### 2a. Query crt.sh Certificate Transparency Logs

```bash
# Query crt.sh via API — returns all certificates ever issued for the domain
echo "[*] Querying certificate transparency logs for $TARGET..."

curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u \
  | grep -v "^$" \
  > artifacts/cert_transparency_domains.txt

echo "[+] Certificate transparency found: $(wc -l < artifacts/cert_transparency_domains.txt) entries"
cat artifacts/cert_transparency_domains.txt | head -20
```

**Expected Output:**
```
[+] Certificate transparency found: 47 entries
api.yourdomain.com
blog.yourdomain.com
dev.yourdomain.com          ← interesting — development environment?
internal-portal.yourdomain.com  ← very interesting
mail.yourdomain.com
staging.yourdomain.com      ← staging environment exposed?
vpn.yourdomain.com          ← high-value: VPN portal
```

**✅ Checkpoint 3:** Any subdomain starting with `dev`, `staging`, `internal`, `test`,
`admin`, or `vpn` is a HIGH PRIORITY finding. Add to your findings list.

### 2b. Certificate Details for High-Value Subdomains

```bash
# Get full certificate details for interesting subdomains
INTERESTING="vpn.$TARGET"

curl -s "https://crt.sh/?q=$INTERESTING&output=json" \
  | jq '.[0] | {issuer: .issuer_name, not_before: .not_before, not_after: .not_after, cn: .common_name}' \
  > artifacts/cert_detail_vpn.json

echo "[+] Certificate details:"
cat artifacts/cert_detail_vpn.json
```

---

## STEP 3 — Shodan Infrastructure Sweep

**Objective:** Identify exposed internet-facing services on the target's IP space
without sending a single packet to the target.

### 3a. Organization & IP Range Discovery

```bash
# Search Shodan for the organization
echo "[*] Searching Shodan for org: $TARGET"
shodan search "hostname:$TARGET" --fields ip_str,port,org,product,version \
  | head -30 \
  | tee artifacts/shodan_services.txt

# Get ASN information
TARGET_IP=$(dig A $TARGET +short | head -1)
echo "[*] Target IP: $TARGET_IP"
shodan host $TARGET_IP | tee artifacts/shodan_host_detail.txt
```

### 3b. Hunt for High-Value Exposed Services

```bash
# Look for commonly exploited remote access portals
echo "[*] Hunting for exposed remote access services..."

# Check for each service and log findings
for service in "Outlook Web App" "Citrix" "GlobalProtect" "Pulse Secure" \
               "Fortinet" "RDP" "VMware Horizon" "Apache Tomcat"; do
  COUNT=$(shodan search "org:\"$TARGET\" \"$service\"" --limit 5 2>/dev/null | wc -l)
  if [ "$COUNT" -gt "0" ]; then
    echo "[!] FOUND: $service — $COUNT results"
    shodan search "org:\"$TARGET\" \"$service\"" \
      --fields ip_str,port,product,version >> artifacts/exposed_services.txt
  fi
done

echo ""
echo "[*] Checking for known vulnerable service versions..."
shodan search "org:\"$TARGET\" vuln:CVE-2021-44228" 2>/dev/null \
  && echo "[!!!] CRITICAL: Log4Shell vulnerable service found!" \
  || echo "[+] No Log4Shell results (good)"
```

**✅ Checkpoint 4:** Any exposed VPN portal, OWA, or RDP is an **automatic High finding**.
Exposed admin panels are Critical. Note all versions for later CVE correlation.

### 3c. Technology Stack Fingerprinting

```bash
# Identify web server, CDN, and application technology
echo "[*] Technology fingerprinting via HTTP headers..."

curl -s -I "https://$TARGET" 2>/dev/null | tee artifacts/http_headers.txt

# Parse key headers
echo ""
echo "=== Technology Indicators ==="
grep -i "server:\|x-powered-by:\|x-aspnet\|x-drupal\|x-wordpress\|via:\|x-cache" \
  artifacts/http_headers.txt

# Check Shodan for tech stack
shodan search "hostname:$TARGET" --fields ip_str,port,product,version,os \
  | sort -u >> artifacts/tech_stack.txt
```

---

## STEP 4 — Email Security Posture Assessment

**Objective:** Evaluate SPF, DKIM, and DMARC configurations. Weak email security
is a direct enabler of phishing attacks against the organization.

```bash
echo "[*] Assessing email security for $TARGET"
echo "================================================"

# SPF Record
echo ""
echo "=== SPF (Sender Policy Framework) ==="
SPF=$(dig TXT $TARGET +short | grep "v=spf1")
if [ -z "$SPF" ]; then
  echo "[!!!] CRITICAL: No SPF record found — domain is spoofable!"
else
  echo "[+] SPF found: $SPF"
  # Check for overly permissive SPF
  echo "$SPF" | grep -q "\+all" && echo "[!!!] CRITICAL: SPF uses +all — allows ANY sender!" || true
  echo "$SPF" | grep -q "~all" && echo "[!] WARNING: SPF uses ~all (softfail) — emails may not be rejected" || true
  echo "$SPF" | grep -q "-all" && echo "[+] GOOD: SPF uses -all (hardfail)" || true
fi

# DMARC Record
echo ""
echo "=== DMARC (Domain-based Message Authentication) ==="
DMARC=$(dig TXT _dmarc.$TARGET +short)
if [ -z "$DMARC" ]; then
  echo "[!!!] CRITICAL: No DMARC record — phishing emails will not be reported or rejected!"
else
  echo "[+] DMARC found: $DMARC"
  echo "$DMARC" | grep -q "p=none"     && echo "[!] WARNING: DMARC policy is p=none (monitor only)" || true
  echo "$DMARC" | grep -q "p=quarantine" && echo "[~] MEDIUM: DMARC policy is quarantine" || true
  echo "$DMARC" | grep -q "p=reject"   && echo "[+] GOOD: DMARC policy is reject" || true
fi

# DKIM check (common selectors)
echo ""
echo "=== DKIM (DomainKeys Identified Mail) ==="
for selector in google default selector1 selector2 mail dkim k1; do
  DKIM=$(dig TXT ${selector}._domainkey.$TARGET +short 2>/dev/null)
  if [ ! -z "$DKIM" ]; then
    echo "[+] DKIM found with selector '$selector': ${DKIM:0:60}..."
  fi
done

# Save full email security report
{
  echo "# Email Security Assessment — $TARGET — $(date)"
  echo "## SPF"; dig TXT $TARGET +short | grep spf
  echo "## DMARC"; dig TXT _dmarc.$TARGET +short
  echo "## MX Records"; dig MX $TARGET +short
} > artifacts/email_security_report.txt

echo ""
echo "[+] Email security report saved to artifacts/email_security_report.txt"
```

**✅ Checkpoint 5:** Score your findings:
- No SPF + No DMARC = **Critical** — domain can be spoofed for phishing with no controls
- SPF `~all` + DMARC `p=none` = **High** — emails not rejected, only monitored
- SPF `-all` + DMARC `p=reject` = **Low risk** — strong email authentication in place

---

## STEP 5 — theHarvester Intelligence Sweep

**Objective:** Harvest emails, employee names, and additional hosts using multiple
OSINT sources simultaneously.

```bash
# Run theHarvester across multiple sources (passive only)
echo "[*] Running theHarvester — this takes 3–5 minutes..."

theHarvester \
  -d $TARGET \
  -b bing,yahoo,duckduckgo,crtsh,certspotter,dnsdumpster,rapiddns \
  -f artifacts/theharvester_results

echo "[+] theHarvester complete — results in artifacts/theharvester_results.xml/.html"

# Parse emails found
echo ""
echo "=== Email Addresses Discovered ==="
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
  artifacts/theharvester_results.xml 2>/dev/null \
  | sort -u | tee artifacts/emails_found.txt

echo ""
echo "[+] Total emails harvested: $(wc -l < artifacts/emails_found.txt)"
```

**✅ Checkpoint 6:** From the emails, derive the **email naming convention**:
- `firstname.lastname@domain.com`
- `flastname@domain.com`
- `firstname@domain.com`

This becomes the attacker's spearphishing target list template.

---

## STEP 6 — Compile Attack Surface Report

**Objective:** Consolidate all findings into a structured risk-rated asset inventory.

```bash
echo "[*] Compiling final attack surface inventory..."

cat > artifacts/attack_surface_summary.md << EOF
# Attack Surface Summary — $TARGET
Generated: $(date)

## Asset Inventory

| Asset | Type | Port/Service | Risk | Notes |
|-------|------|-------------|------|-------|
$(cat artifacts/shodan_services.txt 2>/dev/null | awk '{print "| "$1" | Service | "$2" | TBD | "$3" |"}' | head -10)

## Subdomain Count
- Total discovered: $(wc -l < artifacts/subdomains_all.txt 2>/dev/null || echo "0")
- High-interest (vpn/owa/admin/remote): $(grep -cE "vpn\.|owa\.|admin\.|remote\.|citrix\." artifacts/subdomains_all.txt 2>/dev/null || echo "0")

## Email Security
- SPF: $(dig TXT $TARGET +short | grep -c spf || echo "NOT FOUND")
- DMARC: $(dig TXT _dmarc.$TARGET +short | grep -c dmarc || echo "NOT FOUND")

## Key Findings
[Fill in during lab — copy HIGH and CRITICAL findings here]

EOF

echo "[+] Summary saved to artifacts/attack_surface_summary.md"
echo ""
echo "=== LAB COMPLETE — Artifact Summary ==="
ls -lah artifacts/
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What is the primary IP range/ASN for the target organization?
- [ ] 🚩 **Flag 2:** Does the target have a VPN or OWA portal exposed? What URL?
- [ ] 🚩 **Flag 3:** What is the email security posture rating? (Strong / Moderate / Weak / None)
- [ ] 🚩 **Flag 4:** What email naming convention was identified?
- [ ] 🚩 **Flag 5:** How many subdomains were discovered total?

---

## 📁 Artifacts to Commit

Save the following to `days/day-01/artifacts/` in your GitHub repo:

| File | Contents |
|------|---------|
| `dns_records.txt` | All DNS record types |
| `subdomains_all.txt` | Combined subdomain enumeration |
| `cert_transparency_domains.txt` | Certificate transparency results |
| `shodan_services.txt` | Exposed services from Shodan |
| `email_security_report.txt` | SPF/DKIM/DMARC assessment |
| `emails_found.txt` | Harvested email addresses |
| `attack_surface_summary.md` | Final consolidated summary |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `shodan: command not found` | Run `pip install shodan` then `shodan init YOUR_KEY` |
| Subfinder returns 0 results | Add API keys in `~/.config/subfinder/provider-config.yaml` |
| crt.sh query times out | Retry — site occasionally slow; or use `curl -m 30` timeout flag |
| amass runs for too long | Add `-timeout 10` flag to limit runtime |
| `dig` not found (Windows) | Use WSL, or install BIND tools via `choco install bind-toolsonly` |

---

*Next: [REPORT.md](REPORT.md) — Professional analyst report from these findings*
