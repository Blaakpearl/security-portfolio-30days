# Day 15 — LAB.md
## Red Team Reconnaissance Lab Setup Guide
**NovaCrest Capital Group | Purple Team Week 3**

---

## Overview

This lab replicates the external reconnaissance environment used in the Day 15 red team operation. It covers two distinct setups:

1. **Red Team Environment** — the OSINT workstation used to perform reconnaissance
2. **Blue Team Monitoring Environment** — the detection stack used to attempt detection

Both can be run simultaneously on separate VMs to simulate a realistic purple team engagement. A single-machine setup (red + blue on one host) is also documented for solo practitioners.

---

## Prerequisites

### Hardware / Cloud Resources
```
Red Team VM:
  OS:         Kali Linux 2024.1 (or Ubuntu 22.04)
  RAM:        4 GB minimum
  Disk:       20 GB
  Network:    Outbound internet (no inbound required)
  Purpose:    OSINT tools + Python scripts

Blue Team VM:
  OS:         Ubuntu 22.04 LTS
  RAM:        8 GB minimum (Splunk requires 4+ GB)
  Disk:       50 GB
  Network:    Same subnet as red team VM; inbound log collection
  Purpose:    Splunk/Sentinel forwarding + log analysis
```

### API Keys Required (Red Team)
The simulation scripts work without real API keys (demo mode). For live recon against your own test domain, the following free-tier keys are sufficient:

```
Shodan:          https://account.shodan.io/ (Free tier: 1 query/second)
Censys:          https://censys.io/register (Free tier: 250 queries/month)
SecurityTrails:  https://securitytrails.com/app/signup (Free tier: 50 queries/month)
Hunter.io:       https://hunter.io/users/sign_up (Free tier: 25 searches/month)
GitHub:          No API key needed for public search (rate-limited)
```

> **Note:** The simulation scripts in `scripts/` do NOT make live API calls and do NOT require real keys. Keys are only needed if you extend the lab to test against your own authorized target domain.

---

## Red Team Environment Setup

### 1. Install Core OSINT Tools

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Python 3.11+
sudo apt-get install -y python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv ~/day15-recon-env
source ~/day15-recon-env/bin/activate

# Install Python OSINT libraries (for live recon extensions)
pip install shodan censys requests dnspython python-whois

# Install system OSINT tools
sudo apt-get install -y \
    dnsutils \          # dig, nslookup, host
    whois \             # WHOIS queries
    nmap \              # Port scanning (authorized use only)
    curl \              # HTTP requests / banner grabbing
    git \               # Repository cloning
    jq                  # JSON parsing for API responses

# Verify installations
dig --version
whois --version
python3 --version
```

### 2. Clone and Configure Lab Repository

```bash
# Clone portfolio repository
git clone https://github.com/Blaakpearl/Blaakpearl.git
cd Blaakpearl/day15

# Install Python dependencies
pip install -r requirements.txt  # if present, else:
pip install requests dnspython python-whois shodan

# Verify scripts run in demo mode
python3 scripts/osint_reconnaissance_simulator.py --verbose
python3 scripts/recon_findings_analyzer.py --analyze
```

### 3. Configure API Keys (Optional — For Live Recon Against Authorized Target)

```bash
# Create environment file (do NOT commit to git)
cat > ~/.day15-api-keys << 'EOF'
export SHODAN_API_KEY="your_shodan_key_here"
export CENSYS_API_ID="your_censys_id_here"
export CENSYS_API_SECRET="your_censys_secret_here"
export SECURITYTRAILS_API_KEY="your_st_key_here"
export HUNTER_API_KEY="your_hunter_key_here"
EOF

# Source for current session
source ~/.day15-api-keys

# Verify Shodan key works (requires shodan library)
python3 -c "import shodan; api = shodan.Shodan('$SHODAN_API_KEY'); print(api.info())"
```

### 4. CT Log Queries (Manual — No API Key Required)

```bash
# Query crt.sh directly (no auth needed)
# Replace "novacrest.com" with your authorized target domain

# Method 1: Browser
# https://crt.sh/?q=%.novacrest.com

# Method 2: API
curl -s "https://crt.sh/?q=%25.novacrest.com&output=json" | \
    jq -r '.[].name_value' | \
    sort -u | \
    grep -v '^\*'

# Method 3: Using ctfetcher (Python wrapper)
pip install ctfetcher
ctfetcher novacrest.com
```

### 5. Passive DNS Queries

```bash
# Method 1: SecurityTrails CLI (requires API key)
pip install securitytrails
st domains novacrest.com

# Method 2: Direct DNS lookups (no API key)
# Enumerate common subdomains manually
for sub in www mail api admin dev staging vpn backup; do
    result=$(dig +short ${sub}.novacrest.com A 2>/dev/null)
    if [ -n "$result" ]; then
        echo "${sub}.novacrest.com → ${result}"
    fi
done

# Method 3: amass (subdomain enumeration)
sudo apt-get install -y amass
amass enum -passive -d novacrest.com  # Passive only (authorized target)
```

### 6. WHOIS & ASN Lookup

```bash
# Domain WHOIS
whois novacrest.com

# IP WHOIS (replace with actual IP from DNS lookup)
whois 203.0.113.10

# ASN lookup
whois -h whois.cymru.com " -v 203.0.113.10"

# Netblock lookup
whois -h whois.arin.net "n + 203.0.113.10"
```

### 7. Shodan Search (With API Key)

```bash
# Install Shodan CLI
pip install shodan
shodan init $SHODAN_API_KEY

# Search for organization
shodan search "org:NovaCrest Capital"

# Search by IP range (replace with actual netblock)
shodan search "net:203.0.113.0/24"

# Alternative: Use web interface (no CLI)
# https://www.shodan.io/search?query=org%3ANovaCrest+Capital
```

### 8. GitHub Secret Scanning

```bash
# Method 1: GitHub web search (no auth)
# https://github.com/search?q=org%3Anovacrest+password&type=code

# Method 2: truffleHog (finds secrets in git history)
pip install trufflehog
trufflehog github --org=novacrest  # Replace with authorized org

# Method 3: gitleaks
# https://github.com/gitleaks/gitleaks
# For authorized targets:
git clone https://github.com/novacrest/trading-api.git
gitleaks detect --source=./trading-api

# Method 4: git-secrets
git clone https://github.com/awslabs/git-secrets.git
cd trading-api
git secrets --scan-history
```

### 9. DNS Zone Transfer Attempt

```bash
# Attempt AXFR against target nameservers
# Expected result: REFUSED (this is correct behavior)
dig AXFR novacrest.com @ns1.novacrest.com
dig AXFR novacrest.com @ns2.novacrest.com

# If AXFR succeeds (misconfiguration), you'll see all DNS records
# Report this immediately as a critical finding

# Verify nameservers first
dig NS novacrest.com
```

### 10. SMTP Banner Grabbing

```bash
# Method 1: Netcat (standard)
# Connect to port 25; read banner; immediately disconnect
echo "QUIT" | nc -w 3 mail.novacrest.com 25 2>/dev/null | head -3

# Method 2: curl
curl -v smtp://mail.novacrest.com 2>&1 | grep "^<"

# Method 3: Python (for logging purposes)
python3 -c "
import socket
s = socket.socket()
s.settimeout(5)
s.connect(('mail.novacrest.com', 25))
banner = s.recv(1024).decode()
print(f'Banner: {banner.strip()}')
s.close()
"

# IMPORTANT: Do NOT send MAIL FROM or RCPT TO without authorization
# Banner reading only — connection + recv + close
```

---

## Blue Team Environment Setup

### 1. Install Splunk (Free Trial / Development License)

```bash
# Download Splunk Enterprise (free trial — 500MB/day)
# https://www.splunk.com/en_us/download/splunk-enterprise.html

# Ubuntu install
wget -O splunk-enterprise.tgz "https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-99d8681699cb-Linux-x86_64.tgz"
tar xvzf splunk-enterprise.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license --answer-yes
/opt/splunk/bin/splunk enable boot-start

# Access at http://localhost:8000 (admin/changeme)
```

### 2. Configure DNS Logging to Splunk

```bash
# If running BIND DNS server:
# Edit /etc/bind/named.conf.options
cat >> /etc/bind/named.conf.options << 'EOF'
logging {
    channel query_log {
        file "/var/log/named/queries.log" versions 5 size 20m;
        print-time yes;
        print-severity yes;
        print-category yes;
        severity dynamic;
    };
    category queries { query_log; };
    category query-errors { query_log; };
};
EOF

# Restart BIND
sudo systemctl restart bind9

# Install Splunk Universal Forwarder for DNS logs
wget -O splunk-uf.tgz "https://download.splunk.com/products/universalforwarder/..."
# Configure to send /var/log/named/queries.log to Splunk
```

### 3. Configure Firewall Logging

```bash
# UFW logging (Ubuntu)
sudo ufw logging on
sudo ufw logging high  # Log all connections

# iptables logging for specific ports
sudo iptables -A INPUT -p tcp --dport 25 -j LOG --log-prefix "SMTP-INBOUND: "
sudo iptables -A INPUT -p tcp --dport 443 -j LOG --log-prefix "HTTPS-INBOUND: "

# View logs
sudo tail -f /var/log/ufw.log

# Forward to Splunk via Universal Forwarder
```

### 4. Load Detection Queries into Splunk

```bash
# Import SPL queries from queries/splunk_recon_detection.spl
# In Splunk UI:
# Settings → Searches, Reports, and Alerts → New Alert
# Paste each SPL query and configure alert thresholds

# OR use Splunk CLI to import saved searches
/opt/splunk/bin/splunk add saved-search "DNS NXDOMAIN Threshold" \
    -search "$(cat queries/splunk_recon_detection.spl | grep -A 10 'QUERY 4')" \
    -cron_schedule "*/5 * * * *" \
    -alert_type "number of events" \
    -alert_comparator "greater than" \
    -alert_threshold 20

# Verify queries load correctly
/opt/splunk/bin/splunk search "index=dns | head 10"
```

### 5. Configure Microsoft Sentinel (Alternative to Splunk)

```bash
# Sentinel is cloud-based; requires Azure subscription
# Setup steps:
# 1. Create Log Analytics Workspace in Azure Portal
# 2. Enable Microsoft Sentinel on the workspace
# 3. Connect data sources:
#    → Windows Security Events (via AMA agent)
#    → DNS Events (via DNS Connector)
#    → Syslog (via Syslog Connector)

# Install Azure Monitor Agent on blue team VM
wget https://aka.ms/InstallAzureMonitorAgent -O install-agent.sh
chmod +x install-agent.sh
sudo ./install-agent.sh

# Import KQL queries from queries/sentinel_recon_detection.kql
# In Sentinel → Analytics → Rule Templates → Import

# Configure alerts in Sentinel
# Analytics → Create → Scheduled Query Rule
# Paste KQL from sentinel_recon_detection.kql

# Set alert thresholds per query comments in .kql file
```

---

## Running the Simulation (No Live Target Required)

To practice detection without a live target, run the simulation scripts and load the generated JSON telemetry into Splunk:

```bash
# Step 1: Generate simulated reconnaissance telemetry
python3 scripts/osint_reconnaissance_simulator.py --json > /tmp/recon_telemetry.json

# Step 2: Generate simulated findings report
python3 scripts/recon_findings_analyzer.py --json > /tmp/recon_analysis.json

# Step 3: Load simulated events into Splunk
# (Requires Splunk HTTP Event Collector configured)
HEC_TOKEN="your-hec-token"
curl -k -H "Authorization: Splunk $HEC_TOKEN" \
     -H "Content-Type: application/json" \
     -d @/tmp/recon_telemetry.json \
     https://localhost:8088/services/collector/event

# Step 4: Run SPL queries against simulated data
# Open Splunk UI → Search → paste queries from splunk_recon_detection.spl

# Step 5: Review what fired vs. what should have fired
# Compare against blue_team_gap_analysis.md
```

---

## Validation Exercises

Run these exercises to confirm lab environment is working correctly:

### Exercise 1: DNS NXDOMAIN Threshold Detection
```bash
# Simulate subdomain enumeration from red team VM
for i in $(seq 1 30); do
    dig +short "nonexistent${i}.novacrest.com" A > /dev/null 2>&1
done

# Expected: Query 4 (SPL) or Query 4 (KQL) fires within 5 minutes
# Verify in Splunk: index=dns response_code=NXDOMAIN | stats count by src_ip
```

### Exercise 2: AXFR Alert
```bash
# Attempt zone transfer from red team VM
dig AXFR novacrest.com @ns1.novacrest.com

# Expected: Query 10 (SPL) or Query 10 (KQL) fires immediately
# AXFR queries are rare enough to be high-confidence
```

### Exercise 3: SMTP Rejection Rate
```bash
# Simulate email validation from red team VM (requires SMTP access to test server)
for email in user1 user2 user3 user4 user5; do
    echo "RCPT TO:<${email}@novacrest.com>" | nc -w 2 mail.novacrest.com 25
done

# Expected: Query 7 (SPL) or Query 7 (KQL) fires within 10 minutes
```

### Exercise 4: Multi-Source Correlation
```bash
# After running Exercises 1–3:
# Run Query 11 (SPL) or Query 11 (KQL) — multi-source correlation
# Expected: Critical alert fires combining DNS + SMTP evidence
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `dig` returns no results | Check DNS server connectivity; try `dig @8.8.8.8 novacrest.com` |
| Shodan API returns 403 | Verify API key; check rate limits (1 query/sec on free tier) |
| Splunk not receiving logs | Check Universal Forwarder status: `splunk list forward-server` |
| Python script ImportError | Activate virtual environment: `source ~/day15-recon-env/bin/activate` |
| AXFR attempt hangs | Add timeout: `dig AXFR +time=3 novacrest.com @ns1.novacrest.com` |
| SMTP connection refused | Check firewall; port 25 may be blocked outbound by ISP/cloud provider |

---

## Lab Teardown

```bash
# Remove API keys from environment
unset SHODAN_API_KEY CENSYS_API_ID CENSYS_API_SECRET SECURITYTRAILS_API_KEY
rm -f ~/.day15-api-keys

# Remove cloned repositories (may contain sensitive findings)
rm -rf /tmp/novacrest-* /tmp/recon_*

# Stop Splunk (if not needed beyond this lab)
/opt/splunk/bin/splunk stop

# Deactivate Python virtual environment
deactivate
```

---

*Day 15 Lab Guide | Week 3 Purple Team Adversary Simulation*
*NovaCrest Capital Group Engagement | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
