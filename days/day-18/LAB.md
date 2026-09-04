# Day 18 — LAB.md
## Data Exfiltration Hunt Lab Setup
**NovaCrest Capital Group | Threat Hunt Week**

---

## Overview

This lab configures the detection stack for hunting data exfiltration across
three telemetry layers: **Zeek network logs**, **UEBA behavioral baselines**,
and **DLP policy alerts**. You will parse Zeek log output, build volumetric
baselines, and execute hunt queries against both real and simulated data.

---

## Step 1: Deploy Zeek for Network Telemetry

```bash
# Install Zeek (Ubuntu 22.04)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
    | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
    | sudo gpg --dearmor > /etc/apt/trusted.gpg.d/zeek.gpg
sudo apt-get update && sudo apt-get install -y zeek

# Configure Zeek to monitor primary interface
sudo zeekctl quickstart  # Interactive setup
# OR manually edit /opt/zeek/etc/node.cfg:
cat > /opt/zeek/etc/node.cfg << 'EOF'
[zeek]
type=standalone
host=localhost
interface=eth0    # Change to your capture interface
EOF

# Deploy with local.zeek config additions
cat >> /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load policy/tuning/defaults/json-logs      # JSON format for SIEM
@load policy/protocols/dns/detect-external-names
@load policy/protocols/ssl/log-hostnames
@load policy/frameworks/files/hash-all-files  # Hash transferred files
redef Log::default_rotation_interval = 1hrs;
EOF

sudo zeekctl deploy
sudo zeekctl status

# Verify log output
ls /opt/zeek/logs/current/
# conn.log  dns.log  http.log  ssl.log  files.log  weird.log
```

---

## Step 2: Configure Zeek for DNS Tunnel Detection

```bash
# Add the DNS tunneling script
cat > /opt/zeek/share/zeek/site/dns-tunnel-detect.zeek << 'EOF'
module DNSTunnel;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts:          time   &log;
        src:         addr   &log;
        query:       string &log;
        qtype:       string &log;
        query_len:   count  &log;
        entropy:     double &log;
        suspicious:  bool   &log;
    };
}

# Log DNS queries with long names or high entropy
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local q_len = |query|;
    # Simple entropy approximation: flag queries > 50 chars in subdomain
    local subdomain_part = split_string(query, /\./)[0];
    local suspicious = (|subdomain_part| > 40 || q_len > 75);
    Log::write(DNSTunnel::LOG, [
        $ts=network_time(),
        $src=c$id$orig_h,
        $query=query,
        $qtype=cat(qtype),
        $query_len=q_len,
        $entropy=0.0,    # Compute in Python post-processing
        $suspicious=suspicious
    ]);
}
EOF

# Enable in local.zeek
echo "@load site/dns-tunnel-detect" >> /opt/zeek/share/zeek/site/local.zeek
sudo zeekctl deploy
```

---

## Step 3: Build UEBA Baseline

```bash
# Install Python dependencies for UEBA baseline script
pip install pandas numpy scipy scikit-learn

# Generate 30-day Zeek conn.log baseline (use historical logs)
python3 scripts/exfil_hunt_engine.py \
    --baseline \
    --conn-log /opt/zeek/logs/2026-05-*/conn.log \
    --output /var/lib/hunt/baseline_egress.json

# Alternatively, use the demo baseline built into the script
python3 scripts/exfil_hunt_engine.py --demo --baseline-report

# Verify baseline output
cat /var/lib/hunt/baseline_egress.json | python3 -m json.tool | head -40
```

---

## Step 4: Enable Microsoft Purview DLP (M365)

```powershell
# Connect to Security & Compliance Center
Connect-IPPSSession -UserPrincipalName admin@novacrest.com

# Create DLP policy for financial data
New-DlpCompliancePolicy -Name "NovaCrest Financial Data" `
    -Mode Enable `
    -SharePoint $true `
    -OneDrive $true `
    -Exchange $true

# Add rules for trading data patterns
New-DlpComplianceRule -Name "Trading Algo Detection" `
    -Policy "NovaCrest Financial Data" `
    -ContentContainsSensitiveInformation @{Name="U.S. Bank Account Number"} `
    -BlockAccess $false `
    -NotifyUser "admin@novacrest.com" `
    -GenerateIncidentReport "admin@novacrest.com" `
    -IncidentReportContent "All"

# Enable Insider Risk Management
# M365 Admin Center → Compliance → Insider risk management
# Policy: Data leaks by departing users / General data leaks

# Check recent DLP alerts
Get-DlpDetectionsReport -StartDate (Get-Date).AddDays(-2) -EndDate (Get-Date) `
    | Select-Object Date, Policy, SensitiveInformationType, UserName, DocumentName
```

---

## Step 5: Run the Exfiltration Hunt

```bash
# Full hunt across all hypotheses (demo mode)
python3 scripts/exfil_hunt_engine.py --demo --verbose

# DNS tunneling analysis only
python3 scripts/dns_tunnel_detector.py --demo --verbose

# Parse live Zeek logs (after deployment)
python3 scripts/exfil_hunt_engine.py \
    --conn-log /opt/zeek/logs/current/conn.log \
    --dns-log /opt/zeek/logs/current/dns.log \
    --ssl-log /opt/zeek/logs/current/ssl.log \
    --files-log /opt/zeek/logs/current/files.log \
    --start "2026-06-14T10:00:00" \
    --end "2026-06-15T06:00:00" \
    --host lnx-trade-01

# Load results into Splunk
python3 scripts/exfil_hunt_engine.py --demo --json > /tmp/exfil_telemetry.json
curl -k -H "Authorization: Splunk $HEC_TOKEN" \
     -H "Content-Type: application/json" \
     -d @/tmp/exfil_telemetry.json \
     https://localhost:8088/services/collector/event
```

---

## Step 6: Zeek Log Analysis — Key Commands

```bash
# Find large outbound connections (> 10 MB) in conn.log
cat /opt/zeek/logs/current/conn.log | \
    python3 -c "
import sys, json
for line in sys.stdin:
    r = json.loads(line)
    if float(r.get('resp_bytes', 0)) > 10_000_000:
        print(r['ts'], r['id.orig_h'], r['id.resp_h'], r['resp_bytes'])
"

# Find long DNS queries (> 50 chars) in dns.log
zeek-cut query qtype < /opt/zeek/logs/current/dns.log | \
    awk 'length($1) > 50 {print $0}'

# Find SSL connections with unknown/self-signed certificates
zeek-cut server_name validation_status < /opt/zeek/logs/current/ssl.log | \
    grep -v "ok\|self signed"

# Find file transfers to external IPs in files.log
zeek-cut conn_uids rx_hosts tx_hosts mime_type filename total_bytes \
    < /opt/zeek/logs/current/files.log | \
    awk '{if ($4 ~ /application\/zip|application\/x-tar|application\/x-gzip/) print $0}'
```

---

## Detection Validation Exercises

### Exercise 1: DNS Tunnel Simulation
```bash
# Generate synthetic high-entropy DNS queries (mimics iodine/dnscat2)
python3 scripts/dns_tunnel_detector.py --generate-test-queries \
    --domain tunnel-test.example.com \
    --count 50 \
    --output /tmp/dns-tunnel-test.pcap
# Load pcap into Zeek: zeek -r /tmp/dns-tunnel-test.pcap
# Verify Query 1 (SPL H1-A) fires on resulting dns.log
```

### Exercise 2: Large File Transfer Simulation
```bash
# Create a large test file and transfer externally (lab only)
dd if=/dev/urandom of=/tmp/test-exfil-100mb.tar.gz bs=1M count=100
# Transfer to external test server (netcat, curl, etc.)
# Verify Query H5-A (volumetric anomaly) fires on Zeek conn.log
```

### Exercise 3: Cloud Storage Upload Simulation
```bash
# Simulate S3 PUT request in Zeek proxy log
# (Or use curl against a personal S3 bucket in lab)
curl -X PUT "https://your-lab-bucket.s3.amazonaws.com/test-file.zip" \
     --upload-file /tmp/small-test.zip \
     --header "x-amz-storage-class: STANDARD"
# Verify Query H4-A (cloud storage upload) fires on ssl.log
```

---

*Day 18 Lab Guide | Threat Hunt: Data Exfiltration Patterns*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
