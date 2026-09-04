# Day 18 — Exfiltration Detection Playbook & DLP Hardening Checklist
**NovaCrest Capital Group | Security Operations**
**Classification:** TLP:WHITE — Internal Distribution
**Author:** V. Willis, CISSP

---

## Detection Playbook

### DNS Tunneling (T1048.001)

**Detection signals (priority order):**
1. TXT/NULL record queries from workstations (Queries H1-B) — rare legitimately; high fidelity
2. Long query names > 60 chars with high-entropy subdomain (H1-A) — catches payload in query name
3. Burst queries to single apex domain, 10+ in 5 min (H1-C) — catches data volume

**DNS Tunnel Detector scoring:**
- Score ≥ 50: Investigate
- Score ≥ 75: Alert + block DNS server IP
- Score ≥ 90: Isolate endpoint

**Triage steps:**
1. Pull apex domain from suspicious queries — check domain age (new = suspicious)
2. Decode subdomain base64: `echo [subdomain] | base64 -d` — is it readable data?
3. Check outbound DNS server IP — is it the org's resolver or an external IP?
4. Correlate with conn.log — does this host have large HTTPS egress too? (multi-channel)
5. Block the apex domain at DNS resolver and NGFW

**Preventive controls:**
```bash
# Restrict DNS to internal resolvers only (block external DNS on NGFW)
iptables -A FORWARD -p udp --dport 53 -j DROP  # Block direct external DNS
iptables -A FORWARD -p tcp --dport 53 -j DROP

# Enable DNS over HTTPS inspection (NGFW / Umbrella)
# Force all DNS through Cisco Umbrella or Zscaler for query visibility

# Alert on internal hosts querying external DNS servers
# (Should only query 10.0.0.53 or 10.0.0.54 — internal resolvers)
```

---

### HTTPS / Encrypted Exfiltration (T1048.002)

**Detection signals:**
1. Known C2 JA3 fingerprint (H2-A) — highest fidelity; matches known tools
2. Self-signed certificate + high egress (H2-B) — attacker-deployed TLS infra
3. Destination domain registered < 30 days old — new infra for exfil operation

**Triage steps:**
1. Capture JA3 from Zeek ssl.log; compare against known-bad list
2. Check certificate validity and issuer — self-signed = red flag
3. Pull conn.log bytes for same connection — how much data transferred?
4. Check destination IP reputation (VirusTotal, Shodan)
5. If C2 JA3 confirmed: isolate immediately; preserve memory

**Preventive controls:**
```
1. TLS Inspection (NGFW / Proxy):
   - Decrypt and re-encrypt outbound HTTPS for inspection
   - Allows DLP to scan encrypted content
   - Note: Cannot inspect pinned certificates (native apps)

2. JA3 Blocklist:
   - Deploy known C2 JA3 signatures in NGFW
   - Sources: abuse.ch JA3 feed, Salesforce JA3S feeds

3. DNS Allowlisting:
   - Only allow TLS to destinations that resolve to known-good domains
   - Block TLS to IP-only destinations (no SNI)
```

---

### Data Staging and Archiving (T1560.001)

**Detection signals:**
1. Large archive file in Zeek files.log (H3-A) — file transfer metadata shows archive type
2. Archive utility run by compromised account (H3-B) — auditd/Sysmon process creation
3. Large file creation in temp directories — auditd inode watch on /tmp, /dev/shm

**Triage steps:**
1. Identify archive filename from Zeek files.log — does it reference sensitive data?
2. Check source host for archive utility execution (auditd EXECVE)
3. What directory was archived? `tar czf archive.tar.gz /opt/trading/` in args
4. When was the archive created vs. transferred? Short window = active exfil
5. Pull archive for analysis if still present on host

**Preventive controls:**
```bash
# auditd: monitor large file creation in temp directories
-w /tmp -p wxa -k tmp_write
-w /dev/shm -p wxa -k shm_write
-w /var/tmp -p wxa -k var_tmp_write

# Alert on file creation > 10 MB in temp directories (Linux)
# Use inotifywait for real-time monitoring:
inotifywait -m -r -e create,modify /tmp --format '%w%f %e %T' |
    awk '{if ($3 != "" && size > 10000000) print "LARGE FILE: "$0}'

# DLP: Block archive file types from leaving network (NGFW file type filter)
# Block: .tar.gz, .tar.bz2, .zip, .7z, .rar from non-IT source IPs
```

---

### Cloud Storage Exfiltration (T1567.002)

**Detection signals:**
1. PUT/POST to cloud storage domain (H4-A, H4-B) — Zeek ssl.log destination
2. Large upload bytes to cloud storage (H4-B) — conn.log + ssl.log join
3. Presigned S3 URL usage — no standard AWS auth headers; harder to detect

**Triage steps:**
1. Identify cloud destination from ssl.log — is this a known org bucket?
2. Check bucket name in S3 URL — `novacrest-exfil` ≠ `novacrest-prod-data`
3. Pull Purview DLP alerts for same time window
4. Check CloudTrail for `s3:PutObject` from unexpected source IP
5. Contact AWS to put hold on attacker bucket if exfil was to S3

**Preventive controls:**
```
1. CASB (Cloud Access Security Broker):
   - Enforce approved cloud storage list (only novacrest.sharepoint.com, etc.)
   - Block unauthorized S3 buckets at proxy/NGFW
   - Alert on large uploads to non-corporate cloud destinations

2. AWS Resource Control Policy (RCP):
   Apply to all S3 buckets to prevent access from outside org's VPC endpoints:
   {
     "Effect": "Deny",
     "Principal": "*",
     "Action": "s3:*",
     "Condition": {
       "StringNotEquals": {
         "aws:SourceVpc": "vpc-xxxxxxxx"
       }
     }
   }

3. Purview DLP:
   - Enable DLP for SharePoint, OneDrive, Exchange
   - Enable endpoint DLP for Windows (blocks upload at browser level)
   - Create policy for trading algorithm file extensions (.py, .json config)

4. NGFW URL Category Filtering:
   - Block "File Storage and Sharing" category for endpoints (not file servers)
   - Allowlist only corporate-approved destinations
```

---

### Volumetric Anomaly Detection (T1030)

**UEBA Baseline Parameters (recommended):**
```
Baseline period:  30 days rolling
Alert threshold:  > 3σ from mean daily egress per host
Hard threshold:   > 500 MB in 24 hours from a single workstation (regardless of baseline)
Data granularity: Per-host, per-hour; not aggregated at subnet level
Lookback window:  Compare to same day-of-week (Monday vs. Monday baseline)
```

**Preventive controls:**
```
1. Deploy UEBA (Microsoft Sentinel Analytics / Elastic UEBA):
   - Build egress baseline per host per hour
   - Alert when current hour > 3× rolling average for same hour-of-day
   - Separate thresholds for servers vs. workstations

2. Network QoS / DLP Throttling:
   - Rate-limit egress from user workstations (e.g., max 100 MB/hr)
   - Alert when rate limit is hit

3. DLP by volume:
   - Purview: Alert on any user moving > 1000 files in 1 hour
   - Zeek: Alert when single host exceeds 200 MB external egress in 1 hour
```

---

## DLP Hardening Checklist

### Network DLP (NGFW / Proxy)
```
INSPECTION
  □ Enable TLS inspection for all outbound HTTPS from workstations
  □ Configure DLP policies for financial data patterns:
      Credit card numbers, account numbers, ABA routing numbers
      Bloomberg terminal identifiers
      Trade order formats (JSON with 'side', 'quantity', 'symbol' fields)
  □ Block archive file uploads to non-approved destinations (.tar.gz, .zip, .7z)
  □ Block outbound DNS to non-internal resolvers (port 53 UDP/TCP)

CLOUD STORAGE
  □ Block unauthorized cloud storage at NGFW URL category level:
      mega.nz, wetransfer.com, anonfiles.com, hastebin.com, paste.ee
  □ Allowlist only corporate-approved cloud destinations
  □ Log all PUT/POST to remaining cloud storage (for UEBA correlation)

ANOMALY
  □ Enable NetFlow / Zeek for all perimeter traffic
  □ Alert on > 200 MB egress from single workstation in 1 hour
  □ Alert on TXT/NULL DNS records from internal hosts
  □ Alert on outbound SSH (TCP:22) to non-approved external IPs
```

### Endpoint DLP (Microsoft Purview / EDR)
```
PURVIEW ENDPOINT DLP
  □ Enable Microsoft Purview Endpoint DLP on all Windows endpoints
  □ Create sensitive info types for:
      Trading algorithm file extensions (.py configs, .json params)
      Bloomberg API key patterns (bbg-[a-z0-9]{32})
      Internal account number formats
  □ Block copy to USB / removable media of sensitive content
  □ Block upload to non-approved websites (browser-level)
  □ Alert on email with attachment > 10 MB to external recipients

SENSITIVITY LABELS
  □ Deploy Microsoft Information Protection (MIP) labels:
      - "NovaCrest Confidential — Trading Data"
      - "NovaCrest Restricted — Client Data"
  □ Require labels on all files in /opt/trading/ equivalent paths
  □ Block "Confidential" label files from being uploaded externally
```

### Cloud DLP (AWS / Azure)
```
AWS
  □ Enable Macie on all S3 buckets (detects PII, financial data)
  □ Create S3 bucket policy blocking access from outside VPC endpoints
  □ Enable CloudTrail data events for S3 (log every PutObject/GetObject)
  □ Alert on PutObject from non-corporate IP ranges
  □ Alert on new bucket creation with "exfil", "temp", "drop" in name

AZURE / M365
  □ Enable Microsoft Defender for Cloud Apps (MCAS)
  □ Configure activity policies for mass file download
  □ Enable anomalous external sharing alerts
  □ Block file sharing to unmanaged devices
```

### Detection Rules to Deploy (SIEM)
```
RULE 1: TXT/NULL DNS from workstation
        → Alert immediately; block DNS server IP

RULE 2: Known C2 JA3 in TLS connection
        → Alert immediately; isolate endpoint

RULE 3: Archive file > 50 MB in files.log to external IP
        → Alert: critical; block connection; preserve archive on endpoint

RULE 4: Cloud storage upload > 10 MB from workstation (not file server)
        → Alert high; notify DLP team

RULE 5: Egress > 200 MB from single workstation in 1 hour
        → Alert critical; initiate IR process

RULE 6: Recurring transfers to same external IP at regular intervals
        → Alert high; investigate scheduling mechanism

RULE 7: Exfil kill chain (any H3 + any H5 within 2 hours)
        → Alert critical; auto-isolate endpoint + notify IR team
```

---

*Day 18 — Exfiltration Detection Playbook*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
