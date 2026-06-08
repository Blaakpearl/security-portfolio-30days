# Day 04 — Lab Guide: Network Traffic Anomaly Detection
### Track: Threat Hunting | Duration: ~3 hours | Difficulty: Intermediate

---

## 🛠 Tools Required

| Tool | Purpose | Install / Access |
|------|---------|-----------------|
| **Zeek (Bro)** | Network traffic analysis — log generation from PCAP | `sudo apt install zeek` |
| **Wireshark / tshark** | Packet-level PCAP inspection & DNS analysis | `sudo apt install wireshark tshark` |
| **Python 3 + scipy/numpy** | Statistical beacon analysis — IAT calculations | `pip install scipy numpy pandas matplotlib` |
| **Rita** | Automated C2 beacon detection from Zeek logs | github.com/activecm/rita |
| **ja3** | JA3/JA3S TLS fingerprint extraction | `pip install pyja3` or zeek-ja3 package |
| **Suricata** | IDS/IPS rule testing against PCAP | `sudo apt install suricata` |
| **tcpdump** | Live packet capture + PCAP generation | Pre-installed on Linux |
| **jq / awk** | Log parsing | Pre-installed |

---

## 🖥 Environment Setup

```bash
# 1. Create working directory
mkdir -p ~/security-labs/day-04/artifacts/pcaps
cd ~/security-labs/day-04

# 2. Install tools
sudo apt update && sudo apt install -y zeek tshark wireshark suricata tcpdump jq
pip install scipy numpy pandas matplotlib requests --break-system-packages

# 3. Verify Zeek install
zeek --version

# 4. Download a sample beacon PCAP for practice
# Option A: PCAP-over-IP from malware-traffic-analysis.net (practice PCAPs)
# Option B: Generate synthetic beacon traffic for lab (use the generator below)
# Option C: Use your own lab PCAP if available

# 5. Set environment
export LAB_DIR=~/security-labs/day-04
export PCAP=$LAB_DIR/artifacts/pcaps/beacon_sample.pcap
export ZEEK_LOGS=$LAB_DIR/artifacts/zeek_logs

mkdir -p $ZEEK_LOGS
echo "[+] Environment ready"
```

### Generate a Synthetic Beacon PCAP (if you don't have one)

```python
# Save as: generate_beacon_pcap.py
# Generates a synthetic DNS beacon traffic log for analysis
# (log file format — use with real PCAP tool for full packet generation)

import random
import time
import json
from datetime import datetime, timezone, timedelta

# Beacon parameters mimicking real C2
BEACON_INTERVAL  = 60.3          # seconds
JITTER_PCT       = 0.002         # 0.2% jitter — very low (automated)
BEACON_COUNT     = 500
START_TIME       = datetime(2025, 1, 16, 2, 0, 0, tzinfo=timezone.utc)
C2_DOMAIN        = "updates.cdn-telemetry-svc.net"
C2_IP            = "185.220.101.33"
VICTIM_IP        = "10.10.5.47"   # DESKTOP-FIN-047 internal IP
DNS_RESOLVER     = "8.8.8.8"     # Google DoH abuse

def generate_dns_log():
    """Generate synthetic Zeek dns.log format entries."""
    entries = []
    current_time = START_TIME

    for i in range(BEACON_COUNT):
        # Apply minimal jitter
        jitter = random.uniform(-BEACON_INTERVAL * JITTER_PCT,
                                 BEACON_INTERVAL * JITTER_PCT)
        interval = BEACON_INTERVAL + jitter

        # Every 5th beacon — DNS TXT record (data exfil indicator)
        qtype = "TXT" if i % 5 == 0 else "A"

        # TXT queries have encoded data in subdomain (exfil pattern)
        if qtype == "TXT":
            # Base64-encoded label mimicking DNS exfil
            import base64
            payload = base64.b64encode(
                f"beacon_id={i}&host=FIN047&ts={int(current_time.timestamp())}".encode()
            ).decode()[:40]
            query = f"{payload}.{C2_DOMAIN}"
        else:
            query = C2_DOMAIN

        entry = {
            "ts":           current_time.timestamp(),
            "uid":          f"C{''.join(random.choices('abcdefABCDEF0123456789', k=12))}",
            "id.orig_h":   VICTIM_IP,
            "id.orig_p":   random.randint(49152, 65535),
            "id.resp_h":   DNS_RESOLVER,
            "id.resp_p":   53,
            "proto":        "udp",
            "qtype_name":   qtype,
            "query":        query,
            "answers":      C2_IP if qtype == "A" else f'"beacon_ack_{i}"',
            "TTL":          "30.000000",
            "rcode_name":   "NOERROR"
        }
        entries.append(entry)
        current_time += timedelta(seconds=interval)

    return entries

# Generate and save
entries = generate_dns_log()

# Save as Zeek-format TSV log
with open("artifacts/zeek_logs/dns.log", "w") as f:
    # Zeek header
    f.write("#separator \\x09\n")
    f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
            "proto\tqtype_name\tquery\tanswers\tTTL\trcode_name\n")
    for e in entries:
        f.write(f"{e['ts']:.6f}\t{e['uid']}\t{e['id.orig_h']}\t"
                f"{e['id.orig_p']}\t{e['id.resp_h']}\t{e['id.resp_p']}\t"
                f"{e['proto']}\t{e['qtype_name']}\t{e['query']}\t"
                f"{e['answers']}\t{e['TTL']}\t{e['rcode_name']}\n")

# Also save as JSON for Python analysis
with open("artifacts/zeek_logs/dns_entries.json", "w") as f:
    json.dump(entries, f, indent=2)

print(f"[+] Generated {len(entries)} synthetic DNS log entries")
print(f"[+] Beacon interval: {BEACON_INTERVAL}s ± {JITTER_PCT*100}%")
print(f"[+] C2 domain: {C2_DOMAIN}")
print(f"[+] TXT (exfil) queries: {sum(1 for e in entries if e['qtype_name']=='TXT')}")
print(f"[+] Logs saved to artifacts/zeek_logs/")
```

```bash
python3 generate_beacon_pcap.py
```

---

## STEP 1 — Zeek: Parse Network Logs & Extract DNS Activity

**Objective:** Use Zeek to process PCAP or log data and extract structured
DNS, connection, and HTTP metadata for analysis.

### 1a. Process PCAP with Zeek (if using real PCAP)

```bash
# Process a PCAP file with full Zeek analysis
cd $ZEEK_LOGS

# Run Zeek against PCAP
zeek -r $PCAP \
  /opt/zeek/share/zeek/policy/protocols/dns/detect-external-names.zeek \
  /opt/zeek/share/zeek/policy/protocols/ssl/validate-certs.zeek \
  /opt/zeek/share/zeek/policy/misc/capture-loss.zeek \
  LogAscii::use_json=T  # Output as JSON for easier parsing

echo "[+] Zeek processing complete"
ls -la *.log
```

### 1b. Extract DNS Query Summary from Zeek Logs

```bash
# Top DNS queries by frequency — beacon will appear at top
echo "[*] Top queried domains (last 6 hours)..."

# From Zeek dns.log (JSON format)
cat $ZEEK_LOGS/dns.log \
  | grep -v "^#" \
  | awk -F'\t' '{print $9}' \
  | sort | uniq -c | sort -rn \
  | head -20 \
  | tee artifacts/top_dns_queries.txt

echo ""
echo "[*] DNS query TYPE distribution..."
cat $ZEEK_LOGS/dns.log \
  | grep -v "^#" \
  | awk -F'\t' '{print $8}' \
  | sort | uniq -c | sort -rn \
  | tee artifacts/dns_type_distribution.txt
```

**Expected Output:**
```
Top DNS Queries:
    500  updates.cdn-telemetry-svc.net     ← 500 queries — ANOMALOUS
     43  windowsupdate.microsoft.com
     38  ocsp.digicert.com
     12  api.github.com
     ...

DNS Type Distribution:
    400  A
    100  TXT    ← 20% TXT ratio is anomalous (normal: < 2%)
     43  AAAA
```

**✅ Checkpoint 1:** The single domain with 500 queries AND a high TXT ratio
is your primary beacon indicator. Normal workstations don't query one domain
500 times in 6 hours.

---

### 1c. Extract Unique External IPs from Connections

```bash
# Check what external IPs DESKTOP-FIN-047 is talking to
echo "[*] Unique external connections from victim host..."

# From Zeek conn.log
cat $ZEEK_LOGS/conn.log 2>/dev/null \
  | grep -v "^#" \
  | awk -F'\t' '{print $5}' \
  | grep -v "^10\.\|^192\.168\.\|^172\.\|^127\." \
  | sort | uniq -c | sort -rn \
  | head -20 \
  | tee artifacts/external_connections.txt

echo ""
echo "[*] Long-duration connections (potential C2)..."
cat $ZEEK_LOGS/conn.log 2>/dev/null \
  | grep -v "^#" \
  | awk -F'\t' 'NR>1 {
      if ($9+0 > 300)  # connections > 5 minutes
        print $9"s\t"$5"\t"$8"\t"$10
    }' \
  | sort -rn \
  | head -10 \
  | tee artifacts/long_connections.txt
```

---

## STEP 2 — Statistical Beacon Analysis: Inter-Arrival Time

**Objective:** Mathematically confirm the beaconing pattern using inter-arrival
time (IAT) analysis. A true beacon has very low coefficient of variation (CV)
— human traffic has CV > 1.0, beacons typically have CV < 0.1.

```python
# Save as: beacon_analyzer.py
import json
import numpy  as np
from   scipy  import stats
import matplotlib
matplotlib.use("Agg")          # headless — no GUI needed
import matplotlib.pyplot as plt
from   collections import defaultdict
from   datetime    import datetime

print("=" * 60)
print("  Beacon Frequency Analyzer — Blaakpearl Day 04")
print("=" * 60)

# Load DNS log entries
with open("artifacts/zeek_logs/dns_entries.json") as f:
    entries = json.load(f)

# Group by (source_ip, queried_domain)
streams = defaultdict(list)
for e in entries:
    key = (e["id.orig_h"], e["query"].split(".")[-3] + "." +
           e["query"].split(".")[-2] + "." +
           e["query"].split(".")[-1]
           if len(e["query"].split(".")) > 2 else e["query"])
    streams[key].append(float(e["ts"]))

print(f"\n[*] Analysing {len(streams)} unique (host, domain) streams...\n")

results = []

for (src_ip, domain), timestamps in streams.items():
    if len(timestamps) < 10:   # Need enough samples for stats
        continue

    timestamps_sorted = sorted(timestamps)

    # Inter-arrival times (IAT)
    iats = np.diff(timestamps_sorted)

    if len(iats) < 5:
        continue

    mean_iat  = np.mean(iats)
    std_iat   = np.std(iats)
    cv        = std_iat / mean_iat if mean_iat > 0 else 999
    median    = np.median(iats)
    skewness  = stats.skew(iats)
    count     = len(timestamps)

    # Beacon score — lower CV = more regular = more suspicious
    # Also factor in high query count
    if cv < 0.05:
        beacon_confidence = "CRITICAL — almost certainly automated beacon"
        score = 99
    elif cv < 0.15:
        beacon_confidence = "HIGH — very regular timing, likely beacon"
        score = 85
    elif cv < 0.30:
        beacon_confidence = "MEDIUM — regular timing, investigate"
        score = 60
    elif cv < 0.50:
        beacon_confidence = "LOW — slightly regular, monitor"
        score = 30
    else:
        beacon_confidence = "CLEAN — normal human traffic variation"
        score = 5

    result = {
        "source_ip":          src_ip,
        "domain":             domain,
        "query_count":        count,
        "mean_interval_sec":  round(float(mean_iat), 3),
        "std_dev_sec":        round(float(std_iat), 4),
        "coeff_variation":    round(float(cv), 4),
        "median_sec":         round(float(median), 3),
        "skewness":           round(float(skewness), 3),
        "beacon_score":       score,
        "beacon_confidence":  beacon_confidence,
        "first_seen":         datetime.utcfromtimestamp(timestamps_sorted[0]).isoformat(),
        "last_seen":          datetime.utcfromtimestamp(timestamps_sorted[-1]).isoformat(),
    }
    results.append(result)

# Sort by beacon score descending
results.sort(key=lambda x: x["beacon_score"], reverse=True)

# Print results table
print(f"{'Domain':<35} {'IP':<15} {'Count':>6} {'Interval':>10} {'CV':>8} {'Score':>6}")
print("-" * 85)
for r in results[:15]:
    flag = " ← ⚠️ BEACON" if r["beacon_score"] >= 85 else ""
    print(f"{r['domain'][:34]:<35} {r['source_ip']:<15} "
          f"{r['query_count']:>6} {r['mean_interval_sec']:>9.1f}s "
          f"{r['coeff_variation']:>8.4f} {r['beacon_score']:>6}{flag}")

# Detailed report for top hit
if results:
    top = results[0]
    print(f"\n{'='*60}")
    print(f"  TOP BEACON FINDING")
    print(f"{'='*60}")
    for k, v in top.items():
        print(f"  {k:<25}: {v}")

# Save results
import json as js
with open("artifacts/beacon_analysis_results.json", "w") as f:
    js.dump(results, f, indent=2)

# --- Plot IAT distribution for top beacon ---
if results:
    top_domain   = results[0]["domain"]
    top_src      = results[0]["source_ip"]
    top_ts       = sorted([float(e["ts"]) for e in entries
                           if top_domain in e["query"]
                           and e["id.orig_h"] == top_src])
    top_iats     = np.diff(top_ts)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    fig.suptitle(f"Beacon IAT Analysis — {top_domain}", fontsize=12, color="white")
    fig.patch.set_facecolor("#0a0d12")

    for ax in axes:
        ax.set_facecolor("#0f1318")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("#00d4ff")
        for spine in ax.spines.values():
            spine.set_edgecolor("#1e2733")

    # Histogram
    axes[0].hist(top_iats, bins=40, color="#00d4ff", alpha=0.8, edgecolor="#0a0d12")
    axes[0].axvline(np.mean(top_iats), color="#ff4757", linestyle="--",
                    linewidth=2, label=f"Mean: {np.mean(top_iats):.1f}s")
    axes[0].set_title("IAT Distribution (narrow = beacon)")
    axes[0].set_xlabel("Inter-Arrival Time (seconds)")
    axes[0].set_ylabel("Frequency")
    axes[0].legend(labelcolor="white", facecolor="#0f1318")

    # Time series
    times_rel = [(t - top_ts[0]) / 60 for t in top_ts[:200]]
    axes[1].scatter(times_rel, range(len(times_rel)),
                    s=3, color="#00ff88", alpha=0.6)
    axes[1].set_title("Beacon Timeline (first 200 events)")
    axes[1].set_xlabel("Minutes from first beacon")
    axes[1].set_ylabel("Query sequence number")

    plt.tight_layout()
    plt.savefig("artifacts/beacon_iat_plot.png", dpi=150,
                bbox_inches="tight", facecolor="#0a0d12")
    print(f"\n[+] IAT plot saved: artifacts/beacon_iat_plot.png")

print(f"\n[+] Full results: artifacts/beacon_analysis_results.json")
```

```bash
python3 beacon_analyzer.py | tee artifacts/beacon_analysis_summary.txt
```

**Expected Output:**
```
Domain                              IP              Count   Interval       CV  Score
---------------------------------------------------------------------
updates.cdn-telemetry-svc.net    10.10.5.47       500      60.3s    0.0018    99 ← ⚠️ BEACON
windows-update.microsoft.com     10.10.5.47        43     847.2s    1.2340     5
ocsp.digicert.com                10.10.5.47        38     567.1s    0.9821     5

TOP BEACON FINDING:
  source_ip                : 10.10.5.47
  domain                   : updates.cdn-telemetry-svc.net
  query_count              : 500
  mean_interval_sec        : 60.3
  coeff_variation          : 0.0018   ← near-zero = machine generated
  beacon_score             : 99
  beacon_confidence        : CRITICAL — almost certainly automated beacon
```

**✅ Checkpoint 2:** A CV of < 0.05 is your mathematical proof of automation.
Human users cannot generate network traffic with this level of timing regularity.
This is your primary finding — document the exact interval and CV value.

---

## STEP 3 — DNS Tunnel Detection: Query Entropy Analysis

**Objective:** Detect DNS tunneling by identifying abnormally long subdomain labels
and high-entropy query strings — the signature of data encoded into DNS queries.

```python
# Save as: dns_tunnel_detector.py
import json
import math
import re
from collections import Counter

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely encoded data."""
    if not s:
        return 0.0
    freq = Counter(s.lower())
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())

def is_base64_like(s: str) -> bool:
    """Check if string looks like base64 encoded data."""
    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not s:
        return False
    ratio = sum(1 for c in s if c in b64_chars) / len(s)
    return ratio > 0.90 and len(s) > 20

def analyze_dns_for_tunneling(entries: list) -> list:
    """Score each DNS query for tunneling indicators."""
    results = []

    for e in entries:
        query   = e.get("query", "")
        qtype   = e.get("qtype_name", "A")
        labels  = query.split(".")

        # Longest label (normal DNS labels are short English words)
        max_label_len   = max((len(l) for l in labels), default=0)
        total_len       = len(query)

        # Entropy of longest label
        longest_label   = max(labels, key=len, default="")
        entropy         = shannon_entropy(longest_label)

        # Scoring
        score     = 0
        flags     = []

        if max_label_len > 50:
            score += 40
            flags.append(f"LONG_LABEL:{max_label_len}chars")
        elif max_label_len > 30:
            score += 20
            flags.append(f"MEDIUM_LABEL:{max_label_len}chars")

        if total_len > 100:
            score += 20
            flags.append(f"LONG_QUERY:{total_len}chars")

        if entropy > 4.0:
            score += 30
            flags.append(f"HIGH_ENTROPY:{entropy:.2f}")

        if qtype == "TXT":
            score += 15
            flags.append("TXT_RECORD")

        if qtype in ("NULL", "PRIVATE"):
            score += 25
            flags.append(f"UNUSUAL_TYPE:{qtype}")

        if is_base64_like(longest_label):
            score += 25
            flags.append("BASE64_PATTERN")

        if len(labels) > 5:
            score += 10
            flags.append(f"DEEP_LABELS:{len(labels)}")

        if score >= 30:
            results.append({
                "query":          query,
                "qtype":          qtype,
                "tunnel_score":   min(score, 100),
                "max_label_len":  max_label_len,
                "total_len":      total_len,
                "entropy":        round(entropy, 3),
                "flags":          flags,
                "ts":             e.get("ts")
            })

    return sorted(results, key=lambda x: x["tunnel_score"], reverse=True)

# --- Run analysis ---
with open("artifacts/zeek_logs/dns_entries.json") as f:
    entries = json.load(f)

print("=" * 60)
print("  DNS Tunnel Detector — Blaakpearl Day 04")
print("=" * 60)

tunnel_hits = analyze_dns_for_tunneling(entries)

print(f"\n[*] Total queries analyzed:   {len(entries)}")
print(f"[*] Tunnel-suspicious queries: {len(tunnel_hits)}")
print(f"[*] High-confidence (>= 70):   {sum(1 for h in tunnel_hits if h['tunnel_score'] >= 70)}")

print(f"\n{'Score':>6} {'Type':>5} {'Len':>5} {'Entropy':>8}  Query")
print("-" * 70)
for hit in tunnel_hits[:15]:
    trunc = hit["query"][:45] + "..." if len(hit["query"]) > 45 else hit["query"]
    print(f"{hit['tunnel_score']:>6} {hit['qtype']:>5} "
          f"{hit['total_len']:>5} {hit['entropy']:>8.3f}  {trunc}")
    if hit["flags"]:
        print(f"{'':>6}   Flags: {', '.join(hit['flags'])}")

# Save results
with open("artifacts/dns_tunnel_analysis.json", "w") as f:
    json.dump(tunnel_hits, f, indent=2)

# Summary
txt_count   = sum(1 for e in entries if e.get("qtype_name") == "TXT")
txt_ratio   = txt_count / len(entries) * 100 if entries else 0
print(f"\n[+] TXT query ratio: {txt_ratio:.1f}% "
      f"({'ANOMALOUS > 5%' if txt_ratio > 5 else 'Normal < 2%'})")
print(f"[+] Results saved: artifacts/dns_tunnel_analysis.json")
```

```bash
python3 dns_tunnel_detector.py | tee artifacts/dns_tunnel_summary.txt
```

**✅ Checkpoint 3:** Any query with entropy > 4.0 on a subdomain label
AND a TXT record type is near-certain DNS tunnel traffic. Document the
specific queries and their entropy values — these are your exfiltration evidence.

---

## STEP 4 — JA3 TLS Fingerprinting

**Objective:** Extract JA3 hashes from TLS connections to identify the malware
family by its TLS client hello "fingerprint" — often more reliable than domain
or IP indicators which change frequently.

```bash
# Install zeek-ja3 if using real PCAP
# zeek -r $PCAP /path/to/ja3.zeek

# If using tshark against a PCAP:
echo "[*] Extracting JA3 fingerprints from PCAP..."
tshark -r $PCAP \
  -Y "ssl.handshake.type == 1" \
  -T fields \
  -e ip.src \
  -e ip.dst \
  -e ssl.handshake.ciphersuite \
  -e ssl.handshake.extension.type \
  -e ssl.handshake.extensions_server_name \
  2>/dev/null \
  | head -20 \
  | tee artifacts/tls_client_hellos.txt

echo ""
echo "[*] Checking JA3 hashes against threat intel..."

# Check known malicious JA3 hashes
# Common C2 framework JA3 hashes for reference:
cat > artifacts/known_malicious_ja3.txt << 'EOF'
# Known malicious JA3 hashes — reference list
# Source: tls.fingerprint.io, sslbl.abuse.ch

# Cobalt Strike default
72a589da586844d7f0818ce684948eea    Cobalt Strike Beacon (default)
a0e9f5d64349fb13191bc781f81f42e1    Cobalt Strike Beacon (malleable)

# Metasploit
d187cce734d8b1c5c4c6e1a72a09f6c4    Metasploit Meterpreter

# Generic malware / RATs
b386946a5a44d1ddcc843bc75336dfce    Agent Tesla
f60e0b94e1df1e8b9d0c82e9e88d5b98    NanoCore RAT
051af5a959ad46a33a904c1f0cbb6e85    Emotet variant

# DNS C2 tools (DNScat2, iodine)
# JA3 varies by tool version — check hash against sslbl.abuse.ch
EOF

echo "[+] JA3 reference saved: artifacts/known_malicious_ja3.txt"
```

### Python JA3 Hash Lookup

```python
# Save as: ja3_lookup.py
# Check extracted JA3 hashes against SSLBL abuse.ch database

import requests
import json
import time

def lookup_ja3(ja3_hash: str) -> dict:
    """Query abuse.ch SSLBL for JA3 hash reputation."""
    url = "https://sslbl.abuse.ch/api/v1/"
    payload = {"query": "get_info", "sha1": ja3_hash}
    try:
        r = requests.post(url, data=payload, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# JA3 hashes extracted from your PCAP (replace with real values)
EXTRACTED_HASHES = [
    "72a589da586844d7f0818ce684948eea",   # Example — Cobalt Strike default
    "a0e9f5d64349fb13191bc781f81f42e1",   # Example — CS malleable
]

print("[*] JA3 Hash Threat Intelligence Lookup")
print("=" * 50)

for hash_val in EXTRACTED_HASHES:
    print(f"\n[*] Checking: {hash_val}")
    result = lookup_ja3(hash_val)

    if result.get("query_status") == "ok":
        info = result.get("signature", {})
        print(f"  [!!!] MALICIOUS JA3 HASH IDENTIFIED")
        print(f"  Malware:    {info.get('malware', 'Unknown')}")
        print(f"  Confidence: {info.get('confidence', 'N/A')}")
        print(f"  First Seen: {info.get('firstseen', 'N/A')}")
    elif result.get("query_status") == "no_results":
        print(f"  [+] Not in SSLBL database (novel or clean)")
    else:
        print(f"  [!] Query result: {result}")

    time.sleep(1)
```

```bash
python3 ja3_lookup.py | tee artifacts/ja3_lookup_results.txt
```

---

## STEP 5 — Sigma Rules: Beacon & DNS Tunnel Detection

```bash
# Sigma Rule 1: C2 Beaconing — Periodic DNS Query
cat > artifacts/sigma_c2_beacon_dns.yml << 'SIGEOF'
title: C2 Beacon — Highly Regular DNS Query Pattern
id: b7e4f921-3c8d-4a2e-9f15-6b7e3d8c0a41
status: experimental
description: |
    Detects C2 beaconing via DNS — identified by a single internal host
    querying the same external domain at highly regular intervals.
    Statistical analysis of inter-arrival times (IAT) shows coefficient
    of variation < 0.05, indicating machine-generated timing.
    
    Threshold tuning: adjust query_count based on your environment baseline.
    A legitimate host should not query one external domain > 100 times/hour.

author: Blaakpearl
date: 2025/01/16

references:
    - https://attack.mitre.org/techniques/T1071/004/
    - https://github.com/activecm/rita

tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.t1573
    - attack.t1008

logsource:
    category: dns
    product: zeek

detection:
    # High-frequency repeated queries to same domain
    high_frequency:
        query|contains:
            - '.net'
            - '.com'
            - '.org'
        qtype_name: 'A'

    # Exclude known legitimate high-frequency domains
    filter_legitimate:
        query|contains:
            - 'windowsupdate.microsoft.com'
            - 'ocsp.digicert.com'
            - 'ctldl.windowsupdate.com'
            - 'www.google.com'
            - 'clients1.google.com'
            - 'update.googleapis.com'

    timeframe: 1h
    condition: |
        high_frequency
        and not filter_legitimate
        | stats count() as query_count, dc(id.orig_h) as unique_sources
          by query, id.orig_h
        | where query_count > 100 and unique_sources == 1

falsepositives:
    - Misconfigured software with rapid polling (check application)
    - Time synchronization services (NTP over DNS)
    - Legitimate CDN health check clients

level: high

fields:
    - id.orig_h
    - query
    - qtype_name
    - answers

response:
    - Capture full PCAP from affected host for 30 min
    - Run IAT statistical analysis (beacon_analyzer.py)
    - Check host for persistence mechanisms
    - Isolate host from network pending investigation
SIGEOF

# Sigma Rule 2: DNS Tunneling — Entropy-Based Detection
cat > artifacts/sigma_dns_tunneling.yml << 'SIGEOF'
title: DNS Tunneling — High Entropy Subdomain Labels
id: c9d2e843-4f1a-5b3c-8e26-7c8f4e9d1b52
status: experimental
description: |
    Detects DNS tunneling by identifying queries with abnormally long or
    high-entropy subdomain labels — characteristic of data encoded into
    DNS query strings (Base64, hex, or custom encoding).
    
    DNS tunneling tools (dnscat2, iodine, DNSExfiltrator) encode data
    as subdomains of attacker-controlled domains. Legitimate DNS queries
    use short, human-readable labels. Entropy > 4.0 on a label > 30 chars
    is highly anomalous.

author: Blaakpearl
date: 2025/01/16

tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.exfiltration
    - attack.t1048.001
    - attack.t1132.001

logsource:
    category: dns
    product: zeek

detection:
    # TXT queries from internal hosts to external domains
    txt_exfil:
        qtype_name: 'TXT'
        id.orig_h|cidr: '10.0.0.0/8'
        id.resp_h|not_cidr:
            - '10.0.0.0/8'
            - '192.168.0.0/16'

    # Long query string (> 100 chars total)
    long_query:
        query|re: '.{100,}'

    # Exclude known legitimate TXT queries
    filter_legit_txt:
        query|endswith:
            - '_domainkey.google.com'
            - '_acme-challenge.'
            - 'spf.protection.outlook.com'

    condition: (txt_exfil or long_query) and not filter_legit_txt

falsepositives:
    - ACME certificate validation (Let's Encrypt DNS challenges)
    - SPF/DKIM record lookups during email processing
    - Legitimate TXT-based service discovery

level: high

response:
    - Capture all DNS TXT responses for the source host
    - Decode subdomain labels (base64 -d or xxd) to inspect payload
    - Determine volume of data exfiltrated (payload size × query count)
    - Check C2 domain registration date and reputation
SIGEOF

echo "[+] Sigma rules saved:"
echo "    artifacts/sigma_c2_beacon_dns.yml"
echo "    artifacts/sigma_dns_tunneling.yml"
```

---

## STEP 6 — Network Forensics Timeline

```bash
cat > artifacts/network_forensics_timeline.md << 'EOF'
# Network Forensics Timeline — DESKTOP-FIN-047
**Analyst:** Blaakpearl | **Date:** 2025-01-16 | **Case:** NVC-IR-2025-004

---

## Host Information
- **Hostname:** DESKTOP-FIN-047
- **IP:** 10.10.5.47
- **User:** Senior Analyst, Fixed Income Trading
- **OS:** Windows 11 22H2

---

## Event Timeline

| Timestamp (UTC) | Event | Source | Significance |
|----------------|-------|--------|--------------|
| `2025-01-05 23:44:12` | **First beacon** — DNS query to `updates.cdn-telemetry-svc.net` | Zeek dns.log | 🔴 Critical — same day phishing infra registered |
| `2025-01-05 23:44:12` | Beacon interval established: 60.3s ± 0.1s (CV=0.0018) | IAT analysis | 🔴 Critical — machine-precision timing |
| `2025-01-06 ~08:00` | User logs in — trading session begins | Auth logs | 🟡 Medium — user unaware of compromise |
| `2025-01-06 14:23:31` | First DNS TXT query — encoded subdomain (Base64 pattern) | Zeek dns.log | 🔴 Critical — data exfiltration begins |
| `2025-01-10 ~17:00` | DNS TXT query volume increases — 1 per 5 beacons → 1 per 3 | Traffic analysis | 🟠 High — exfil rate escalating |
| `2025-01-14 09:15:44` | C2 fallback channel attempt — ICMP echo to 185.220.101.33 | Zeek conn.log | 🟠 High — secondary C2 (T1008) |
| `2025-01-16 02:17:00` | **EDR alert fires** — DNS anomaly detection (low confidence) | EDR platform | 🟡 Medium — 11-day detection gap |
| `2025-01-16 02:19:00` | Analyst begins hunt — pulls DNS logs for DESKTOP-FIN-047 | Manual review | 🟢 Low — detection begins |
| `2025-01-16 02:47:00` | Beacon confirmed via IAT analysis (CV=0.0018, score=99/100) | beacon_analyzer.py | 🔴 Critical — confirmed C2 |
| `2025-01-16 03:12:00` | DNS tunnel confirmed — 100 TXT exfil queries identified | dns_tunnel_detector.py | 🔴 Critical — data exfiltration confirmed |
| `2025-01-16 03:30:00` | Host isolated from network — IR process initiated | Network team | 🟢 Low — containment action |

---

## Summary Statistics
- **Total beacons:** ~15,800 over 11 days
- **Estimated exfil queries:** ~3,160 TXT records
- **Estimated data exfiltrated:** ~126KB (40 bytes/query × 3,160 queries)
- **Dwell time before detection:** 11 days
- **Detection source:** Proactive overnight threat hunt (not automated alert)

---

## Key Finding
The initial low-confidence EDR alert would have aged out unreviewed under normal
triage volume. Only active threat hunting identified and confirmed the compromise.
This demonstrates the critical value of scheduled hunting beyond alert-queue processing.
EOF

echo "[+] Timeline saved: artifacts/network_forensics_timeline.md"
echo ""
echo "=== Final Artifact Summary ==="
ls -lah artifacts/
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What is the coefficient of variation (CV) for the beacon, and what does it prove?
- [ ] 🚩 **Flag 2:** What percentage of DNS queries were TXT type, and why is this suspicious?
- [ ] 🚩 **Flag 3:** What Shannon entropy threshold distinguishes encoded tunnel data from normal DNS labels?
- [ ] 🚩 **Flag 4:** What MITRE technique ID covers data exfiltration over DNS?
- [ ] 🚩 **Flag 5:** How many days did the attacker dwell undetected, and what finally found them?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `zeek_logs/dns.log` | Synthetic or real Zeek DNS log |
| `zeek_logs/dns_entries.json` | Parsed DNS entries for Python analysis |
| `top_dns_queries.txt` | Top queried domains by frequency |
| `dns_type_distribution.txt` | DNS query type breakdown |
| `external_connections.txt` | Unique external IP connections |
| `long_connections.txt` | Long-duration connection list |
| `beacon_analysis_results.json` | Full IAT statistical analysis output |
| `beacon_analysis_summary.txt` | Console output from beacon_analyzer.py |
| `beacon_iat_plot.png` | IAT distribution and timeline chart |
| `dns_tunnel_analysis.json` | DNS tunnel entropy scoring results |
| `dns_tunnel_summary.txt` | Console output from dns_tunnel_detector.py |
| `tls_client_hellos.txt` | Extracted TLS client hello fields |
| `known_malicious_ja3.txt` | JA3 hash reference list |
| `ja3_lookup_results.txt` | Abuse.ch SSLBL lookup results |
| `sigma_c2_beacon_dns.yml` | Sigma rule — DNS beacon detection |
| `sigma_dns_tunneling.yml` | Sigma rule — DNS tunnel detection |
| `network_forensics_timeline.md` | Full 5-event forensic timeline |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| `zeek: command not found` | `sudo apt install zeek` or `sudo apt install bro` on older systems |
| `tshark` requires sudo | `sudo dpkg-reconfigure wireshark-common` → select "Yes" for non-root capture |
| `scipy` not found | `pip install scipy numpy matplotlib --break-system-packages` |
| Matplotlib display error | Add `matplotlib.use("Agg")` before other matplotlib imports (headless mode) |
| PCAP file too large | Use `tcpdump -r big.pcap -w small.pcap -c 10000` to sample first 10k packets |

---

*Next: [REPORT.md](REPORT.md) — Professional network threat hunt report*
