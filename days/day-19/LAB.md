# Day 19 — LAB.md
## Log Forensics & SIEM Lab Setup
**NovaCrest Capital Group | Digital Forensics Track**

---

## Overview

This lab ingests multi-source forensic log evidence into Elastic SIEM via
Plaso/log2timeline, normalizes timestamps across sources, detects log
tampering, and builds an attack timeline dashboard. All steps are documented
for evidence integrity and chain of custody.

---

## Step 1: Install Plaso (log2timeline)

```bash
# Ubuntu 22.04 — recommended for Plaso
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv

# Create isolated environment
python3 -m venv ~/plaso-env
source ~/plaso-env/bin/activate

# Install Plaso via pip
pip install plaso

# Verify
log2timeline.py --version
psort.py --version
pinfo.py --version
```

---

## Step 2: Acquire and Verify Evidence

```bash
# Create working evidence directory with proper permissions
sudo mkdir -p /forensics/case-NCA-2026-06/{raw,processed,exports}
sudo chown $USER:$USER -R /forensics/case-NCA-2026-06/

# Copy evidence files (already imaged by IR team)
# EVTX files from WS-FIN-04
cp /media/evidence/WS-FIN-04/Security.evtx     /forensics/case-NCA-2026-06/raw/
cp /media/evidence/WS-FIN-04/System.evtx        /forensics/case-NCA-2026-06/raw/
cp /media/evidence/WS-FIN-04/Sysmon.evtx        /forensics/case-NCA-2026-06/raw/
cp /media/evidence/WS-FIN-04/PowerShell.evtx    /forensics/case-NCA-2026-06/raw/

# Linux logs from lnx-trade-01
cp /media/evidence/lnx-trade-01/audit.log       /forensics/case-NCA-2026-06/raw/
cp /media/evidence/lnx-trade-01/auth.log        /forensics/case-NCA-2026-06/raw/
cp /media/evidence/lnx-trade-01/syslog          /forensics/case-NCA-2026-06/raw/

# Network logs
cp /media/evidence/zeek/conn.log                /forensics/case-NCA-2026-06/raw/
cp /media/evidence/zeek/dns.log                 /forensics/case-NCA-2026-06/raw/
cp /media/evidence/zeek/ssl.log                 /forensics/case-NCA-2026-06/raw/

# Generate evidence hashes (integrity baseline)
cd /forensics/case-NCA-2026-06/raw/
sha256sum * > /forensics/case-NCA-2026-06/evidence_hashes_SHA256.txt
md5sum    * > /forensics/case-NCA-2026-06/evidence_hashes_MD5.txt
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Evidence hashed by: $USER" \
    >> /forensics/case-NCA-2026-06/chain_of_custody.log
```

---

## Step 3: Run log2timeline (Plaso)

```bash
source ~/plaso-env/bin/activate

# Process Windows EVTX files
log2timeline.py \
    --parsers winevt,winevtx \
    --timezone UTC \
    /forensics/case-NCA-2026-06/processed/WS-FIN-04.plaso \
    /forensics/case-NCA-2026-06/raw/Security.evtx \
    /forensics/case-NCA-2026-06/raw/System.evtx \
    /forensics/case-NCA-2026-06/raw/Sysmon.evtx \
    /forensics/case-NCA-2026-06/raw/PowerShell.evtx

# Process Linux logs
log2timeline.py \
    --parsers linux_utmp,syslog,selinux,auditd \
    --timezone UTC \
    /forensics/case-NCA-2026-06/processed/lnx-trade-01.plaso \
    /forensics/case-NCA-2026-06/raw/auth.log \
    /forensics/case-NCA-2026-06/raw/audit.log \
    /forensics/case-NCA-2026-06/raw/syslog

# Sort and filter to incident window — output L2T CSV
psort.py \
    --output-format l2tcsv \
    --output /forensics/case-NCA-2026-06/exports/timeline.csv \
    --filter "date > '2026-06-14 07:00:00' AND date < '2026-06-19 00:00:00'" \
    /forensics/case-NCA-2026-06/processed/WS-FIN-04.plaso \
    /forensics/case-NCA-2026-06/processed/lnx-trade-01.plaso

echo "Timeline entries: $(wc -l < /forensics/case-NCA-2026-06/exports/timeline.csv)"

# Also export as JSON for Elastic ingestion
psort.py \
    --output-format elastic \
    --server localhost \
    --port 9200 \
    --index forensic-timeline-nca-2026 \
    /forensics/case-NCA-2026-06/processed/*.plaso
```

---

## Step 4: Install and Configure Elastic SIEM

```bash
# Install Elasticsearch + Kibana (Docker — quickest for lab)
docker network create elastic

docker run -d --name elasticsearch \
    --network elastic \
    -p 9200:9200 \
    -e "discovery.type=single-node" \
    -e "xpack.security.enabled=false" \
    docker.elastic.co/elasticsearch/elasticsearch:8.12.0

docker run -d --name kibana \
    --network elastic \
    -p 5601:5601 \
    -e "ELASTICSEARCH_HOSTS=http://elasticsearch:9200" \
    docker.elastic.co/kibana/kibana:8.12.0

# Verify
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
echo "Kibana available at http://localhost:5601"
```

---

## Step 5: Ingest Timeline into Elastic

```bash
# Install Filebeat
sudo apt-get install -y filebeat

# Configure Filebeat to ingest Plaso L2T CSV
cat > /etc/filebeat/filebeat.yml << 'EOF'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /forensics/case-NCA-2026-06/exports/timeline.csv
    fields:
      case_id: "NCA-2026-06"
      analyst: "V.Willis"
    fields_under_root: true
    multiline.pattern: '^[0-9]{2}/'  # L2T CSV starts with date
    multiline.negate: true
    multiline.match: after

output.elasticsearch:
  hosts: ["http://localhost:9200"]
  index: "forensic-timeline-nca-2026-%{+YYYY.MM.dd}"

setup.kibana:
  host: "http://localhost:5601"
EOF

sudo systemctl start filebeat
sudo filebeat setup --index-management
sudo filebeat setup --dashboards

# Verify ingestion
curl -s "http://localhost:9200/forensic-timeline-nca-2026-*/_count" | python3 -m json.tool
```

---

## Step 6: Build Elastic SIEM Timeline Dashboard

```
# In Kibana:
1. Stack Management → Index Patterns → Create: forensic-timeline-nca-2026-*
   Set time field: @timestamp

2. SIEM → Timelines → Create new timeline
   Name: "NCA-2026-06 Intrusion Timeline"
   Date range: 2026-06-14 08:00:00 UTC → 2026-06-18 18:00:00 UTC

3. Add columns:
   @timestamp | source_host | event_id | message | mitre_technique | severity

4. Add filters:
   source_host: WS-FIN-04 OR lnx-trade-01
   severity: high OR critical

5. Save timeline as evidence artifact:
   Export → JSON → /forensics/case-NCA-2026-06/exports/elastic_timeline.json

6. Visualize: Lens → Area chart
   X axis: @timestamp (1h buckets)
   Y axis: count()
   Split: mitre_technique
   → Attack density visualization across intrusion window
```

---

## Step 7: Run Timeline and Tampering Scripts

```bash
# Build normalized timeline from simulated log data (demo mode)
python3 scripts/timeline_builder.py --demo --output /tmp/timeline_output/

# Detect log tampering indicators
python3 scripts/log_tampering_detector.py --demo --verbose

# Run forensic SIEM queries
# Load elastic_timeline_queries.eql into Kibana → Security → Rules
# Load splunk_forensic_queries.spl into Splunk → Search
```

---

## Clock Skew Reconciliation Reference

```
Source              Raw Timezone    Offset to UTC    Normalized
WS-FIN-04 Events    EDT (UTC-4)     Add 4 hours      WS times + 04:00
NGFW-01 Proxy       UTC+1           Sub 1 hour       NGFW times - 01:00
NGFW-01 Firewall    UTC+1           Sub 1 hour       NGFW times - 01:00
lnx-trade-01        UTC             None             As-is
Zeek logs           UTC             None             As-is
AWS CloudTrail      UTC             None             As-is
```

---

*Day 19 Lab Guide | Log Forensics & SIEM*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
