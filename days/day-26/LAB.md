# Day 26 — LAB.md
## Threat Actor Profiling Lab Guide
**NovaCrest Capital Group | Threat Intelligence Track**

---

## Part 1: OpenCTI Setup

```bash
# Deploy OpenCTI via Docker Compose (self-hosted)
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker

# Configure environment
cp .env.sample .env
# Edit .env: set OPENCTI_ADMIN_EMAIL, OPENCTI_ADMIN_PASSWORD, API keys

# Launch stack (OpenCTI + ElasticSearch + MinIO + RabbitMQ)
docker-compose up -d

# Verify all services healthy
docker-compose ps
# Access UI: http://localhost:8080

# Install connectors for threat intelligence feeds
# Connector: MITRE ATT&CK
docker run -d opencti/connector-mitre:latest \
    -e OPENCTI_URL=http://localhost:8080 \
    -e OPENCTI_TOKEN=$OPENCTI_TOKEN \
    -e CONNECTOR_ID=$(uuidgen) \
    -e CONNECTOR_TYPE=EXTERNAL_IMPORT \
    -e CONNECTOR_NAME="MITRE ATT&CK"

# Connector: CISA Known Exploited Vulnerabilities
docker run -d opencti/connector-cisa-known-exploited-vulnerabilities:latest \
    -e OPENCTI_URL=http://localhost:8080 \
    -e OPENCTI_TOKEN=$OPENCTI_TOKEN

# Connector: Ransomwatch (public ransomware group monitoring)
# Manual import — see Part 4 below
```

---

## Part 2: IOC Pivoting

### Step 1 — C2 IP Pivot (198.51.100.99)

```bash
# VirusTotal API — IP reputation and related IOCs
VT_KEY="your_vt_api_key"
curl -s "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99" \
    -H "x-apikey: $VT_KEY" | python3 -m json.tool

# Key fields to extract:
#   last_analysis_stats.malicious  → detection count
#   last_modification_date         → last activity
#   network                        → ASN / hosting provider
#   country                        → registration country
#   whois                          → registrant info

# Pivot: find domains/URLs hosted on this IP
curl -s "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99/urls" \
    -H "x-apikey: $VT_KEY" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    attrs = item.get('attributes', {})
    print(attrs.get('url'), '|', attrs.get('last_analysis_stats', {}).get('malicious'))
"

# AlienVault OTX — community threat intelligence
curl -s "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.99/general" \
    -H "X-OTX-API-KEY: $OTX_KEY" | python3 -m json.tool

# Shodan — infrastructure fingerprinting
curl -s "https://api.shodan.io/shodan/host/198.51.100.99?key=$SHODAN_KEY" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Hostnames:', d.get('hostnames'))
print('Ports:', d.get('ports'))
print('OS:', d.get('os'))
print('ISP:', d.get('isp'))
for s in d.get('data', []):
    print('  Port:', s.get('port'), '| Banner:', str(s.get('data',''))[:80])
"
```

### Step 2 — Ransomware Hash Pivot

```bash
# VirusTotal — binary analysis
HASH="a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3"
curl -s "https://www.virustotal.com/api/v3/files/$HASH" \
    -H "x-apikey: $VT_KEY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
a = d.get('data', {}).get('attributes', {})
print('Name:', a.get('meaningful_name'))
print('Type:', a.get('type_description'))
print('Size:', a.get('size'))
print('Detections:', a.get('last_analysis_stats', {}).get('malicious'))
print('Families:', a.get('popular_threat_classification', {}).get('suggested_threat_label'))
print('Compile time:', a.get('pe_info', {}).get('timestamp'))
# Sandbox behavior
for name, result in a.get('sandbox_verdicts', {}).items():
    print(f'  Sandbox [{name}]:', result.get('category'))
"

# MalwareBazaar — community malware repository
curl -s "https://mb-api.abuse.ch/api/v1/" \
    -d "query=get_info&hash=$HASH" \
    | python3 -m json.tool
```

### Step 3 — Ransom Note Email Pivot

```bash
# Search for ncrypt-support@protonmail.com in threat intel
# Sources: IntelX, Hunter.io, public breach databases

# IntelligenceX (commercial)
curl -s "https://2.intelx.io/intelligent/search" \
    -H "x-key: $IX_KEY" \
    -H "Content-Type: application/json" \
    -d '{"term": "ncrypt-support@protonmail.com", "maxresults": 20}'

# Search RansomWatch for known group using this email
python3 scripts/actor_profiler.py --mode email-pivot \
    --email "ncrypt-support@protonmail.com" --demo
```

### Step 4 — Onion Site Monitoring

```bash
# Ransomwatch — tracks ransomware group leak sites
git clone https://github.com/joshhighet/ransomwatch
cd ransomwatch

# Check if ncrypt3k4j7mxbwz.onion is tracked
grep -r "ncrypt" posts.json | head -20

# DarkOwl / Recorded Future dark web monitoring (commercial)
# These index .onion content for threat intelligence

# Manual check via Tor (lab only — use isolated VM)
# torsocks curl http://ncrypt3k4j7mxbwz.onion/novacrest
# WARNING: Only in air-gapped lab environment
```

---

## Part 3: STIX 2.1 Authoring

```bash
# Install python-stix2 library
pip install stix2 --break-system-packages

# Basic STIX 2.1 object creation
python3 - << 'EOF'
from stix2 import ThreatActor, Malware, Indicator, Relationship, Bundle

# Create threat actor
actor = ThreatActor(
    name="FIN-NC-001",
    description="Financially motivated threat actor targeting financial services",
    threat_actor_types=["crime-syndicate"],
    sophistication="advanced",
    resource_level="organization",
    primary_motivation="financial-gain",
    aliases=["ncrypt group"],
    labels=["ransomware", "double-extortion", "financial-sector"]
)

# Create malware
malware = Malware(
    name="ncrypt ransomware",
    malware_types=["ransomware"],
    is_family=False,
    description="LockBit 3.0 builder variant; .ncrypt extension; double-extortion",
    aliases=["Ransom.ncrypt", "LockBit-ncrypt"]
)

# Create relationship
rel = Relationship(
    relationship_type="uses",
    source_ref=actor.id,
    target_ref=malware.id
)

# Bundle
bundle = Bundle(actor, malware, rel)
print(bundle.serialize(pretty=True))
EOF

# Run the full STIX builder script
python3 scripts/stix_builder.py --demo --output artifacts/fin_nc_001_stix_bundle.json
```

---

## Part 4: TAXII Feed Integration

```bash
# TAXII 2.1 — threat intel sharing protocol
pip install taxii2-client --break-system-packages

python3 - << 'EOF'
from taxii2client.v21 import Server, Collection
import json

# Connect to CISA AIS TAXII server (Automated Indicator Sharing)
# Registration required: https://www.cisa.gov/ais
server = Server(
    "https://ais2.cisa.dhs.gov/taxii2/",
    user="your_ais_username",
    password="your_ais_password"
)

# List available collections
for api_root in server.api_roots:
    print("API Root:", api_root.url)
    for collection in api_root.collections:
        print(f"  Collection: {collection.title} [{collection.id}]")

# Pull indicators from FS-ISAC TAXII feed (financial sector)
fsisac_collection = Collection(
    "https://taxii.fs-isac.com/taxii2/collections/cyber-threat-intel/",
    user="member_username", password="member_password"
)

# Fetch STIX objects added in last 7 days
from datetime import datetime, timedelta
objects = fsisac_collection.get_objects(
    added_after=datetime.utcnow() - timedelta(days=7)
)

# Filter for ransomware IOCs
for obj in objects.get("objects", []):
    if obj.get("type") == "indicator":
        pattern = obj.get("pattern", "")
        if "ransomware" in str(obj.get("labels", [])):
            print(f"IOC: {pattern}")
EOF

# Run the automated IOC pivot script
python3 scripts/actor_profiler.py --demo --mode full-profile --verbose
```

---

## Part 5: OpenCTI Import

```bash
# Import STIX bundle into OpenCTI via API
OPENCTI_TOKEN="your_opencti_token"
OPENCTI_URL="http://localhost:8080"

curl -s -X POST "$OPENCTI_URL/graphql" \
    -H "Authorization: Bearer $OPENCTI_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"query\": \"mutation { stixObjectsImport(file: \\\"$(base64 -w0 artifacts/fin_nc_001_stix_bundle.json)\\\") { id } }\"
    }"

# Verify import in OpenCTI UI:
#   → Threats → Threat Actors → FIN-NC-001
#   → Shows relationships to malware, indicators, attack patterns
#   → ATT&CK technique overlay visible in Diamond Model view
```

---

*Day 26 Lab Guide | Threat Actor Profiling*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
