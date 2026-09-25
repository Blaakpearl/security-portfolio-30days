# Day 28 — LAB.md
## OSINT Investigation Lab Guide
**NovaCrest Capital Group | OSINT Track**

---

## Phase 1: Maltego Infrastructure Mapping

```
MALTEGO TRANSFORM CHAIN — Starting from C2 IP 198.51.100.99:

1. Create Entity: IPv4Address → 198.51.100.99
2. Run Transforms:
   → "To Domains (Passive DNS)" [ShodanTransform]
      Returns: trading-updates.novacrest-secure.com
               updates-cdn.financialdata.net
               telemetry.marketsync.io
   → "To AS Number" [MaxMind]
      Returns: AS209588 (Flyservers S.A.)
   → "To Netblock" [ARIN/RIPE]
      Returns: 198.51.100.0/24 (full CIDR range)
   → "To SSL Certificate" [Censys]
      Returns: cert SHA1 fingerprint, CN, SAN entries

3. Pivot from AS209588:
   → "To IP Addresses (ASN)" [Shodan]
      Returns: Additional IPs in AS209588 used by same hosting cluster
              → 198.51.100.101 (second C2 candidate)
              → 198.51.100.103 (potential phishing infra)

4. Pivot from domains:
   → "To IP Addresses (DNS)" — current resolution
   → "To IP Addresses (Passive DNS)" — historical resolutions
   → "To MX Records" — mail infrastructure
   → "To SSL Certificates (Domain)" — cert history

5. Pivot from SSL certificates:
   → "To Domains (Certificate SAN)" — other domains on same cert
   → "To IP Addresses (Certificate)" — other IPs using same cert
```

```bash
# Maltego Community Edition command-line equivalent (maltego-trx)
pip install maltego-trx --break-system-packages

# Run IP-to-domain passive DNS lookup
python3 - << 'EOF'
from maltego_trx.entities import DNSName, IPAddress
# Simulated passive DNS pivot (replace with actual API calls)
ip = "198.51.100.99"
# API: https://api.virustotal.com/api/v3/ip_addresses/{ip}/resolutions
domains_from_ip = [
    "trading-updates.novacrest-secure.com",
    "updates-cdn.financialdata.net",
    "telemetry.marketsync.io",
    "secure-trading-api.financedocs.net",    # Historical (2026-03)
    "portfolio-sync.capitalupdates.org",      # Historical (2026-04)
]
for d in domains_from_ip:
    print(f"  Domain: {d}")
EOF
```

---

## Phase 2: SpiderFoot Automated OSINT

```bash
# Install SpiderFoot
pip install spiderfoot --break-system-packages

# Launch SpiderFoot web interface
spiderfoot -l 127.0.0.1:5001 &
# Access: http://127.0.0.1:5001

# SpiderFoot CLI — targeted scan on C2 IP
spiderfoot -s "198.51.100.99" \
    -m sfp_shodan,sfp_whois,sfp_dns,sfp_virustotal,sfp_censys,sfp_passivedns \
    -o /tmp/spiderfoot_c2_ip.json \
    --quiet

# SpiderFoot scan on phishing domain
spiderfoot -s "novacrest-secure.com" \
    -m sfp_whois,sfp_dns,sfp_ssl,sfp_censys,sfp_virustotal,sfp_waybackmachine \
    -o /tmp/spiderfoot_phish_domain.json \
    --quiet

# Key SpiderFoot modules for threat actor OSINT:
# sfp_shodan        — Shodan host data
# sfp_censys        — Certificate transparency
# sfp_passivedns    — Historical DNS
# sfp_virustotal    — VT IOC enrichment
# sfp_whois         — Domain/IP registration
# sfp_ssl           — TLS certificate analysis
# sfp_waybackmachine— Historical web content
# sfp_threatminer   — ThreatMiner correlation
# sfp_dnsbrute      — DNS subdomain enumeration (careful — active)
```

---

## Phase 3: Shodan Deep Dive

```bash
SHODAN_KEY="your_shodan_api_key"

# Full host data for C2 IP
curl -s "https://api.shodan.io/shodan/host/198.51.100.99?key=$SHODAN_KEY" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('ISP:', d.get('isp'))
print('Org:', d.get('org'))
print('Country:', d.get('country_name'))
print('City:', d.get('city'))
print('Hostnames:', d.get('hostnames'))
print('Ports:', d.get('ports'))
print('Last Update:', d.get('last_update'))
for svc in d.get('data', []):
    print(f'  Port {svc[\"port\"]}: {str(svc.get(\"data\",\"\"))[:80]}')
"

# Search for other hosts with same JARM (same C2 framework)
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=jarm:1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Hosts with Sliver JARM: {d[\"total\"]}')
for h in d.get('matches', [])[:10]:
    print(f'  {h[\"ip_str\"]}:{h.get(\"port\")} — {h.get(\"org\",\"unknown\")} ({h.get(\"country_name\")})')
"

# ASN search — find all hosts in AS209588 (Flyservers)
curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_KEY&query=asn:AS209588%20port:443" \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'AS209588 hosts on port 443: {d[\"total\"]}')
for h in d.get('matches', [])[:15]:
    print(f'  {h[\"ip_str\"]} — {h.get(\"hostnames\",[])} — ports: {h.get(\"port\")}')
"
```

---

## Phase 4: Certificate Transparency (crt.sh)

```bash
# Find all certificates for actor-controlled domains
# crt.sh — public CT log search

# Search for certs issued to phishing domain cluster
curl -s "https://crt.sh/?q=%25novacrest-secure%25&output=json" \
    | python3 -c "
import sys, json
certs = json.load(sys.stdin)
for c in certs[:20]:
    print(f'{c[\"entry_timestamp\"][:10]} | {c[\"common_name\"]} | {c[\"issuer_name\"][:40]}')
"

# Search for actor email in cert issuer (sometimes reveals operator info)
curl -s "https://crt.sh/?q=ncrypt-support%40protonmail.com&output=json" \
    | python3 -c "
import sys, json
certs = json.load(sys.stdin)
print(f'Certs containing actor email: {len(certs)}')
for c in certs:
    print(f'  {c[\"common_name\"]} ({c[\"entry_timestamp\"][:10]})')
"

# Find all domains on same TLS certificate (SAN expansion)
# Certificate SAN: find domains that share certs with C2 infrastructure
CERT_SHA="$(openssl s_client -connect 198.51.100.99:443 2>/dev/null | \
    openssl x509 -fingerprint -sha256 -noout 2>/dev/null | cut -d= -f2)"
echo "Cert fingerprint: $CERT_SHA"
```

---

## Phase 5: Passive DNS (DNSDB / VirusTotal)

```bash
# DNSDB passive DNS — historical resolution records
DNSDB_KEY="your_dnsdb_key"

# Who else has resolved to 198.51.100.99?
curl -s -H "X-API-Key: $DNSDB_KEY" \
    "https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/198.51.100.99?limit=50" \
    | python3 -c "
import sys
for line in sys.stdin:
    import json
    try:
        r = json.loads(line)
        obj = r.get('obj', {})
        print(f'{obj.get(\"rrname\",\"\"):50} first:{obj.get(\"time_first_iso8601\",\"\")[:10]} last:{obj.get(\"time_last_iso8601\",\"\")[:10]}')
    except: pass
"

# VirusTotal passive DNS
curl -s "https://www.virustotal.com/api/v3/ip_addresses/198.51.100.99/resolutions?limit=20" \
    -H "x-apikey: $VT_KEY" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for r in d.get('data', []):
    attrs = r.get('attributes', {})
    print(f'{attrs.get(\"host_name\",\"\"):55} resolved: {attrs.get(\"date\",0)}')
"
```

---

## Phase 6: i2 Analyst's Notebook Integration

```
i2 ANALYST'S NOTEBOOK WORKFLOW:

1. Import link chart data
   File → Import → Universal Data Link
   Source: artifacts/infrastructure_graph.json
   
2. Configure entity types:
   • IP Address (red circle) — C2 nodes
   • Domain (blue box) — infrastructure domains
   • Organization (yellow hexagon) — hosting providers
   • Person/Actor (green diamond) — threat actor entities
   • Victim (gray square) — confirmed victims

3. Apply link types:
   • Resolves-to (solid line, blue)
   • Hosted-by (dashed line, gray)
   • Related-to (dotted line, orange)
   • Targeted (red arrow) — actor → victim

4. Timeline analysis:
   View → Timeline → Set date field: first_seen
   This shows infrastructure creation vs victim targeting sequence

5. Network clustering:
   Analyze → Social Network Analysis → Centrality
   High centrality nodes = most connected infrastructure
   (IP 198.51.100.99 will be highest centrality)

6. Export for law enforcement:
   File → Export → PDF (link chart for FBI briefing)
   File → Export → XML (for import to FBI Palantir/Analyst environment)
```

---

## Phase 7: Dark Web Monitoring (Ransomwatch)

```bash
# Clone Ransomwatch — public ransomware group monitoring
git clone https://github.com/joshhighet/ransomwatch.git
cd ransomwatch

# Check if ncrypt group is tracked
cat groups.json | python3 -c "
import sys, json
groups = json.load(sys.stdin)
for g in groups:
    if 'ncrypt' in g.get('name', '').lower():
        print(json.dumps(g, indent=2))
"

# Check posts (victim publications) for ncrypt/FIN-NC-001
cat posts.json | python3 -c "
import sys, json
posts = json.load(sys.stdin)
nc_posts = [p for p in posts if 'novacrest' in str(p).lower()
            or 'ncrypt' in str(p.get('group_name','')).lower()]
for p in nc_posts:
    print(json.dumps(p, indent=2))
"

# Run the full investigation
python3 ../scripts/campaign_tracker.py --demo --verbose
```

---

*Day 28 Lab Guide | OSINT Investigation*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
