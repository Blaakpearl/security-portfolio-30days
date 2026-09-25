"""
Day 28 — Infrastructure Mapper
NovaCrest Capital Group | OSINT Investigation

PURPOSE: Automates the passive OSINT pivot chain from a seed IOC (C2 IP)
         through ASN, passive DNS, certificate transparency, Shodan banners,
         and co-hosted domain analysis to map the full FIN-NC-001 operational
         infrastructure visible in open sources. Produces a link graph
         compatible with Maltego and i2 Analyst's Notebook.

PIVOT CHAIN:
  Seed IP → ASN → Netblock → Co-hosted IPs
         → Passive DNS → Domains → Certs → SAN domains
         → Cert issuers → Historical IPs
         → Shodan banners → JARM → Other same-JARM hosts
         → WHOIS → Registrar patterns → Registration clusters

OPSEC ANALYSIS:
  Tracks attacker OPSEC quality per infrastructure node:
  - Domain registration timing vs. victim targeting
  - Certificate authority selection (Let's Encrypt = automation = low OPSEC)
  - Hosting provider consistency
  - Domain naming pattern consistency (identifies actor tradecraft)

Usage:
    python infrastructure_mapper.py --demo --verbose
    python infrastructure_mapper.py --seed-ip 198.51.100.99
    python infrastructure_mapper.py --demo --output artifacts/infrastructure_graph.json
"""

import argparse
import datetime
import json
import logging
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("infrastructure_mapper")


# ── Simulated OSINT Pivot Results ──────────────────────────────────────

SIMULATED_ASN_DATA = {
    "ip": "198.51.100.99",
    "asn": "AS209588",
    "asn_name": "Flyservers S.A.",
    "asn_country": "PA",           # Registered in Panama (OPSEC note)
    "asn_description": "Bulletproof hosting provider; minimal abuse response",
    "netblock": "198.51.100.0/24",
    "abuse_email": "abuse@flyservers.com",
    "abuse_response_rating": "Poor — rarely responds to takedowns",
    "known_malicious_use": True,
    "prior_incident_reports": 23,
    "fs_isac_flagged": True,
}

SIMULATED_PASSIVE_DNS = [
    # Domains resolving to 198.51.100.99 (historical + current)
    {"domain": "trading-updates.novacrest-secure.com", "first_seen": "2026-06-10", "last_seen": "2026-06-19", "current": True, "victim_link": "NovaCrest (confirmed)"},
    {"domain": "updates-cdn.financialdata.net",        "first_seen": "2026-04-02", "last_seen": "2026-04-18", "current": False, "victim_link": "EU asset manager (April 2026)"},
    {"domain": "telemetry.marketsync.io",              "first_seen": "2026-05-15", "last_seen": "2026-06-05", "current": False, "victim_link": "US hedge fund (May 2026)"},
    {"domain": "secure-trading-api.financedocs.net",  "first_seen": "2026-03-12", "last_seen": "2026-03-28", "current": False, "victim_link": "UK private equity (March 2026)"},
    {"domain": "portfolio-sync.capitalupdates.org",   "first_seen": "2026-04-25", "last_seen": "2026-05-10", "current": False, "victim_link": "Potential 5th victim (unconfirmed)"},
    # Second C2 IP discovered via ASN pivot
    {"domain": "api-gateway.fintradeops.com",          "first_seen": "2026-05-01", "last_seen": "2026-06-20", "current": True, "victim_link": "Second C2 node (198.51.100.101)"},
]

SIMULATED_CERT_DATA = [
    {
        "domain": "trading-updates.novacrest-secure.com",
        "issued": "2026-06-09",       # 5 days before NovaCrest attack — OPSEC signal
        "ca": "Let's Encrypt",
        "san": ["trading-updates.novacrest-secure.com", "www.novacrest-secure.com"],
        "validity_days": 90,
        "wildcard": False,
        "opsec_note": "Let's Encrypt automated cert — low OPSEC (automated infrastructure); issued 5 days pre-attack",
    },
    {
        "domain": "updates-cdn.financialdata.net",
        "issued": "2026-03-30",       # 3 days before EU victim
        "ca": "Let's Encrypt",
        "san": ["updates-cdn.financialdata.net", "financialdata.net"],
        "validity_days": 90,
        "wildcard": False,
        "opsec_note": "Same CA, same pattern — confirms automated infrastructure deployment playbook",
    },
    {
        "domain": "secure-trading-api.financedocs.net",
        "issued": "2026-03-10",
        "ca": "Let's Encrypt",
        "san": ["secure-trading-api.financedocs.net"],
        "validity_days": 90,
        "wildcard": False,
        "opsec_note": "Earliest cert in cluster — first campaign operation",
    },
]

SIMULATED_SHODAN_HOSTS = [
    {
        "ip": "198.51.100.99",
        "ports": [22, 80, 443, 8443],
        "banner_443": "HTTP/1.1 403 Forbidden\r\nServer: nginx/1.24.0",
        "jarm": "1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c",
        "server_header": "nginx/1.24.0",
        "ssl_cn": "trading-updates.novacrest-secure.com",
        "last_scan": "2026-06-18",
        "tags": ["c2", "bulletproof-hosting"],
        "same_jarm_host_count": 7,     # 7 other hosts with same Sliver JARM in Shodan
        "opsec_note": "nginx default server header exposed; JARM links to 7 other potential C2 nodes globally",
    },
    {
        "ip": "198.51.100.101",        # Second C2 node found via ASN pivot
        "ports": [443, 8080],
        "banner_443": "HTTP/1.1 403 Forbidden\r\nServer: nginx/1.24.0",
        "jarm": "1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c",
        "server_header": "nginx/1.24.0",
        "ssl_cn": "api-gateway.fintradeops.com",
        "last_scan": "2026-06-20",
        "tags": ["c2", "bulletproof-hosting"],
        "opsec_note": "Same JARM, same server, same ASN — second C2 node confirmed",
    },
]

SIMULATED_WHOIS = {
    "novacrest-secure.com": {
        "registrar": "Namecheap, Inc.",
        "registered": "2026-06-08",
        "expires": "2027-06-08",
        "registrant": "REDACTED (privacy protection)",
        "registrant_email": "REDACTED",
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "privacy_protected": True,
        "opsec_note": "Cloudflare nameservers — hides origin IP from DNS; registered 6 days before attack",
    },
    "financialdata.net": {
        "registrar": "GoDaddy",
        "registered": "2026-03-28",
        "expires": "2027-03-28",
        "registrant": "REDACTED",
        "registrant_email": "REDACTED",
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "privacy_protected": True,
        "opsec_note": "Same registrar pattern + Cloudflare = automated domain provisioning",
    },
    "financedocs.net": {
        "registrar": "Namecheap, Inc.",
        "registered": "2026-03-08",
        "expires": "2027-03-08",
        "registrant": "REDACTED",
        "registrant_email": "REDACTED",
        "nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "privacy_protected": True,
        "opsec_note": "Earliest domain registration — ~1 month before first victim",
    },
}

SIMULATED_DARK_WEB = {
    "leak_site": "http://ncrypt3k4j7mxbwz.onion",
    "site_first_seen": "2026-02-20",
    "ransomwatch_entry": True,
    "group_name": "ncrypt",
    "group_description": "Double-extortion ransomware targeting financial sector",
    "victims_published": [
        {
            "victim_name": "Redacted EU Financial Services",
            "posted": "2026-03-30",
            "data_published": True,
            "ransom_paid": False,
            "data_size_gb": 42,
            "teaser_samples": True,
        },
        {
            "victim_name": "Redacted US Hedge Fund",
            "posted": "2026-05-12",
            "data_published": False,
            "ransom_paid": True,    # Paid — data not published
            "data_size_gb": 0,
            "note": "Entry removed after payment — consistent with group policy",
        },
        {
            "victim_name": "Redacted UK Private Equity",
            "posted": "2026-04-05",
            "data_published": True,
            "ransom_paid": False,
            "data_size_gb": 67,
            "teaser_samples": True,
        },
        {
            "victim_name": "NovaCrest Capital Group",
            "posted": "2026-06-19",     # Posted same day as ransomware deployment
            "data_published": False,
            "ransom_paid": False,
            "data_size_gb": 0,          # Not yet published (deadline June 22)
            "note": "Active — deadline June 22, 2026 06:14 UTC",
            "current": True,
        },
    ],
    "negotiation_pattern": "Responds within 4 hours; 30-40% discount offered if paid within 24hrs",
    "blog_style": "Professional English; no grammar errors; consistent formatting",
    "opsec_note": "Leak site hosted on Tor hidden service — high OPSEC; consistent uptime suggests dedicated hosting",
}


def map_asn_infrastructure(asn_data: Dict, verbose: bool) -> List[Dict]:
    """Analyze ASN and hosting infrastructure."""
    nodes = []
    log.info(f"  ASN: {asn_data['asn']} ({asn_data['asn_name']})")
    log.info(f"  Registration: {asn_data['asn_country']} — {asn_data['asn_description'][:60]}")
    log.info(f"  Abuse reports: {asn_data['prior_incident_reports']} | FS-ISAC flagged: {asn_data['fs_isac_flagged']}")

    nodes.append({"type": "ASN", "id": asn_data["asn"], "label": asn_data["asn_name"],
                  "country": asn_data["asn_country"], "threat_level": "High"})
    return nodes


def pivot_passive_dns(pdns: List[Dict], verbose: bool) -> List[Dict]:
    """Extract infrastructure nodes from passive DNS."""
    nodes = []
    campaigns_found = set()
    for record in pdns:
        domain = record["domain"]
        victim_link = record["victim_link"]
        age_days = (datetime.date.today() -
                    datetime.date.fromisoformat(record["first_seen"])).days

        nodes.append({
            "type": "Domain", "id": domain, "label": domain,
            "first_seen": record["first_seen"], "last_seen": record["last_seen"],
            "current": record["current"], "victim_link": victim_link,
            "age_at_attack_days": age_days,
        })

        if record["victim_link"] not in campaigns_found:
            campaigns_found.add(record["victim_link"])
            if verbose:
                status = "✅ CURRENT" if record["current"] else "📁 Historical"
                log.info(f"  {status} {domain:55} → {victim_link}")

    log.info(f"  Total infrastructure domains found: {len(pdns)}")
    log.info(f"  Unique campaigns identified: {len(campaigns_found)}")
    return nodes


def analyze_cert_transparency(certs: List[Dict], verbose: bool) -> Dict:
    """Analyze certificate patterns for OPSEC and timing signals."""
    analysis = {
        "cert_count": len(certs),
        "ca_breakdown": {},
        "timing_patterns": [],
        "opsec_signals": [],
    }

    for cert in certs:
        ca = cert["ca"]
        analysis["ca_breakdown"][ca] = analysis["ca_breakdown"].get(ca, 0) + 1

        # Timing: days between cert issue and attack
        issued = datetime.date.fromisoformat(cert["issued"])
        # Estimate attack date (5 days after cert for NovaCrest pattern)
        pre_attack_days = 5
        analysis["timing_patterns"].append({
            "domain": cert["domain"],
            "cert_issued": cert["issued"],
            "days_before_use": pre_attack_days,
            "opsec_note": cert["opsec_note"],
        })
        if cert["opsec_note"] not in analysis["opsec_signals"]:
            analysis["opsec_signals"].append(cert["opsec_note"])

    if verbose:
        for ca, count in analysis["ca_breakdown"].items():
            log.info(f"  Certificate Authority: {ca} × {count} certs")
        log.info(f"  OPSEC finding: All certs use Let's Encrypt → automated provisioning pipeline")
        log.info(f"  Timing: Certs issued 3-6 days before each victim attack — consistent pattern")

    return analysis


def score_actor_opsec(asn: Dict, pdns: List[Dict], certs: List[Dict],
                       whois: Dict, dark_web: Dict) -> Dict:
    """Score attacker OPSEC quality across each dimension."""
    scores = {
        "hosting": {
            "score": 7,         # Out of 10
            "rating": "Good",
            "notes": "Bulletproof VPS in Panama-registered ASN; abuse-resistant; OPSEC weakness: same ASN reused across 3+ campaigns",
        },
        "domains": {
            "score": 5,
            "rating": "Moderate",
            "notes": "Privacy-protected WHOIS; Cloudflare DNS. Weakness: consistent naming pattern (finance/trading theme; always uses .com/.net/.org); domain age <2 weeks at time of use",
        },
        "certificates": {
            "score": 4,
            "rating": "Low-Moderate",
            "notes": "Let's Encrypt automation is smart (no cert purchase paper trail) but exposes automated infrastructure creation. All certs issued 3-6 days pre-attack — detectable preparation pattern",
        },
        "c2_fingerprint": {
            "score": 5,
            "rating": "Moderate",
            "notes": "Sliver is open source (good for deniability); JARM fingerprint is distinctive and unchanged across campaigns — should rotate C2 framework or TLS parameters between victims",
        },
        "dark_web": {
            "score": 8,
            "rating": "Good",
            "notes": "Tor hidden service for leak site; professional presentation; consistent victim policy. Weakness: group name ('ncrypt') is distinctive and searchable in Ransomwatch",
        },
        "operational": {
            "score": 6,
            "rating": "Moderate",
            "notes": "Maintained persistent C2 IP for 3+ months — unusual for sophisticated actor. May indicate comfort with current hosting arrangement or operational laziness",
        },
    }

    avg_score = sum(v["score"] for v in scores.values()) / len(scores)
    overall = "Moderate-Advanced" if avg_score >= 6 else "Moderate" if avg_score >= 4 else "Low"

    return {
        "overall_score": round(avg_score, 1),
        "overall_rating": overall,
        "dimension_scores": scores,
        "key_weakness": "Domain naming pattern + Let's Encrypt timing + static C2 IP create detectable infrastructure preparation signature",
        "key_strength": "Bulletproof hosting + Tor leak site + professional OPSEC mindset",
    }


def build_link_graph(asn_nodes: List[Dict], dns_nodes: List[Dict],
                      cert_data: Dict, shodan: List[Dict]) -> Dict:
    """Build link analysis graph for Maltego/i2 export."""
    nodes = []
    edges = []

    # Seed node
    nodes.append({"id": "ip_198.51.100.99", "type": "IPv4", "label": "198.51.100.99",
                   "threat_level": "Critical", "role": "Primary C2"})
    nodes.append({"id": "ip_198.51.100.101", "type": "IPv4", "label": "198.51.100.101",
                   "threat_level": "High", "role": "Secondary C2"})
    nodes.append({"id": "asn_AS209588", "type": "ASN", "label": "AS209588 Flyservers",
                   "threat_level": "High"})

    edges.append({"source": "ip_198.51.100.99", "target": "asn_AS209588",
                   "type": "hosted-by", "weight": 3})
    edges.append({"source": "ip_198.51.100.101", "target": "asn_AS209588",
                   "type": "hosted-by", "weight": 3})
    edges.append({"source": "ip_198.51.100.99", "target": "ip_198.51.100.101",
                   "type": "same-jarm", "weight": 2, "label": "Same Sliver JARM"})

    # DNS pivot nodes
    victim_colors = {
        "NovaCrest (confirmed)": "red",
        "EU asset manager (April 2026)": "orange",
        "US hedge fund (May 2026)": "orange",
        "UK private equity (March 2026)": "orange",
        "Potential 5th victim (unconfirmed)": "yellow",
        "Second C2 node (198.51.100.101)": "red",
    }
    for dns in dns_nodes:
        node_id = f"domain_{dns['id'].replace('.','_')}"
        nodes.append({"id": node_id, "type": "Domain", "label": dns["id"],
                       "first_seen": dns["first_seen"], "last_seen": dns["last_seen"],
                       "victim_link": dns["victim_link"],
                       "color": victim_colors.get(dns["victim_link"], "gray")})
        edges.append({"source": node_id, "target": "ip_198.51.100.99",
                       "type": "resolves-to", "first_seen": dns["first_seen"]})

    # Victim nodes
    victims = [
        {"id": "victim_novacrest", "label": "NovaCrest Capital Group", "type": "Victim", "date": "2026-06-14"},
        {"id": "victim_eu_asset", "label": "EU Asset Manager", "type": "Victim", "date": "2026-04-02"},
        {"id": "victim_us_hedge", "label": "US Hedge Fund", "type": "Victim", "date": "2026-05-01"},
        {"id": "victim_uk_pe", "label": "UK Private Equity", "type": "Victim", "date": "2026-03-12"},
    ]
    domain_to_victim = {
        "domain_trading-updates_novacrest-secure_com": "victim_novacrest",
        "domain_updates-cdn_financialdata_net": "victim_eu_asset",
        "domain_telemetry_marketsync_io": "victim_us_hedge",
        "domain_secure-trading-api_financedocs_net": "victim_uk_pe",
    }
    for v in victims:
        nodes.append(v)
    for domain_node_id, victim_id in domain_to_victim.items():
        edges.append({"source": domain_node_id, "target": victim_id,
                       "type": "targeted", "color": "red"})

    # Actor node
    nodes.append({"id": "actor_fin_nc_001", "type": "ThreatActor",
                   "label": "FIN-NC-001 (GOLD MYSTIC affiliate)",
                   "attribution_confidence": "78%"})
    for v in victims:
        edges.append({"source": "actor_fin_nc_001", "target": v["id"],
                       "type": "attacked"})

    return {"nodes": nodes, "edges": edges,
            "metadata": {"tool": "NovaCrest OSINT Investigation Day 28",
                          "generated": datetime.datetime.utcnow().isoformat() + "Z",
                          "total_nodes": len(nodes),
                          "total_edges": len(edges)}}


def main():
    parser = argparse.ArgumentParser(description="Day 28 Infrastructure Mapper")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--seed-ip", default="198.51.100.99")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day28_infrastructure_graph.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 28 — Infrastructure Mapper | FIN-NC-001 OSINT")
    log.info(f" Seed IOC: {args.seed_ip}")
    log.info("=" * 70)
    log.info("")

    log.info("[1] ASN / Hosting Analysis")
    asn_nodes = map_asn_infrastructure(SIMULATED_ASN_DATA, args.verbose)
    log.info("")

    log.info("[2] Passive DNS Pivot")
    dns_nodes = pivot_passive_dns(SIMULATED_PASSIVE_DNS, args.verbose)
    log.info("")

    log.info("[3] Certificate Transparency Analysis")
    cert_analysis = analyze_cert_transparency(SIMULATED_CERT_DATA, args.verbose)
    log.info("")

    log.info("[4] Actor OPSEC Scoring")
    opsec = score_actor_opsec(SIMULATED_ASN_DATA, SIMULATED_PASSIVE_DNS,
                               SIMULATED_CERT_DATA, SIMULATED_WHOIS,
                               SIMULATED_DARK_WEB)
    log.info(f"  Overall OPSEC score: {opsec['overall_score']}/10 ({opsec['overall_rating']})")
    log.info(f"  Key weakness: {opsec['key_weakness'][:65]}")
    log.info("")

    log.info("[5] Building Link Analysis Graph")
    graph = build_link_graph(asn_nodes, dns_nodes, cert_analysis,
                              SIMULATED_SHODAN_HOSTS)
    log.info(f"  Nodes: {graph['metadata']['total_nodes']} | Edges: {graph['metadata']['total_edges']}")
    log.info("")

    print("\n" + "=" * 70)
    print("  OSINT INVESTIGATION SUMMARY — Day 28")
    print("  FIN-NC-001 | NovaCrest Capital Group")
    print("=" * 70)
    print(f"\n  Infrastructure nodes mapped: {len(dns_nodes)} domains + 2 C2 IPs")
    print(f"  Confirmed prior victims: 3 (+ NovaCrest = 4 total)")
    print(f"  Potential 5th victim domain: portfolio-sync.capitalupdates.org")
    print(f"  Actor OPSEC: {opsec['overall_score']}/10 ({opsec['overall_rating']})")
    print(f"  Key weakness: {opsec['key_weakness'][:62]}")
    print(f"  Dark web: NovaCrest live on leak site (deadline June 22)")
    print()

    output = {
        "investigation": "FIN-NC-001 Infrastructure OSINT",
        "seed_ip": args.seed_ip,
        "asn": SIMULATED_ASN_DATA,
        "passive_dns": SIMULATED_PASSIVE_DNS,
        "certificates": SIMULATED_CERT_DATA,
        "shodan": SIMULATED_SHODAN_HOSTS,
        "whois": SIMULATED_WHOIS,
        "dark_web": SIMULATED_DARK_WEB,
        "opsec_analysis": opsec,
        "link_graph": graph,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Graph written: {args.output}")


if __name__ == "__main__":
    main()
