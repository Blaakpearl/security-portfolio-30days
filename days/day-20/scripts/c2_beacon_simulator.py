"""
Day 20 — C2 Beacon Simulator
NovaCrest Capital Group | Purple Team C2 Exercise

PURPOSE: Generates realistic C2 beaconing telemetry for all four exercise
         variants without deploying actual C2 infrastructure. Produces
         Zeek-format conn.log, ssl.log, dns.log, and EDR event data that
         the detection scripts and SIEM queries can operate against.

VARIANTS SIMULATED:
  V1 — Sliver HTTPS baseline (60s interval, 0% jitter, known JA3)
  V2 — Sliver HTTPS with jitter (300s ± 50%, legit-looking SNI)
  V3 — Domain fronting (SNI ≠ Host header, Azure CDN)
  V4 — Havoc C2 with DNS-over-HTTPS fallback

OUTPUTS:
  - Zeek conn.log format (JSON)
  - Zeek ssl.log format (JSON) with JA3/JARM
  - Zeek dns.log format (JSON) for DoH detection
  - EDR event format (JSON) for behavioral detection

Usage:
    python c2_beacon_simulator.py --variants all --demo --verbose
    python c2_beacon_simulator.py --variant v1 --duration 3600
    python c2_beacon_simulator.py --output /tmp/lab-logs/ --variants all
"""

import argparse
import datetime
import json
import logging
import math
import os
import random
import sys
from typing import List, Dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("c2_beacon_simulator")

# ── Known C2 JA3/JARM Fingerprints ────────────────────────────────────
SLIVER_JA3   = "a0e9f5d64349fb13191bc781f81f42e1"
SLIVER_JARM  = "1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c"
HAVOC_JA3    = "f4febc55ea12b31ae17cfb7e614afda8"
HAVOC_JARM   = "2ad2ad16d2ad2ad22c2ad2ad2ad2ade1a3ed4e7d7b6bd1c1b8fa9c0dcfd2b9"
LEGIT_JA3    = "3b5074b1b5d032e5620f69f9f700ff0e"  # Chrome 120

# ── Variant Profiles ──────────────────────────────────────────────────
VARIANTS = {
    "v1": {
        "name": "Sliver Baseline (No Evasion)",
        "technique": "T1071.001",
        "interval": 60,
        "jitter_pct": 0,
        "dst_ip": "198.51.100.99",
        "dst_port": 443,
        "sni": "evil-c2.novacrest-updates.com",
        "host_header": None,  # Same as SNI — no fronting
        "ja3": SLIVER_JA3,
        "jarm": SLIVER_JARM,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "payload_bytes_range": (2048, 4096),
        "doh": False,
        "domain_age_days": 3,
        "detection_expected_min": 5,
    },
    "v2": {
        "name": "Sliver + Jitter + CDN Lookalike",
        "technique": "T1071.001,T1001.001",
        "interval": 300,
        "jitter_pct": 50,
        "dst_ip": "198.51.100.50",
        "dst_port": 443,
        "sni": "cdn-assets.azureedge-novacrest.com",
        "host_header": None,
        "ja3": SLIVER_JA3,
        "jarm": SLIVER_JARM,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ],
        "payload_bytes_range": (1024, 8192),  # Variable for jitter
        "doh": False,
        "domain_age_days": 3,
        "detection_expected_min": 15,
    },
    "v3": {
        "name": "Domain Fronting via Azure CDN",
        "technique": "T1090.004,T1573.002",
        "interval": 600,
        "jitter_pct": 30,
        "dst_ip": "13.107.246.45",  # Azure CDN IP
        "dst_port": 443,
        "sni": "legitimate-corp.azureedge.net",  # Outer SNI — legit Azure
        "host_header": "evil-c2.attacker.com",   # Inner Host header — actual C2
        "ja3": SLIVER_JA3,
        "jarm": SLIVER_JARM,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "payload_bytes_range": (4096, 16384),
        "doh": False,
        "domain_age_days": 45,  # Older domain (CDN)
        "detection_expected_min": 20,
        "evasion_note": "SNI shows legitimate Azure CDN; Host header contains actual C2 — requires TLS inspection",
    },
    "v4": {
        "name": "Havoc C2 + DNS-over-HTTPS Fallback",
        "technique": "T1008,T1071.004,T1573.002",
        "interval": 900,
        "jitter_pct": 25,
        "dst_ip": "198.51.100.50",
        "dst_port": 443,
        "doh_resolver": "1.1.1.1",
        "doh_port": 443,
        "sni": "cloudflare-dns.com",  # DoH looks like legit Cloudflare
        "host_header": None,
        "ja3": HAVOC_JA3,
        "jarm": HAVOC_JARM,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "payload_bytes_range": (512, 2048),
        "doh": True,
        "domain_age_days": 365,  # Cloudflare is old
        "detection_expected_min": 25,
        "evasion_note": "HTTPS primary; falls back to DoH via 1.1.1.1:443 when HTTPS blocked",
    },
}


def generate_beacon_interval(base_interval: int, jitter_pct: int) -> float:
    """Apply jitter to beacon interval."""
    if jitter_pct == 0:
        return float(base_interval)
    max_delta = base_interval * (jitter_pct / 100.0)
    return base_interval + random.uniform(-max_delta, max_delta)


def simulate_variant_beacons(variant_key: str, profile: Dict,
                              start_time: datetime.datetime,
                              duration_seconds: int = 3600) -> Dict:
    """Simulate all beacon events for one variant over a time window."""
    conn_events = []
    ssl_events = []
    dns_events = []
    edr_events = []

    ts = start_time
    end_time = start_time + datetime.timedelta(seconds=duration_seconds)
    beacon_count = 0

    user_agents = profile.get("user_agents", [profile.get("user_agent", "")])

    while ts < end_time:
        interval = generate_beacon_interval(profile["interval"], profile["jitter_pct"])
        beacon_count += 1

        orig_bytes = random.randint(*profile["payload_bytes_range"])
        resp_bytes = random.randint(512, 2048)
        ua = random.choice(user_agents)

        # Zeek conn.log entry
        conn_event = {
            "ts": ts.timestamp(),
            "ts_readable": ts.isoformat() + "Z",
            "uid": f"C{random.randint(100000,999999)}",
            "id.orig_h": "10.0.1.40",
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": profile["dst_ip"],
            "id.resp_p": profile["dst_port"],
            "proto": "tcp",
            "service": "ssl",
            "duration": random.uniform(0.5, 3.0),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": "SF",
            "_variant": variant_key,
            "_beacon_count": beacon_count,
        }
        conn_events.append(conn_event)

        # Zeek ssl.log entry
        ssl_event = {
            "ts": ts.timestamp(),
            "ts_readable": ts.isoformat() + "Z",
            "uid": conn_event["uid"],
            "id.orig_h": "10.0.1.40",
            "id.resp_h": profile["dst_ip"],
            "id.resp_p": profile["dst_port"],
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "server_name": profile["sni"],
            "host_header": profile.get("host_header"),  # None unless fronting
            "validation_status": "ok",
            "ja3": profile["ja3"],
            "ja3s": profile["ja3"],
            "jarm": profile["jarm"],
            "_variant": variant_key,
            "_fronting": profile.get("host_header") is not None,
        }
        ssl_events.append(ssl_event)

        # DNS/DoH events for V4
        if profile.get("doh"):
            dns_event = {
                "ts": (ts - datetime.timedelta(seconds=2)).timestamp(),
                "ts_readable": ts.isoformat() + "Z",
                "id.orig_h": "10.0.1.40",
                "id.resp_h": profile["doh_resolver"],
                "id.resp_p": profile["doh_port"],
                "query": f"resolve.{profile['sni']}",
                "qtype_name": "A",
                "proto": "tcp",
                "is_doh": True,
                "_variant": variant_key,
                "_evasion": "DNS-over-HTTPS to external resolver",
            }
            dns_events.append(dns_event)

        # EDR behavioral event
        edr_event = {
            "ts": ts.isoformat() + "Z",
            "host": "LAB-WIN-01",
            "process": "svchost.exe",
            "pid": random.randint(1000, 9999),
            "parent": "services.exe",
            "network_event": {
                "type": "outbound_connection",
                "dst_ip": profile["dst_ip"],
                "dst_port": profile["dst_port"],
                "protocol": "HTTPS",
                "bytes_sent": orig_bytes,
                "bytes_recv": resp_bytes,
            },
            "user_agent": ua,
            "_variant": variant_key,
            "_beacon_count": beacon_count,
            "_interval": round(interval),
        }
        edr_events.append(edr_event)

        ts = ts + datetime.timedelta(seconds=interval)

    return {
        "variant": variant_key,
        "name": profile["name"],
        "technique": profile["technique"],
        "beacon_count": beacon_count,
        "conn_events": conn_events,
        "ssl_events": ssl_events,
        "dns_events": dns_events,
        "edr_events": edr_events,
        "detection_expected_min": profile.get("detection_expected_min"),
        "evasion_note": profile.get("evasion_note", ""),
    }


def emit_detection_summary(all_results: List[Dict]) -> None:
    """Print beacon detection summary for blue team reference."""
    print("\n" + "=" * 70)
    print("  C2 BEACON SIMULATION RESULTS — Day 20")
    print("=" * 70 + "\n")

    for result in all_results:
        print(f"  VARIANT: {result['variant'].upper()} — {result['name']}")
        print(f"  Technique: {result['technique']}")
        print(f"  Beacons simulated: {result['beacon_count']}")
        print(f"  Detection SLA target: {result['detection_expected_min']} minutes")
        if result["evasion_note"]:
            print(f"  Evasion: {result['evasion_note']}")

        # Key detection signals
        conn_sample = result["conn_events"][0] if result["conn_events"] else {}
        ssl_sample = result["ssl_events"][0] if result["ssl_events"] else {}
        print(f"  JA3: {ssl_sample.get('ja3','?')}")
        print(f"  SNI: {ssl_sample.get('server_name','?')}")
        if ssl_sample.get("_fronting"):
            print(f"  ⚠️  DOMAIN FRONTING: Host header = {ssl_sample.get('host_header')}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Day 20 C2 Beacon Simulator")
    parser.add_argument("--variants", default="all",
                        help="Variants to simulate: all, v1, v2, v3, v4")
    parser.add_argument("--duration", type=int, default=3600,
                        help="Simulation duration in seconds (default 3600)")
    parser.add_argument("--output", default="/tmp/day20-beacons/",
                        help="Output directory for log files")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 20 — C2 Beacon Simulator")
    log.info(" NovaCrest Capital Group — Purple Team Exercise")
    log.info("=" * 70)
    log.info(" MODE: Simulation only — no live C2 deployed")
    log.info("")

    os.makedirs(args.output, exist_ok=True)
    start_time = datetime.datetime(2026, 6, 20, 9, 0, 0,
                                   tzinfo=datetime.timezone.utc)

    if args.variants == "all":
        variant_keys = list(VARIANTS.keys())
    else:
        variant_keys = [v.strip() for v in args.variants.split(",")]

    all_results = []
    for key in variant_keys:
        if key not in VARIANTS:
            log.warning(f"Unknown variant: {key}")
            continue
        profile = VARIANTS[key]
        log.info(f"Simulating {key.upper()}: {profile['name']}")
        result = simulate_variant_beacons(key, profile, start_time, args.duration)
        all_results.append(result)
        log.info(f"  Generated {result['beacon_count']} beacons")

        # Write per-variant output files
        for log_type in ("conn_events", "ssl_events", "dns_events", "edr_events"):
            events = result[log_type]
            if not events:
                continue
            fname = f"{key}_{log_type.replace('_events','')}.json"
            with open(os.path.join(args.output, fname), "w") as f:
                json.dump(events, f, indent=2)

    emit_detection_summary(all_results)

    # Write combined report
    report = {
        "simulation": True,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "variants": [
            {
                "variant": r["variant"],
                "name": r["name"],
                "technique": r["technique"],
                "beacon_count": r["beacon_count"],
                "detection_sla_minutes": r["detection_expected_min"],
            }
            for r in all_results
        ],
    }
    with open(os.path.join(args.output, "simulation_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    log.info(f"\nAll outputs written to: {args.output}")
    log.info("Load JSON files into Splunk/Sentinel or feed to beacon_timing_analyzer.py")


if __name__ == "__main__":
    main()
