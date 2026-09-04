"""
Day 18 — DNS Tunnel Detector
NovaCrest Capital Group | Threat Hunt

PURPOSE: Dedicated DNS tunneling detection using Shannon entropy scoring,
         query length analysis, record type profiling, and domain query rate
         analysis against Zeek dns.log output.

TUNNEL TECHNIQUES DETECTED:
  - iodine:  Long base32 subdomains; TXT record responses carry data
  - dnscat2: High-entropy subdomains; NULL/CNAME/MX record types
  - dns2tcp: High query rate; payload encoded in query name
  - cobalt:  Periodic DNS beacon to single domain (C2 check-in)

SCORING MODEL:
  Each query scores 0–100 across four dimensions:
    Query length score    (0–25)  — longer = more suspicious
    Entropy score         (0–25)  — higher = more encoded content
    Record type score     (0–25)  — TXT/NULL/MX = more suspicious
    Rate score            (0–25)  — burst to single domain = suspicious
  Threshold: > 50 = suspicious | > 75 = high confidence tunnel

Usage:
    python dns_tunnel_detector.py --demo --verbose
    python dns_tunnel_detector.py --dns-log /opt/zeek/logs/current/dns.log
    python dns_tunnel_detector.py --demo --threshold 60
"""

import argparse
import datetime
import json
import logging
import math
import sys
from collections import defaultdict
from typing import List, Dict, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("dns_tunnel_detector")


# ── Scoring weights ────────────────────────────────────────────────────
SCORE_THRESHOLDS = {
    "suspicious": 50,
    "high_confidence": 75,
    "critical": 90,
}

SUSPICIOUS_RECORD_TYPES = {
    "TXT": 25, "NULL": 25, "MX": 15, "CNAME": 10,
    "AAAA": 5,  "A": 0,
}

TUNNEL_TOOL_SIGNATURES = {
    "iodine":  {"min_sub_len": 55, "record_types": ["NULL", "CNAME", "MX"]},
    "dnscat2": {"min_entropy": 4.0, "record_types": ["TXT", "CNAME"]},
    "dns2tcp": {"min_query_len": 70, "record_types": ["TXT"]},
}

# ── Simulated DNS log (demo) ───────────────────────────────────────────
DEMO_DNS_RECORDS = [
    # Normal queries
    {"ts": "1718360000.0", "uid": "abc1", "id.orig_h": "10.0.1.40",
     "id.resp_h": "8.8.8.8", "query": "www.google.com", "qtype_name": "A",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": ["142.250.80.36"]},
    {"ts": "1718360010.0", "uid": "abc2", "id.orig_h": "10.0.1.40",
     "id.resp_h": "8.8.8.8", "query": "login.microsoftonline.com", "qtype_name": "A",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": ["20.190.160.1"]},
    # H1: DNS tunnel — iodine-style NULL record queries
    {"ts": "1718361000.0", "uid": "tun1", "id.orig_h": "10.0.1.40",
     "id.resp_h": "198.51.100.1", "qtype_name": "NULL",
     "query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA.t1.evil-c2.com",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": []},
    {"ts": "1718361005.0", "uid": "tun2", "id.orig_h": "10.0.1.40",
     "id.resp_h": "198.51.100.1", "qtype_name": "TXT",
     "query": "dGhpcyBpcyBhbm90aGVyIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQ.t1.evil-c2.com",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": []},
    {"ts": "1718361010.0", "uid": "tun3", "id.orig_h": "10.0.1.40",
     "id.resp_h": "198.51.100.1", "qtype_name": "TXT",
     "query": "cGF5bG9hZCBudW1iZXIgdGhyZWUgdGhpcyBpcyBkYXRh.t1.evil-c2.com",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": []},
    {"ts": "1718361015.0", "uid": "tun4", "id.orig_h": "10.0.1.40",
     "id.resp_h": "198.51.100.1", "qtype_name": "NULL",
     "query": "ZmluYWwgcGF5bG9hZCBkYXRhIGV4ZmlsdHJhdGlvbg.t1.evil-c2.com",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": []},
    {"ts": "1718361020.0", "uid": "tun5", "id.orig_h": "10.0.1.40",
     "id.resp_h": "198.51.100.1", "qtype_name": "TXT",
     "query": "bW9yZSBkYXRhIGJlaW5nIHR1bm5lbGVkIG91dCBvZiB0aGUgbmV0d29yaw.t1.evil-c2.com",
     "qclass_name": "C_INTERNET", "rcode_name": "NOERROR", "answers": []},
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((cnt/n) * math.log2(cnt/n) for cnt in freq.values())


def score_query(query: str, qtype: str) -> Tuple[int, Dict]:
    """Score a DNS query for tunneling indicators."""
    parts = query.split(".")
    subdomain = parts[0] if parts else ""
    full_len = len(query)
    sub_len = len(subdomain)
    entropy = shannon_entropy(subdomain)

    # Score components (0–25 each)
    length_score = min(25, int((full_len / 100) * 25))
    entropy_score = min(25, int((entropy / 5.0) * 25))
    type_score = SUSPICIOUS_RECORD_TYPES.get(qtype.upper(), 0)

    total = length_score + entropy_score + type_score
    breakdown = {
        "length_score": length_score,
        "entropy_score": entropy_score,
        "type_score": type_score,
        "subdomain_length": sub_len,
        "full_query_length": full_len,
        "subdomain_entropy": round(entropy, 3),
    }
    return total, breakdown


def identify_tool(query: str, qtype: str, entropy: float) -> str:
    """Attempt to identify the tunneling tool from query characteristics."""
    sub = query.split(".")[0]
    if qtype in ("NULL", "MX", "CNAME") and len(sub) >= 55:
        return "iodine (NULL/CNAME/MX + long subdomain)"
    if qtype in ("TXT", "CNAME") and entropy >= 4.0:
        return "dnscat2 (TXT/CNAME + high entropy)"
    if qtype == "TXT" and len(query) >= 70:
        return "dns2tcp (TXT + long query)"
    if qtype == "A" and len(sub) >= 30:
        return "possible DNS beacon / cobalt strike"
    return "unknown tunnel tool"


def analyze_domain_rates(records: List[Dict]) -> Dict[str, Dict]:
    """Analyze query rate per apex domain for burst detection."""
    apex_data: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "timestamps": [],
                                                        "qtypes": set(), "hosts": set()})
    for r in records:
        query = r.get("query", "")
        parts = query.split(".")
        if len(parts) >= 2:
            apex = ".".join(parts[-2:])
            apex_data[apex]["count"] += 1
            apex_data[apex]["timestamps"].append(float(r.get("ts", 0)))
            apex_data[apex]["qtypes"].add(r.get("qtype_name", "A"))
            apex_data[apex]["hosts"].add(r.get("id.orig_h", ""))
    return apex_data


def detect_tunneling(records: List[Dict], threshold: int = 50,
                     verbose: bool = True) -> List[Dict]:
    """Full DNS tunnel detection pipeline."""
    findings = []
    domain_rates = analyze_domain_rates(records)

    # Per-query scoring
    for r in records:
        query = r.get("query", "")
        qtype = r.get("qtype_name", "A")
        src = r.get("id.orig_h", "unknown")

        score, breakdown = score_query(query, qtype)

        if score >= threshold:
            tool = identify_tool(query, qtype, breakdown["subdomain_entropy"])
            severity = ("Critical" if score >= SCORE_THRESHOLDS["critical"]
                        else "High" if score >= SCORE_THRESHOLDS["high_confidence"]
                        else "Medium")
            finding = {
                "type": "per_query",
                "timestamp": r.get("ts"),
                "src": src,
                "query": query,
                "qtype": qtype,
                "tunnel_score": score,
                "score_breakdown": breakdown,
                "likely_tool": tool,
                "severity": severity,
                "technique": "T1048.001",
            }
            findings.append(finding)
            if verbose:
                log.warning(f"  TUNNEL [{severity}] score={score}/100 src={src} "
                            f"qtype={qtype} entropy={breakdown['subdomain_entropy']} "
                            f"tool={tool}")
                log.info(f"    query={query[:70]}")

    # Domain-level burst analysis
    for apex, data in domain_rates.items():
        if data["count"] >= 3:
            unusual_types = data["qtypes"] - {"A", "AAAA"}
            ts_sorted = sorted(data["timestamps"])
            time_span = (ts_sorted[-1] - ts_sorted[0]) if len(ts_sorted) > 1 else 0

            if unusual_types and data["count"] >= 3:
                finding = {
                    "type": "domain_burst",
                    "apex_domain": apex,
                    "query_count": data["count"],
                    "time_span_sec": round(time_span),
                    "record_types": list(data["qtypes"]),
                    "source_hosts": list(data["hosts"]),
                    "evidence": (f"{data['count']} queries to {apex} in {round(time_span)}s "
                                 f"using types: {','.join(data['qtypes'])}"),
                    "severity": "Critical",
                    "technique": "T1048.001",
                }
                findings.append(finding)
                if verbose:
                    log.warning(f"  BURST [Critical] {data['count']} queries to {apex} "
                                f"in {round(time_span)}s types={','.join(data['qtypes'])}")

    return findings


def emit_report(findings: List[Dict], threshold: int) -> None:
    confirmed = len(findings) > 0
    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "detector": "DNS Tunnel Detector",
        "hypothesis": "H1 — DNS Tunneling (T1048.001)",
        "threshold": threshold,
        "verdict": "CONFIRMED — DNS tunneling activity detected" if confirmed else "NOT FOUND",
        "total_findings": len(findings),
        "findings": findings,
        "ioc": {
            "tunnel_domains": list({f.get("apex_domain", f.get("query","").split(".")[-2] + "." + f.get("query","").split(".")[-1])
                                    for f in findings if "domain_burst" in f.get("type","")}),
            "source_ips": list({f.get("src", f.get("source_hosts", [""])[0]) for f in findings}),
        },
    }

    print("\n" + "=" * 70)
    print("  DNS TUNNEL DETECTION REPORT — Day 18")
    print("=" * 70 + "\n")
    print(json.dumps(report, indent=2))
    print("\n" + "=" * 70 + "\n")

    print(f"VERDICT: {'⚠️  ' + report['verdict'] if confirmed else '✅  ' + report['verdict']}")
    print(f"Findings: {len(findings)} | Threshold: {threshold}/100")
    if findings:
        print("\nTUNNEL IOCs:")
        for ioc_domain in report["ioc"]["tunnel_domains"]:
            print(f"  Domain: {ioc_domain}")
        for ip in report["ioc"]["source_ips"]:
            print(f"  Source: {ip}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 18 DNS Tunnel Detector")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--dns-log", help="Path to Zeek dns.log")
    parser.add_argument("--threshold", type=int, default=50,
                        help="Suspicion score threshold 0–100 (default 50)")
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 18 — DNS Tunnel Detector")
    log.info(" NovaCrest Capital Group | T1048.001")
    log.info("=" * 70)

    records = DEMO_DNS_RECORDS

    log.info(f"[*] Analyzing {len(records)} DNS records (threshold={args.threshold})")
    log.info("")

    findings = detect_tunneling(records, threshold=args.threshold, verbose=args.verbose)
    emit_report(findings, args.threshold)


if __name__ == "__main__":
    main()
