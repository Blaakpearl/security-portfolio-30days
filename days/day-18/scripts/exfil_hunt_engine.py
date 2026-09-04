"""
Day 18 — Exfiltration Hunt Engine
NovaCrest Capital Group | Threat Hunt

PURPOSE: Parse Zeek network logs and apply multi-hypothesis detection logic
         to identify data exfiltration patterns following confirmed privilege
         escalation (Day 17). Covers DNS tunneling, HTTPS exfil, data staging,
         cloud storage uploads, volumetric anomalies, and scheduled transfers.

DATA SOURCES:
  Zeek conn.log   — connection metadata (bytes, duration, destination)
  Zeek dns.log    — DNS queries (for tunneling detection)
  Zeek ssl.log    — TLS connections (certificate anomalies, JA3)
  Zeek files.log  — File transfers (archives, large files)

HYPOTHESES:
  H1 — DNS tunneling (T1048.001)
  H2 — HTTPS exfiltration (T1048.002)
  H3 — Local data staging / archiving (T1560.001)
  H4 — Cloud storage exfiltration (T1567.002)
  H5 — Volumetric anomaly (T1030)
  H6 — Scheduled / automated exfiltration (T1029)

Usage:
    python exfil_hunt_engine.py --demo --verbose
    python exfil_hunt_engine.py --conn-log conn.log --dns-log dns.log --verbose
    python exfil_hunt_engine.py --demo --baseline-report
    python exfil_hunt_engine.py --json --demo
"""

import argparse
import datetime
import json
import logging
import math
import sys
from collections import defaultdict
from typing import List, Dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("exfil_hunt_engine")


# ── Known cloud storage / exfil destinations ───────────────────────────
CLOUD_STORAGE_DOMAINS = {
    "s3.amazonaws.com", "amazonaws.com", "blob.core.windows.net",
    "dropbox.com", "www.dropbox.com", "content.dropboxapi.com",
    "onedrive.live.com", "sharepoint.com", "drive.google.com",
    "storage.googleapis.com", "mega.nz", "anonfiles.com",
    "wetransfer.com", "paste.ee", "hastebin.com", "pastebin.com",
}

KNOWN_C2_JA3 = {
    "51c64c77e60f3980eea90869b68c58a8",  # Metasploit default
    "a0e9f5d64349fb13191bc781f81f42e1",  # Cobalt Strike
    "6734f37431670b3ab4292b8f60f29984",  # Sliver C2
}

# ── Simulated Zeek log events (demo mode) ─────────────────────────────
SIMULATED_CONN_LOG = [
    # Normal traffic
    {"ts": "1718359200.0", "id.orig_h": "10.0.1.40", "id.resp_h": "8.8.8.8",
     "proto": "udp", "service": "dns", "orig_bytes": 120, "resp_bytes": 200, "duration": 0.05},
    {"ts": "1718359500.0", "id.orig_h": "10.0.1.40", "id.resp_h": "13.107.4.52",
     "proto": "tcp", "service": "https", "orig_bytes": 5200, "resp_bytes": 45000, "duration": 2.3},
    # H5: Anomalous large egress from compromised host
    {"ts": "1718362800.0", "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.99",
     "proto": "tcp", "service": "https", "orig_bytes": 125_000_000,
     "resp_bytes": 1200, "duration": 480.0,
     "note": "125 MB outbound to unknown IP — data exfiltration"},
    # H4: Upload to S3
    {"ts": "1718363400.0", "id.orig_h": "10.0.1.40", "id.resp_h": "52.216.0.1",
     "proto": "tcp", "service": "https", "orig_bytes": 85_000_000,
     "resp_bytes": 800, "duration": 310.0,
     "note": "85 MB to amazonaws.com — cloud exfil staging"},
    # H6: Recurring scheduled transfer (same destination, every 30 min)
    {"ts": "1718366400.0", "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.99",
     "proto": "tcp", "service": "https", "orig_bytes": 22_000_000,
     "resp_bytes": 900, "duration": 90.0,
     "note": "Recurring transfer — same dest, 30 min later"},
    {"ts": "1718368200.0", "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.99",
     "proto": "tcp", "service": "https", "orig_bytes": 21_500_000,
     "resp_bytes": 850, "duration": 88.0,
     "note": "Recurring transfer — 30 min interval pattern"},
]

SIMULATED_DNS_LOG = [
    # Normal DNS
    {"ts": "1718359210.0", "id.orig_h": "10.0.1.40",
     "query": "www.google.com", "qtype_name": "A", "answers": ["142.250.80.36"]},
    {"ts": "1718359215.0", "id.orig_h": "10.0.1.40",
     "query": "microsoft.com", "qtype_name": "A", "answers": ["20.236.44.162"]},
    # H1: DNS tunneling — high-entropy subdomain queries
    {"ts": "1718361000.0", "id.orig_h": "10.0.1.40",
     "query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGF5bG9hZA.tunnel.evil-c2.com",
     "qtype_name": "TXT", "answers": [],
     "note": "Base64 payload in subdomain — DNS tunnel indicator"},
    {"ts": "1718361005.0", "id.orig_h": "10.0.1.40",
     "query": "dGhpcyBpcyBhbm90aGVyIGJhc2U2NCBlbmNvZGVkIHBheWxvYWQ.tunnel.evil-c2.com",
     "qtype_name": "TXT", "answers": [],
     "note": "Second TXT query — DNS exfil in progress"},
    {"ts": "1718361010.0", "id.orig_h": "10.0.1.40",
     "query": "cGF5bG9hZCBudW1iZXIgdGhyZWUgdGhpcyBpcyBkYXRh.tunnel.evil-c2.com",
     "qtype_name": "TXT", "answers": [],
     "note": "Third TXT query — DNS exfil continued"},
    {"ts": "1718361015.0", "id.orig_h": "10.0.1.40",
     "query": "ZmluYWwgcGF5bG9hZCBkYXRhIGV4ZmlsdHJhdGlvbg.tunnel.evil-c2.com",
     "qtype_name": "NULL", "answers": [],
     "note": "NULL record DNS query — advanced tunnel technique"},
]

SIMULATED_SSL_LOG = [
    # Normal HTTPS
    {"ts": "1718359500.0", "id.orig_h": "10.0.1.40",
     "server_name": "login.microsoftonline.com",
     "validation_status": "ok", "ja3": "3b5074b1b5d032e5620f69f9f700ff0e"},
    # H2: Unknown destination with suspicious JA3
    {"ts": "1718362800.0", "id.orig_h": "10.0.1.40",
     "server_name": "data-xfer.evil-c2.com",
     "validation_status": "self signed certificate",
     "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
     "note": "Cobalt Strike JA3 fingerprint + self-signed cert"},
    # H4: S3 cloud upload
    {"ts": "1718363400.0", "id.orig_h": "10.0.1.40",
     "server_name": "novacrest-exfil.s3.amazonaws.com",
     "validation_status": "ok", "ja3": "3b5074b1b5d032e5620f69f9f700ff0e",
     "note": "S3 bucket novacrest-exfil — possibly attacker-controlled"},
]

SIMULATED_FILES_LOG = [
    # H3: Archive file created and transferred
    {"ts": "1718362700.0", "tx_hosts": ["10.0.1.40"], "rx_hosts": ["198.51.100.99"],
     "mime_type": "application/x-gzip", "filename": "trading_data_20260614.tar.gz",
     "total_bytes": 125_000_000,
     "note": "125 MB gzip archive transferred externally — data staging + exfil"},
    {"ts": "1718362650.0", "tx_hosts": ["10.0.1.40"], "rx_hosts": [],
     "mime_type": "application/x-gzip", "filename": "trading_data_20260614.tar.gz",
     "total_bytes": 125_000_000,
     "note": "Same archive — local staging event before transfer"},
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def hunt_h1_dns_tunneling(dns_records: List[Dict], verbose: bool) -> Dict:
    """H1: Detect DNS tunneling via entropy and query type analysis."""
    findings = []
    domain_query_counts = defaultdict(list)

    for r in dns_records:
        query = r.get("query", "")
        qtype = r.get("qtype_name", "A")
        src = r.get("id.orig_h", "unknown")

        parts = query.split(".")
        subdomain = parts[0] if parts else ""
        entropy = shannon_entropy(subdomain)
        query_len = len(query)

        # Extract apex domain (last 2 parts)
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else query
        domain_query_counts[apex].append(r)

        is_suspicious = (
            entropy > 3.5               # High entropy subdomain
            or query_len > 60           # Long query
            or qtype in ("TXT", "NULL", "CNAME", "MX")  # Unusual types for data
        )

        if is_suspicious:
            finding = {
                "hypothesis": "H1",
                "technique": "T1048.001",
                "timestamp": r.get("ts", "unknown"),
                "src_ip": src,
                "query": query,
                "qtype": qtype,
                "subdomain_entropy": round(entropy, 3),
                "query_length": query_len,
                "evidence": r.get("note", "Suspicious DNS query pattern"),
                "severity": "High",
            }
            findings.append(finding)

            if verbose:
                log.info(f"  [H1] DNS Tunnel: {query[:60]} (entropy={entropy:.2f}, type={qtype})")

    # Check for burst query pattern to single domain
    for apex, records in domain_query_counts.items():
        if len(records) >= 3 and "evil" in apex:
            findings.append({
                "hypothesis": "H1",
                "technique": "T1048.001",
                "severity": "Critical",
                "evidence": f"Burst DNS queries to {apex}: {len(records)} queries — DNS tunnel active",
                "query_count": len(records),
                "apex_domain": apex,
            })
            if verbose:
                log.warning(f"  [H1] BURST: {len(records)} queries to {apex} — DNS tunnel confirmed")

    return {
        "hypothesis": "H1",
        "name": "DNS Tunneling",
        "technique": "T1048.001",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def hunt_h2_https_exfil(ssl_records: List[Dict], verbose: bool) -> Dict:
    """H2: Detect HTTPS exfiltration via JA3 fingerprint and cert anomalies."""
    findings = []

    for r in ssl_records:
        ja3 = r.get("ja3", "")
        cert_status = r.get("validation_status", "ok")
        server_name = r.get("server_name", "")
        src = r.get("id.orig_h", "unknown")

        suspicious = False
        reasons = []

        if ja3 in KNOWN_C2_JA3:
            suspicious = True
            reasons.append(f"Known C2 JA3 fingerprint: {ja3}")
        if "self signed" in cert_status:
            suspicious = True
            reasons.append("Self-signed certificate")
        if any(kw in server_name for kw in ["evil", "c2", "tunnel", "exfil"]):
            suspicious = True
            reasons.append(f"Suspicious server name: {server_name}")

        if suspicious:
            finding = {
                "hypothesis": "H2",
                "technique": "T1048.002",
                "timestamp": r.get("ts", "unknown"),
                "src_ip": src,
                "server_name": server_name,
                "ja3": ja3,
                "cert_status": cert_status,
                "reasons": reasons,
                "evidence": r.get("note", "; ".join(reasons)),
                "severity": "Critical" if ja3 in KNOWN_C2_JA3 else "High",
            }
            findings.append(finding)
            if verbose:
                log.warning(f"  [H2] HTTPS Exfil: {server_name} — {'; '.join(reasons)}")

    return {
        "hypothesis": "H2",
        "name": "HTTPS Exfiltration",
        "technique": "T1048.002",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def hunt_h3_data_staging(files_records: List[Dict], verbose: bool) -> Dict:
    """H3: Detect data staging via archive file creation/transfer."""
    findings = []
    archive_mimes = {
        "application/x-gzip", "application/gzip", "application/zip",
        "application/x-tar", "application/x-7z-compressed",
        "application/x-rar-compressed",
    }

    for r in files_records:
        mime = r.get("mime_type", "")
        filename = r.get("filename", "")
        size = r.get("total_bytes", 0)

        if mime in archive_mimes and size > 1_000_000:  # > 1 MB archive
            findings.append({
                "hypothesis": "H3",
                "technique": "T1560.001",
                "timestamp": r.get("ts", "unknown"),
                "filename": filename,
                "mime_type": mime,
                "size_mb": round(size / 1_048_576, 1),
                "tx_hosts": r.get("tx_hosts", []),
                "rx_hosts": r.get("rx_hosts", []),
                "evidence": r.get("note", f"Archive file {filename} ({round(size/1_048_576,1)} MB)"),
                "severity": "Critical" if size > 50_000_000 else "High",
            })
            if verbose:
                log.warning(f"  [H3] Archive: {filename} ({round(size/1_048_576,1)} MB)")

    return {
        "hypothesis": "H3",
        "name": "Data Staging / Archiving",
        "technique": "T1560.001",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def hunt_h4_cloud_storage(ssl_records: List[Dict], conn_records: List[Dict],
                           verbose: bool) -> Dict:
    """H4: Detect exfiltration to cloud storage providers."""
    findings = []

    for r in ssl_records:
        server_name = r.get("server_name", "")
        src = r.get("id.orig_h", "unknown")
        if any(domain in server_name for domain in CLOUD_STORAGE_DOMAINS):
            findings.append({
                "hypothesis": "H4",
                "technique": "T1567.002",
                "timestamp": r.get("ts", "unknown"),
                "src_ip": src,
                "cloud_destination": server_name,
                "evidence": r.get("note", f"Connection to cloud storage: {server_name}"),
                "severity": "High",
            })
            if verbose:
                log.warning(f"  [H4] Cloud Exfil: {src} → {server_name}")

    return {
        "hypothesis": "H4",
        "name": "Cloud Storage Exfiltration",
        "technique": "T1567.002",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def hunt_h5_volumetric_anomaly(conn_records: List[Dict], verbose: bool,
                                baseline_mb: float = 50.0) -> Dict:
    """H5: Detect anomalous outbound data volume vs. 30-day baseline."""
    findings = []
    host_egress: Dict[str, float] = defaultdict(float)

    for r in conn_records:
        src = r.get("id.orig_h", "")
        dst = r.get("id.resp_h", "")
        orig_bytes = float(r.get("orig_bytes", 0))
        # Only count egress to external IPs
        if src.startswith("10.") and not dst.startswith("10."):
            host_egress[src] += orig_bytes

    for host, total_bytes in host_egress.items():
        total_mb = total_bytes / 1_048_576
        if total_mb > baseline_mb:
            sigma = (total_mb - baseline_mb) / (baseline_mb * 0.2)  # simplified
            findings.append({
                "hypothesis": "H5",
                "technique": "T1030",
                "src_host": host,
                "total_egress_mb": round(total_mb, 1),
                "baseline_mb": baseline_mb,
                "sigma_deviation": round(sigma, 1),
                "evidence": f"{host} sent {round(total_mb,1)} MB external (baseline: {baseline_mb} MB)",
                "severity": "Critical" if sigma > 5 else "High",
            })
            if verbose:
                log.warning(f"  [H5] Volume: {host} → {round(total_mb,1)} MB egress ({round(sigma,1)}σ above baseline)")

    return {
        "hypothesis": "H5",
        "name": "Volumetric Anomaly",
        "technique": "T1030",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def hunt_h6_scheduled_transfer(conn_records: List[Dict], verbose: bool) -> Dict:
    """H6: Detect periodic/automated exfiltration via interval pattern."""
    findings = []
    dst_times: Dict[str, List[float]] = defaultdict(list)

    for r in conn_records:
        dst = r.get("id.resp_h", "")
        ts = float(r.get("ts", 0))
        orig_bytes = float(r.get("orig_bytes", 0))
        if orig_bytes > 1_000_000:  # Only track substantial transfers
            dst_times[dst].append(ts)

    for dst, timestamps in dst_times.items():
        if len(timestamps) < 2:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)

        # Low variance = regular schedule
        if variance < (avg_interval * 0.1)**2 and avg_interval < 3600:
            findings.append({
                "hypothesis": "H6",
                "technique": "T1029",
                "dst_ip": dst,
                "transfer_count": len(timestamps),
                "avg_interval_sec": round(avg_interval),
                "avg_interval_min": round(avg_interval / 60, 1),
                "variance": round(variance, 1),
                "evidence": f"Periodic transfers to {dst}: {len(timestamps)} transfers every {round(avg_interval/60,1)} min",
                "severity": "High",
            })
            if verbose:
                log.warning(f"  [H6] Scheduled: {len(timestamps)} transfers to {dst} every {round(avg_interval/60,1)} min")

    return {
        "hypothesis": "H6",
        "name": "Scheduled / Automated Exfiltration",
        "technique": "T1029",
        "confirmed": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if findings else "NOT FOUND",
    }


def emit_hunt_report(results: List[Dict]) -> None:
    confirmed = [r for r in results if r["confirmed"]]
    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "hunt": "Data Exfiltration Patterns",
        "day": 18,
        "window": "2026-06-14 10:00 → 2026-06-15 06:00 UTC",
        "summary": {
            "hypotheses_tested": len(results),
            "confirmed": len(confirmed),
            "ruled_out": len(results) - len(confirmed),
        },
        "results": results,
        "overall_verdict": "DATA EXFILTRATION CONFIRMED" if confirmed else "NO EXFILTRATION FOUND",
    }

    print("\n" + "=" * 70)
    print("  EXFILTRATION HUNT REPORT — Day 18")
    print("=" * 70 + "\n")
    print(json.dumps(report, indent=2))
    print("\n" + "=" * 70 + "\n")

    print("HUNT SUMMARY")
    print("─" * 55)
    for r in results:
        icon = "✅ CONFIRMED" if r["confirmed"] else "⬜ NOT FOUND"
        print(f"  {r['hypothesis']} [{r['technique']}] {r['name']:35} {icon}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 18 Exfiltration Hunt Engine")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--conn-log", help="Path to Zeek conn.log")
    parser.add_argument("--dns-log", help="Path to Zeek dns.log")
    parser.add_argument("--ssl-log", help="Path to Zeek ssl.log")
    parser.add_argument("--files-log", help="Path to Zeek files.log")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 18 — Exfiltration Hunt Engine")
    log.info(" NovaCrest Capital Group — Data Exfil Patterns")
    log.info("=" * 70)
    log.info(" Mode: Demo (simulated Zeek telemetry)" if args.demo else " Mode: Live logs")
    log.info("")

    conn_records  = SIMULATED_CONN_LOG
    dns_records   = SIMULATED_DNS_LOG
    ssl_records   = SIMULATED_SSL_LOG
    files_records = SIMULATED_FILES_LOG

    results = []
    log.info("[H1] DNS Tunneling Hunt")
    results.append(hunt_h1_dns_tunneling(dns_records, args.verbose))
    log.info("[H2] HTTPS Exfiltration Hunt")
    results.append(hunt_h2_https_exfil(ssl_records, args.verbose))
    log.info("[H3] Data Staging Hunt")
    results.append(hunt_h3_data_staging(files_records, args.verbose))
    log.info("[H4] Cloud Storage Exfil Hunt")
    results.append(hunt_h4_cloud_storage(ssl_records, conn_records, args.verbose))
    log.info("[H5] Volumetric Anomaly Hunt")
    results.append(hunt_h5_volumetric_anomaly(conn_records, args.verbose))
    log.info("[H6] Scheduled Transfer Hunt")
    results.append(hunt_h6_scheduled_transfer(conn_records, args.verbose))
    log.info("")

    emit_hunt_report(results)


if __name__ == "__main__":
    main()
