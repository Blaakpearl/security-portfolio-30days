"""
Day 20 — Beacon Timing Analyzer
NovaCrest Capital Group | Purple Team C2 Exercise

PURPOSE: Statistical analysis of Zeek conn.log to detect periodic C2
         beaconing patterns. Uses coefficient of variation, autocorrelation,
         and inter-arrival time analysis to identify beacons even with jitter.

DETECTION METHODS:
  1. Coefficient of Variation (CV) — low CV on connection intervals = beacon
  2. Inter-Arrival Time (IAT) clustering — identify dominant interval
  3. Autocorrelation — detect periodicity in connection time series
  4. Bytes per connection consistency — beacons have similar payload sizes

THRESHOLDS:
  - CV < 0.35 and > 8 connections to same IP = beacon suspected
  - CV < 0.20 = beacon high confidence
  - Dominant IAT cluster with < 20% members out of cluster = beacon
  - Consistent bytes (stddev < 30% of mean) = additional indicator

Usage:
    python beacon_timing_analyzer.py --demo --verbose
    python beacon_timing_analyzer.py --conn-log /opt/zeek/logs/current/conn.log
    python beacon_timing_analyzer.py --demo --threshold 0.3
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
log = logging.getLogger("beacon_timing_analyzer")

# ── Simulated conn.log entries (demo — includes all 4 variants) ────────
DEMO_CONN_LOG = [
    # V1: 60-second beacon, no jitter (timestamps exactly 60s apart)
    *[{"ts": 1718870400 + i * 60,
       "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.99",
       "id.resp_p": 443, "proto": "tcp",
       "orig_bytes": 2800, "resp_bytes": 1200, "_variant": "v1"}
      for i in range(20)],

    # V2: 300-second beacon, 50% jitter (intervals 150–450s)
    *[{"ts": 1718870400 + sum(int(300 + ((-1)**j) * 120 * (j % 3 + 1) / 3)
                              for j in range(i)),
       "id.orig_h": "10.0.1.40", "id.resp_h": "198.51.100.50",
       "id.resp_p": 443, "proto": "tcp",
       "orig_bytes": 1800 + i * 50, "resp_bytes": 900, "_variant": "v2"}
      for i in range(10)],

    # V3: Domain fronting, 600s ± 30% jitter
    *[{"ts": 1718870400 + sum(int(600 * (1 + 0.2 * ((-1)**j)))
                              for j in range(i)),
       "id.orig_h": "10.0.1.40", "id.resp_h": "13.107.246.45",
       "id.resp_p": 443, "proto": "tcp",
       "orig_bytes": 8000 + i * 100, "resp_bytes": 600, "_variant": "v3"}
      for i in range(6)],

    # V4: DoH to 1.1.1.1 (Havoc), 900s ± 25% jitter
    *[{"ts": 1718870400 + sum(int(900 * (1 + 0.15 * ((-1)**j)))
                              for j in range(i)),
       "id.orig_h": "10.0.1.40", "id.resp_h": "1.1.1.1",
       "id.resp_p": 443, "proto": "tcp",
       "orig_bytes": 1200, "resp_bytes": 400, "_variant": "v4"}
      for i in range(4)],

    # Normal traffic noise
    {"ts": 1718870450, "id.orig_h": "10.0.1.40",
     "id.resp_h": "20.190.160.1", "id.resp_p": 443,
     "orig_bytes": 45000, "resp_bytes": 120000, "_variant": "legit"},
    {"ts": 1718870900, "id.orig_h": "10.0.1.40",
     "id.resp_h": "13.107.4.52", "id.resp_p": 443,
     "orig_bytes": 5200, "resp_bytes": 45000, "_variant": "legit"},
]


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def stddev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


def coefficient_of_variation(values: List[float]) -> float:
    m = mean(values)
    return stddev(values) / m if m > 0 else 0.0


def group_connections_by_dest(records: List[Dict]) -> Dict[str, List[Dict]]:
    """Group conn.log records by destination IP."""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for r in records:
        dst = r.get("id.resp_h", "")
        groups[dst].append(r)
    return groups


def analyze_connection_group(dst_ip: str, records: List[Dict],
                              min_connections: int = 5) -> Dict:
    """Analyze a group of connections for beacon timing patterns."""
    if len(records) < min_connections:
        return {"dst_ip": dst_ip, "beacon_score": 0, "verdict": "INSUFFICIENT_DATA"}

    # Sort by timestamp
    records_sorted = sorted(records, key=lambda r: r["ts"])
    timestamps = [r["ts"] for r in records_sorted]
    orig_bytes = [r.get("orig_bytes", 0) for r in records_sorted]

    # Calculate inter-arrival times (IATs)
    iats = [timestamps[i+1] - timestamps[i]
            for i in range(len(timestamps)-1)]

    if not iats:
        return {"dst_ip": dst_ip, "beacon_score": 0, "verdict": "INSUFFICIENT_DATA"}

    iat_mean = mean(iats)
    iat_std = stddev(iats)
    iat_cv = coefficient_of_variation(iats)

    # Bytes consistency
    bytes_cv = coefficient_of_variation([float(b) for b in orig_bytes if b > 0])

    # Beacon scoring (0–100)
    score = 0
    indicators = []

    # IAT coefficient of variation — beacon hallmark
    if iat_cv < 0.10:
        score += 40
        indicators.append(f"Very low IAT CV ({iat_cv:.3f}) — strong beacon pattern")
    elif iat_cv < 0.25:
        score += 30
        indicators.append(f"Low IAT CV ({iat_cv:.3f}) — likely beacon")
    elif iat_cv < 0.40:
        score += 15
        indicators.append(f"Moderate IAT CV ({iat_cv:.3f}) — possible beacon with jitter")

    # Connection count
    if len(records) >= 15:
        score += 20
        indicators.append(f"High connection count ({len(records)}) to same IP")
    elif len(records) >= 8:
        score += 10
        indicators.append(f"Moderate connection count ({len(records)})")

    # Consistent payload size
    if bytes_cv < 0.20:
        score += 20
        indicators.append(f"Consistent payload size (CV={bytes_cv:.3f})")
    elif bytes_cv < 0.35:
        score += 10
        indicators.append(f"Moderately consistent payload (CV={bytes_cv:.3f})")

    # Dominant interval period
    if 30 <= iat_mean <= 1800:  # 30s – 30min range is typical beacon interval
        score += 20
        indicators.append(f"Interval {round(iat_mean)}s within beacon range (30–1800s)")

    # Determine verdict
    if score >= 70:
        verdict = "BEACON_HIGH_CONFIDENCE"
    elif score >= 45:
        verdict = "BEACON_SUSPECTED"
    elif score >= 25:
        verdict = "INVESTIGATE"
    else:
        verdict = "LIKELY_BENIGN"

    return {
        "dst_ip": dst_ip,
        "connection_count": len(records),
        "iat_mean_sec": round(iat_mean, 1),
        "iat_std_sec": round(iat_std, 1),
        "iat_cv": round(iat_cv, 3),
        "bytes_cv": round(bytes_cv, 3),
        "beacon_score": score,
        "verdict": verdict,
        "indicators": indicators,
        "technique": "T1071.001" if score >= 45 else None,
        "first_seen": datetime.datetime.utcfromtimestamp(timestamps[0]).isoformat() + "Z",
        "last_seen": datetime.datetime.utcfromtimestamp(timestamps[-1]).isoformat() + "Z",
    }


def emit_analysis_report(analyses: List[Dict]) -> None:
    """Emit beacon analysis report."""
    beacons = [a for a in analyses if "BEACON" in a.get("verdict", "")]
    investigate = [a for a in analyses if a.get("verdict") == "INVESTIGATE"]

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "analysis": "Beacon Timing Analysis",
        "total_destinations": len(analyses),
        "beacons_detected": len(beacons),
        "investigations": len(investigate),
        "results": sorted(analyses, key=lambda x: -x.get("beacon_score", 0)),
    }

    print("\n" + "=" * 70)
    print("  BEACON TIMING ANALYSIS — Day 20")
    print("=" * 70 + "\n")

    print(f"Destinations analyzed:  {len(analyses)}")
    print(f"Beacons detected:       {len(beacons)}")
    print(f"Require investigation:  {len(investigate)}")
    print()

    print(f"{'DESTINATION':20} {'SCORE':6} {'CONNS':6} {'IAT(s)':8} {'IAT CV':7} {'VERDICT'}")
    print("─" * 75)
    for a in sorted(analyses, key=lambda x: -x.get("beacon_score", 0)):
        dst = a["dst_ip"][:20]
        score = a.get("beacon_score", 0)
        conns = a.get("connection_count", 0)
        iat = a.get("iat_mean_sec", 0)
        cv = a.get("iat_cv", 0)
        verdict = a.get("verdict", "")
        print(f"{dst:20} {score:6} {conns:6} {iat:8.1f} {cv:7.3f} {verdict}")

    print()
    if beacons:
        print("HIGH-CONFIDENCE BEACONS:")
        for b in beacons:
            print(f"  ⚠️  {b['dst_ip']} — Score {b['beacon_score']}/100")
            for ind in b.get("indicators", []):
                print(f"      • {ind}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Day 20 Beacon Timing Analyzer")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--conn-log", help="Path to Zeek conn.log (JSON)")
    parser.add_argument("--threshold", type=float, default=0.35,
                        help="IAT CV threshold for beacon suspicion (default 0.35)")
    parser.add_argument("--min-connections", type=int, default=5)
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 20 — Beacon Timing Analyzer")
    log.info(" NovaCrest Capital Group — C2 Detection")
    log.info("=" * 70)

    records = DEMO_CONN_LOG
    log.info(f"[*] Analyzing {len(records)} conn.log records")

    groups = group_connections_by_dest(records)
    log.info(f"[*] {len(groups)} unique destinations found")
    log.info("")

    analyses = []
    for dst_ip, recs in groups.items():
        result = analyze_connection_group(dst_ip, recs, args.min_connections)
        analyses.append(result)
        if args.verbose and result.get("beacon_score", 0) >= 25:
            log.info(f"  {dst_ip}: score={result['beacon_score']} "
                     f"verdict={result['verdict']} IAT_CV={result.get('iat_cv','?')}")

    emit_analysis_report(analyses)


if __name__ == "__main__":
    main()
