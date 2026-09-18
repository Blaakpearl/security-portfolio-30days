"""
Day 26 — Threat Actor Profiler
NovaCrest Capital Group | Threat Intelligence

PURPOSE: Builds a structured threat actor profile for FIN-NC-001 by
         correlating NovaCrest IOCs with external intelligence sources,
         scoring attribution confidence, mapping techniques to ATT&CK
         groups, and predicting next-move activity based on playbook analysis.

INTELLIGENCE MODULES:
  1. IOC Enrichment     — Simulates VT/OTX/Shodan pivot results
  2. Actor Correlation  — Match IOC clusters to known threat groups
  3. TTP Analysis       — ATT&CK technique coverage + deviation analysis
  4. Infrastructure     — C2 hosting pattern, reuse, rotation cadence
  5. Targeting Profile  — Sector, geography, size, selection criteria
  6. Confidence Scoring — Admiralty Code + Diamond Model
  7. Next Move Intel    — Predictive analysis based on actor playbook

Usage:
    python actor_profiler.py --demo --verbose
    python actor_profiler.py --mode ioc-pivot --demo
    python actor_profiler.py --mode full-profile --demo
    python actor_profiler.py --mode next-move --demo
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
log = logging.getLogger("actor_profiler")


# ── Known Threat Groups for Correlation (Simplified ATT&CK-aligned) ────
KNOWN_GROUPS = {
    "GOLD MYSTIC": {
        "aliases": ["LockBit", "ABCD Group"],
        "motivation": "financial-gain",
        "targeting": ["financial", "healthcare", "manufacturing", "critical-infrastructure"],
        "geography": ["US", "EU", "AU", "CA"],
        "ttps": ["T1486","T1490","T1562.001","T1136.003","T1078.004",
                 "T1021.002","T1555.006","T1530","T1047"],
        "tools": ["LockBit", "Cobalt Strike", "Sliver"],
        "infrastructure_pattern": "Bulletproof hosting (NL/RU); frequent IP rotation",
        "ransomware_families": ["LockBit 2.0", "LockBit 3.0", "LockBit Green"],
        "double_extortion": True,
        "avg_ransom_usd": 4_200_000,
        "sector_focus": "financial-services",
        "dwell_time_days": "3-14",
        "note": "Ransomware-as-a-Service operation; builder kit leaked 2022",
    },
    "SCATTERED SPIDER": {
        "aliases": ["UNC3944", "Muddled Libra"],
        "motivation": "financial-gain",
        "targeting": ["financial", "telecom", "retail", "gaming"],
        "geography": ["US", "UK"],
        "ttps": ["T1566.002","T1621","T1078.004","T1530","T1537","T1619"],
        "tools": ["Okta MFA bombing", "SIM swap", "Cobalt Strike"],
        "infrastructure_pattern": "US/EU cloud providers; VPN exit nodes",
        "ransomware_families": ["BlackCat/ALPHV", "RansomHub"],
        "double_extortion": True,
        "avg_ransom_usd": 8_000_000,
        "sector_focus": "financial-services",
        "dwell_time_days": "7-30",
        "note": "Social engineering specialist; targets help desks and Okta",
    },
    "CARBON SPIDER": {
        "aliases": ["Anunak", "Carbanak", "FIN7"],
        "motivation": "financial-gain",
        "targeting": ["financial", "hospitality", "retail"],
        "geography": ["US", "EU", "AU"],
        "ttps": ["T1566.001","T1055","T1003.001","T1021.002","T1041",
                 "T1078","T1560","T1486"],
        "tools": ["Carbanak backdoor", "Cobalt Strike", "PowerShell Empire"],
        "infrastructure_pattern": "Compromised hosting; long-lived C2 infrastructure",
        "ransomware_families": ["DarkSide", "BlackMatter", "REvil (affiliated)"],
        "double_extortion": True,
        "avg_ransom_usd": 3_800_000,
        "sector_focus": "financial-services",
        "dwell_time_days": "14-180",
        "note": "Longest-running financial cybercrime group; ATM jackpotting history",
    },
}

# ── Simulated IOC Enrichment Results ──────────────────────────────────
SIMULATED_ENRICHMENT = {
    "198.51.100.99": {
        "vt_malicious_detections": 47,
        "vt_first_seen": "2026-04-12",
        "vt_last_seen": "2026-06-19",
        "asn": "AS209588",
        "asn_name": "Flyservers S.A.",
        "country": "NL",            # Netherlands — bulletproof hosting
        "city": "Amsterdam",
        "hosting_type": "Bulletproof VPS",
        "related_domains": [
            "trading-updates.novacrest-secure.com",
            "updates-cdn.financialdata.net",
            "telemetry.marketsync.io",
        ],
        "related_hashes": [
            "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
            "c3f4e5d6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",  # Prior victim
        ],
        "prior_campaigns": ["Financial sector phishing April 2026", "EU asset manager March 2026"],
        "otx_pulses": 3,
        "ransomwatch_hits": 1,
        "shodan_ports": [443, 80, 8443, 22],
        "shodan_jarm": "1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c",
        "intel_note": "IP previously flagged in FS-ISAC advisory TLP:WHITE April 2026 re: financial sector C2",
    },
    "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3": {
        "vt_malicious_detections": 34,
        "vt_name": "Ransom.LockBit.ncrypt",
        "vt_family": "LockBit",
        "vt_type": "win32 exe",
        "malwarebazaar_tags": ["lockbit", "ransomware", "double-extortion"],
        "sandbox_behavior": [
            "Deletes shadow copies",
            "Disables Windows Defender",
            "Creates mutex Global\\NovaCryptMutex_*",
            "Connects to 198.51.100.99:443",
            "Enumerates network shares",
        ],
        "similar_samples": [
            "Prior LockBit 3.0 sample April 2026 (EU financial sector)",
            "LockBit builder output confirmed by Ghidra code diff",
        ],
        "intel_note": "Matches LockBit 3.0 builder kit (leaked Sept 2022). Custom victim build confirmed by mutex.",
    },
    "ncrypt-support@protonmail.com": {
        "first_seen": "2026-03-15",
        "prior_victims": [
            "EU asset manager (March 2026) — ransom paid, data not published",
            "US hedge fund (April 2026) — negotiated, partial decryption",
            "UK private equity (May 2026) — did not pay, data published",
        ],
        "ransom_pattern": "Always demands 3-5% of victim AUM in Monero",
        "negotiation_pattern": "Responds within 4 hours; offers 30-40% discount for quick payment",
        "intel_note": "Email active since March 2026; 3 confirmed prior victims in financial sector",
    },
}

# ── ATT&CK Technique Coverage (NovaCrest vs Known Groups) ─────────────
NOVACREST_TTPS = [
    "T1598.002",  # Spearphishing via service (LinkedIn/conference)
    "T1566.001",  # Spearphishing attachment (macro)
    "T1204.002",  # User execution: malicious file
    "T1059.003",  # PowerShell
    "T1055.002",  # Process injection
    "T1547.001",  # Registry run key persistence
    "T1543.003",  # Windows service
    "T1548.002",  # UAC bypass
    "T1134.001",  # Token impersonation
    "T1558.003",  # Kerberoasting
    "T1550.002",  # Pass-the-Ticket
    "T1021.002",  # Lateral movement SMB
    "T1047",      # WMI execution
    "T1071.001",  # C2 over HTTPS
    "T1573.002",  # Encrypted channel: asymmetric
    "T1008",      # Fallback channels
    "T1555.006",  # Secrets Manager credentials
    "T1530",      # S3 data access
    "T1537",      # Transfer to cloud
    "T1048.003",  # Exfil over HTTPS
    "T1041",      # Exfil over C2
    "T1136.003",  # Create cloud account (backdoor)
    "T1078.004",  # Valid cloud accounts
    "T1562.008",  # Disable cloud logs
    "T1562.001",  # Disable security tools (Defender)
    "T1070.001",  # Clear Windows event logs
    "T1486",      # Data encrypted for impact
    "T1490",      # Inhibit system recovery
    "T1489",      # Service stop
]


def enrich_iocs(iocs: Dict, verbose: bool) -> List[Dict]:
    """Simulate IOC enrichment from threat intel platforms."""
    results = []
    for ioc, enrichment in iocs.items():
        result = {"ioc": ioc, "enrichment": enrichment}
        results.append(result)
        if verbose:
            detections = enrichment.get("vt_malicious_detections", 0)
            intel_note = enrichment.get("intel_note", "")
            icon = "🔴" if detections > 20 else "🟠" if detections > 5 else "🟡"
            log.info(f"  {icon} {ioc[:40]:42} VT:{detections:3d} — {intel_note[:55]}")
    return results


def correlate_actor(novacrest_ttps: List[str],
                    known_groups: Dict, verbose: bool) -> List[Dict]:
    """Score similarity between NovaCrest TTPs and known threat groups."""
    results = []
    for group_name, profile in known_groups.items():
        group_ttps = set(profile["ttps"])
        nc_ttps = set(novacrest_ttps)
        overlap = nc_ttps & group_ttps
        overlap_pct = len(overlap) / len(group_ttps) * 100

        # Additional signal matching
        signals = []
        if profile.get("double_extortion"):
            signals.append("double-extortion model matches")
        if "financial-services" in profile.get("sector_focus", ""):
            signals.append("financial sector targeting aligns")
        if "LockBit" in str(profile.get("ransomware_families", [])):
            signals.append("LockBit 3.0 builder variant confirmed")
        if "Sliver" in str(profile.get("tools", [])):
            signals.append("Sliver C2 tooling matches")

        # Confidence scoring
        base_score = overlap_pct
        signal_bonus = len(signals) * 8
        confidence = min(int(base_score + signal_bonus), 95)

        results.append({
            "group": group_name,
            "ttp_overlap_count": len(overlap),
            "ttp_overlap_pct": round(overlap_pct, 1),
            "matching_signals": signals,
            "confidence_pct": confidence,
            "avg_ransom": profile["avg_ransom_usd"],
            "dwell_time": profile["dwell_time_days"],
            "note": profile.get("note", ""),
        })
        if verbose:
            icon = "🔴" if confidence >= 70 else "🟠" if confidence >= 40 else "⬜"
            log.info(f"  {icon} {group_name}: {confidence}% confidence "
                     f"({len(overlap)}/{len(group_ttps)} TTPs match)")
            for sig in signals[:2]:
                log.info(f"       + {sig}")

    return sorted(results, key=lambda x: -x["confidence_pct"])


def score_confidence_admiralty(attribution: List[Dict]) -> Dict:
    """Apply Admiralty Code confidence framework to attribution."""
    top = attribution[0] if attribution else {}
    confidence = top.get("confidence_pct", 0)

    # Source reliability (A-F): A=completely reliable, F=reliability unknown
    source_reliability = "B"   # Usually reliable (VT, sandbox, FS-ISAC, prior victims)

    # Information credibility (1-6): 1=confirmed, 6=impossible to judge
    if confidence >= 80:
        info_credibility = "2"   # Probably true
    elif confidence >= 60:
        info_credibility = "3"   # Possibly true
    else:
        info_credibility = "4"   # Doubtful

    admiralty_rating = f"{source_reliability}{info_credibility}"

    return {
        "admiralty_code": admiralty_rating,
        "attribution_confidence_pct": confidence,
        "primary_suspect": top.get("group", "Unknown"),
        "confidence_label": (
            "HIGH (≥80%)" if confidence >= 80 else
            "MEDIUM (60–79%)" if confidence >= 60 else
            "LOW (<60%)"
        ),
        "caveats": [
            "LockBit builder kit is publicly available — impersonation possible",
            "C2 IP may be shared infrastructure (bulletproof hosting resold)",
            "Attribution based on TTPs and tooling; no human intelligence source",
            "Confidence would increase with: additional victim correlation, dark web actor comms, law enforcement deconfliction",
        ],
    }


def predict_next_move(profile: Dict, verbose: bool) -> List[Dict]:
    """Predict threat actor next actions based on playbook analysis."""
    predictions = [
        {
            "scenario": "Ransom deadline expires (unpaid)",
            "probability": "HIGH (70%)",
            "timeframe": "2026-06-22 06:14 UTC (deadline)",
            "action": "Publish client financial data on http://ncrypt3k4j7mxbwz.onion/novacrest",
            "impact": "SEC mandatory disclosure; client notification; reputational damage",
            "mitigation": "Legal injunction preparation; SEC pre-notification; client outreach plan",
        },
        {
            "scenario": "Use IAM backdoor (svc-monitoring-ops) for persistence",
            "probability": "HIGH (85%) — key already used June 18",
            "timeframe": "Ongoing until key deleted",
            "action": "Additional S3 data access; potential secondary ransomware deployment",
            "impact": "Additional data exfil; second encryption event possible",
            "mitigation": "DELETE AKIAIOSFODNN7BACKDOOR IMMEDIATELY",
        },
        {
            "scenario": "Target other NovaCrest employees (lateral spearphishing)",
            "probability": "MEDIUM (45%)",
            "timeframe": "Within 30 days",
            "action": "Phishing campaign using NovaCrest domain knowledge; target C-suite",
            "impact": "Additional credential compromise; executive account takeover",
            "mitigation": "MFA enforcement; security awareness training; email gateway rules for NovaCrest impersonation",
        },
        {
            "scenario": "Sell stolen data to competitor/short-seller",
            "probability": "MEDIUM (40%)",
            "timeframe": "Within 60 days",
            "action": "Market client portfolio data and trading algorithm to financial adversaries",
            "impact": "Front-running of NovaCrest positions; competitive intelligence loss",
            "mitigation": "Trading desk awareness; monitor for unusual market activity in NovaCrest positions",
        },
        {
            "scenario": "Additional financial sector targeting using NovaCrest intel",
            "probability": "MEDIUM (35%)",
            "timeframe": "Within 90 days",
            "action": "Use harvested Bloomberg API patterns and financial sector knowledge for next victim",
            "impact": "NovaCrest client/counterparty ecosystem at risk",
            "mitigation": "FS-ISAC IOC sharing; notify counterparties of potential spearphishing",
        },
    ]
    if verbose:
        log.info("  Next-move predictions (by probability):")
        for p in sorted(predictions, key=lambda x: -int(x["probability"].split("(")[1].rstrip("%)"))):
            log.info(f"  → [{p['probability']}] {p['scenario']}")
            log.info(f"       Action: {p['action'][:60]}")
    return predictions


def emit_profile_report(enrichment: List[Dict], attribution: List[Dict],
                         confidence: Dict, predictions: List[Dict]) -> None:
    """Print full threat actor profile summary."""
    print("\n" + "=" * 70)
    print("  FIN-NC-001 THREAT ACTOR PROFILE — Day 26")
    print("  NovaCrest Capital Group | Case NCA-2026-06-TI")
    print("=" * 70 + "\n")

    print(f"  ATTRIBUTION: {confidence['primary_suspect']}")
    print(f"  Confidence:  {confidence['confidence_label']} ({confidence['attribution_confidence_pct']}%)")
    print(f"  Admiralty:   {confidence['admiralty_code']} (Source: Usually Reliable | Info: Probably True)")
    print()

    print("  IOC ENRICHMENT SUMMARY:")
    print("  " + "─" * 50)
    for r in enrichment:
        ioc = r["ioc"][:38]
        note = r["enrichment"].get("intel_note", "")[:50]
        print(f"  {ioc:40} {note}")
    print()

    print("  GROUP ATTRIBUTION SCORES:")
    print("  " + "─" * 50)
    for a in attribution:
        bar = "█" * (a["confidence_pct"] // 10)
        print(f"  {a['group']:20} {bar:10} {a['confidence_pct']}%")
    print()

    print("  TOP 3 PREDICTED NEXT MOVES:")
    print("  " + "─" * 50)
    top3 = sorted(predictions, key=lambda x: -int(x["probability"].split("(")[1].rstrip("%)"))
                  )[:3]
    for i, p in enumerate(top3, 1):
        print(f"  {i}. [{p['probability']}] {p['scenario']}")
        print(f"     → {p['action'][:60]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 26 Threat Actor Profiler")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--mode", choices=["ioc-pivot","correlate","next-move","full-profile"],
                        default="full-profile")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day26_actor_profile.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 26 — Threat Actor Profiler")
    log.info(" NovaCrest Capital Group | FIN-NC-001 Attribution")
    log.info("=" * 70)
    log.info("")

    log.info("[MODULE 1] IOC Enrichment (simulated VT + OTX + FS-ISAC)")
    enrichment = enrich_iocs(SIMULATED_ENRICHMENT, args.verbose)
    log.info("")

    log.info("[MODULE 2] Threat Actor Correlation (ATT&CK TTP matching)")
    attribution = correlate_actor(NOVACREST_TTPS, KNOWN_GROUPS, args.verbose)
    log.info("")

    log.info("[MODULE 3] Confidence Scoring (Admiralty Code)")
    confidence = score_confidence_admiralty(attribution)
    log.info(f"  Attribution: {confidence['primary_suspect']} — "
             f"{confidence['confidence_label']} ({confidence['admiralty_code']})")
    log.info("")

    log.info("[MODULE 4] Next-Move Prediction")
    predictions = predict_next_move({}, args.verbose)
    log.info("")

    emit_profile_report(enrichment, attribution, confidence, predictions)

    output = {
        "case": "NCA-2026-06-TI",
        "actor_designation": "FIN-NC-001",
        "ioc_enrichment": enrichment,
        "attribution": attribution,
        "confidence": confidence,
        "next_move_predictions": predictions,
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Profile written: {args.output}")


if __name__ == "__main__":
    main()
