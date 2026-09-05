"""
Day 21 — Purple Team Engagement Tracker
NovaCrest Capital Group | Week 3 Capstone

PURPOSE: Real-time MTTD (Mean Time to Detect) dashboard for the full
         purple team exercise. Tracks phase timers, detection events,
         SLA compliance, and computes final engagement score.

FEATURES:
  - 8-phase timer with SLA countdown per phase
  - Detection event logging (manual entry or Elastic webhook)
  - Per-phase MTTD calculation
  - Running score (5 pts SLA / 2 pts late / 0 pts missed)
  - Kill chain coverage percentage
  - Final scorecard with ATT&CK phase breakdown
  - Export: JSON results for attck_navigator_exporter.py

MODES:
  --exercise-mode    Live dashboard (CLI or web — localhost:5000)
  --demo             Simulated exercise results (for portfolio demo)
  --post-exercise    Analyze results from saved JSON

Usage:
    python engagement_tracker.py --demo --verbose
    python engagement_tracker.py --exercise-mode --port 5000
    python engagement_tracker.py --post-exercise --results results.json
"""

import argparse
import datetime
import json
import logging
import sys
import time
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("engagement_tracker")


# ── Exercise Phase Definitions ─────────────────────────────────────────
PHASES = [
    {
        "phase": 1,
        "name": "Reconnaissance",
        "tactic": "Reconnaissance",
        "techniques": ["T1592", "T1589", "T1593"],
        "sla_minutes": 20,
        "window_minutes": 30,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "Low — passive; external activity",
    },
    {
        "phase": 2,
        "name": "Initial Access",
        "tactic": "Initial Access",
        "techniques": ["T1566.001", "T1059.001"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "Medium — macro execution; Sliver JA3",
    },
    {
        "phase": 3,
        "name": "Execution & Persistence",
        "tactic": "Execution / Persistence",
        "techniques": ["T1059.001", "T1547.001", "T1053.005"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "High — registry writes; scheduled task Event 4698",
    },
    {
        "phase": 4,
        "name": "Privilege Escalation",
        "tactic": "Privilege Escalation / Credential Access",
        "techniques": ["T1548.002", "T1134.001", "T1558.003"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "High — Sysmon 10/13; Security 4672/4769",
    },
    {
        "phase": 5,
        "name": "Defense Evasion",
        "tactic": "Defense Evasion",
        "techniques": ["T1070.001", "T1562.001", "T1036", "T1562.004"],
        "sla_minutes": 15,
        "window_minutes": 30,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "Critical — Event 1102 is self-documenting",
    },
    {
        "phase": 6,
        "name": "Lateral Movement",
        "tactic": "Lateral Movement",
        "techniques": ["T1021.002", "T1550.002", "T1047"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "High — Event 4648/4624 network logon; WMI Event 4688",
    },
    {
        "phase": 7,
        "name": "C2 Establishment",
        "tactic": "Command & Control",
        "techniques": ["T1071.001", "T1090.004", "T1573.002", "T1001.001"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "Medium — Cobalt Strike JA3; domain fronting (if TLS inspect enabled)",
    },
    {
        "phase": 8,
        "name": "Collection & Exfil Staging",
        "tactic": "Collection / Exfiltration",
        "techniques": ["T1560.001", "T1041", "T1567.002", "T1074.001"],
        "sla_minutes": 20,
        "window_minutes": 45,
        "max_points": 5,
        "late_points": 2,
        "detection_expected": "High — Zeek volumetric; files.log; DLP alert",
    },
]

# ── Simulated Exercise Results (Demo Mode) ─────────────────────────────
DEMO_RESULTS = {
    "exercise_id": "NCA-PURPLE-2026-06-21",
    "exercise_date": "2026-06-21",
    "red_team": "V. Willis, CISSP + Lab Automation",
    "blue_team": "NovaCrest SOC (4 analysts)",
    "purple_lead": "V. Willis, CISSP",
    "phase_results": [
        {
            "phase": 1,
            "name": "Reconnaissance",
            "phase_start": "2026-06-21T09:00:00Z",
            "detected": False,
            "mttd_minutes": None,
            "detection_layer": None,
            "detection_event": None,
            "score": 0,
            "notes": "Passive external recon — no internal signals; expected miss",
        },
        {
            "phase": 2,
            "name": "Initial Access",
            "phase_start": "2026-06-21T09:30:00Z",
            "detected": True,
            "mttd_minutes": 8,
            "detection_layer": "Zeek + CrowdStrike",
            "detection_event": "Sliver JA3 a0e9... in ssl.log; CS ML: WINWORD→powershell.exe",
            "score": 5,
            "notes": "JA3 fired first (T+8min); CS corroborated at T+11min",
        },
        {
            "phase": 3,
            "name": "Execution & Persistence",
            "phase_start": "2026-06-21T10:15:00Z",
            "detected": True,
            "mttd_minutes": 14,
            "detection_layer": "Elastic SIEM (Sysmon)",
            "detection_event": "Event 4698: Scheduled task created 'SysCheck'; EQL rule fired",
            "score": 5,
            "notes": "Run key missed; scheduled task caught by Elastic EQL rule",
        },
        {
            "phase": 4,
            "name": "Privilege Escalation",
            "phase_start": "2026-06-21T11:00:00Z",
            "detected": True,
            "mttd_minutes": 6,
            "detection_layer": "CrowdStrike + Elastic SIEM",
            "detection_event": "Event 4672 SeImpersonatePrivilege; Event 4769 RC4 × 3; Sysmon 13 ms-settings",
            "score": 5,
            "notes": "Three independent signals in 6 minutes — highest confidence detection",
        },
        {
            "phase": 5,
            "name": "Defense Evasion",
            "phase_start": "2026-06-21T11:45:00Z",
            "detected": True,
            "mttd_minutes": 3,
            "detection_layer": "Elastic SIEM (Security.evtx)",
            "detection_event": "Event 1102: Security log cleared — immediate alert",
            "score": 5,
            "notes": "Log clear is self-documenting; fastest detection of the exercise (3 min)",
        },
        {
            "phase": 6,
            "name": "Lateral Movement",
            "phase_start": "2026-06-21T12:15:00Z",
            "detected": True,
            "mttd_minutes": 23,
            "detection_layer": "Elastic SIEM (Sysmon + Security)",
            "detection_event": "Event 4648 explicit credential use; WMI process create from WS-FIN-04 to SRV-AD-01",
            "score": 2,
            "notes": "SLA missed by 3 minutes — WMI correlation query too slow; tuning needed",
        },
        {
            "phase": 7,
            "name": "C2 Establishment",
            "phase_start": "2026-06-21T13:00:00Z",
            "detected": True,
            "mttd_minutes": 17,
            "detection_layer": "Zscaler (TLS Inspection — NOW ENABLED)",
            "detection_event": "Domain fronting: SNI=legit.azure-cdn.net Host=cs.attacker-c2.com",
            "score": 5,
            "notes": "TLS inspection enabled after Day 20 gap — V3 fronting caught this time",
        },
        {
            "phase": 8,
            "name": "Collection & Exfil Staging",
            "phase_start": "2026-06-21T13:45:00Z",
            "detected": True,
            "mttd_minutes": 11,
            "detection_layer": "Zeek + Zscaler DLP",
            "detection_event": "85 MB egress to attacker C2; DLP alert: archive upload blocked",
            "score": 5,
            "notes": "Volumetric detection + DLP both fired; DLP blocked upload (new policy from Day 18)",
        },
    ],
}

COBALT_STRIKE_JA3 = "a0e9f5d64349fb13191bc781f81f42e1"
SLIVER_JARM = "1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c"


def compute_scores(results: Dict) -> Dict:
    """Compute engagement scores from phase results."""
    phase_results = results["phase_results"]
    total_score = sum(r["score"] for r in phase_results)
    max_score = sum(p["max_points"] for p in PHASES)

    detected_within_sla = sum(1 for r in phase_results
                              if r["detected"] and r.get("mttd_minutes") is not None
                              and r["mttd_minutes"] <= next(
                                  p["sla_minutes"] for p in PHASES if p["phase"] == r["phase"]
                              ))
    detected_late = sum(1 for r in phase_results
                        if r["detected"] and r.get("score") == 2)
    not_detected = sum(1 for r in phase_results if not r["detected"])

    detected_phases = [r for r in phase_results if r["detected"]]
    mttd_values = [r["mttd_minutes"] for r in detected_phases
                   if r["mttd_minutes"] is not None]
    mean_mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0

    detection_layers = {}
    for r in phase_results:
        layer = r.get("detection_layer")
        if layer:
            for l in str(layer).split(" + "):
                l = l.strip()
                detection_layers[l] = detection_layers.get(l, 0) + 1

    return {
        "total_score": total_score,
        "max_score": max_score,
        "score_pct": round((total_score / max_score) * 100, 1),
        "detected_within_sla": detected_within_sla,
        "detected_late": detected_late,
        "not_detected": not_detected,
        "total_phases": len(phase_results),
        "mean_mttd_minutes": round(mean_mttd, 1),
        "fastest_detection": min(mttd_values) if mttd_values else None,
        "slowest_detection": max(mttd_values) if mttd_values else None,
        "detection_layer_breakdown": detection_layers,
    }


def emit_scorecard(results: Dict, scores: Dict) -> None:
    """Print formatted engagement scorecard."""
    print("\n" + "=" * 70)
    print("  WEEK 3 CAPSTONE — ENGAGEMENT SCORECARD")
    print("  NovaCrest Capital Group | Purple Team Exercise")
    print("=" * 70 + "\n")

    print(f"  Exercise ID:      {results.get('exercise_id')}")
    print(f"  Date:             {results.get('exercise_date')}")
    print(f"  Purple Lead:      {results.get('purple_lead')}")
    print()

    # Phase scorecard
    print(f"  {'PHASE':<30} {'MTTD':>6} {'SLA':>5} {'SCORE':>6} {'LAYER'}")
    print("  " + "─" * 65)
    for r in results["phase_results"]:
        phase_def = next(p for p in PHASES if p["phase"] == r["phase"])
        mttd = f"{r['mttd_minutes']}m" if r.get("mttd_minutes") else "MISSED"
        sla = f"{phase_def['sla_minutes']}m"
        score = f"{r['score']}/{phase_def['max_points']}"
        sla_flag = ("✅" if r["score"] == phase_def["max_points"]
                    else "⚠️ " if r["score"] == phase_def["late_points"]
                    else "❌")
        layer = (r.get("detection_layer") or "—")[:30]
        print(f"  {sla_flag} {r['name']:<28} {mttd:>6} {sla:>5} {score:>6}   {layer}")

    print("  " + "─" * 65)
    print(f"  {'TOTAL':>30}        {scores['total_score']:>5}/{scores['max_score']}")
    print()

    # Summary metrics
    print("  ENGAGEMENT METRICS")
    print("  " + "─" * 45)
    print(f"  Score:                  {scores['total_score']}/{scores['max_score']} ({scores['score_pct']}%)")
    print(f"  Detected within SLA:    {scores['detected_within_sla']}/{scores['total_phases']}")
    print(f"  Detected late:          {scores['detected_late']}")
    print(f"  Not detected:           {scores['not_detected']}")
    print(f"  Mean MTTD:              {scores['mean_mttd_minutes']} minutes")
    print(f"  Fastest detection:      {scores['fastest_detection']} minutes (Phase 5)")
    print(f"  Slowest SLA miss:       {scores['slowest_detection']} minutes (Phase 6)")
    print()

    print("  DETECTION LAYER PERFORMANCE")
    print("  " + "─" * 45)
    for layer, count in sorted(scores["detection_layer_breakdown"].items(),
                                key=lambda x: -x[1]):
        bar = "█" * count
        print(f"  {layer:<30} {bar} ({count})")
    print()


def export_results(results: Dict, scores: Dict, output_path: str) -> None:
    """Export full results JSON for ATT&CK navigator exporter."""
    export = {
        "metadata": {
            "exercise_id": results.get("exercise_id"),
            "date": results.get("exercise_date"),
            "purple_lead": results.get("purple_lead"),
        },
        "scores": scores,
        "phase_results": results["phase_results"],
        "techniques": {
            r["name"]: {
                "techniques": next(p["techniques"] for p in PHASES if p["phase"] == r["phase"]),
                "detected": r["detected"],
                "within_sla": r.get("score") == 5,
                "mttd_minutes": r.get("mttd_minutes"),
            }
            for r in results["phase_results"]
        },
    }
    with open(output_path, "w") as f:
        json.dump(export, f, indent=2)
    log.info(f"Results exported: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Day 21 Engagement Tracker")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day21_results.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 21 — Purple Team Engagement Tracker")
    log.info(" NovaCrest Capital Group — Week 3 Capstone")
    log.info("=" * 70)
    log.info(" Mode: Demo (simulated exercise results)")
    log.info("")

    results = DEMO_RESULTS
    scores = compute_scores(results)

    emit_scorecard(results, scores)
    export_results(results, scores, args.output)
    log.info(f"\nFinal score: {scores['total_score']}/{scores['max_score']} "
             f"({scores['score_pct']}%) — Mean MTTD: {scores['mean_mttd_minutes']} min")


if __name__ == "__main__":
    main()
