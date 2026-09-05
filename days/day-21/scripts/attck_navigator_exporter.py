"""
Day 21 — ATT&CK Navigator Layer Exporter
NovaCrest Capital Group | Week 3 Capstone

PURPOSE: Generates an ATT&CK Navigator JSON layer from purple team
         exercise results. Color-codes techniques by detection outcome:
           Green  (#4CAF50) — Detected within SLA
           Yellow (#FFC107) — Detected late (outside SLA)
           Red    (#F44336) — Not detected / Missed
           Gray   (#9E9E9E) — Not tested in this exercise

OUTPUT: Standard ATT&CK Navigator layer JSON loadable at:
        https://mitre-attack.github.io/attack-navigator/

Usage:
    python attck_navigator_exporter.py --demo
    python attck_navigator_exporter.py --results /tmp/day21_results.json
    python attck_navigator_exporter.py --demo --output attck_layer.json
"""

import argparse
import datetime
import json
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("attck_navigator_exporter")


# Color scheme
COLOR_DETECTED_SLA  = "#4CAF50"   # Green — within SLA
COLOR_DETECTED_LATE = "#FFC107"   # Amber — late detection
COLOR_MISSED        = "#F44336"   # Red — not detected
COLOR_NOT_TESTED    = "#9E9E9E"   # Gray — not in scope


# All techniques used in the Day 21 exercise with detection outcomes
EXERCISE_TECHNIQUE_MAP = {
    # Phase 1 — Reconnaissance (not detected — expected)
    "T1592": {"name": "Gather Victim Host Information", "detected": False, "sla": False, "phase": 1},
    "T1589": {"name": "Gather Victim Identity Information", "detected": False, "sla": False, "phase": 1},
    "T1593": {"name": "Search Open Websites/Domains", "detected": False, "sla": False, "phase": 1},

    # Phase 2 — Initial Access (detected within SLA)
    "T1566.001": {"name": "Spearphishing Attachment", "detected": True, "sla": True, "phase": 2, "mttd": 8},
    "T1059.001": {"name": "PowerShell", "detected": True, "sla": True, "phase": 2, "mttd": 8},

    # Phase 3 — Execution & Persistence (detected within SLA)
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "detected": False, "sla": False, "phase": 3,
                  "note": "Run key missed; task caught"},
    "T1053.005": {"name": "Scheduled Task", "detected": True, "sla": True, "phase": 3, "mttd": 14},

    # Phase 4 — Privilege Escalation (detected within SLA)
    "T1548.002": {"name": "Bypass UAC", "detected": True, "sla": True, "phase": 4, "mttd": 6},
    "T1134.001": {"name": "Token Impersonation/Theft", "detected": True, "sla": True, "phase": 4, "mttd": 6},
    "T1558.003": {"name": "Kerberoasting", "detected": True, "sla": True, "phase": 4, "mttd": 6},

    # Phase 5 — Defense Evasion (detected within SLA — fastest)
    "T1070.001": {"name": "Clear Windows Event Logs", "detected": True, "sla": True, "phase": 5, "mttd": 3},
    "T1562.001": {"name": "Disable or Modify Tools", "detected": True, "sla": True, "phase": 5, "mttd": 3},
    "T1036":     {"name": "Masquerading", "detected": False, "sla": False, "phase": 5,
                  "note": "Renamed binary not flagged — PE hash still known"},
    "T1562.004": {"name": "Disable or Modify System Firewall", "detected": False, "sla": False, "phase": 5},

    # Phase 6 — Lateral Movement (detected LATE — SLA missed)
    "T1021.002": {"name": "SMB/Windows Admin Shares", "detected": True, "sla": False, "phase": 6, "mttd": 23},
    "T1550.002": {"name": "Pass the Ticket", "detected": True, "sla": False, "phase": 6, "mttd": 23},
    "T1047":     {"name": "Windows Management Instrumentation", "detected": True, "sla": False, "phase": 6, "mttd": 23},

    # Phase 7 — C2 (detected within SLA — TLS inspection now on)
    "T1071.001": {"name": "Application Layer Protocol: HTTPS", "detected": True, "sla": True, "phase": 7, "mttd": 17},
    "T1090.004": {"name": "Domain Fronting", "detected": True, "sla": True, "phase": 7, "mttd": 17},
    "T1573.002": {"name": "Asymmetric Cryptography", "detected": True, "sla": True, "phase": 7, "mttd": 17},
    "T1001.001": {"name": "Junk Data / Jitter", "detected": False, "sla": False, "phase": 7,
                  "note": "Jitter not explicitly detected; timing analysis inconclusive"},

    # Phase 8 — Exfil (detected within SLA)
    "T1560.001": {"name": "Archive via Utility", "detected": True, "sla": True, "phase": 8, "mttd": 11},
    "T1041":     {"name": "Exfiltration Over C2 Channel", "detected": True, "sla": True, "phase": 8, "mttd": 11},
    "T1567.002": {"name": "Exfiltration to Cloud Storage", "detected": True, "sla": True, "phase": 8, "mttd": 11},
    "T1074.001": {"name": "Local Data Staging", "detected": False, "sla": False, "phase": 8,
                  "note": "Staging in %SYSTEMROOT%\\Temp\\ not flagged — legitimate path"},
}


def build_navigator_layer(technique_map: dict,
                           exercise_id: str = "NCA-PURPLE-2026-06-21") -> dict:
    """Build ATT&CK Navigator layer JSON."""
    techniques = []

    for technique_id, data in technique_map.items():
        if data["detected"] and data["sla"]:
            color = COLOR_DETECTED_SLA
            comment = (f"✅ Detected within SLA — Phase {data['phase']} — "
                       f"MTTD {data.get('mttd','?')} min")
        elif data["detected"] and not data["sla"]:
            color = COLOR_DETECTED_LATE
            comment = (f"⚠️ Detected LATE (SLA missed) — Phase {data['phase']} — "
                       f"MTTD {data.get('mttd','?')} min")
        else:
            color = COLOR_MISSED
            note = data.get("note", "Not detected during exercise")
            comment = f"❌ Missed — Phase {data['phase']} — {note}"

        # Handle sub-techniques (e.g., T1566.001)
        tactic_entry = {
            "techniqueID": technique_id,
            "color": color,
            "comment": comment,
            "enabled": True,
            "metadata": [
                {"name": "phase", "value": str(data["phase"])},
                {"name": "detected", "value": str(data["detected"])},
                {"name": "within_sla", "value": str(data["sla"])},
            ],
        }
        if data.get("mttd"):
            tactic_entry["metadata"].append(
                {"name": "mttd_minutes", "value": str(data["mttd"])}
            )
        techniques.append(tactic_entry)

    layer = {
        "name": f"Day 21 — Week 3 Capstone Purple Team Results",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"NovaCrest Capital Group — {exercise_id} — "
            f"Full APT lifecycle purple team exercise. "
            f"Green=detected within SLA. Yellow=detected late. "
            f"Red=missed. 8 phases, 40 max points."
        ),
        "filters": {
            "platforms": [
                "Windows", "Linux", "Cloud"
            ],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [
            {"label": "Detected within SLA", "color": COLOR_DETECTED_SLA},
            {"label": "Detected (SLA missed)", "color": COLOR_DETECTED_LATE},
            {"label": "Not detected", "color": COLOR_MISSED},
        ],
        "metadata": [
            {"name": "exercise", "value": exercise_id},
            {"name": "date", "value": datetime.datetime.utcnow().strftime("%Y-%m-%d")},
            {"name": "analyst", "value": "V. Willis, CISSP"},
            {"name": "score", "value": "32/40 (80%)"},
            {"name": "mean_mttd", "value": "12.3 minutes"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    return layer


def print_coverage_summary(technique_map: dict) -> None:
    """Print human-readable coverage summary."""
    total = len(technique_map)
    detected_sla = sum(1 for t in technique_map.values() if t["detected"] and t["sla"])
    detected_late = sum(1 for t in technique_map.values() if t["detected"] and not t["sla"])
    missed = sum(1 for t in technique_map.values() if not t["detected"])

    print("\n" + "=" * 70)
    print("  ATT&CK TECHNIQUE COVERAGE — Day 21 Capstone")
    print("=" * 70 + "\n")

    print(f"  Total techniques tested: {total}")
    print(f"  ✅ Detected within SLA:   {detected_sla} ({round(detected_sla/total*100)}%)")
    print(f"  ⚠️  Detected late:         {detected_late} ({round(detected_late/total*100)}%)")
    print(f"  ❌ Missed:                 {missed} ({round(missed/total*100)}%)")
    print()

    print("  BY PHASE:")
    print("  " + "─" * 55)
    for phase_num in range(1, 9):
        phase_techs = {k: v for k, v in technique_map.items()
                       if v["phase"] == phase_num}
        phase_detected = sum(1 for t in phase_techs.values() if t["detected"] and t["sla"])
        phase_late = sum(1 for t in phase_techs.values() if t["detected"] and not t["sla"])
        phase_missed = sum(1 for t in phase_techs.values() if not t["detected"])
        phase_name = {
            1: "Reconnaissance", 2: "Initial Access", 3: "Exec/Persist",
            4: "Priv Escalation", 5: "Defense Evasion", 6: "Lateral Movement",
            7: "C2", 8: "Exfil"
        }[phase_num]
        status = ("✅" if phase_detected == len(phase_techs) else
                  "⚠️ " if phase_detected + phase_late > 0 else "❌")
        print(f"  {status} P{phase_num} {phase_name:<22} "
              f"✅{phase_detected} ⚠️{phase_late} ❌{phase_missed}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 21 ATT&CK Navigator Exporter")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--results", help="Path to engagement tracker JSON output")
    parser.add_argument("--output", default="/tmp/attck_layer_day21.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 21 — ATT&CK Navigator Layer Exporter")
    log.info(" NovaCrest Capital Group — Week 3 Capstone")
    log.info("=" * 70)

    technique_map = EXERCISE_TECHNIQUE_MAP

    print_coverage_summary(technique_map)

    layer = build_navigator_layer(technique_map)

    with open(args.output, "w") as f:
        json.dump(layer, f, indent=2)

    log.info(f"ATT&CK Navigator layer written: {args.output}")
    log.info("Load at: https://mitre-attack.github.io/attack-navigator/")
    log.info("  → Open → Upload from local → select attck_layer_day21.json")

    print(f"\n  Navigator layer written to: {args.output}")
    print(f"  Load at: https://mitre-attack.github.io/attack-navigator/")
    print(f"  Techniques: {len(technique_map)} | Colors: "
          f"🟢 SLA  🟡 Late  🔴 Missed")


if __name__ == "__main__":
    main()
