"""
Day 19 — Log Tampering Detector
NovaCrest Capital Group | Digital Forensics

PURPOSE: Detect evidence of log tampering, deletion, and anti-forensics
         across Windows Event Log, Sysmon, and Linux auditd sources.

TAMPERING INDICATORS:
  Windows:
    - Event ID 1102: Security Audit Log Cleared
    - Event ID 104:  System Log Cleared
    - Event sequence number gaps (evtx RecordID gaps)
    - Sysmon log present but Security log cleared (asymmetry)
    - PowerShell history cleared (ConsoleHost_history.txt deleted)
    - Windows Defender real-time protection disabled (Event 5001/5004)

  Linux:
    - auditd key fields absent post-escalation (attacker disabled logging)
    - auth.log timestamps non-sequential
    - .bash_history file cleared or truncated (T1070.003)
    - /var/log/syslog truncated

  Cross-source:
    - Time gap in one source with normal activity in another
      (suggests selective deletion)
    - Event density drop following attacker activity

Usage:
    python log_tampering_detector.py --demo --verbose
    python log_tampering_detector.py --evtx-dir /forensics/evtx/
    python log_tampering_detector.py --audit-log /forensics/audit.log
"""

import argparse
import datetime
import json
import logging
import sys
from typing import List, Dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("log_tampering_detector")


# ── Simulated Evidence Dataset (demo mode) ─────────────────────────────
SIMULATED_EVIDENCE = {
    "windows_events": {
        "Security.evtx": {
            "total_records": 892,  # Low — expected 4000+ for 10hr window
            "first_record_id": 14201,
            "last_record_id": 15093,
            "expected_gap": False,
            "log_clear_events": [
                {
                    "record_id": 14850,
                    "timestamp_utc": "2026-06-14T15:04:22Z",
                    "event_id": 1102,
                    "user": "j.henderson",
                    "message": "The audit log was cleared. Previous entries: 4,231",
                }
            ],
            "record_gaps": [
                {
                    "gap_before": 14201,
                    "gap_after": 14850,
                    "gap_size": 649,
                    "time_before": "2026-06-14T13:18:00Z",
                    "time_after": "2026-06-14T15:04:22Z",
                    "significance": "649 events missing — covers initial access window",
                }
            ],
        },
        "Sysmon.evtx": {
            "total_records": 4218,
            "first_record_id": 1,
            "last_record_id": 4218,
            "expected_gap": False,
            "log_clear_events": [],   # Sysmon NOT cleared (attacker overlooked)
            "record_gaps": [],
        },
        "System.evtx": {
            "total_records": 210,
            "first_record_id": 4800,
            "last_record_id": 5010,
            "log_clear_events": [
                {
                    "record_id": 4980,
                    "timestamp_utc": "2026-06-14T15:04:25Z",
                    "event_id": 104,
                    "user": "j.henderson",
                    "message": "The System log file was cleared",
                }
            ],
            "record_gaps": [],
        },
    },
    "linux_artifacts": {
        "bash_history": {
            "path": "/home/svc_ncg/.bash_history",
            "status": "CLEARED",
            "size_bytes": 0,
            "expected_size_bytes": "> 500",
            "note": "History cleared post-escalation — T1070.003",
        },
        "auditd": {
            "status": "Intact",
            "note": "auditd not tampered — key source of escalation evidence",
        },
        "syslog": {
            "status": "Intact",
            "note": "syslog complete — confirms auth events",
        },
    },
    "cross_source_gaps": [
        {
            "gap_window_start": "2026-06-14T13:18:00Z",
            "gap_window_end": "2026-06-14T15:04:22Z",
            "sources_with_gap": ["Security.evtx"],
            "sources_intact": ["Sysmon.evtx", "zeek/ssl.log", "zeek/conn.log"],
            "gap_duration_minutes": 106,
            "significance": "CRITICAL — Security.evtx has 106-min gap; Sysmon shows active process creation during same window. Selective deletion confirmed.",
            "surviving_evidence": [
                "Sysmon Event 1: svc_update.exe → lsass.exe access at 13:32 UTC",
                "Sysmon Event 13: ms-settings registry write at 13:35 UTC",
                "Zeek ssl.log: C2 connection established at 13:40 UTC",
            ],
        }
    ],
}


def detect_log_clear_events(evtx_data: Dict) -> List[Dict]:
    """Identify explicit log clear events (1102, 104)."""
    findings = []
    for filename, data in evtx_data.items():
        for event in data.get("log_clear_events", []):
            finding = {
                "type": "LOG_CLEAR_EVENT",
                "source": filename,
                "technique": "T1070.001",
                "timestamp_utc": event["timestamp_utc"],
                "event_id": event["event_id"],
                "user": event["user"],
                "evidence": event["message"],
                "severity": "Critical",
                "forensic_note": (
                    f"Attacker cleared {filename} at {event['timestamp_utc']}. "
                    f"Evidence from this log prior to clearing is DESTROYED. "
                    f"Surviving evidence: Sysmon.evtx (not cleared)."
                ),
            }
            findings.append(finding)
            log.warning(f"[TAMPER] LOG CLEAR: {filename} at {event['timestamp_utc']} by {event['user']}")
    return findings


def detect_record_id_gaps(evtx_data: Dict) -> List[Dict]:
    """Detect gaps in EventRecord ID sequence (indicates selective deletion)."""
    findings = []
    for filename, data in evtx_data.items():
        for gap in data.get("record_gaps", []):
            finding = {
                "type": "RECORD_ID_GAP",
                "source": filename,
                "technique": "T1070.001",
                "gap_before_record_id": gap["gap_before"],
                "gap_after_record_id": gap["gap_after"],
                "missing_records": gap["gap_size"],
                "time_before": gap.get("time_before"),
                "time_after": gap.get("time_after"),
                "significance": gap["significance"],
                "severity": "Critical",
                "forensic_note": (
                    f"{gap['gap_size']} Event Records missing from {filename}. "
                    f"Sequential gap from record {gap['gap_before']} to {gap['gap_after']}. "
                    f"Likely selective event deletion or log wipe-and-recreate."
                ),
            }
            findings.append(finding)
            log.warning(f"[TAMPER] RECORD GAP: {filename}: {gap['gap_size']} records missing "
                        f"({gap.get('time_before','?')} → {gap.get('time_after','?')})")
    return findings


def detect_log_asymmetry(evtx_data: Dict) -> List[Dict]:
    """
    Detect asymmetric log clearing — Sysmon intact while Security log cleared.
    Asymmetry = attacker cleared some but not all logs (oversight).
    """
    findings = []
    cleared = [f for f, d in evtx_data.items() if d.get("log_clear_events")]
    intact = [f for f, d in evtx_data.items() if not d.get("log_clear_events")]

    if cleared and intact:
        finding = {
            "type": "LOG_ASYMMETRY",
            "technique": "T1070.001",
            "cleared_sources": cleared,
            "intact_sources": intact,
            "severity": "High",
            "forensic_note": (
                f"Attacker cleared {', '.join(cleared)} but overlooked "
                f"{', '.join(intact)}. Sysmon.evtx contains corroborating "
                f"evidence for the cleared period and should be prioritized."
            ),
        }
        findings.append(finding)
        log.warning(f"[TAMPER] ASYMMETRY: Cleared: {cleared} | Intact: {intact}")
    return findings


def detect_linux_tampering(linux_data: Dict) -> List[Dict]:
    """Detect Linux-side anti-forensics (history clearing, log truncation)."""
    findings = []
    for artifact, data in linux_data.items():
        if data.get("status") in ("CLEARED", "TRUNCATED", "DELETED"):
            finding = {
                "type": "LINUX_ARTIFACT_CLEARED",
                "artifact": artifact,
                "path": data.get("path", artifact),
                "technique": "T1070.003",
                "status": data["status"],
                "size_bytes": data.get("size_bytes"),
                "expected": data.get("expected_size_bytes"),
                "severity": "High",
                "note": data.get("note", ""),
                "forensic_note": (
                    f"{artifact} was {data['status']}. "
                    f"Attacker used this to conceal command history. "
                    f"Recover from auditd EXECVE records."
                ),
            }
            findings.append(finding)
            log.warning(f"[TAMPER] LINUX CLEARED: {artifact} ({data['status']})")
    return findings


def detect_cross_source_gaps(gaps_data: List[Dict]) -> List[Dict]:
    """
    Identify windows where one source has a gap but other sources show activity.
    This is the strongest indicator of selective evidence deletion.
    """
    findings = []
    for gap in gaps_data:
        if gap.get("sources_intact"):
            finding = {
                "type": "SELECTIVE_DELETION",
                "technique": "T1070",
                "gap_window": f"{gap['gap_window_start']} → {gap['gap_window_end']}",
                "gap_duration_minutes": gap["gap_duration_minutes"],
                "tampered_sources": gap["sources_with_gap"],
                "corroborating_sources": gap["sources_intact"],
                "surviving_evidence": gap.get("surviving_evidence", []),
                "severity": "Critical",
                "significance": gap["significance"],
                "forensic_note": (
                    "Selective deletion confirmed. Attacker deleted evidence from "
                    f"{gap['sources_with_gap']} but corroborating evidence survives "
                    f"in {gap['sources_intact']}. Use surviving evidence to reconstruct "
                    "deleted events."
                ),
            }
            findings.append(finding)
            log.warning(f"[TAMPER] SELECTIVE DELETION: {gap['gap_duration_minutes']} min gap in "
                        f"{gap['sources_with_gap']} — activity visible in {gap['sources_intact']}")
    return findings


def emit_tampering_report(all_findings: List[Dict]) -> None:
    """Emit structured tampering detection report."""
    critical = [f for f in all_findings if f.get("severity") == "Critical"]
    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "case": "NCA-2026-06",
        "analysis": "Log Tampering Detection",
        "total_findings": len(all_findings),
        "critical_findings": len(critical),
        "findings": all_findings,
        "anti_forensics_summary": {
            "techniques_used": list({f.get("technique", "") for f in all_findings}),
            "evidence_destroyed": "Security.evtx pre-15:04 UTC (649 events), System.evtx partial",
            "evidence_surviving": "Sysmon.evtx (complete), auditd (complete), Zeek logs (complete)",
            "key_insight": (
                "Attacker cleared Security and System logs but not Sysmon. "
                "Sysmon + Zeek provide full coverage of the deleted window. "
                "Reconstruction is possible."
            ),
        },
    }

    print("\n" + "=" * 70)
    print("  LOG TAMPERING DETECTION REPORT — Day 19")
    print("=" * 70 + "\n")
    print(json.dumps(report, indent=2))
    print("\n" + "=" * 70 + "\n")

    print("TAMPERING FINDINGS SUMMARY:")
    print("─" * 60)
    for f in all_findings:
        icon = "🔴" if f["severity"] == "Critical" else "🟡"
        print(f"  {icon} [{f['type']}] {f['technique']} — {f['severity']}")
        print(f"     {f.get('forensic_note','')[:90]}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 19 Log Tampering Detector")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--verbose", action="store_true", default=True)
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 19 — Log Tampering Detector")
    log.info(" NovaCrest Capital Group | Case: NCA-2026-06")
    log.info("=" * 70)

    all_findings = []

    log.info("[1] Detecting log clear events (Event 1102/104)...")
    all_findings.extend(detect_log_clear_events(SIMULATED_EVIDENCE["windows_events"]))

    log.info("[2] Detecting EventRecord ID gaps...")
    all_findings.extend(detect_record_id_gaps(SIMULATED_EVIDENCE["windows_events"]))

    log.info("[3] Detecting log asymmetry (Sysmon vs Security)...")
    all_findings.extend(detect_log_asymmetry(SIMULATED_EVIDENCE["windows_events"]))

    log.info("[4] Detecting Linux artifact tampering...")
    all_findings.extend(detect_linux_tampering(SIMULATED_EVIDENCE["linux_artifacts"]))

    log.info("[5] Detecting cross-source selective deletion...")
    all_findings.extend(detect_cross_source_gaps(SIMULATED_EVIDENCE["cross_source_gaps"]))

    log.info("")
    emit_tampering_report(all_findings)


if __name__ == "__main__":
    main()
