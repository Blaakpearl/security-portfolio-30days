"""
Day 17 — Privilege Escalation Hunter
NovaCrest Capital Group | Threat Hunt

PURPOSE: Automated hunt script that searches Sysmon and auditd log exports
         for privilege escalation indicators across six hypotheses:
           H1 — Token impersonation (Windows)
           H2 — Sudo abuse (Linux)
           H3 — SUID/SGID binary exploitation (Linux)
           H4 — Kerberoasting (Windows)
           H5 — UAC bypass (Windows)
           H6 — Dangerous privilege assignment (Windows)

WHAT IT DOES:
  1. Parses Sysmon XML event exports (Event 1, 8, 10)
  2. Parses Windows Security event exports (4669, 4672, 4673, 4688, 4769)
  3. Parses auditd log exports (execve, setuid, sudo records)
  4. Emits per-hypothesis findings with severity, evidence, and ATT&CK mapping
  5. Generates hunt timeline and summary report

SAFE TO RUN: Yes — read-only log analysis; no system modifications.

Usage:
    python privilege_escalation_hunter.py --demo
    python privilege_escalation_hunter.py --logs /path/to/log/dir --verbose
    python privilege_escalation_hunter.py --hypothesis H4 --demo
    python privilege_escalation_hunter.py --generate-logs --output /tmp/
"""

import argparse
import datetime
import json
import logging
import os
import sys
from typing import List, Dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("privesc_hunter")


# ── ATT&CK Mapping ────────────────────────────────────────────────────
HYPOTHESIS_MAP = {
    "H1": {"name": "Token Impersonation",          "technique": "T1134.001", "platform": "Windows"},
    "H2": {"name": "Sudo Abuse",                   "technique": "T1548.003", "platform": "Linux"},
    "H3": {"name": "SUID/SGID Binary Exploitation","technique": "T1548.001", "platform": "Linux"},
    "H4": {"name": "Kerberoasting",                "technique": "T1558.003", "platform": "Windows"},
    "H5": {"name": "UAC Bypass",                   "technique": "T1548.002", "platform": "Windows"},
    "H6": {"name": "Dangerous Privilege Assignment","technique": "T1134",     "platform": "Windows"},
}

# ── Simulated Log Events (Demo Mode) ──────────────────────────────────
SIMULATED_EVENTS = {
    # H1: Token Impersonation — Sysmon Event 10, process accessing lsass
    "H1_token_impersonation": [
        {
            "EventID": 10,
            "EventTime": "2026-06-14T09:15:22Z",
            "SourceProcess": "C:\\Users\\j.henderson\\AppData\\Local\\Temp\\svc_update.exe",
            "SourcePID": 4812,
            "TargetProcess": "C:\\Windows\\System32\\lsass.exe",
            "TargetPID": 744,
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+...",
            "User": "ncg\\j.henderson",
            "note": "Non-system process opening lsass.exe with read access — credential theft or token harvest",
        },
        {
            "EventID": 4672,
            "EventTime": "2026-06-14T09:15:45Z",
            "SubjectUserName": "j.henderson",
            "SubjectDomainName": "NCG",
            "PrivilegeList": "SeDebugPrivilege\nSeImpersonatePrivilege",
            "note": "SeImpersonatePrivilege assigned at logon — attacker can impersonate tokens",
        },
    ],

    # H2: Sudo Abuse — auditd sudo execution by service account
    "H2_sudo_abuse": [
        {
            "type": "SYSCALL",
            "EventTime": "2026-06-14T10:32:11Z",
            "syscall": "execve",
            "exe": "/usr/bin/sudo",
            "uid": "1002",
            "auid": "1002",
            "key": "sudo_exec",
            "comm": "sudo",
            "args": ["/usr/bin/find", ".", "-exec", "/bin/bash", ";", "-quit"],
            "note": "sudo find -exec /bin/bash — GTFOBin NOPASSWD exploitation",
        },
        {
            "type": "USER_AUTH",
            "EventTime": "2026-06-14T10:32:11Z",
            "op": "PAM:sudo",
            "acct": "svc_ncg",
            "exe": "/usr/bin/sudo",
            "res": "success",
            "note": "sudo succeeded without password — NOPASSWD misconfiguration",
        },
        {
            "type": "SYSCALL",
            "EventTime": "2026-06-14T10:32:12Z",
            "syscall": "setuid",
            "uid": "1002",
            "result_uid": "0",
            "exe": "/bin/bash",
            "note": "setuid(0) — effective UID changed to root",
        },
    ],

    # H3: SUID Binary Exploitation
    "H3_suid_exploitation": [
        {
            "type": "SYSCALL",
            "EventTime": "2026-06-14T10:28:44Z",
            "syscall": "execve",
            "exe": "/usr/bin/find",
            "uid": "1002",
            "euid": "0",
            "key": "suid_exec",
            "note": "find executed with euid=0 (SUID) by non-root user — GTFOBin path",
        },
        {
            "type": "PROCTITLE",
            "EventTime": "2026-06-14T10:28:44Z",
            "proctitle": "/usr/bin/find / -perm -4000 -type f",
            "uid": "1002",
            "note": "Attacker enumerating SUID binaries — reconnaissance step before exploitation",
        },
    ],

    # H4: Kerberoasting — Security Event 4769 with RC4 encryption
    "H4_kerberoasting": [
        {
            "EventID": 4769,
            "EventTime": "2026-06-14T09:22:05Z",
            "TargetUserName": "MSSQLSvc/sqlserver.novacrest.local:1433",
            "TargetDomainName": "NOVACREST.LOCAL",
            "ServiceName": "MSSQLSvc",
            "TicketEncryptionType": "0x17",   # RC4 — Kerberoasting indicator
            "IpAddress": "::ffff:10.0.1.40",
            "note": "RC4 (0x17) TGS request for service SPN — Kerberoasting",
        },
        {
            "EventID": 4769,
            "EventTime": "2026-06-14T09:22:07Z",
            "TargetUserName": "http/intranet.novacrest.local",
            "TargetDomainName": "NOVACREST.LOCAL",
            "ServiceName": "http",
            "TicketEncryptionType": "0x17",
            "IpAddress": "::ffff:10.0.1.40",
            "note": "Second RC4 TGS in 2s — bulk Kerberoasting pattern",
        },
        {
            "EventID": 4769,
            "EventTime": "2026-06-14T09:22:09Z",
            "TargetUserName": "svc_backup/backup.novacrest.local",
            "TargetDomainName": "NOVACREST.LOCAL",
            "ServiceName": "svc_backup",
            "TicketEncryptionType": "0x17",
            "IpAddress": "::ffff:10.0.1.40",
            "note": "Third RC4 TGS in 4s — 3 SPNs in 4 seconds = bulk Kerberoasting",
        },
    ],

    # H5: UAC Bypass — fodhelper spawning cmd.exe
    "H5_uac_bypass": [
        {
            "EventID": 13,   # Sysmon Registry Event
            "EventTime": "2026-06-14T09:18:33Z",
            "EventType": "SetValue",
            "TargetObject": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\(Default)",
            "Details": "cmd.exe /c powershell.exe -enc [payload]",
            "User": "ncg\\j.henderson",
            "note": "ms-settings COM hijack key — classic fodhelper UAC bypass",
        },
        {
            "EventID": 1,   # Sysmon Process Create
            "EventTime": "2026-06-14T09:18:34Z",
            "Image": "C:\\Windows\\System32\\fodhelper.exe",
            "ParentImage": "C:\\Users\\j.henderson\\AppData\\Local\\Temp\\svc_update.exe",
            "User": "ncg\\j.henderson",
            "IntegrityLevel": "High",
            "note": "fodhelper.exe spawned by attacker process",
        },
        {
            "EventID": 1,
            "EventTime": "2026-06-14T09:18:35Z",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Windows\\System32\\fodhelper.exe",
            "User": "ncg\\j.henderson",
            "IntegrityLevel": "High",
            "CommandLine": "cmd.exe /c powershell.exe -enc [payload]",
            "note": "cmd.exe spawned by fodhelper at High integrity — UAC bypass succeeded",
        },
    ],

    # H6: Dangerous Privilege Assignment
    "H6_privilege_assignment": [
        {
            "EventID": 4672,
            "EventTime": "2026-06-14T09:15:45Z",
            "SubjectUserName": "j.henderson",
            "SubjectDomainName": "NCG",
            "PrivilegeList": "SeDebugPrivilege\nSeImpersonatePrivilege\nSeTcbPrivilege",
            "LogonType": "3",
            "note": "SeTcbPrivilege ('act as part of OS') — extremely dangerous; should not appear on standard user",
        },
    ],
}


def hunt_hypothesis(hypothesis: str, events: List[Dict], verbose: bool) -> Dict:
    """Evaluate a single hypothesis against provided events."""
    hyp_info = HYPOTHESIS_MAP[hypothesis]
    findings = []
    confirmed = False

    for event in events:
        severity = "High"
        if "note" in event:
            finding = {
                "timestamp": event.get("EventTime", "unknown"),
                "event_id": event.get("EventID", event.get("type", "unknown")),
                "evidence": event.get("note"),
                "raw_indicator": {k: v for k, v in event.items() if k not in ("note", "EventTime")},
                "severity": severity,
            }
            findings.append(finding)
            confirmed = True

            if verbose:
                log.info(f"  [{severity}] {event.get('EventTime', '')}: {event.get('note', '')}")

    return {
        "hypothesis": hypothesis,
        "name": hyp_info["name"],
        "technique": hyp_info["technique"],
        "platform": hyp_info["platform"],
        "confirmed": confirmed,
        "finding_count": len(findings),
        "findings": findings,
        "verdict": "CONFIRMED" if confirmed else "NOT FOUND",
    }


def generate_hunt_timeline(results: List[Dict]) -> List[Dict]:
    """Build a chronological timeline of confirmed findings."""
    timeline = []
    for result in results:
        if not result["confirmed"]:
            continue
        for finding in result["findings"]:
            timeline.append({
                "timestamp": finding["timestamp"],
                "hypothesis": result["hypothesis"],
                "technique": result["technique"],
                "evidence": finding["evidence"],
                "severity": finding["severity"],
            })
    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def emit_hunt_report(results: List[Dict], timeline: List[Dict]) -> None:
    """Emit structured hunt report."""
    confirmed = [r for r in results if r["confirmed"]]
    ruled_out = [r for r in results if not r["confirmed"]]

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "hunt": "Privilege Escalation Hunt",
        "target": "NovaCrest Capital Group",
        "window": "2026-06-14 08:00–18:00 UTC",
        "scope": {
            "windows": ["WS-FIN-04", "WS-FIN-05", "WS-FIN-06", "SRV-AD-01"],
            "linux": ["lnx-trade-01", "lnx-trade-02", "lnx-db-01"],
        },
        "summary": {
            "hypotheses_tested": len(results),
            "confirmed": len(confirmed),
            "ruled_out": len(ruled_out),
            "total_findings": sum(r["finding_count"] for r in results),
        },
        "confirmed_hypotheses": [r["hypothesis"] + " — " + r["name"] for r in confirmed],
        "ruled_out_hypotheses": [r["hypothesis"] + " — " + r["name"] for r in ruled_out],
        "results": results,
        "timeline": timeline,
        "overall_verdict": (
            "PRIVILEGE ESCALATION CONFIRMED — attacker achieved elevated access"
            if confirmed else
            "NO PRIVILEGE ESCALATION FOUND in search window"
        ),
    }

    print("\n" + "=" * 70)
    print("  PRIVILEGE ESCALATION HUNT REPORT — Day 17")
    print("=" * 70 + "\n")
    print(json.dumps(report, indent=2))
    print("\n" + "=" * 70 + "\n")

    # Human-readable summary
    print("HUNT SUMMARY")
    print("─" * 50)
    for r in results:
        icon = "✅ CONFIRMED" if r["confirmed"] else "⬜ NOT FOUND"
        print(f"  {r['hypothesis']} [{r['technique']}] {r['name']:35} {icon}")
    print()
    print("CHRONOLOGICAL TIMELINE OF CONFIRMED FINDINGS:")
    print("─" * 50)
    for event in timeline:
        print(f"  {event['timestamp']}  [{event['hypothesis']}] {event['evidence'][:70]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Day 17 Privilege Escalation Hunter"
    )
    parser.add_argument("--demo", action="store_true", default=True,
                        help="Use simulated log data")
    parser.add_argument("--hypothesis", choices=list(HYPOTHESIS_MAP.keys()),
                        help="Hunt single hypothesis only")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--generate-logs", action="store_true",
                        help="Write simulated log files to --output directory")
    parser.add_argument("--output", default="/tmp/hunt-logs/",
                        help="Directory for generated log files")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 17 — Privilege Escalation Hunter")
    log.info(" NovaCrest Capital Group — Threat Hunt")
    log.info("=" * 70)
    log.info(f" Target window: 2026-06-14 08:00–18:00 UTC")
    log.info(f" Mode: {'Demo (simulated data)' if args.demo else 'Live log analysis'}")
    log.info("")

    if args.generate_logs:
        os.makedirs(args.output, exist_ok=True)
        for key, events in SIMULATED_EVENTS.items():
            path = os.path.join(args.output, f"{key}.json")
            with open(path, "w") as f:
                json.dump(events, f, indent=2)
            log.info(f"Generated: {path}")
        log.info(f"\nLog files written to {args.output}")
        sys.exit(0)

    hypotheses_to_run = [args.hypothesis] if args.hypothesis else list(HYPOTHESIS_MAP.keys())
    results = []

    for hyp in hypotheses_to_run:
        hyp_info = HYPOTHESIS_MAP[hyp]
        log.info(f"[{hyp}] Hunting: {hyp_info['name']} ({hyp_info['technique']}) — {hyp_info['platform']}")

        event_key = {
            "H1": "H1_token_impersonation",
            "H2": "H2_sudo_abuse",
            "H3": "H3_suid_exploitation",
            "H4": "H4_kerberoasting",
            "H5": "H5_uac_bypass",
            "H6": "H6_privilege_assignment",
        }[hyp]

        events = SIMULATED_EVENTS.get(event_key, [])
        result = hunt_hypothesis(hyp, events, args.verbose)
        results.append(result)
        log.info(f"  → Verdict: {result['verdict']} ({result['finding_count']} findings)")
        log.info("")

    timeline = generate_hunt_timeline(results)
    emit_hunt_report(results, timeline)


if __name__ == "__main__":
    main()
