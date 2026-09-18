"""
Day 25 — Ransomware Analyzer
NovaCrest Capital Group | Digital Forensics

PURPOSE: Analyzes disk and event log artifacts to characterize a ransomware
         incident — encryption scope, IOC extraction, timeline reconstruction,
         and recovery assessment. Simulates the output of Autopsy + FTK
         analysis against the NovaCrest SRV-FS-01 ransomware deployment.

MODULES:
  1. Encryption scope analysis (file count, directory count, data volume)
  2. IOC extraction (ransom note fields, C2, wallet address, victim ID)
  3. Timeline reconstruction (staging → VSS delete → encryption → ransom note drop)
  4. Persistence artifact detection (service, scheduled task, registry)
  5. Recovery assessment (backup status, VSS status, decryptor availability)

Usage:
    python ransomware_analyzer.py --demo --verbose
    python ransomware_analyzer.py --mode scope --path /mnt/evidence/
    python ransomware_analyzer.py --mode ioc --demo
    python ransomware_analyzer.py --mode timeline --demo
"""

import argparse
import datetime
import json
import logging
import os
from typing import Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ransomware_analyzer")


# ── Simulated Forensic Artifacts (Demo Mode) ───────────────────────────

RANSOM_NOTE_CONTENT = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! YOUR FILES HAVE BEEN ENCRYPTED BY NCRYPT  !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Your network has been breached. All your important files have been encrypted
using military-grade AES-256 + RSA-4096 encryption.

WHAT HAPPENED?
Your data was exfiltrated before encryption. We have downloaded:
- Client financial records
- Trading algorithms and models
- Employee personnel files

YOUR VICTIM ID: NOVA-20260619-7X4K

TO RECOVER YOUR FILES:
1. Purchase 127.4 XMR (Monero)
2. Send to wallet: 48edfhj3kHJKsdnc8x7mNkLPqRsTuVwXy...
3. Email proof to: ncrypt-support@protonmail.com
4. Include your victim ID in the subject

DEADLINE: 72 hours from 2026-06-19 06:14 UTC
After deadline, price doubles. After 96 hours, data is published.

Leak site: http://ncrypt3k4j7mxbwz.onion/novacrest
Support: ncrypt-support@protonmail.com

DO NOT:
- Rename encrypted files
- Try third-party decryption tools (permanent damage)
- Contact law enforcement (data will be published immediately)
"""

SIMULATED_ENCRYPTION_SCOPE = {
    "shares_affected": [
        {
            "share": "\\\\SRV-FS-01\\Finance",
            "path": "C:\\Shares\\Finance",
            "files_encrypted": 14823,
            "files_skipped": 312,    # system files, already encrypted
            "size_encrypted_gb": 847.3,
            "ransom_notes_dropped": 412,
            "file_types_hit": [".xlsx", ".pdf", ".docx", ".csv", ".msg", ".pst"],
        },
        {
            "share": "\\\\SRV-FS-01\\Trading",
            "path": "C:\\Shares\\Trading",
            "files_encrypted": 8241,
            "files_skipped": 88,
            "size_encrypted_gb": 1243.7,
            "ransom_notes_dropped": 287,
            "file_types_hit": [".parquet", ".csv", ".py", ".json", ".db", ".log"],
        },
        {
            "share": "\\\\SRV-FS-01\\HR",
            "path": "C:\\Shares\\HR",
            "files_encrypted": 3104,
            "files_skipped": 41,
            "size_encrypted_gb": 124.1,
            "ransom_notes_dropped": 148,
            "file_types_hit": [".pdf", ".docx", ".xlsx", ".png", ".msg"],
        },
    ],
    "system_files_skipped": [
        "*.exe", "*.dll", "*.sys", "*.ini", "*.lnk",
        "ntldr", "bootmgr", "pagefile.sys", "hiberfil.sys",
    ],
    "total_files_encrypted": 26168,
    "total_size_encrypted_gb": 2215.1,
    "total_ransom_notes": 847,
    "encryption_algorithm": "AES-256-CBC per file + RSA-4096 (key encapsulation)",
    "key_storage": "Encrypted session key appended to each file; master key held by attacker",
}

SIMULATED_TIMELINE = [
    # Lateral movement (from Day 21 findings)
    {
        "timestamp": "2026-06-19T03:15:44Z",
        "source": "Security.evtx (SRV-AD-01)",
        "event_id": "4648",
        "technique": "T1550.002",
        "event": "Pass-the-Ticket: SRV-FS-01$ authenticated from SRV-AD-01 using Kerberos ticket",
        "severity": "Critical",
        "phase": "Lateral Movement",
    },
    {
        "timestamp": "2026-06-19T03:16:02Z",
        "source": "Security.evtx (SRV-FS-01)",
        "event_id": "4624",
        "technique": "T1021.002",
        "event": "Network logon Type 3: NOVACREST\\svc_backup authenticated from SRV-AD-01",
        "severity": "Critical",
        "phase": "Lateral Movement",
    },
    # Ransomware staging
    {
        "timestamp": "2026-06-19T03:22:11Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "11",
        "technique": "T1105",
        "event": "File created: C:\\Windows\\Temp\\svchost32.exe (5.4 MB) — ransomware binary staged",
        "severity": "Critical",
        "phase": "Staging",
    },
    {
        "timestamp": "2026-06-19T03:22:45Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1047",
        "event": "Process: WmiPrvSE.exe spawned svchost32.exe — WMI remote execution",
        "severity": "Critical",
        "phase": "Execution",
    },
    # Defense evasion pre-encryption
    {
        "timestamp": "2026-06-19T03:23:01Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1562.001",
        "event": "Process: svchost32.exe → cmd.exe /c sc stop WinDefend",
        "severity": "Critical",
        "phase": "Defense Evasion",
    },
    {
        "timestamp": "2026-06-19T03:23:08Z",
        "source": "System.evtx (SRV-FS-01)",
        "event_id": "7036",
        "technique": "T1562.001",
        "event": "Windows Defender Antivirus Service entered the stopped state",
        "severity": "Critical",
        "phase": "Defense Evasion",
    },
    {
        "timestamp": "2026-06-19T03:23:15Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1490",
        "event": "Process: cmd.exe /c vssadmin delete shadows /all /quiet",
        "severity": "Critical",
        "phase": "Defense Evasion",
    },
    {
        "timestamp": "2026-06-19T03:23:22Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1490",
        "event": "Process: cmd.exe /c wbadmin delete catalog -quiet",
        "severity": "Critical",
        "phase": "Defense Evasion",
    },
    {
        "timestamp": "2026-06-19T03:23:29Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1490",
        "event": "Process: cmd.exe /c bcdedit /set {default} recoveryenabled No",
        "severity": "Critical",
        "phase": "Defense Evasion",
    },
    # Encryption begins
    {
        "timestamp": "2026-06-19T03:24:05Z",
        "source": "MFT Analysis",
        "event_id": "MFT",
        "technique": "T1486",
        "event": "First .ncrypt file observed: Finance\\Q1_2026_client_balances.xlsx.ncrypt",
        "severity": "Critical",
        "phase": "Encryption",
    },
    {
        "timestamp": "2026-06-19T03:24:05Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1486",
        "event": "svchost32.exe: mass file modification observed (high I/O — 2+ GB/min)",
        "severity": "Critical",
        "phase": "Encryption",
    },
    # Ransom notes dropped (after encryption sweep completes)
    {
        "timestamp": "2026-06-19T06:11:44Z",
        "source": "MFT Analysis",
        "event_id": "MFT",
        "technique": "T1486",
        "event": "Ransom note drop begins: !!READ_ME_NOW!!.txt in 847 directories",
        "severity": "Critical",
        "phase": "Ransom Note Delivery",
    },
    {
        "timestamp": "2026-06-19T06:13:58Z",
        "source": "Sysmon.evtx (SRV-FS-01)",
        "event_id": "1",
        "technique": "T1491.001",
        "event": "SystemPropertiesAdvanced.exe called: desktop wallpaper changed to ransom image",
        "severity": "High",
        "phase": "Ransom Note Delivery",
    },
    # First detection
    {
        "timestamp": "2026-06-19T06:14:00Z",
        "source": "Monitoring Alert",
        "event_id": "N/A",
        "technique": None,
        "event": "First monitoring alert: file share anomaly detected — unusual extension proliferation",
        "severity": "Critical",
        "phase": "Detection",
    },
    {
        "timestamp": "2026-06-19T06:31:00Z",
        "source": "IR Action",
        "event_id": "N/A",
        "technique": None,
        "event": "Trading operations suspended. SRV-FS-01 network-isolated.",
        "severity": "Info",
        "phase": "Response",
    },
]

SIMULATED_IOCS = {
    "victim_id": "NOVA-20260619-7X4K",
    "ransomware_extension": ".ncrypt",
    "ransom_note_filename": "!!READ_ME_NOW!!.txt",
    "payment_wallet": "48edfhj3kHJKsdnc8x7mNkLPqRsTuVwXy...",
    "payment_amount_xmr": 127.4,
    "payment_deadline_utc": "2026-06-22T06:14:00Z",
    "contact_email": "ncrypt-support@protonmail.com",
    "leak_site": "http://ncrypt3k4j7mxbwz.onion/novacrest",
    "ransomware_binary": {
        "filename": "svchost32.exe",
        "staged_path": "C:\\Windows\\Temp\\svchost32.exe",
        "size_bytes": 5662720,
        "sha256": "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "compiled": "2026-06-15T14:22:00Z",  # Compiled AFTER initial access
        "packer": "UPX 3.96",
        "language": "C++",
        "linker": "Microsoft Linker 14.0",
    },
    "network_iocs": {
        "c2_ip": "198.51.100.99",
        "c2_check_in": "2026-06-19T03:23:55Z",
        "onion_service": "ncrypt3k4j7mxbwz.onion",
        "protocol": "HTTPS (TCP:443)",
    },
    "persistence": {
        "service_name": "NovaCrypt Service",
        "service_display": "Novacrest Cryptographic Services",
        "service_path": "C:\\Windows\\System32\\svchost32.exe -k netsvcs",
        "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NovaCrypt",
        "status": "INSTALLED — not yet deleted during IR",
    },
    "commands_executed": [
        "vssadmin delete shadows /all /quiet",
        "wbadmin delete catalog -quiet",
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        "sc stop WinDefend",
        "sc config WinDefend start= disabled",
        "netsh advfirewall firewall add rule name='Block SMB' dir=out action=block protocol=TCP localport=445",
    ],
}

SIMULATED_PERSISTENCE_ARTIFACTS = {
    "service": {
        "name": "NovaCrypt",
        "display": "Novacrest Cryptographic Services",
        "path": "C:\\Windows\\System32\\svchost32.exe -k netsvcs",
        "start_type": "AUTO_START",
        "status": "Running",
        "installed": "2026-06-19T03:23:00Z",
    },
    "registry": {
        "key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe",
        "value": "Debugger",
        "data": "C:\\Windows\\Temp\\svchost32.exe",
        "note": "IFEO debugger hijack — Task Manager launches ransomware if opened",
    },
}


def extract_iocs(note_content: str, verbose: bool) -> Dict:
    """Extract IOCs from ransom note content."""
    import re
    iocs = {}

    # Victim ID
    victim_match = re.search(r'YOUR VICTIM ID: (\S+)', note_content)
    if victim_match:
        iocs["victim_id"] = victim_match.group(1)

    # Email
    email_match = re.search(r'[\w.-]+@[\w.-]+\.\w+', note_content)
    if email_match:
        iocs["contact_email"] = email_match.group(0)

    # Onion URL
    onion_match = re.search(r'http://\S+\.onion\S*', note_content)
    if onion_match:
        iocs["leak_site"] = onion_match.group(0)

    # Monero wallet (simplified pattern)
    xmr_match = re.search(r'[4-9][0-9A-Za-z]{90,}', note_content)
    if xmr_match:
        iocs["xmr_wallet"] = xmr_match.group(0)[:20] + "..."

    if verbose:
        for k, v in iocs.items():
            log.info(f"  IOC [{k}]: {v}")

    return iocs


def analyze_encryption_scope(scope: Dict, verbose: bool) -> None:
    """Report on encryption scope."""
    total_files = scope["total_files_encrypted"]
    total_gb = scope["total_size_encrypted_gb"]
    total_notes = scope["total_ransom_notes"]

    print("\nENCRYPTION SCOPE ANALYSIS")
    print("─" * 55)
    print(f"  Total files encrypted:  {total_files:,}")
    print(f"  Total data encrypted:   {total_gb:,} GB")
    print(f"  Ransom notes dropped:   {total_notes:,} directories")
    print(f"  Encryption algorithm:   {scope['encryption_algorithm']}")
    print()

    for share in scope["shares_affected"]:
        print(f"  Share: {share['share']}")
        print(f"    Files encrypted: {share['files_encrypted']:,} "
              f"({share['size_encrypted_gb']:.1f} GB)")
        print(f"    File types: {', '.join(share['file_types_hit'][:4])}")
        print()


def reconstruct_timeline(events: List[Dict], verbose: bool) -> None:
    """Print forensic timeline."""
    print("\nFORENSIC TIMELINE (UTC)")
    print("─" * 80)
    print(f"  {'TIMESTAMP':22} {'PHASE':20} {'TECHNIQUE':12} {'EVENT'}")
    print("  " + "─" * 78)

    current_phase = ""
    for event in sorted(events, key=lambda x: x["timestamp"]):
        phase = event["phase"]
        if phase != current_phase:
            print(f"\n  ── {phase} ──")
            current_phase = phase

        tech = event.get("technique") or "—"
        sev_icon = ("🔴" if event["severity"] == "Critical" else
                    "🟡" if event["severity"] == "High" else "ℹ️ ")
        ts = event["timestamp"].replace("Z", " UTC")
        evt = event["event"][:55]
        print(f"  {sev_icon} {ts:22} {tech:12} {evt}")

    # Key metrics
    events_sorted = sorted(events, key=lambda x: x["timestamp"])
    first = events_sorted[0]["timestamp"]
    encrypt_start = next(e for e in events_sorted if "First .ncrypt" in e["event"])["timestamp"]
    detection = next(e for e in events_sorted if "monitoring alert" in e["event"].lower())["timestamp"]

    d_encrypt = (datetime.datetime.fromisoformat(encrypt_start.replace("Z", "+00:00")) -
                 datetime.datetime.fromisoformat(first.replace("Z", "+00:00")))
    d_detect = (datetime.datetime.fromisoformat(detection.replace("Z", "+00:00")) -
                datetime.datetime.fromisoformat(encrypt_start.replace("Z", "+00:00")))

    print(f"\n  METRICS:")
    print(f"  Lateral movement → Encryption start: {int(d_encrypt.total_seconds() // 60)} minutes")
    print(f"  Encryption start → First detection:  {int(d_detect.total_seconds() // 60)} minutes")
    print(f"  Total encryption window: ~2h 50min (03:24 → 06:12 UTC)")
    print()


def assess_recovery(verbose: bool) -> None:
    """Print recovery options assessment."""
    print("\nRECOVERY ASSESSMENT")
    print("─" * 55)
    options = [
        ("Backup restore (pre-June 14)", "VIABLE", "Last clean backup: June 13 23:00 UTC"),
        ("Shadow copy recovery", "NOT VIABLE", "VSS deleted by ransomware at 03:23 UTC"),
        ("No More Ransom decryptor", "INVESTIGATE", "ncrypt variant not yet confirmed in NMR database"),
        ("FBI/CISA decryptor", "POSSIBLE", "LockBit 3.0 keys seized in Cronos 2024; check if this key set applies"),
        ("Pay ransom", "NOT RECOMMENDED", "OFAC risk; no guarantee; funds criminal enterprise"),
    ]
    for option, status, note in options:
        icon = "✅" if status == "VIABLE" else ("🔍" if status in ("INVESTIGATE","POSSIBLE") else "❌")
        print(f"  {icon} {option}: {status}")
        print(f"     {note}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 25 Ransomware Analyzer")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--mode", choices=["ioc","scope","timeline","persistence","all"],
                        default="all")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day25_ransomware_analysis.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 25 — Ransomware Analyzer")
    log.info(" NovaCrest Capital Group | Case NCA-2026-06-R")
    log.info(" Target: SRV-FS-01 | Strain: ncrypt (.ncrypt extension)")
    log.info("=" * 70)
    log.info("")

    print("\n" + "=" * 70)
    print("  RANSOMWARE FORENSICS REPORT — Day 25 | NCA-2026-06-R")
    print("  Target: SRV-FS-01 | NovaCrest Capital Group")
    print("=" * 70)

    log.info("[1] Extracting IOCs from ransom note...")
    extracted_iocs = extract_iocs(RANSOM_NOTE_CONTENT, args.verbose)
    log.info("")

    log.info("[2] Analyzing encryption scope...")
    analyze_encryption_scope(SIMULATED_ENCRYPTION_SCOPE, args.verbose)

    log.info("[3] Reconstructing forensic timeline...")
    reconstruct_timeline(SIMULATED_TIMELINE, args.verbose)

    log.info("[4] Assessing recovery options...")
    assess_recovery(args.verbose)

    output = {
        "case": "NCA-2026-06-R",
        "target": "SRV-FS-01",
        "iocs": SIMULATED_IOCS,
        "encryption_scope": SIMULATED_ENCRYPTION_SCOPE,
        "timeline": SIMULATED_TIMELINE,
        "persistence": SIMULATED_PERSISTENCE_ARTIFACTS,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Analysis written: {args.output}")


if __name__ == "__main__":
    main()
