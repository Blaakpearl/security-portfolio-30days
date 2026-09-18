"""
Day 25 — Memory Forensics: Ransomware Artifact Hunter
NovaCrest Capital Group | Digital Forensics

PURPOSE: Simulates Volatility3 memory analysis output for ransomware
         investigation — process injection detection, encrypted key
         material recovery, C2 network connections, and unpacked binary
         extraction from a live memory dump of SRV-FS-01.

VOLATILITY3 PLUGINS COVERED:
  windows.pslist        — Running processes at time of dump
  windows.pstree        — Process parent-child relationships
  windows.psxview       — Cross-view process comparison (find hidden)
  windows.malfind       — Injected/suspicious memory regions
  windows.dlllist       — Loaded DLLs per process
  windows.netstat       — Network connections
  windows.handles       — Open handles (files, keys, mutexes)
  windows.registry      — Registry key inspection
  windows.dumpfiles     — Extract binary from memory

MEMORY DUMP: SRV-FS-01_memory_2026-06-19_0645UTC.mem (39 GB)
ACQUISITION TIME: 06:45 UTC (31 minutes after ransomware note drop, 
                              14 minutes after network isolation)

Usage:
    python memory_forensics.py --demo --verbose
    python memory_forensics.py --dump SRV-FS-01_memory.mem
    python memory_forensics.py --demo --plugin malfind
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
log = logging.getLogger("memory_forensics")


# ── Simulated Volatility3 Output (Demo Mode) ───────────────────────────

SIMULATED_PSLIST = [
    # Legitimate processes
    {"pid": 4,    "ppid": 0,    "name": "System",       "threads": 142, "start": "2026-06-19T00:00:01Z", "suspicious": False},
    {"pid": 504,  "ppid": 4,    "name": "smss.exe",     "threads": 3,   "start": "2026-06-19T00:00:01Z", "suspicious": False},
    {"pid": 680,  "ppid": 672,  "name": "csrss.exe",    "threads": 14,  "start": "2026-06-19T00:00:02Z", "suspicious": False},
    {"pid": 768,  "ppid": 672,  "name": "wininit.exe",  "threads": 1,   "start": "2026-06-19T00:00:02Z", "suspicious": False},
    {"pid": 792,  "ppid": 768,  "name": "services.exe", "threads": 11,  "start": "2026-06-19T00:00:02Z", "suspicious": False},
    {"pid": 812,  "ppid": 768,  "name": "lsass.exe",    "threads": 10,  "start": "2026-06-19T00:00:02Z", "suspicious": False},
    {"pid": 1024, "ppid": 792,  "name": "svchost.exe",  "threads": 22,  "start": "2026-06-19T00:00:05Z", "suspicious": False},
    # WMI — parent of ransomware execution
    {"pid": 2884, "ppid": 1024, "name": "WmiPrvSE.exe", "threads": 8,   "start": "2026-06-19T03:22:40Z", "suspicious": False,
     "note": "WMI provider host — spawned ransomware at 03:22:45"},
    # RANSOMWARE PROCESS
    {"pid": 3412, "ppid": 2884, "name": "svchost32.exe","threads": 24,  "start": "2026-06-19T03:22:45Z", "suspicious": True,
     "note": "RANSOMWARE: svchost32.exe (not svchost.exe). Parent: WmiPrvSE.exe. 24 threads = file encryption thread pool.",
     "path": "C:\\Windows\\Temp\\svchost32.exe",
     "cmdline": "C:\\Windows\\Temp\\svchost32.exe --encrypt --threads 24 --shares C:\\Shares\\"},
    # Cmd processes spawned by ransomware (VSS deletion, etc.)
    {"pid": 3588, "ppid": 3412, "name": "cmd.exe",      "threads": 1,   "start": "2026-06-19T03:23:01Z", "suspicious": True,
     "note": "cmd.exe spawned by ransomware — executed vssadmin, bcdedit, sc stop WinDefend"},
    {"pid": 3644, "ppid": 3588, "name": "vssadmin.exe", "threads": 1,   "start": "2026-06-19T03:23:15Z", "suspicious": True,
     "note": "vssadmin delete shadows /all /quiet — VSS destroyed"},
]

SIMULATED_MALFIND = [
    {
        "pid": 3412,
        "process": "svchost32.exe",
        "address": "0x0000000003A00000",
        "size": 5791744,
        "protection": "PAGE_EXECUTE_READWRITE",
        "vad_type": "VadS",
        "header_bytes": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
        "finding": "MZ header at base — PE executable injected into process memory",
        "pe_extracted": True,
        "extracted_sha256": "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
        "severity": "Critical",
        "note": "Unpacked ransomware binary recovered from memory. UPX decompressed in-memory.",
    },
    {
        "pid": 812,
        "process": "lsass.exe",
        "address": "0x0000000004B10000",
        "size": 8192,
        "protection": "PAGE_EXECUTE_READWRITE",
        "vad_type": "VadS",
        "header_bytes": "FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51",
        "finding": "Shellcode pattern — no MZ header; possible credential dumping shellcode",
        "pe_extracted": False,
        "severity": "High",
        "note": "Injected shellcode in lsass.exe — likely credential dumping prior to ransomware deployment",
    },
]

SIMULATED_DLLS = {
    3412: [
        {"name": "ntdll.dll",       "base": "0x00007FF800000000", "suspicious": False},
        {"name": "kernel32.dll",    "base": "0x00007FF7F0000000", "suspicious": False},
        {"name": "bcrypt.dll",      "base": "0x00007FF7C0000000", "suspicious": False,
         "note": "Windows crypto API — AES-256 implementation"},
        {"name": "ncrypt.dll",      "base": "0x00007FF7B0000000", "suspicious": False,
         "note": "Windows Next-Gen Crypto — RSA-4096 key operations (explains .ncrypt extension naming)"},
        {"name": "winhttp.dll",     "base": "0x00007FF7A0000000", "suspicious": False,
         "note": "HTTP client — used for C2 check-in and key upload"},
        {"name": "CRYPTSP.dll",     "base": "0x00007FF790000000", "suspicious": False},
    ]
}

SIMULATED_NETSTAT = [
    {
        "proto": "TCPv4",
        "local": "10.0.3.20:49812",
        "foreign": "198.51.100.99:443",
        "state": "CLOSE_WAIT",
        "pid": 3412,
        "process": "svchost32.exe",
        "note": "C2 connection (CLOSE_WAIT = disconnected at isolation time). Attacker IP confirmed.",
    },
    {
        "proto": "TCPv4",
        "local": "10.0.3.20:445",
        "foreign": "0.0.0.0:*",
        "state": "LISTENING",
        "pid": 4,
        "process": "System",
        "note": "SMB listener — used for share access during lateral movement",
    },
]

SIMULATED_MUTEX = [
    {
        "pid": 3412,
        "process": "svchost32.exe",
        "handle_type": "Mutant",
        "name": "Global\\NovaCryptMutex_NOVA-20260619-7X4K",
        "note": "CRITICAL: Mutex contains victim ID — prevents double-encryption; confirms unique per-victim build",
    }
]

SIMULATED_REGISTRY = {
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NovaCrypt": {
        "ImagePath": "C:\\Windows\\System32\\svchost32.exe -k netsvcs",
        "DisplayName": "Novacrest Cryptographic Services",
        "Start": 2,  # AUTO_START
        "ObjectName": "LocalSystem",
        "note": "PERSISTENCE: Ransomware installed as service; will restart on reboot",
    }
}


def run_pslist(processes: List[Dict], verbose: bool) -> None:
    """Display simulated process list with anomaly highlighting."""
    print("\n[VOLATILITY3] windows.pslist")
    print("─" * 75)
    print(f"  {'PID':6} {'PPID':6} {'NAME':20} {'THREADS':8} {'START UTC':22} {'FLAG'}")
    print("  " + "─" * 73)
    for p in processes:
        icon = "🔴" if p["suspicious"] else "  "
        note = f" ← {p['note'][:40]}" if p.get("note") and p["suspicious"] else ""
        print(f"  {icon} {p['pid']:<6} {p['ppid']:<6} {p['name']:<20} "
              f"{p['threads']:<8} {p['start']:22}{note}")


def run_malfind(findings: List[Dict], verbose: bool) -> None:
    """Display simulated malfind output."""
    print("\n[VOLATILITY3] windows.malfind")
    print("─" * 70)
    for f in findings:
        print(f"\n  PID: {f['pid']} | Process: {f['process']}")
        print(f"  Address: {f['address']} | Size: {f['size']:,} bytes")
        print(f"  Protection: {f['protection']}")
        print(f"  Header: {f['header_bytes']}")
        print(f"  Finding: {f['finding']}")
        print(f"  Severity: {f['severity']}")
        if f.get("pe_extracted"):
            print(f"  ✅ PE extracted → SHA256: {f['extracted_sha256'][:32]}...")
        print(f"  Note: {f['note']}")


def run_netstat(connections: List[Dict], verbose: bool) -> None:
    """Display simulated network connections."""
    print("\n[VOLATILITY3] windows.netstat")
    print("─" * 70)
    print(f"  {'PROTO':8} {'LOCAL':22} {'FOREIGN':22} {'STATE':12} {'PID':6} {'PROCESS'}")
    print("  " + "─" * 68)
    for c in connections:
        icon = "🔴" if "198.51.100.99" in c["foreign"] else "  "
        print(f"  {icon} {c['proto']:8} {c['local']:22} {c['foreign']:22} "
              f"{c['state']:12} {c['pid']:<6} {c['process']}")
        if c.get("note"):
            print(f"       ↳ {c['note']}")


def run_crypto_hunt(dlls: Dict, verbose: bool) -> None:
    """Identify crypto libraries loaded by ransomware process."""
    print("\n[VOLATILITY3] windows.dlllist — Crypto library hunt (PID 3412)")
    print("─" * 70)
    for dll in dlls.get(3412, []):
        icon = "🔑" if "crypt" in dll["name"].lower() else "  "
        note = f" ← {dll['note']}" if dll.get("note") else ""
        print(f"  {icon} {dll['base']}  {dll['name']}{note}")


def run_mutex_hunt(mutexes: List[Dict], verbose: bool) -> None:
    """Display mutex handles — ransomware anti-double-encryption."""
    print("\n[VOLATILITY3] windows.handles (Mutant/Mutex filter)")
    print("─" * 70)
    for m in mutexes:
        print(f"  🔴 PID: {m['pid']} ({m['process']})")
        print(f"     Mutex: {m['name']}")
        print(f"     Note:  {m['note']}")


def emit_memory_report(verbose: bool) -> None:
    """Run full memory forensics analysis pipeline."""
    print("\n" + "=" * 70)
    print("  MEMORY FORENSICS REPORT — Day 25")
    print("  SRV-FS-01 | Dump: 2026-06-19T06:45:00Z | Size: 39 GB")
    print("=" * 70)

    run_pslist(SIMULATED_PSLIST, verbose)
    run_malfind(SIMULATED_MALFIND, verbose)
    run_netstat(SIMULATED_NETSTAT, verbose)
    run_crypto_hunt(SIMULATED_DLLS, verbose)
    run_mutex_hunt(SIMULATED_MUTEX, verbose)

    print("\n[SUMMARY] Key Memory Forensics Findings:")
    print("─" * 55)
    findings = [
        ("Critical", "svchost32.exe (PID 3412) — ransomware process, WmiPrvSE.exe parent"),
        ("Critical", "PE binary recovered from memory (unpacked from UPX) — SHA256 confirmed"),
        ("Critical", "C2 connection to 198.51.100.99:443 (CLOSE_WAIT at isolation)"),
        ("Critical", "NovaCrypt service persistence installed (survives reboot)"),
        ("High",     "Shellcode injected into lsass.exe — credential harvesting pre-encryption"),
        ("High",     "bcrypt.dll + ncrypt.dll loaded — AES-256 + RSA-4096 confirmed"),
        ("Medium",   "Mutex NOVA-20260619-7X4K confirms unique victim build — custom deployment"),
    ]
    for severity, finding in findings:
        icon = "🔴" if severity == "Critical" else "🟠"
        print(f"  {icon} [{severity}] {finding}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 25 Memory Forensics")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--dump", help="Path to memory dump file")
    parser.add_argument("--plugin", choices=["pslist","malfind","netstat",
                                              "dlls","mutex","all"], default="all")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day25_memory_findings.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 25 — Memory Forensics | Volatility3")
    log.info(" NovaCrest SRV-FS-01 | Case NCA-2026-06-R")
    log.info("=" * 70)
    log.info("")

    emit_memory_report(args.verbose)

    output = {
        "dump": "SRV-FS-01_memory_2026-06-19_0645UTC.mem",
        "size_gb": 39,
        "acquisition_utc": "2026-06-19T06:45:00Z",
        "pslist": SIMULATED_PSLIST,
        "malfind": SIMULATED_MALFIND,
        "netstat": SIMULATED_NETSTAT,
        "mutex": SIMULATED_MUTEX,
        "registry": SIMULATED_REGISTRY,
        "ransomware_pid": 3412,
        "ransomware_binary_sha256": SIMULATED_MALFIND[0]["extracted_sha256"],
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Memory findings written: {args.output}")


if __name__ == "__main__":
    main()
