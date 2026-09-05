"""
Day 22 — Risk Register Builder
NovaCrest Capital Group | Threat Intelligence

PURPOSE: Builds the full risk register from scored findings — generating
         a formatted markdown document with all three scores, business
         impact narrative, regulatory mapping, and prioritized remediation
         actions. Also produces a JSON artifact for GRC tool ingestion.

OUTPUTS:
  - reports/day22_risk_register.md  (detailed, analyst-grade)
  - reports/day22_executive_brief.md (condensed, board-ready)
  - artifacts/risk_scores.json      (machine-readable)

Usage:
    python risk_register_builder.py --demo
    python risk_register_builder.py --demo --format executive
    python risk_register_builder.py --input risk_scores.json --format all
"""

import argparse
import datetime
import json
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("risk_register_builder")


# ── Full Finding Detail (augments risk_scorer.py output) ──────────────
FINDING_DETAIL = {
    "RF-001": {
        "category": "Credential Exposure",
        "affected_systems": ["AWS cloud environment", "All AWS-connected systems"],
        "data_at_risk": "Full AWS admin access; all S3 buckets; all EC2/RDS",
        "regulatory": ["SEC Reg S-P", "NY DFS §500.07", "SOX"],
        "business_impact": "An attacker with this credential has full AWS admin rights. The confirmed intrusion used this key to assume the novacrest-admin-role (CloudTrail confirmed). Trading infrastructure, client data storage, and all cloud-hosted systems were at risk.",
        "remediation": [
            "Revoke and rotate AWS key immediately (DONE — Day 16 response)",
            "Enable AWS Config rule: access-keys-rotated (90-day max)",
            "Deploy git-secrets or TruffleHog in CI/CD pre-commit hook",
            "Enable GitHub secret scanning with push protection",
            "Audit all repositories for historical credential exposure",
        ],
        "effort": "Low",
        "owner": "DevOps / Cloud Security",
        "target_date": "2026-06-25",
    },
    "RF-002": {
        "category": "Misconfiguration — Linux Privilege",
        "affected_systems": ["lnx-trade-01", "lnx-trade-02", "lnx-db-01"],
        "data_at_risk": "Root access to trading servers; all trading data; Bloomberg API keys",
        "regulatory": ["NY DFS §500.07", "SOX"],
        "business_impact": "The NOPASSWD sudo misconfiguration allowed the attacker to obtain a root shell on lnx-trade-01 in a single command, accessing all trading algorithms and live position data.",
        "remediation": [
            "Remove NOPASSWD rule from /etc/sudoers.d/svc_ncg (DONE)",
            "Audit all sudoers files: grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/",
            "Implement RBAC: restrict svc_ncg to specific service restart commands only",
            "Enable requiretty in /etc/sudoers for all service accounts",
            "Deploy quarterly sudoers audit as part of vulnerability management",
        ],
        "effort": "Low",
        "owner": "Linux Infrastructure",
        "target_date": "2026-06-28",
    },
    "RF-003": {
        "category": "Misconfiguration — Linux SUID",
        "affected_systems": ["lnx-trade-01"],
        "data_at_risk": "Root escalation on trading server",
        "regulatory": ["NY DFS §500.07"],
        "business_impact": "Three GTFOBin-abusable SUID binaries provided three independent root escalation paths. Any one path is sufficient; the attacker used the find binary in combination with the NOPASSWD rule.",
        "remediation": [
            "Remove SUID from find, python3, vim: chmod -s (DONE)",
            "Deploy SUID baseline audit (suid_audit_scanner.py — Day 17)",
            "Mount /tmp, /home with nosuid in /etc/fstab",
            "Run quarterly: find / -perm -4000 -o -perm -2000 | diff baseline -",
        ],
        "effort": "Low",
        "owner": "Linux Infrastructure",
        "target_date": "2026-06-28",
    },
    "RF-004": {
        "category": "Credential Policy — Kerberos",
        "affected_systems": ["SRV-AD-01", "All domain-joined systems"],
        "data_at_risk": "Service account credentials; potential DA escalation",
        "regulatory": ["NY DFS §500.07", "SOX"],
        "business_impact": "Three service accounts were Kerberoasted during the engagement. If the svc_backup hash was cracked offline, the attacker gains Backup Operator rights — enabling read access to every file on domain-joined servers.",
        "remediation": [
            "Rotate all kerberoasted account passwords: 25+ chars (URGENT)",
            "Convert all service accounts to gMSA (Group Managed Service Accounts)",
            "Force AES-256 only on all service accounts; remove RC4 support",
            "Audit all SPNs: Get-ADUser -Filter {ServicePrincipalName -ne '$null'}",
            "Deploy Event 4769 RC4 alert (Splunk SPL already written — Day 17)",
        ],
        "effort": "Medium",
        "owner": "Active Directory / Identity",
        "target_date": "2026-07-05",
    },
    "RF-005": {
        "category": "Detection Gap — SIEM Coverage",
        "affected_systems": ["All Linux hosts", "Network perimeter"],
        "data_at_risk": "N/A — detection gap; enables all other techniques",
        "regulatory": ["NY DFS §500.06", "SEC Reg SCI"],
        "business_impact": "The absence of Zeek and auditd in the SIEM meant the entire Day 18 exfiltration was invisible in real time. Detection was only possible retrospectively via log forensics (Day 19). During an active incident, this delay is the difference between stopping exfil and a confirmed breach.",
        "remediation": [
            "Forward Zeek logs to Elastic SIEM via Filebeat (NOW)",
            "Forward auditd to SIEM via Filebeat Linux audit module (NOW)",
            "Configure Elastic EQL rules for exfil detection (queries/elastic_killchain.eql)",
            "Set UEBA baseline on all endpoints (Day 21 roadmap ROAD-08)",
            "Monthly SIEM coverage audit — verify all log sources are ingesting",
        ],
        "effort": "Low",
        "owner": "Security Operations / SIEM",
        "target_date": "2026-06-30",
    },
    "RF-006": {
        "category": "Detection Gap — TLS Inspection",
        "affected_systems": ["All HTTPS egress traffic"],
        "data_at_risk": "C2 channels; data exfil via encrypted HTTPS",
        "regulatory": ["NY DFS §500.15"],
        "business_impact": "Without TLS inspection, domain fronting (Variant 3, Day 20) was completely invisible. The C2 channel appeared as legitimate Azure CDN traffic. TLS inspection was enabled before the Day 21 capstone and caught the domain fronting in 17 minutes.",
        "remediation": [
            "Enable Zscaler SSL inspection for uncategorized/new domains (DONE — Day 21)",
            "Enable for all categories over time; exemption list for pinned-cert apps",
            "Deploy JA3 blocklist (Sigma rules — sigma_c2_detection.yml)",
            "Quarterly review of TLS inspection coverage and bypass exceptions",
        ],
        "effort": "Low",
        "owner": "Network Security / Zscaler Admin",
        "target_date": "2026-06-30",
    },
    "RF-007": {
        "category": "Data Loss — Confirmed Exfiltration",
        "affected_systems": ["WS-FIN-04", "lnx-trade-01"],
        "data_at_risk": "Trading algorithms (IP), Bloomberg API key, client account balances (PII), SSH keys",
        "regulatory": ["SEC Reg S-P", "SEC Reg SCI", "NY DFS §500.17 (72-hr)", "GDPR Art. 33"],
        "business_impact": "253 MB of data was confirmed exfiltrated including proprietary trading algorithms (competitive loss), live trading position data (potential market manipulation), and client account balances (SEC Reg S-P breach). Notification is legally required.",
        "remediation": [
            "Notify SEC (Reg S-P) within 30 days — DEADLINE: July 17, 2026",
            "Notify NY DFS within 72 hours — OVERDUE as of June 19, 2026",
            "Notify affected clients — work with legal for timeline",
            "Bloomberg: revoke and reissue API key",
            "Rebuild trading algorithm repository from pre-incident backup",
            "Deploy Purview Endpoint DLP on all Windows endpoints",
        ],
        "effort": "High",
        "owner": "CISO / Legal / Compliance",
        "target_date": "2026-07-17",
    },
    "RF-008": {
        "category": "Evidence Integrity — Log Destruction",
        "affected_systems": ["WS-FIN-04 (Security.evtx, System.evtx)"],
        "data_at_risk": "649 Windows Security events destroyed; forensic timeline incomplete",
        "regulatory": ["SEC Reg S-P", "SOX", "NY DFS §500.06"],
        "business_impact": "The attacker cleared Windows Security and System logs at 15:04 UTC, destroying 649 events covering the initial access and escalation window. Sysmon and Zeek filled the gap, but evidence was still compromised. Legal hold may be required.",
        "remediation": [
            "Deploy Event 1102/104 alert — fires immediately when log is cleared",
            "Forward Windows events in real-time (not batch) to SIEM",
            "Enable Windows Event Forwarding (WEF) to dedicated log server",
            "Consider: audit log protection via WMI subscription or PPL",
            "Legal hold: preserve all remaining forensic evidence",
        ],
        "effort": "Low",
        "owner": "Security Operations",
        "target_date": "2026-07-05",
    },
    "RF-009": {
        "category": "DLP Gap — Cloud Egress",
        "affected_systems": ["All endpoints with internet access"],
        "data_at_risk": "Any data uploadable to attacker-controlled S3 buckets",
        "regulatory": ["SEC Reg S-P", "NY DFS §500.15"],
        "business_impact": "The 85 MB S3 upload to an attacker-controlled bucket was undetected by DLP because the policy covered M365 content only — not network-level uploads to external S3. Zscaler DLP was not configured for cloud storage upload detection.",
        "remediation": [
            "Deploy Zscaler Cloud App Control — block unauthorized S3 buckets",
            "Microsoft Purview: enable Endpoint DLP + cloud egress policy",
            "AWS Organizations SCP: restrict S3 PutObject to org-owned accounts only",
            "Zeek files.log alert: large archive (.tar.gz/.zip) to external IP",
            "CASB: allowlist only corporate cloud storage destinations",
        ],
        "effort": "Medium",
        "owner": "Network Security / DLP",
        "target_date": "2026-07-15",
    },
    "RF-010": {
        "category": "C2 Evasion — Domain Fronting",
        "affected_systems": ["All outbound HTTPS traffic"],
        "data_at_risk": "C2 channel persistence; attacker dwell time extension",
        "regulatory": ["NY DFS §500.15"],
        "business_impact": "Domain fronting allowed the attacker to maintain a C2 channel that appeared to be Azure CDN traffic. Without TLS inspection, it was completely invisible. This technique was used for the Cobalt Strike C2 in Phase 7 of the capstone.",
        "remediation": [
            "TLS inspection enabled (DONE — covers this gap going forward)",
            "Block TLS connections to IP-only destinations (no SNI)",
            "Deploy Sigma rule: domain fronting Host≠SNI",
            "Monitor CDN connections with unusual timing patterns",
            "Quarterly: review CDN provider terms on fronting; major CDNs now block",
        ],
        "effort": "Low",
        "owner": "Network Security",
        "target_date": "2026-07-05",
    },
}


def build_risk_register(scored_findings: List, output_path: str) -> None:
    """Write full markdown risk register."""
    lines = [
        "# Day 22 — Risk Register",
        "## NovaCrest Capital Group | Post-Incident Risk Assessment",
        f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d')}",
        "**Author:** V. Willis, CISSP",
        "**Classification:** TLP:AMBER",
        "",
        "---",
        "",
        "## Risk Register Summary",
        "",
        "| ID | Finding | CVSS | DREAD | ATT&CK Tier | Priority |",
        "|----|---------|------|-------|-------------|---------|",
    ]

    for f in scored_findings:
        pri = f["priority"].split("—")[0].strip()
        lines.append(
            f"| {f['id']} | {f['name'][:45]} | {f['cvss_score']} | "
            f"{f['dread_score']} | {f['attck_tier']} | {pri} |"
        )

    lines += ["", "---", ""]

    for f in scored_findings:
        detail = FINDING_DETAIL.get(f["id"], {})
        lines += [
            f"## {f['id']} — {f['name']}",
            "",
            f"**Category:** {detail.get('category', '—')}  ",
            f"**ATT&CK Technique:** {f['technique']}  ",
            f"**Priority:** {f['priority']}  ",
            f"**Remediation Owner:** {detail.get('owner', '—')}  ",
            f"**Target Date:** {detail.get('target_date', '—')}  ",
            "",
            "### Scores",
            "",
            f"| Methodology | Score | Severity |",
            f"|-------------|-------|---------|",
            f"| CVSS 3.1 | {f['cvss_score']} | {f['cvss_severity']} |",
            f"| DREAD | {f['dread_score']}/10 | — |",
            f"| ATT&CK Tier | {f['attck_tier_score']}/5.0 | {f['attck_tier']} |",
            "",
            "### Business Impact",
            "",
            detail.get("business_impact", "—"),
            "",
            "### Regulatory Exposure",
            "",
        ]
        for reg in detail.get("regulatory", []):
            lines.append(f"- {reg}")
        lines += [
            "",
            "### Remediation Actions",
            "",
        ]
        for i, action in enumerate(detail.get("remediation", []), 1):
            lines.append(f"{i}. {action}")
        lines += ["", "---", ""]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    log.info(f"Risk register written: {output_path}")


def build_executive_brief(scored_findings: List, output_path: str) -> None:
    """Write condensed board/CISO-level risk summary."""
    p1 = [f for f in scored_findings if "P1" in f["priority"]]
    p2 = [f for f in scored_findings if "P2" in f["priority"]]
    reg_required = ["RF-007"]  # Confirmed regulatory notification needed

    lines = [
        "# Executive Risk Brief — NovaCrest Capital Group",
        f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d')}",
        "**Prepared by:** V. Willis, CISSP",
        "**Distribution:** CISO · General Counsel · Board Risk Committee",
        "",
        "---",
        "",
        "## Situation",
        "",
        "A confirmed intrusion against NovaCrest Capital Group resulted in "
        "unauthorized access across Windows and Linux trading infrastructure, "
        "privilege escalation to SYSTEM and root, and confirmed exfiltration "
        "of approximately **253 MB** of data including proprietary trading "
        "algorithms, Bloomberg API credentials, and client account records.",
        "",
        "The security team has completed full forensic analysis (Days 15–21). "
        "This brief summarizes the ten confirmed risk findings, their severity "
        "scores, and required actions.",
        "",
        "---",
        "",
        "## Top Risks Requiring Immediate Action",
        "",
    ]

    for f in p1:
        detail = FINDING_DETAIL.get(f["id"], {})
        lines += [
            f"### {f['id']} — {f['name']}",
            f"**Score:** CVSS {f['cvss_score']} | DREAD {f['dread_score']}/10 | {f['attck_tier']}",
            f"**Owner:** {detail.get('owner', '—')} | **Due:** {detail.get('target_date', '—')}",
            "",
            detail.get("business_impact", "")[:200] + "...",
            "",
        ]

    lines += [
        "---",
        "",
        "## Regulatory Notifications Required",
        "",
        "| Regulation | Trigger | Deadline | Status |",
        "|-----------|---------|----------|--------|",
        "| SEC Regulation S-P | Client PII exfiltrated | **July 17, 2026** | ⚠️ REQUIRED |",
        "| NY DFS 23 NYCRR 500 §500.17 | Material cyber event | **June 19, 2026** | ❌ OVERDUE |",
        "| SEC Regulation SCI | Trading system compromise | Promptly | ⚠️ REQUIRED |",
        "",
        "---",
        "",
        "## Overall Risk Posture",
        "",
        f"- **Critical findings (P1):** {len(p1)}",
        f"- **High findings (P2):** {len(p2)}",
        f"- **Regulatory notifications due:** 3",
        f"- **Estimated remediation (P1 items):** < 2 weeks, < $50K engineering cost",
        "",
        "The majority of technical gaps close with configuration changes "
        "to existing tools — Zscaler, CrowdStrike, and Elastic — already "
        "under license. No new tooling procurement is required for P1 and P2 "
        "remediation.",
        "",
        "---",
        "",
        "*Day 22 — Risk Scoring Framework | NovaCrest Capital Group*",
        "*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*",
    ]

    with open(output_path, "w") as f:
        f.write("\n".join(lines))
    log.info(f"Executive brief written: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Day 22 Risk Register Builder")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--format", choices=["register", "executive", "json", "all"],
                        default="all")
    parser.add_argument("--output-dir", default="/tmp/day22/")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Import scorer to get scored findings
    sys.path.insert(0, os.path.dirname(__file__))
    from risk_scorer import score_all_findings
    scored = score_all_findings()

    if args.format in ("register", "all"):
        build_risk_register(
            scored,
            os.path.join(args.output_dir, "day22_risk_register.md"),
        )

    if args.format in ("executive", "all"):
        build_executive_brief(
            scored,
            os.path.join(args.output_dir, "day22_executive_brief.md"),
        )

    if args.format in ("json", "all"):
        json_path = os.path.join(args.output_dir, "risk_scores.json")
        with open(json_path, "w") as f:
            import json
            json.dump({"findings": scored}, f, indent=2)
        log.info(f"JSON written: {json_path}")

    log.info("Risk register build complete.")


# Fix List import
from typing import List

if __name__ == "__main__":
    main()
