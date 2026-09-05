"""
Day 22 — Risk Scorer
NovaCrest Capital Group | Threat Intelligence

PURPOSE: Calculates CVSS 3.1, DREAD, and ATT&CK risk tier scores for
         the ten confirmed findings from the Week 3 NovaCrest engagement.
         Produces a unified risk score, priority tier, and remediation
         recommendation for each finding.

METHODOLOGIES:
  CVSS 3.1   — NIST standard vulnerability severity (0–10)
  DREAD      — Attacker-centric risk scoring (Damage, Reproducibility,
               Exploitability, Affected users, Discoverability) (0–10)
  ATT&CK Tier — Detectability gap + Business impact + Prevalence (1–5)

OUTPUT: JSON risk register + console scorecard

Usage:
    python risk_scorer.py --demo
    python risk_scorer.py --method cvss --demo
    python risk_scorer.py --method dread --finding RF-001 --demo
    python risk_scorer.py --all --output /tmp/scores.json
"""

import argparse
import json
import logging
import math
from typing import Dict, List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("risk_scorer")


# ── CVSS 3.1 Scoring Data ──────────────────────────────────────────────
# Pre-computed base scores from vector strings
# Full vectors defined in LAB.md
CVSS_FINDINGS = {
    "RF-001": {
        "name": "GitHub-Exposed AWS Credentials",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 10.0,
        "severity": "Critical",
        "technique": "T1552.001",
        "rationale": "Network-reachable; no privileges or interaction needed; full C/I/A compromise; scope change (cloud admin achieved)",
    },
    "RF-002": {
        "name": "NOPASSWD Sudo Rule (svc_ncg → find)",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 8.8,
        "severity": "High",
        "technique": "T1548.003",
        "rationale": "Local access required (attacker already on system); Low privilege (domain service account); scope changes to root",
    },
    "RF-003": {
        "name": "SUID GTFOBins on lnx-trade-01 (find, python3, vim)",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 8.8,
        "severity": "High",
        "technique": "T1548.001",
        "rationale": "Three separate escalation paths; any one sufficient for root; Low complexity post-enumeration",
    },
    "RF-004": {
        "name": "Kerberoastable Service Accounts (RC4 + Weak Password)",
        "vector": "CVSS:3.1/AV:N/AC:H/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "base_score": 8.5,
        "severity": "High",
        "technique": "T1558.003",
        "rationale": "Network attack via Kerberos; High complexity (requires domain auth + offline cracking); scope change to service account privileges",
    },
    "RF-005": {
        "name": "Zeek/auditd Not Forwarded to SIEM (Detection Gap)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "base_score": 9.3,
        "severity": "Critical",
        "technique": "T1562.001",
        "rationale": "Detection gap enables all network-based techniques to operate undetected; confidentiality impact is the inability to detect breaches",
    },
    "RF-006": {
        "name": "TLS Inspection Disabled (Domain Fronting Undetected)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "base_score": 7.5,
        "severity": "High",
        "technique": "T1090.004",
        "rationale": "Allows C2 channel via CDN fronting; confidentiality impact from undetected communication",
    },
    "RF-007": {
        "name": "253 MB Data Exfiltrated (Trading Algos + Client PII)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "base_score": 9.6,
        "severity": "Critical",
        "technique": "T1567.002",
        "rationale": "Confirmed exfiltration of trading algorithms (IP) and client PII (regulatory); authenticated attacker; scope change via cloud upload",
    },
    "RF-008": {
        "name": "Windows Security Log Cleared (649 Events Destroyed)",
        "vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H",
        "base_score": 8.2,
        "severity": "High",
        "technique": "T1070.001",
        "rationale": "Requires SYSTEM (High priv); destroys forensic integrity and availability of log data; scope change (affects SIEM/SOC)",
    },
    "RF-009": {
        "name": "No DLP on Egress S3 Uploads (85 MB Undetected)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "base_score": 8.5,
        "severity": "High",
        "technique": "T1005",
        "rationale": "Network attack via presigned S3 URL; low privilege (no AWS credentials needed for presigned); confidentiality impact of PII/IP loss",
    },
    "RF-010": {
        "name": "Domain Fronting C2 Channel (Cobalt Strike via Azure CDN)",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N",
        "base_score": 8.0,
        "severity": "High",
        "technique": "T1090.004",
        "rationale": "High complexity (requires CDN configuration); persistent C2 channel blends with legitimate traffic",
    },
}


# ── DREAD Scoring Data ─────────────────────────────────────────────────
DREAD_FINDINGS = {
    "RF-001": {
        "D_damage": 10,         # Full cloud takeover confirmed
        "R_reproducibility": 10, # GitHub dork → instant find
        "E_exploitability": 10,  # aws sts get-caller-identity; trivial
        "A_affected": 9,         # All cloud resources + most internal
        "D_discoverability": 10, # TruffleHog / gitleaks finds it automatically
    },
    "RF-002": {
        "D_damage": 9,
        "R_reproducibility": 9,  # sudo -l reveals it; exploit is one command
        "E_exploitability": 9,   # GTFOBins recipe; zero skill
        "A_affected": 6,         # lnx-trade-01 + lateral from there
        "D_discoverability": 8,  # sudo -l or sudoers read reveals it
    },
    "RF-003": {
        "D_damage": 9,
        "R_reproducibility": 9,
        "E_exploitability": 9,   # GTFOBins; automated
        "A_affected": 6,
        "D_discoverability": 9,  # find / -perm -4000 is standard recon
    },
    "RF-004": {
        "D_damage": 8,           # Service account → domain privilege risk
        "R_reproducibility": 8,  # Rubeus/Impacket; automated
        "E_exploitability": 7,   # Requires domain account; offline cracking
        "A_affected": 7,         # All services accessible by cracked account
        "D_discoverability": 8,  # Get-ADUser SPNs; automated enumeration
    },
    "RF-005": {
        "D_damage": 9,           # Enables all undetected techniques
        "R_reproducibility": 10, # Configuration gap; always exploitable
        "E_exploitability": 10,  # No attack required; gap is structural
        "A_affected": 10,        # Affects detection of all techniques
        "D_discoverability": 7,  # Requires SIEM audit to find
    },
    "RF-006": {
        "D_damage": 8,
        "R_reproducibility": 9,
        "E_exploitability": 9,   # Domain fronting well-documented
        "A_affected": 9,         # All HTTPS traffic evades inspection
        "D_discoverability": 6,  # Requires proxy audit to discover
    },
    "RF-007": {
        "D_damage": 10,          # Trading IP + client PII + regulatory exposure
        "R_reproducibility": 8,
        "E_exploitability": 7,
        "A_affected": 10,        # External clients impacted
        "D_discoverability": 9,  # Easy to find after breach; hard before
    },
    "RF-008": {
        "D_damage": 8,           # Destroys forensic evidence
        "R_reproducibility": 10, # wevtutil cl Security; one command
        "E_exploitability": 10,  # Requires SYSTEM; trivial once achieved
        "A_affected": 8,         # Affects all forensic investigation
        "D_discoverability": 5,  # Only discoverable if Sysmon intact (gap)
    },
    "RF-009": {
        "D_damage": 9,
        "R_reproducibility": 8,
        "E_exploitability": 8,   # Presigned URL; no AWS creds on client
        "A_affected": 8,
        "D_discoverability": 6,
    },
    "RF-010": {
        "D_damage": 8,
        "R_reproducibility": 7,  # Requires CDN setup; moderate effort
        "E_exploitability": 6,
        "A_affected": 8,
        "D_discoverability": 4,  # Requires TLS inspection; hard without it
    },
}


# ── ATT&CK Risk Tier Data ──────────────────────────────────────────────
ATTCK_TIER_FINDINGS = {
    "RF-001": {
        "detectability_gap": 5,  # External recon; not detected
        "business_impact": 5,    # Trading platform; client data; regulatory
        "adversary_prevalence": 5, # Credential hunting is universal
    },
    "RF-002": {
        "detectability_gap": 3,  # auditd catches it; SIEM didn't alert real-time
        "business_impact": 4,    # Root on trading server; data access
        "adversary_prevalence": 4, # Common post-compromise technique
    },
    "RF-003": {
        "detectability_gap": 3,
        "business_impact": 4,
        "adversary_prevalence": 4,
    },
    "RF-004": {
        "detectability_gap": 2,  # Event 4769 RC4 detected within SLA
        "business_impact": 4,    # Service account → broad access
        "adversary_prevalence": 5, # Kerberoasting is ubiquitous
    },
    "RF-005": {
        "detectability_gap": 5,  # By definition: the gap itself
        "business_impact": 5,    # Enables all other gaps
        "adversary_prevalence": 3, # Attackers exploit gaps when found
    },
    "RF-006": {
        "detectability_gap": 4,  # Was 5 (D20 miss); now 3 (D21 caught)
        "business_impact": 4,
        "adversary_prevalence": 4,
    },
    "RF-007": {
        "detectability_gap": 3,  # Detected in hunt; now DLP blocks
        "business_impact": 5,    # SEC S-P violation; trading IP gone
        "adversary_prevalence": 4,
    },
    "RF-008": {
        "detectability_gap": 1,  # Event 1102 is self-documenting
        "business_impact": 3,    # Sysmon filled the gap; manageable
        "adversary_prevalence": 5, # Every attacker clears logs
    },
    "RF-009": {
        "detectability_gap": 4,  # DLP gap now closed; was 5
        "business_impact": 4,
        "adversary_prevalence": 4,
    },
    "RF-010": {
        "detectability_gap": 2,  # Now detected (TLS inspect enabled)
        "business_impact": 4,
        "adversary_prevalence": 3, # Domain fronting increasingly CDN-blocked
    },
}


def compute_dread_score(finding_id: str) -> Tuple[float, Dict]:
    data = DREAD_FINDINGS[finding_id]
    score = sum(data.values()) / 5
    return round(score, 1), data


def compute_attck_tier(finding_id: str) -> Tuple[float, str]:
    data = ATTCK_TIER_FINDINGS[finding_id]
    score = (
        data["detectability_gap"] * 2 +
        data["business_impact"] * 2 +
        data["adversary_prevalence"] * 1
    ) / 5

    tier = ("Tier 1 — Critical" if score >= 4.0 else
            "Tier 2 — High" if score >= 3.0 else
            "Tier 3 — Medium" if score >= 2.0 else
            "Tier 4 — Low")

    return round(score, 2), tier


def compute_unified_priority(cvss: float, dread: float, attck: float) -> str:
    """Weighted unified risk score → priority label."""
    unified = (cvss / 10 * 0.35) + (dread / 10 * 0.35) + (attck / 5 * 0.30)
    if unified >= 0.85:
        return "P1 — CRITICAL: Immediate action required"
    elif unified >= 0.70:
        return "P2 — HIGH: Address this sprint"
    elif unified >= 0.50:
        return "P3 — MEDIUM: Address this quarter"
    else:
        return "P4 — LOW: Schedule for next cycle"


def score_all_findings() -> List[Dict]:
    results = []
    for fid, cvss_data in CVSS_FINDINGS.items():
        dread_score, dread_detail = compute_dread_score(fid)
        attck_score, attck_tier = compute_attck_tier(fid)
        priority = compute_unified_priority(
            cvss_data["base_score"], dread_score, attck_score
        )

        results.append({
            "id": fid,
            "name": cvss_data["name"],
            "technique": cvss_data["technique"],
            "cvss_score": cvss_data["base_score"],
            "cvss_severity": cvss_data["severity"],
            "cvss_vector": cvss_data["vector"],
            "dread_score": dread_score,
            "dread_detail": dread_detail,
            "attck_tier_score": attck_score,
            "attck_tier": attck_tier,
            "priority": priority,
            "rationale": cvss_data.get("rationale", ""),
        })

    results.sort(key=lambda x: -x["cvss_score"])
    return results


def emit_scorecard(results: List[Dict]) -> None:
    print("\n" + "=" * 80)
    print("  RISK SCORING FRAMEWORK — Day 22 | NovaCrest Capital Group")
    print("=" * 80 + "\n")
    print(f"  {'FINDING':<10} {'NAME':<45} {'CVSS':>5} {'DREAD':>6} {'ATT&CK':>7}  PRIORITY")
    print("  " + "─" * 78)
    for r in results:
        sev_icon = ("🔴" if r["cvss_score"] >= 9.0 else
                    "🟠" if r["cvss_score"] >= 7.0 else
                    "🟡" if r["cvss_score"] >= 4.0 else "🟢")
        p = r["priority"].split("—")[0].strip()
        print(f"  {sev_icon} {r['id']:<8} {r['name']:<45} "
              f"{r['cvss_score']:>5.1f} {r['dread_score']:>6.1f} "
              f"{r['attck_tier_score']:>7.2f}  {p}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Day 22 Risk Scorer")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--method", choices=["cvss", "dread", "attck", "all"],
                        default="all")
    parser.add_argument("--output", default="/tmp/day22_risk_scores.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 22 — Risk Scorer | NovaCrest Capital Group")
    log.info(" Methods: CVSS 3.1 · DREAD · ATT&CK Risk Tier")
    log.info("=" * 70)

    results = score_all_findings()
    emit_scorecard(results)

    import json
    output = {"findings": results, "methodology": {
        "cvss": "NIST CVSS 3.1 Base Score",
        "dread": "Microsoft DREAD (D×1+R×1+E×1+A×1+D×1)/5",
        "attck_tier": "Custom (DetectGap×2 + Impact×2 + Prevalence×1)/5",
        "unified": "CVSS×0.35 + DREAD×0.35 + ATT&CK×0.30",
    }}
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Scores written: {args.output}")


if __name__ == "__main__":
    main()
