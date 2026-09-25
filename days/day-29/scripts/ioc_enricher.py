"""
Day 29 — IOC Enrichment, Hunt Query Generator & Report Drafter Agents
NovaCrest Capital Group | AI Agent Integration

Three specialized agents in one module:

1. IOC ENRICHER
   Input:  List of raw IOCs (IPs, hashes, domains, emails)
   Output: Enriched STIX indicators with scores and context
   Value:  Replaces 30-min manual VT/OTX/Shodan pivoting per IOC set

2. HUNT QUERY GENERATOR
   Input:  ATT&CK technique ID + target SIEM platform
   Output: Production-ready detection query (SPL/KQL/EQL)
   Value:  Replaces 45-min query authoring per technique

3. REPORT DRAFTER
   Input:  Structured findings JSON (from triage + enrichment)
   Output: Draft incident report in NovaCrest template format
   Value:  Replaces 2-hr initial report writing per incident

Usage:
    python ioc_enricher.py --mode enrich --demo
    python ioc_enricher.py --mode query --technique T1566.001 --siem splunk
    python ioc_enricher.py --mode report --demo
    python ioc_enricher.py --mode all --demo --verbose
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
log = logging.getLogger("ioc_enricher")

# ── Sample IOC Set (from NCA-2026-06) ─────────────────────────────────
SAMPLE_IOCS = [
    {"type": "ipv4",   "value": "198.51.100.99",                                                    "source": "Zeek conn"},
    {"type": "sha256", "value": "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3", "source": "Volatility3 malfind"},
    {"type": "domain", "value": "trading-updates.novacrest-secure.com",                              "source": "Zeek dns"},
    {"type": "email",  "value": "ncrypt-support@protonmail.com",                                     "source": "Ransom note"},
    {"type": "ja3",    "value": "a0e9f5d64349fb13191bc781f81f42e1",                                  "source": "Zeek ssl"},
    {"type": "url",    "value": "http://ncrypt3k4j7mxbwz.onion/novacrest",                           "source": "Ransom note"},
    {"type": "ipv4",   "value": "198.51.100.101",                                                    "source": "ASN pivot (Day 28)"},
]

# Simulated enrichment DB
ENRICHMENT_DB = {
    "198.51.100.99": {
        "vt_score": 47, "otx_pulses": 3, "shodan_ports": [22,80,443,8443],
        "asn": "AS209588 Flyservers NL", "hosting": "Bulletproof VPS",
        "tags": ["c2","ransomware","fin-nc-001"],
        "verdict": "MALICIOUS", "confidence": 99,
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "198.51.100.101": {
        "vt_score": 12, "otx_pulses": 1, "shodan_ports": [443,8080],
        "asn": "AS209588 Flyservers NL", "hosting": "Bulletproof VPS",
        "tags": ["c2","fin-nc-001","secondary"],
        "verdict": "MALICIOUS", "confidence": 85,
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3": {
        "vt_score": 34, "family": "LockBit", "type": "ransomware",
        "tags": ["lockbit3","ncrypt","double-extortion"],
        "verdict": "MALICIOUS", "confidence": 99,
        "compiled": "2026-06-15", "packer": "UPX",
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "trading-updates.novacrest-secure.com": {
        "vt_score": 28, "registrar": "Namecheap",
        "registered": "2026-06-08", "age_days": 6,
        "nameservers": ["Cloudflare"], "cert_ca": "Let's Encrypt",
        "resolves_to": "198.51.100.99",
        "tags": ["phishing","fin-nc-001","typosquat"],
        "verdict": "MALICIOUS", "confidence": 97,
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "ncrypt-support@protonmail.com": {
        "prior_victims": 3, "active_since": "2026-03-15",
        "negotiation_pattern": "responds <4hr; 30-40% discount",
        "tags": ["ransomware","ransom-contact","fin-nc-001"],
        "verdict": "MALICIOUS", "confidence": 95,
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "framework": "Sliver C2",
        "description": "Sliver default JA3 — open-source C2 framework",
        "confirmed_in": "NCA-2026-06 (Day 20 purple team)",
        "verdict": "MALICIOUS", "confidence": 98,
        "tags": ["sliver","c2","fin-nc-001"],
        "tlp": "AMBER", "stix_type": "indicator",
    },
    "http://ncrypt3k4j7mxbwz.onion/novacrest": {
        "type": "leak site", "group": "ncrypt",
        "victim_count_known": 4, "first_seen": "2026-02-20",
        "novacrest_posted": "2026-06-19",
        "deadline": "2026-06-22T06:14:00Z",
        "verdict": "MALICIOUS", "confidence": 100,
        "tags": ["leak-site","double-extortion","fin-nc-001"],
        "tlp": "AMBER", "stix_type": "indicator",
    },
}

# Demo query outputs (what Claude would generate)
DEMO_QUERIES = {
    ("T1566.001", "splunk"): """| Search: DET-001 — Office Macro Spawning Encoded Payload (T1566.001)
index=sysmon EventCode=1
| where (ParentImage LIKE "%WINWORD%"
      OR ParentImage LIKE "%EXCEL%"
      OR ParentImage LIKE "%POWERPNT%")
AND (Image LIKE "%cmd.exe%"
  OR Image LIKE "%powershell.exe%"
  OR Image LIKE "%wscript.exe%")
AND (CommandLine LIKE "%-enc %"
  OR CommandLine LIKE "%-EncodedCommand%"
  OR CommandLine LIKE "%IEX%"
  OR CommandLine LIKE "%DownloadString%")
| eval attk_technique="T1566.001"
| eval severity="High"
| table _time, host, User, ParentImage, Image, CommandLine, severity
| sort -_time""",

    ("T1566.001", "sentinel"): """// DET-001: Office Macro Spawning Encoded Payload (T1566.001)
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName has_any ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE")
| where FileName has_any ("cmd.exe","powershell.exe","wscript.exe")
| where ProcessCommandLine has_any ("-enc","-EncodedCommand","IEX","DownloadString")
| extend Technique = "T1566.001"
| extend Severity = "High"
| project TimeGenerated, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, ProcessCommandLine,
          Technique, Severity
| order by TimeGenerated desc""",

    ("T1490", "splunk"): """| Search: DET-008 — VSS and Recovery Destruction (T1490)
index=sysmon EventCode=1
| where match(CommandLine, "(?i)vssadmin.*delete.*shadows|wbadmin.*delete.*catalog|bcdedit.*/set.*recoveryenabled.*No|wmic.*shadowcopy.*delete")
| eval attk_technique="T1490"
| eval severity="Critical"
| eval impact="Ransomware pre-encryption: backup destruction imminent"
| table _time, host, User, Image, ParentImage, CommandLine, impact
| sort -_time""",

    ("T1490", "sentinel"): """// DET-008: VSS and Recovery Destruction (T1490)
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit /set {default} recoveryenabled No",
    "wmic shadowcopy delete"
  )
| extend Technique = "T1490"
| extend Severity = "Critical"
| extend Impact = "Ransomware pre-encryption: recovery destruction"
| project TimeGenerated, DeviceName, AccountName,
          FileName, InitiatingProcessFileName, ProcessCommandLine,
          Technique, Severity, Impact""",

    ("T1136.003", "splunk"): """| Search: DET-006 — IAM Backdoor Creation Chain (T1136.003)
index=cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateUser","AttachUserPolicy","CreateAccessKey","CreateRole")
| where NOT cidrmatch("10.0.0.0/8", sourceIPAddress)
| bucket span=10m _time
| stats count as iam_events,
        values(eventName) as actions,
        values(requestParameters.userName) as target_users
    by sourceIPAddress, _time
| where iam_events >= 2
| eval attk_technique="T1136.003"
| eval severity="Critical"
| table _time, sourceIPAddress, iam_events, actions, target_users, severity""",
}

# Demo findings for report drafting
DEMO_FINDINGS = {
    "case_id": "NCA-2026-06",
    "incident_date": "2026-06-14",
    "report_date": "2026-06-29",
    "analyst": "V. Willis, CISSP",
    "severity": "Critical",
    "status": "Ongoing — Recovery in Progress",
    "summary": "FIN-NC-001 threat actor compromised NovaCrest via spearphishing, exfiltrated ~293 MB, and deployed LockBit 3.0 ransomware encrypting 2,215 GB.",
    "confirmed_ttps": ["T1566.001","T1204.002","T1071.001","T1550.002","T1136.003","T1555.006","T1490","T1486","T1562.008"],
    "confirmed_iocs": ["198.51.100.99","a4b3c2d1e0f9...","ncrypt-support@protonmail.com"],
    "data_at_risk": "Client balances (4 MB), trading positions (18 MB), ML models (60 MB), trading archives (125 MB)",
    "regulatory_impact": ["SEC Reg S-P notification required","NY DFS 72hr OVERDUE","FBI report filed"],
    "recovery_path": "June 13 backup viable; ransomware persistence (service + IFEO) must be removed first",
    "actor": "FIN-NC-001 (GOLD MYSTIC affiliate, 78% confidence)",
    "ransom_demanded": "$4.2M XMR",
    "ransom_deadline": "2026-06-22 06:14 UTC",
}


# ── Agent 1: IOC Enricher ──────────────────────────────────────────────
def run_ioc_enricher(iocs: List[Dict], verbose: bool) -> List[Dict]:
    """Enrich a list of IOCs using simulated threat intel."""
    enriched = []
    log.info(f"  Enriching {len(iocs)} IOCs...")

    for ioc in iocs:
        raw_value = ioc["value"]
        # Lookup clean key
        enrich_key = raw_value if raw_value in ENRICHMENT_DB else None

        if enrich_key:
            db_entry = ENRICHMENT_DB[enrich_key]
            enriched_ioc = {
                "type": ioc["type"],
                "value": raw_value,
                "source": ioc["source"],
                "verdict": db_entry["verdict"],
                "confidence": db_entry["confidence"],
                "tags": db_entry["tags"],
                "stix_pattern": _to_stix_pattern(ioc["type"], raw_value),
                "enrichment": db_entry,
                "tlp": db_entry.get("tlp", "AMBER"),
            }
        else:
            enriched_ioc = {
                "type": ioc["type"],
                "value": raw_value,
                "source": ioc["source"],
                "verdict": "UNKNOWN",
                "confidence": 0,
                "tags": [],
                "stix_pattern": _to_stix_pattern(ioc["type"], raw_value),
                "enrichment": {},
                "tlp": "GREEN",
            }

        enriched.append(enriched_ioc)

        if verbose:
            icon = "🔴" if enriched_ioc["verdict"] == "MALICIOUS" else "⬜"
            log.info(f"  {icon} [{enriched_ioc['verdict']:10}] {ioc['type']:7} "
                     f"{raw_value[:45]:47} conf:{enriched_ioc['confidence']}%")

    malicious = sum(1 for e in enriched if e["verdict"] == "MALICIOUS")
    log.info(f"  → {malicious}/{len(enriched)} IOCs confirmed malicious")
    return enriched


def _to_stix_pattern(ioc_type: str, value: str) -> str:
    """Convert IOC to STIX 2.1 pattern string."""
    mapping = {
        "ipv4":   f"[ipv4-addr:value = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "email":  f"[email-addr:value = '{value}']",
        "ja3":    f"[network-traffic:extensions.'tls-ext'.ja3_hash = '{value}']",
        "url":    f"[url:value = '{value}']",
        "md5":    f"[file:hashes.MD5 = '{value}']",
    }
    return mapping.get(ioc_type, f"[{ioc_type}:value = '{value}']")


# ── Agent 2: Hunt Query Generator ─────────────────────────────────────
def run_query_generator(technique_id: str, siem: str,
                         verbose: bool) -> Dict:
    """Generate SIEM detection query for a given ATT&CK technique."""
    key = (technique_id, siem)
    log.info(f"  Generating {siem.upper()} query for {technique_id}...")

    query = DEMO_QUERIES.get(key)
    if not query:
        query = f"""| /* AI-generated query for {technique_id} on {siem} */
| /* NOTE: Review and tune before production deployment */
index={"cloudtrail" if "cloud" in technique_id.lower() else "sysmon"} EventCode=1
| search for {technique_id} indicators
| eval attk_technique="{technique_id}"
| table _time, host, CommandLine, Image"""

    result = {
        "technique_id": technique_id,
        "siem": siem,
        "query": query,
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "status": "REVIEW_REQUIRED",
        "fp_rate_estimate": "Requires baseline testing before production",
    }

    if verbose:
        log.info(f"  Query generated ({len(query)} chars). Status: REVIEW_REQUIRED")
        log.info("  ⚠️  All AI-generated queries require human review before deployment")

    return result


# ── Agent 3: Report Drafter ────────────────────────────────────────────
def run_report_drafter(findings: Dict, verbose: bool) -> str:
    """Draft an incident report from structured findings."""
    log.info("  Drafting incident report from structured findings...")

    # Build draft using findings — real version would call Claude API
    ttps_str = "\n".join(f"  - {t}" for t in findings["confirmed_ttps"])
    iocs_str = "\n".join(f"  - {i}" for i in findings["confirmed_iocs"])
    reg_str = "\n".join(f"  - {r}" for r in findings["regulatory_impact"])

    draft = f"""# DRAFT INCIDENT REPORT — {findings['case_id']}
## {findings['case_id']} | Severity: {findings['severity']}
**Status:** {findings['status']}
**Analyst:** {findings['analyst']} | **Date:** {findings['report_date']}

> ⚠️ AI DRAFT — REQUIRES HUMAN REVIEW BEFORE DISTRIBUTION

---

## Executive Summary

{findings['summary']} The threat actor, designated {findings['actor']},
demanded {findings['ransom_demanded']} with a deadline of {findings['ransom_deadline']}.
Recovery from clean backup (June 13) is viable and recommended over paying.

## Confirmed ATT&CK Techniques ({len(findings['confirmed_ttps'])})

{ttps_str}

## Key IOCs

{iocs_str}

## Data at Risk

{findings['data_at_risk']}

## Regulatory Impact

{reg_str}

## Recovery Path

{findings['recovery_path']}

---
*DRAFT GENERATED: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}*
*Model: claude-sonnet-4-6 | Review required: YES | Confidence: MEDIUM*
"""

    if verbose:
        log.info(f"  Draft generated ({len(draft)} chars)")
        log.info("  ✅ Report includes ATT&CK mapping, IOCs, regulatory flags")
        log.info("  ⚠️  AI-generated content — human analyst must review before sending")

    return draft


def main():
    parser = argparse.ArgumentParser(description="Day 29 Agent Suite")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--mode", choices=["enrich","query","report","all"], default="all")
    parser.add_argument("--technique", default="T1566.001")
    parser.add_argument("--siem", choices=["splunk","sentinel","elastic"], default="splunk")
    parser.add_argument("--verbose", action="store_true", default=True)
    parser.add_argument("--output", default="/tmp/day29_agent_outputs.json")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 29 — AI Agent Suite (IOC Enricher / Query Gen / Report Drafter)")
    log.info(" NovaCrest Capital Group | claude-sonnet-4-6")
    log.info("=" * 70)
    log.info("")

    outputs = {}

    if args.mode in ("enrich", "all"):
        log.info("[AGENT 1] IOC Enrichment Pipeline")
        enriched = run_ioc_enricher(SAMPLE_IOCS, args.verbose)
        outputs["enriched_iocs"] = enriched
        log.info("")

    if args.mode in ("query", "all"):
        log.info("[AGENT 2] Hunt Query Generator")
        techniques = (
            [args.technique] if args.mode == "query"
            else ["T1566.001", "T1490", "T1136.003"]
        )
        queries = []
        for tech in techniques:
            for siem in (["splunk", "sentinel"] if args.mode == "all" else [args.siem]):
                q = run_query_generator(tech, siem, args.verbose)
                queries.append(q)
        outputs["generated_queries"] = queries
        log.info("")

    if args.mode in ("report", "all"):
        log.info("[AGENT 3] Report Drafter")
        report = run_report_drafter(DEMO_FINDINGS, args.verbose)
        outputs["draft_report"] = report
        log.info("")

    # Summary
    print("\n" + "=" * 65)
    print("  AI AGENT SUITE — EXECUTION SUMMARY")
    print("=" * 65)
    if "enriched_iocs" in outputs:
        malicious = sum(1 for e in outputs["enriched_iocs"] if e["verdict"] == "MALICIOUS")
        print(f"  IOC Enrichment: {len(outputs['enriched_iocs'])} processed | {malicious} malicious")
    if "generated_queries" in outputs:
        print(f"  Query Generator: {len(outputs['generated_queries'])} queries generated")
        print(f"  Status: ALL require human review before production")
    if "draft_report" in outputs:
        print(f"  Report Draft: {len(outputs['draft_report'])} chars | REVIEW REQUIRED")
    print(f"\n  ⚠️  Human-in-the-loop policy: ALL outputs are DRAFTS")
    print(f"  Audit trail: {args.output}")
    print()

    with open(args.output, "w") as f:
        json.dump(outputs, f, indent=2)
    log.info(f"Outputs written: {args.output}")


if __name__ == "__main__":
    main()
