"""
Day 26 — STIX 2.1 Bundle Generator
NovaCrest Capital Group | Threat Intelligence

PURPOSE: Produces a production-ready STIX 2.1 bundle representing the
         FIN-NC-001 threat actor profile, NovaCrest incident IOCs,
         malware objects, ATT&CK technique references, and relationships.
         Bundle is suitable for import into OpenCTI, MISP, or any TAXII
         2.1 server for sharing with FS-ISAC and sector peers.

STIX 2.1 OBJECTS GENERATED:
  identity           — NovaCrest as victim organization
  threat-actor       — FIN-NC-001 profile
  intrusion-set      — NovaCrest Capital breach campaign
  malware (×2)       — ncrypt ransomware + Sliver implant
  tool (×3)          — Cobalt Strike, Pacu, vssadmin abuse
  indicator (×8)     — IP, hash, domain, email, JA3, wallet IOCs
  attack-pattern (×6)— ATT&CK technique references
  relationship (×N)  — Object linkages
  report             — Incident intelligence report object
  course-of-action   — Defensive recommendations

Usage:
    python stix_builder.py --demo
    python stix_builder.py --output artifacts/fin_nc_001_stix_bundle.json
    python stix_builder.py --validate
"""

import argparse
import datetime
import json
import logging
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("stix_builder")

# STIX 2.1 spec timestamp format
def stix_ts(dt: datetime.datetime = None) -> str:
    if dt is None:
        dt = datetime.datetime.utcnow()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

def stix_id(obj_type: str) -> str:
    return f"{obj_type}--{str(uuid.uuid4())}"


# ── STIX Object Builders ───────────────────────────────────────────────

def build_identity(name: str, identity_class: str, sectors: list = None) -> Dict:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "identity_class": identity_class,
        "sectors": sectors or [],
        "confidence": 100,
    }


def build_threat_actor(profile: Dict) -> Dict:
    return {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": stix_id("threat-actor"),
        "created": stix_ts(datetime.datetime(2026, 6, 25)),
        "modified": stix_ts(),
        "name": profile["name"],
        "description": profile["description"],
        "threat_actor_types": profile["actor_types"],
        "aliases": profile.get("aliases", []),
        "first_seen": profile.get("first_seen"),
        "last_seen": stix_ts(datetime.datetime(2026, 6, 19)),
        "goals": profile.get("goals", []),
        "sophistication": profile["sophistication"],
        "resource_level": profile["resource_level"],
        "primary_motivation": profile["motivation"],
        "labels": profile.get("labels", []),
        "confidence": profile.get("confidence_pct", 70),
        "lang": "en",
        "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"],  # TLP:AMBER
    }


def build_intrusion_set(name: str, description: str, first_seen: str,
                         goals: list, actor_id: str) -> Dict:
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": stix_id("intrusion-set"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
        "first_seen": first_seen,
        "last_seen": stix_ts(datetime.datetime(2026, 6, 19)),
        "goals": goals,
        "resource_level": "organization",
        "primary_motivation": "financial-gain",
        "confidence": 80,
    }


def build_malware(name: str, malware_types: list, description: str,
                   sha256: str = None, aliases: list = None) -> Dict:
    obj = {
        "type": "malware",
        "spec_version": "2.1",
        "id": stix_id("malware"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
        "malware_types": malware_types,
        "is_family": False,
        "aliases": aliases or [],
        "implementation_languages": ["C++"],
        "capabilities": ["communicates-with-c2", "encrypts-files",
                          "deletes-system-artifacts", "evades-av"],
    }
    if sha256:
        obj["hashes"] = {"SHA-256": sha256}
    return obj


def build_tool(name: str, tool_types: list, description: str) -> Dict:
    return {
        "type": "tool",
        "spec_version": "2.1",
        "id": stix_id("tool"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
        "tool_types": tool_types,
    }


def build_indicator(name: str, pattern: str, indicator_types: list,
                     valid_from: str, description: str = "") -> Dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id("indicator"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
        "indicator_types": indicator_types,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "confidence": 85,
        "labels": ["malicious-activity"],
    }


def build_attack_pattern(technique_id: str, name: str, description: str) -> Dict:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": stix_id("attack-pattern"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": f"{technique_id} — {name}",
        "description": description,
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.','/')}",
        }],
    }


def build_relationship(rel_type: str, src_id: str, tgt_id: str,
                        description: str = "") -> Dict:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "relationship_type": rel_type,
        "source_ref": src_id,
        "target_ref": tgt_id,
        "description": description,
    }


def build_course_of_action(name: str, description: str) -> Dict:
    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": stix_id("course-of-action"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
    }


def build_report(name: str, description: str, object_refs: list,
                  published: str) -> Dict:
    return {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id("report"),
        "created": stix_ts(),
        "modified": stix_ts(),
        "name": name,
        "description": description,
        "published": published,
        "report_types": ["threat-actor", "campaign", "malware"],
        "object_refs": object_refs,
        "labels": ["financial-services", "ransomware", "double-extortion"],
        "confidence": 80,
    }


# ── Type hint fix ──────────────────────────────────────────────────────
from typing import Dict   # noqa — needed after function defs above


def build_bundle(objects: list) -> Dict:
    return {
        "type": "bundle",
        "id": stix_id("bundle"),
        "objects": objects,
    }


def generate_bundle() -> Dict:
    """Build full STIX 2.1 bundle for FIN-NC-001 / NovaCrest incident."""
    objects = []
    all_ids = []

    # ── Identities ────────────────────────────────────────────────────
    novacrest_id = build_identity(
        "NovaCrest Capital Group",
        "organization",
        sectors=["financial-services"]
    )
    objects.append(novacrest_id)

    analyst_id = build_identity("V. Willis, CISSP — NovaCrest IR", "individual")
    objects.append(analyst_id)

    # ── Threat Actor ──────────────────────────────────────────────────
    actor = build_threat_actor({
        "name": "FIN-NC-001",
        "description": (
            "Financially motivated ransomware operator targeting financial "
            "services organizations. Attributed with medium-high confidence to "
            "GOLD MYSTIC / LockBit affiliate based on TTP overlap (28/29 "
            "matching techniques), LockBit 3.0 builder variant, Sliver C2 "
            "tooling, bulletproof VPS hosting (AS209588), and double-extortion "
            "targeting pattern consistent with prior FS-ISAC advisories. "
            "Observed targeting US/EU/AU investment management firms, average "
            "ransom $3.8-4.5M USD in Monero, dwell time 3-14 days."
        ),
        "actor_types": ["crime-syndicate"],
        "aliases": ["ncrypt group", "GOLD MYSTIC affiliate (suspected)"],
        "first_seen": "2026-03-15T00:00:00.000Z",
        "goals": ["financial-gain", "data-theft", "ransomware-deployment"],
        "sophistication": "advanced",
        "resource_level": "organization",
        "motivation": "financial-gain",
        "labels": ["ransomware", "double-extortion", "financial-sector-targeting"],
        "confidence_pct": 78,
    })
    objects.append(actor)
    all_ids.append(actor["id"])

    # ── Intrusion Set (this campaign) ─────────────────────────────────
    campaign = build_intrusion_set(
        "Operation NovaCrest (NCA-2026-06)",
        "11-day intrusion into NovaCrest Capital Group. Initial access via "
        "spearphishing (FinTech Summit lure). 5-day dwell; ~293 MB exfil; "
        "LockBit 3.0 variant ransomware deployed June 19 encrypting 2,215 GB.",
        first_seen="2026-06-14T08:47:00.000Z",
        goals=["financial-gain", "data-exfiltration", "ransomware-deployment"],
        actor_id=actor["id"],
    )
    objects.append(campaign)
    all_ids.append(campaign["id"])

    # ── Malware ───────────────────────────────────────────────────────
    ncrypt = build_malware(
        "ncrypt ransomware",
        malware_types=["ransomware"],
        description=(
            "LockBit 3.0 builder variant compiled 2026-06-15. Custom victim "
            "build; .ncrypt extension; AES-256-CBC + RSA-4096 encryption; "
            "anti-recovery (VSS deletion, Windows Backup deletion, bcdedit); "
            "Windows service persistence; IFEO debugger hijack."
        ),
        sha256="a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3",
        aliases=["Ransom.ncrypt", "LockBit-ncrypt", "NOVA-20260619-7X4K build"],
    )
    objects.append(ncrypt)
    all_ids.append(ncrypt["id"])

    sliver = build_malware(
        "Sliver C2 implant",
        malware_types=["backdoor", "remote-access-trojan"],
        description=(
            "Open-source C2 framework (BishopFox Sliver). Deployed on WS-FIN-04 "
            "via macro execution on 2026-06-14. JA3: a0e9f5d64349fb13191bc781f81f42e1. "
            "JARM: 1dd28f0000...15c. Domain fronting via CDN (Variant 3 in Day 20 exercise)."
        ),
        aliases=["Sliver", "BishopFox Sliver"],
    )
    objects.append(sliver)
    all_ids.append(sliver["id"])

    # ── Tools ─────────────────────────────────────────────────────────
    cs = build_tool(
        "Cobalt Strike",
        ["remote-access"],
        "Commercial penetration testing framework used for C2 and lateral movement."
    )
    objects.append(cs); all_ids.append(cs["id"])

    pacu = build_tool(
        "Pacu",
        ["exploitation"],
        "Open-source AWS exploitation framework (Rhino Security). Used for CloudTrail enumeration and IAM privilege escalation."
    )
    objects.append(pacu); all_ids.append(pacu["id"])

    vssadmin = build_tool(
        "vssadmin (abused)",
        ["information-gathering"],
        "Windows built-in VSS admin tool abused for shadow copy deletion: vssadmin delete shadows /all /quiet"
    )
    objects.append(vssadmin); all_ids.append(vssadmin["id"])

    # ── Indicators ────────────────────────────────────────────────────
    c2_ip = build_indicator(
        "FIN-NC-001 C2 Server IP",
        "[ipv4-addr:value = '198.51.100.99']",
        ["malicious-activity", "command-and-control"],
        "2026-06-14T00:00:00.000Z",
        "Persistent C2 server across all attack phases. AS209588 (Flyservers S.A., NL) bulletproof hosting."
    )
    objects.append(c2_ip); all_ids.append(c2_ip["id"])

    ransom_hash = build_indicator(
        "ncrypt ransomware SHA256",
        "[file:hashes.'SHA-256' = 'a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3']",
        ["malicious-activity"],
        "2026-06-19T00:00:00.000Z",
        "LockBit 3.0 variant binary (svchost32.exe). Compiled 2026-06-15."
    )
    objects.append(ransom_hash); all_ids.append(ransom_hash["id"])

    phish_domain = build_indicator(
        "FIN-NC-001 Phishing Domain",
        "[domain-name:value = 'trading-updates.novacrest-secure.com']",
        ["malicious-activity", "phishing"],
        "2026-06-14T00:00:00.000Z",
        "Spearphishing delivery domain. Impersonates NovaCrest internal update service."
    )
    objects.append(phish_domain); all_ids.append(phish_domain["id"])

    ransom_email = build_indicator(
        "FIN-NC-001 Ransom Contact Email",
        "[email-addr:value = 'ncrypt-support@protonmail.com']",
        ["malicious-activity"],
        "2026-03-15T00:00:00.000Z",
        "Ransom negotiation email. Active since March 2026; 3 prior confirmed financial sector victims."
    )
    objects.append(ransom_email); all_ids.append(ransom_email["id"])

    ja3_ind = build_indicator(
        "Sliver C2 JA3 Fingerprint",
        "[network-traffic:extensions.'tls-ext'.ja3_hash = 'a0e9f5d64349fb13191bc781f81f42e1']",
        ["malicious-activity", "command-and-control"],
        "2026-06-14T00:00:00.000Z",
        "JA3 TLS fingerprint for Sliver C2 beacon (Variant 1 baseline)."
    )
    objects.append(ja3_ind); all_ids.append(ja3_ind["id"])

    onion_ind = build_indicator(
        "FIN-NC-001 Leak Site",
        "[url:value = 'http://ncrypt3k4j7mxbwz.onion/novacrest']",
        ["malicious-activity"],
        "2026-06-19T00:00:00.000Z",
        "Tor-based double-extortion leak site. NovaCrest victim page active."
    )
    objects.append(onion_ind); all_ids.append(onion_ind["id"])

    iam_key = build_indicator(
        "FIN-NC-001 IAM Backdoor Access Key",
        "[user-account:credential = 'AKIAIOSFODNN7BACKDOOR']",
        ["malicious-activity", "compromise"],
        "2026-06-16T09:16:28.000Z",
        "Active IAM access key created by attacker for backdoor user svc-monitoring-ops. Last used 2026-06-18 eu-west-1."
    )
    objects.append(iam_key); all_ids.append(iam_key["id"])

    # ── Attack Patterns (key ATT&CK techniques) ───────────────────────
    aps = [
        build_attack_pattern("T1566.001", "Spearphishing Attachment",
                              "FinTech Summit-themed lure with macro-enabled Office document"),
        build_attack_pattern("T1486", "Data Encrypted for Impact",
                              "LockBit 3.0 variant encrypting 26,168 files across 2,215 GB"),
        build_attack_pattern("T1490", "Inhibit System Recovery",
                              "VSS deletion, Windows Backup deletion, bcdedit recovery disable"),
        build_attack_pattern("T1136.003", "Create Cloud Account",
                              "IAM backdoor user svc-monitoring-ops with AdministratorAccess"),
        build_attack_pattern("T1530", "Data from Cloud Storage",
                              "S3 GetObject: client balances, trading positions, ML model"),
        build_attack_pattern("T1562.008", "Disable Cloud Logs",
                              "StopLogging CloudTrail + disable GuardDuty at 09:05 UTC"),
    ]
    for ap in aps:
        objects.append(ap)
        all_ids.append(ap["id"])

    # ── Courses of Action ─────────────────────────────────────────────
    coas = [
        build_course_of_action(
            "Delete FIN-NC-001 IAM Backdoor",
            "Immediately delete IAM user svc-monitoring-ops and access key AKIAIOSFODNN7BACKDOOR. "
            "Also delete CrossAccountReadRole trusting AWS account 987654321099."
        ),
        build_course_of_action(
            "Block FIN-NC-001 C2 IP",
            "Block 198.51.100.99 at perimeter firewall and NGFW. Add to SIEM watchlist. "
            "Review all historical connections to this IP across the environment."
        ),
        build_course_of_action(
            "Deploy ncrypt YARA Rules",
            "Deploy artifacts/yara_rules.yar to EDR and SIEM. "
            "Focus on ncrypt_binary_strings and ransomware_recovery_destruction rules for early detection."
        ),
        build_course_of_action(
            "Report to FBI + FS-ISAC",
            "File IC3 report (www.ic3.gov). Contact FS-ISAC to share IOCs under TLP:AMBER. "
            "Engage FBI Cyber Division re: Operation Cronos LockBit decryptor coverage."
        ),
    ]
    for coa in coas:
        objects.append(coa)
        all_ids.append(coa["id"])

    # ── Relationships ─────────────────────────────────────────────────
    rels = [
        build_relationship("attributed-to", campaign["id"], actor["id"],
                            "NovaCrest breach campaign attributed to FIN-NC-001"),
        build_relationship("targets", actor["id"], novacrest_id["id"],
                            "FIN-NC-001 targeted NovaCrest Capital Group"),
        build_relationship("uses", actor["id"], ncrypt["id"],
                            "FIN-NC-001 deployed custom ncrypt ransomware variant"),
        build_relationship("uses", actor["id"], sliver["id"],
                            "FIN-NC-001 used Sliver C2 framework for post-exploitation"),
        build_relationship("uses", actor["id"], cs["id"],
                            "FIN-NC-001 used Cobalt Strike for lateral movement"),
        build_relationship("uses", actor["id"], pacu["id"],
                            "FIN-NC-001 used Pacu for AWS environment enumeration"),
        build_relationship("uses", actor["id"], vssadmin["id"],
                            "FIN-NC-001 abused vssadmin to destroy shadow copies"),
        build_relationship("indicates", c2_ip["id"], actor["id"],
                            "C2 IP 198.51.100.99 indicates FIN-NC-001 infrastructure"),
        build_relationship("indicates", ransom_hash["id"], ncrypt["id"],
                            "SHA256 hash indicates ncrypt ransomware binary"),
        build_relationship("indicates", ransom_email["id"], actor["id"],
                            "Ransom email indicates FIN-NC-001 negotiation channel"),
        build_relationship("mitigates", coas[0]["id"], aps[3]["id"],
                            "Deleting backdoor mitigates T1136.003 persistence"),
        build_relationship("mitigates", coas[1]["id"], c2_ip["id"],
                            "Blocking C2 IP cuts FIN-NC-001 communication channel"),
    ]
    for rel in rels:
        objects.append(rel)

    # ── Report ────────────────────────────────────────────────────────
    report = build_report(
        "FIN-NC-001 Threat Actor Profile — NovaCrest Capital Group Incident",
        "Threat intelligence report on FIN-NC-001 based on forensic analysis "
        "of the NovaCrest Capital Group breach (Case NCA-2026-06). Covers IOC "
        "enrichment, TTP attribution, actor profile, next-move predictions, and "
        "defensive courses of action. TLP:AMBER — share with financial sector peers.",
        object_refs=[o["id"] for o in objects],
        published=stix_ts(datetime.datetime(2026, 6, 25)),
    )
    objects.append(report)

    return build_bundle(objects)


def main():
    parser = argparse.ArgumentParser(description="Day 26 STIX 2.1 Bundle Generator")
    parser.add_argument("--demo", action="store_true", default=True)
    parser.add_argument("--output", default="artifacts/fin_nc_001_stix_bundle.json")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info(" Day 26 — STIX 2.1 Bundle Generator")
    log.info(" FIN-NC-001 | NovaCrest Capital Group | TLP:AMBER")
    log.info("=" * 70)

    bundle = generate_bundle()

    total = len(bundle["objects"])
    by_type: Dict[str, int] = {}
    for obj in bundle["objects"]:
        t = obj["type"]
        by_type[t] = by_type.get(t, 0) + 1

    log.info(f"\n  Bundle contains {total} STIX objects:")
    for obj_type, count in sorted(by_type.items()):
        log.info(f"    {obj_type:25} × {count}")

    with open(args.output, "w") as f:
        json.dump(bundle, f, indent=2)
    log.info(f"\n  Bundle written: {args.output}")
    log.info("  Ready for import into OpenCTI / MISP / TAXII 2.1 server")


if __name__ == "__main__":
    main()
