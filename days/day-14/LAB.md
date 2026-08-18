# Day 14 — Lab Guide: Week 2 Capstone Intelligence Synthesis
### Track: Full Stack | Duration: ~3 hours | Difficulty: Advanced

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Python 3** | Synthesis automation, IOC merge, report generation | Pre-installed |
| **stix2** | STIX 2.1 bundle updates | `pip install stix2` |
| **pandas** | IOC deduplication across weeks | `pip install pandas` |
| **jinja2** | Multi-format report templating (RED/AMBER/WHITE) | `pip install jinja2` |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-14/artifacts/{synthesis,ioc_merge,tlp_variants,tracker}
cd ~/security-labs/day-14

pip install stix2 pandas jinja2 --break-system-packages

echo "[+] Week 2 capstone synthesis environment ready"
echo "[+] Synthesizing Days 08-13 into finished intelligence product"
```

---

## STEP 1 — Key Judgments Extraction

**Objective:** Distill six days of detailed technical findings into a
confidence-graded Key Judgments summary — the single most important
artifact for executive consumption. This must be written BEFORE the full
report, following the intelligence community principle of leading with
conclusions, not chronology.

```python
# Save as: build_key_judgments.py
import json

KEY_JUDGMENTS = [
    {
        "judgment": "The malware deployed against DESKTOP-FIN-047 successfully "
                   "extracted domain credentials from LSASS memory. This is "
                   "now CONFIRMED via live memory forensics, not merely "
                   "suspected from sandbox analysis.",
        "confidence": "HIGH",
        "source_days": ["08", "12"],
        "business_impact": "All accounts authenticated to the affected host "
                          "during the compromise window must be treated as "
                          "compromised — credential rotation already underway.",
    },
    {
        "judgment": "No confirmed lateral movement occurred beyond the single "
                   "compromised workstation, based on comprehensive hunting "
                   "across three distinct techniques (Pass-the-Hash, "
                   "Pass-the-Ticket, DCOM/WMI).",
        "confidence": "MODERATE-HIGH",
        "source_days": ["10"],
        "business_impact": "Incident scope can reasonably be bounded to one "
                          "workstation, pending resolution of one open item "
                          "(see Judgment 3).",
    },
    {
        "judgment": "An unresolved risk exists: a privileged service account "
                   "(Backup Operators group) has a historical authentication "
                   "session on the compromised host. If this occurred during "
                   "the compromise window, credential exposure extends to "
                   "domain-wide impact.",
        "confidence": "MODERATE (risk); LOW (timing confirmation)",
        "source_days": ["10"],
        "business_impact": "This is the single highest-priority unresolved "
                          "question in the entire investigation and should "
                          "be resolved before final incident closure.",
    },
    {
        "judgment": "A criminal forum claim to be selling NovaCrest data is "
                   "assessed as LOW-MODERATE credibility. The specific "
                   "credential count claimed matches a previously known "
                   "public breach dataset almost exactly, suggesting "
                   "repackaging of old data rather than exclusively fresh "
                   "exfiltration.",
        "confidence": "MODERATE",
        "source_days": ["09"],
        "business_impact": "Reduces — but does not eliminate — concern about "
                          "a new large-scale data breach. Financial document "
                          "exfiltration claim remains unresolved pending DNS "
                          "payload decode.",
    },
    {
        "judgment": "Current evidence does NOT support attribution of this "
                   "intrusion to any specific named threat actor group. The "
                   "actor's profile is more consistent with an independent, "
                   "financially motivated operation than a nation-state "
                   "campaign, based on infrastructure and monetization "
                   "pattern analysis.",
        "confidence": "HIGH (no named attribution); MODERATE (financial "
                     "motivation profile)",
        "source_days": ["11"],
        "business_impact": "External communications should use profile "
                          "language, not named-actor attribution.",
    },
    {
        "judgment": "NovaCrest's current automated detection coverage against "
                   "a comprehensive reference threat profile is approximately "
                   "24%, with the most significant gaps in Discovery and "
                   "Lateral Movement tactics — precisely the techniques that "
                   "required manual hunting during this incident.",
        "confidence": "HIGH",
        "source_days": ["13"],
        "business_impact": "A 90-day phased detection engineering roadmap "
                          "has been developed and should be resourced "
                          "immediately; the organization is currently "
                          "dependent on manual analyst hunting for entire "
                          "categories of attack technique.",
    },
]

print("=" * 65)
print("  KEY JUDGMENTS — Week 2 Capstone")
print("  NovaCrest Capital Group Incident (NVC-IR-2025-004)")
print("=" * 65)

for i, kj in enumerate(KEY_JUDGMENTS, 1):
    print(f"\n  {i}. [{kj['confidence']}] {kj['judgment']}")
    print(f"     Business Impact: {kj['business_impact']}")
    print(f"     Source: Day(s) {', '.join(kj['source_days'])}")

with open("artifacts/synthesis/key_judgments.json", "w") as f:
    json.dump(KEY_JUDGMENTS, f, indent=2)

print(f"\n[+] Key Judgments saved: artifacts/synthesis/key_judgments.json")
```

```bash
python3 build_key_judgments.py | tee artifacts/synthesis/key_judgments_summary.txt
```

**✅ Checkpoint 1:** These six judgments should be readable in under two
minutes and should give a CISO everything needed to brief the board without
reading a single underlying technical report. This is the test of a good
Key Judgments section.

---

## STEP 2 — Consolidated IOC Merge (Week 1 + Week 2)

**Objective:** Merge the Week 1 IOC master list (Day 07) with all new
indicators discovered during Week 2 (Days 08-12), deduplicating and
producing a single authoritative reference.

```python
# Save as: merge_ioc_lists.py
import json

# Week 1 IOCs (from Day 07)
WEEK1_IOCS = {
    "ips": ["185.220.101.12", "185.220.101.33", "185.220.101.47", "91.108.4.11"],
    "domains": ["microsoftonline-portal.com", "updates.cdn-telemetry-svc.net",
                "ms-account-portal.net", "cdn-telemetry-svc.net"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    "asns": ["AS209588"],
}

# Week 2 additions (Days 08-12)
WEEK2_ADDITIONS = {
    "hashes": [
        {"type": "SHA-256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "note": "updater.exe — confirmed C2 dropper (Day 08)"},
    ],
    "files": [
        "C:\\Users\\Public\\Libraries\\updater.exe",
        "C:\\Windows\\Temp\\~tmp4891.dll",
    ],
    "mutexes": [
        "Global\\{4A8C3B91-2E7F-4D15-88AC-9B7E3C1D0F22}",
    ],
    "urls": [
        "hxxps://185.220.101.33/stage2",
    ],
    "actor_handles": [
        {"handle": "fin_broker_01", "platform": "criminal forum (indexed)",
         "credibility": "23/100 — LOW", "note": "Day 09 dark web claim"},
    ],
    "yara_rules": [
        "NovaCrest_Dropper_updater_exe_Exact",
        "NovaCrest_Dropper_updater_exe_Behavioral",
        "NovaCrest_DNS_C2_Beacon_Pattern",
    ],
    "unresolved_indicators": [
        {"item": "svc_backup authentication timing on FIN-047",
         "status": "PENDING — Day 10 critical open item",
         "priority": "P0"},
    ],
}

print("=" * 65)
print("  Consolidated IOC Master List — Week 1 + Week 2")
print("=" * 65)

print(f"\n  WEEK 1 CARRIED FORWARD:")
for category, items in WEEK1_IOCS.items():
    print(f"    {category}: {len(items)} indicators")

print(f"\n  WEEK 2 NEW ADDITIONS:")
for category, items in WEEK2_ADDITIONS.items():
    print(f"    {category}: {len(items)} new indicators")

total_ioc_count = sum(len(v) for v in WEEK1_IOCS.values()) + \
                  sum(len(v) for k, v in WEEK2_ADDITIONS.items()
                      if k not in ("unresolved_indicators", "yara_rules"))

print(f"\n  TOTAL CONSOLIDATED IOCs: {total_ioc_count}")
print(f"  YARA rules available: {len(WEEK2_ADDITIONS['yara_rules'])}")
print(f"  Unresolved items requiring action: {len(WEEK2_ADDITIONS['unresolved_indicators'])}")

merged = {
    "week1_ips": WEEK1_IOCS["ips"],
    "week1_domains": WEEK1_IOCS["domains"],
    "week1_asns": WEEK1_IOCS["asns"],
    "week2_hashes": WEEK2_ADDITIONS["hashes"],
    "week2_files": WEEK2_ADDITIONS["files"],
    "week2_mutexes": WEEK2_ADDITIONS["mutexes"],
    "week2_urls": WEEK2_ADDITIONS["urls"],
    "week2_actor_handles": WEEK2_ADDITIONS["actor_handles"],
    "yara_rules_available": WEEK2_ADDITIONS["yara_rules"],
    "unresolved_items": WEEK2_ADDITIONS["unresolved_indicators"],
}

with open("artifacts/ioc_merge/consolidated_ioc_week1_week2.json", "w") as f:
    json.dump(merged, f, indent=2)

# Defanged plain text export
with open("artifacts/ioc_merge/consolidated_ioc_master.txt", "w") as f:
    f.write("# Consolidated IOC Master List — Weeks 1-2\n")
    f.write("# NVC-IR-2025-004 | Analyst: Blaakpearl | TLP:AMBER\n\n")
    f.write("## IP ADDRESSES\n")
    for ip in WEEK1_IOCS["ips"]:
        f.write(f"{ip}\n")
    f.write("\n## DOMAINS (defanged)\n")
    for d in WEEK1_IOCS["domains"]:
        f.write(f"{d.replace('.com','[.]com').replace('.net','[.]net')}\n")
    f.write("\n## FILE HASHES\n")
    for h in WEEK2_ADDITIONS["hashes"]:
        f.write(f"{h['type']}: {h['value']}  # {h['note']}\n")
    f.write("\n## FILE PATHS\n")
    for fp in WEEK2_ADDITIONS["files"]:
        f.write(f"{fp}\n")

print(f"\n[+] Consolidated IOCs saved:")
print(f"    artifacts/ioc_merge/consolidated_ioc_week1_week2.json")
print(f"    artifacts/ioc_merge/consolidated_ioc_master.txt")
```

```bash
python3 merge_ioc_lists.py | tee artifacts/ioc_merge/merge_summary.txt
```

---

## STEP 3 — TLP Dissemination Package (3 Variants)

**Objective:** Produce three properly classified versions of the same
intelligence for three different audiences — internal leadership,
sector-sharing partners, and (if warranted) public advisory.

```python
# Save as: build_tlp_variants.py
from datetime import datetime

# ── TLP:RED — Internal only, named organization, full detail ──
TLP_RED = """# NovaCrest Capital Group Incident — Internal Report
## TLP:RED — Restricted to Named Recipients Only

**Distribution:** CISO, CEO, Legal Counsel, Board Risk Committee ONLY
**Do not forward, copy, or discuss outside this distribution list.**

---

Full technical details including confirmed LSASS credential dump,
process injection evidence, all internal hostnames, employee names,
and unresolved svc_backup privileged account exposure risk are contained
in the complete Day 08-13 technical reports (linked in appendix).

Key unresolved item requiring IMMEDIATE leadership decision:
Whether svc_backup (Backup Operators) authenticated to the compromised
host during the exposure window — pending confirmation, this represents
a possible domain-wide compromise requiring KRBTGT reset procedures.

[Full technical content — see Days 08-13 REPORT.md files]
"""

# ── TLP:AMBER — Sector sharing (FS-ISAC), organization named to trusted peers ──
TLP_AMBER = """# Threat Intelligence Advisory — Financial Sector Campaign
## TLP:AMBER — Limited Disclosure, Restricted to Community

**Distribution:** FS-ISAC members, authorized threat intelligence sharing partners
**May be shared within your organization and with clients/customers who need
to know, but not published or shared on public channels.**

---

## Summary

A financial services organization experienced a targeted intrusion involving
phishing-based initial access, custom malware deployment, DNS-based C2 with
data exfiltration, and multi-layered persistence. Confirmed credential access
(LSASS memory dumping) occurred on the compromised endpoint.

## Indicators of Compromise (Shareable)

```
IPs:      185.220.101.12, 185.220.101.33, 185.220.101.47
Domains:  microsoftonline-portal[.]com, updates.cdn-telemetry-svc[.]net
ASN:      AS209588 (Flyservers S.A., Seychelles) — recommend blocking
Hash:     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## TTPs Observed (ATT&CK)

T1566.001 (Spearphishing), T1539 (MFA-bypass session theft),
T1071.004 (DNS C2), T1048.001 (DNS Exfiltration), T1053.005/T1547.001/
T1546.003 (Multi-layered persistence), T1055.012 (Process Hollowing),
T1003.001 (LSASS Memory)

## Recommendation for Sector Peers

Organizations in the financial sector should:
1. Block the IOCs above at network perimeter and DNS resolvers
2. Deploy detection for the ATT&CK techniques listed (Sigma rules
   available on request through appropriate channels)
3. Review MFA implementation — this actor's tooling specifically
   targets and defeats TOTP/SMS-based MFA; FIDO2 hardware keys are
   recommended for high-value accounts

## Attribution

No specific named threat actor is attributed to this campaign. Available
evidence suggests a financially motivated actor. Do not over-index on
attribution for defensive planning purposes — focus on the TTPs and IOCs above.
"""

# ── TLP:WHITE — Public-safe advisory (if organization chooses to publish) ──
TLP_WHITE = """# Public Security Advisory — Financial Sector Phishing Campaign
## TLP:WHITE — Unlimited Disclosure

---

## Summary

Security researchers have identified an active phishing campaign targeting
financial services organizations. The campaign uses convincing Microsoft 365
login page impersonations to harvest credentials, including techniques
capable of bypassing standard multi-factor authentication.

## What Organizations Should Do

1. **Train employees** to recognize phishing emails, particularly those
   referencing HR benefits, account verification, or urgent security alerts
2. **Deploy hardware security keys (FIDO2/WebAuthn)** for privileged accounts —
   this MFA type cannot be bypassed by the reverse-proxy phishing technique
   observed in this campaign
3. **Enforce DMARC** with a reject policy to prevent domain spoofing
4. **Monitor DNS traffic** for unusual query patterns — this campaign uses
   DNS-based command and control that can evade traditional network monitoring

## Indicator Sharing

Specific technical indicators are available to verified security researchers
and information sharing organizations through appropriate channels
(FS-ISAC, CISA AIS). Contact your sector ISAC for the full technical package.

## No Attribution Claim

This advisory does not attribute this activity to any specific named threat
actor or nation. It is shared to raise awareness of an active campaign
pattern affecting the financial sector.
"""

for name, content in [("tlp_red", TLP_RED), ("tlp_amber", TLP_AMBER), ("tlp_white", TLP_WHITE)]:
    with open(f"artifacts/tlp_variants/{name}_advisory.md", "w") as f:
        f.write(content)
    print(f"[+] Generated: artifacts/tlp_variants/{name}_advisory.md")

print(f"\n[+] Three TLP-classified variants complete")
print(f"    TLP:RED   — Full detail, named org, internal leadership only")
print(f"    TLP:AMBER — Sector sharing, named org, trusted community")
print(f"    TLP:WHITE — Public advisory, no org name, general awareness")
```

```bash
python3 build_tlp_variants.py | tee artifacts/tlp_variants/tlp_generation_summary.txt
```

**✅ Checkpoint 2:** Note how the level of detail, specificity, and
organizational naming decreases as the TLP classification opens up to wider
audiences — this is the core discipline of intelligence dissemination.

---

## STEP 4 — Outstanding Actions Tracker

**Objective:** Consolidate every unresolved item scattered across Days
08–13 into a single, trackable action list — nothing should fall through
the cracks between six separate reports.

```python
# Save as: build_action_tracker.py
import json

OUTSTANDING_ACTIONS = [
    {
        "id": "ACT-001",
        "source_day": "10",
        "description": "Confirm svc_backup Event 4624 authentication timestamp "
                       "on DESKTOP-FIN-047 against the compromise window "
                       "(Jan 5-16). CRITICAL — determines if incident scope "
                       "extends to domain-wide compromise.",
        "priority": "P0",
        "owner": "IR Team / AD Admin",
        "status": "OPEN",
        "deadline": "2 hours from Day 10 report",
    },
    {
        "id": "ACT-002",
        "source_day": "09",
        "description": "Decode all 3,160 captured DNS TXT exfiltration queries "
                       "from Day 04 to determine actual content exfiltrated — "
                       "resolves the Day 09 financial document claim uncertainty.",
        "priority": "P0",
        "owner": "Forensics Team",
        "status": "OPEN",
        "deadline": "48 hours from Day 09 report",
    },
    {
        "id": "ACT-003",
        "source_day": "09",
        "description": "Pull M365 audit logs for CEO's unauthorized Ukrainian "
                       "session — determine if SharePoint/OneDrive document "
                       "access occurred during that session.",
        "priority": "P0",
        "owner": "SOC / Azure Admin",
        "status": "OPEN",
        "deadline": "24 hours from Day 09 report",
    },
    {
        "id": "ACT-004",
        "source_day": "09",
        "description": "Submit FBI IC3 report with full evidence package.",
        "priority": "P1",
        "owner": "Legal / CISO",
        "status": "OPEN",
        "deadline": "72 hours from incident confirmation",
    },
    {
        "id": "ACT-005",
        "source_day": "13",
        "description": "Begin Phase 1 detection engineering (6 highest-priority "
                       "gaps): Pass-the-Hash, Session Cookie Theft, LSASS "
                       "automation, Account Manipulation, Password Spraying, "
                       "Command Shell execution.",
        "priority": "P1",
        "owner": "Detection Engineering",
        "status": "OPEN",
        "deadline": "30 days from Day 13 report",
    },
    {
        "id": "ACT-006",
        "source_day": "08",
        "description": "Submit updater.exe sample to VirusTotal, MalwareBazaar, "
                       "and abuse.ch to seed community detection signatures.",
        "priority": "P1",
        "owner": "Threat Intelligence",
        "status": "OPEN",
        "deadline": "Same day as Day 08 report",
    },
    {
        "id": "ACT-007",
        "source_day": "12",
        "description": "Perform static analysis on the memory-extracted "
                       "injected code region — compare to Day 08 dropper sample.",
        "priority": "P2",
        "owner": "Forensics Team",
        "status": "OPEN",
        "deadline": "48 hours from Day 12 report",
    },
    {
        "id": "ACT-008",
        "source_day": "13",
        "description": "Present full coverage gap findings and 90-day roadmap "
                       "to CISO and board risk committee.",
        "priority": "P1",
        "owner": "Threat Intelligence",
        "status": "OPEN",
        "deadline": "1 week from Day 13 report",
    },
    {
        "id": "ACT-009",
        "source_day": "09",
        "description": "Continue 24/7 dark web monitoring for follow-up posts "
                       "by fin_broker_01 or new posts naming NovaCrest.",
        "priority": "P2",
        "owner": "Threat Intelligence",
        "status": "ONGOING",
        "deadline": "Continuous",
    },
]

print("=" * 70)
print("  Outstanding Actions Tracker — Week 2 Consolidated")
print("=" * 70)

p0 = [a for a in OUTSTANDING_ACTIONS if a["priority"] == "P0"]
p1 = [a for a in OUTSTANDING_ACTIONS if a["priority"] == "P1"]
p2 = [a for a in OUTSTANDING_ACTIONS if a["priority"] == "P2"]

print(f"\n  🔴 P0 — IMMEDIATE ({len(p0)} items):")
for a in p0:
    print(f"    [{a['id']}] {a['description'][:80]}...")
    print(f"      Owner: {a['owner']} | Deadline: {a['deadline']} | Status: {a['status']}")

print(f"\n  🟠 P1 — HIGH PRIORITY ({len(p1)} items):")
for a in p1:
    print(f"    [{a['id']}] {a['description'][:80]}...")
    print(f"      Owner: {a['owner']} | Deadline: {a['deadline']} | Status: {a['status']}")

print(f"\n  🟡 P2 — STANDARD ({len(p2)} items):")
for a in p2:
    print(f"    [{a['id']}] {a['description'][:80]}...")
    print(f"      Owner: {a['owner']} | Deadline: {a['deadline']} | Status: {a['status']}")

with open("artifacts/tracker/outstanding_actions.json", "w") as f:
    json.dump(OUTSTANDING_ACTIONS, f, indent=2)

print(f"\n[+] Action tracker saved: artifacts/tracker/outstanding_actions.json")
print(f"[+] Total tracked items: {len(OUTSTANDING_ACTIONS)}")
```

```bash
python3 build_action_tracker.py | tee artifacts/tracker/tracker_summary.txt
```

---

## STEP 5 — Assemble the Finished Intelligence Report

The full synthesis document is assembled from all prior artifacts and
presented in [REPORT.md](REPORT.md). This is the culmination of the
Week 2 capstone — a single document that could be handed to any
stakeholder audience.

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** How many Key Judgments were produced, and what confidence level was assigned to the "no lateral movement" finding?
- [ ] 🚩 **Flag 2:** What is the single highest-priority (P0) outstanding action across the entire Week 2 investigation?
- [ ] 🚩 **Flag 3:** What changes between the TLP:RED, TLP:AMBER, and TLP:WHITE variants of the same intelligence?
- [ ] 🚩 **Flag 4:** How many total consolidated IOCs exist across Week 1 and Week 2 combined?
- [ ] 🚩 **Flag 5:** What does BLUF stand for, and why does it matter for executive-facing intelligence products?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `synthesis/key_judgments.json` | 6 confidence-graded key judgments |
| `synthesis/key_judgments_summary.txt` | Key judgments console output |
| `ioc_merge/consolidated_ioc_week1_week2.json` | Full merged IOC structure |
| `ioc_merge/consolidated_ioc_master.txt` | Plain text merged IOC list |
| `ioc_merge/merge_summary.txt` | IOC merge console output |
| `tlp_variants/tlp_red_advisory.md` | Internal-only full detail variant |
| `tlp_variants/tlp_amber_advisory.md` | Sector-sharing variant |
| `tlp_variants/tlp_white_advisory.md` | Public-safe advisory variant |
| `tlp_variants/tlp_generation_summary.txt` | TLP variant generation output |
| `tracker/outstanding_actions.json` | 9 consolidated outstanding actions |
| `tracker/tracker_summary.txt` | Action tracker console output |

---

*Next: [REPORT.md](REPORT.md) — Complete Week 2 finished intelligence product*
