# Day 07 — Lab Guide: Week 1 Capstone Synthesis
### Track: Full Stack | Duration: ~3 hours | Difficulty: Advanced

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Python 3** | Navigator layer gen, IOC consolidation, STIX export | Pre-installed |
| **stix2** | STIX 2.1 bundle generation | `pip install stix2` |
| **pandas** | IOC deduplication and CSV export | `pip install pandas` |
| **jinja2** | Executive brief HTML rendering | `pip install jinja2` |
| **ATT&CK Navigator** | Import and review the exported layer | attack.mitre.org/navigator |
| **jq** | JSON formatting | `sudo apt install jq` |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-07/artifacts
cd ~/security-labs/day-07

pip install stix2 pandas jinja2 requests --break-system-packages

echo "[+] Capstone environment ready"
echo "[+] Bringing together findings from Days 01–06"
```

---

## STEP 1 — Kill Chain Timeline: Full Narrative Assembly

**Objective:** Pull every timestamped event from Days 01–06 into a single
chronological timeline that tells the complete story of the intrusion.

```python
# Save as: build_kill_chain.py
from datetime import datetime
import json

# ── Complete Week 1 Kill Chain ─────────────────────────────────────
# Each entry maps a confirmed attacker or defender action to:
#   timestamp, phase, technique, evidence source, and significance

KILL_CHAIN = [
    # ── PRE-INTRUSION RECONNAISSANCE ──────────────────────────────
    {
        "timestamp":    "2025-01-05 14:32 UTC",
        "day_source":   "Day 03",
        "phase":        "Reconnaissance / Resource Development",
        "actor":        "Attacker",
        "action":       "Phishing domain registered: microsoftonline-portal.com",
        "technique":    "T1583.001",
        "technique_name":"Acquire Infrastructure: Domains",
        "evidence":     "WHOIS registration record — Namecheap privacy protected",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-05 16:00 UTC",
        "day_source":   "Day 04",
        "phase":        "Resource Development",
        "actor":        "Attacker",
        "action":       "C2 domain registered: updates.cdn-telemetry-svc.net",
        "technique":    "T1583.001",
        "technique_name":"Acquire Infrastructure: Domains",
        "evidence":     "WHOIS + crt.sh — same registrar, 90 min after phishing domain",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-05 18:00 UTC",
        "day_source":   "Day 03",
        "phase":        "Resource Development",
        "actor":        "Attacker",
        "action":       "Let's Encrypt wildcard certificate issued for phishing domain",
        "technique":    "T1587.003",
        "technique_name":"Develop Capabilities: Digital Certificates",
        "evidence":     "crt.sh certificate transparency log",
        "significance": "HIGH",
    },
    {
        "timestamp":    "2025-01-06 – 2025-01-14",
        "day_source":   "Day 01 / Day 05",
        "phase":        "Reconnaissance",
        "actor":        "Attacker",
        "action":       "Passive external recon: LinkedIn enumeration, job posting review, "
                        "DNS/certificate scan, OSINT surface mapping",
        "technique":    "T1591 / T1589 / T1596",
        "technique_name":"Gather Victim Org / Identity / Open Technical DB",
        "evidence":     "Day 01 Shodan results, Day 05 org chart reconstruction",
        "significance": "HIGH",
    },
    # ── INITIAL ACCESS ────────────────────────────────────────────
    {
        "timestamp":    "2025-01-14 ~09:00 UTC",
        "day_source":   "Day 03",
        "phase":        "Initial Access",
        "actor":        "Attacker",
        "action":       "Phishing campaign delivered to financial sector targets — "
                        "207 delivery attempts to NovaCrest",
        "technique":    "T1566.001",
        "technique_name":"Phishing: Spearphishing Attachment",
        "evidence":     "Email gateway quarantine logs — 14 blocked, 207 attempted",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-14 ~09:07 UTC",
        "day_source":   "Day 03 / Day 04",
        "phase":        "Initial Access",
        "actor":        "Victim",
        "action":       "DESKTOP-FIN-047 user (Mike Thompson) clicks phishing link — "
                        "HR benefits lure — does not enter credentials but malware "
                        "delivered via drive-by",
        "technique":    "T1204.001",
        "technique_name":"User Execution: Malicious Link",
        "evidence":     "Email gateway click log, Day 04 first beacon timestamp correlation",
        "significance": "CRITICAL",
    },
    # ── EXECUTION & C2 ESTABLISHMENT ─────────────────────────────
    {
        "timestamp":    "2025-01-14 ~09:12 UTC",
        "day_source":   "Day 04",
        "phase":        "Execution / Command & Control",
        "actor":        "Attacker",
        "action":       "Malware payload executes — first C2 DNS beacon fires to "
                        "updates.cdn-telemetry-svc.net at 60.3s interval (CV=0.0018)",
        "technique":    "T1071.004",
        "technique_name":"Application Layer Protocol: DNS",
        "evidence":     "Zeek dns.log — IAT analysis, first beacon timestamp 23:44:12 UTC",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-14 ~14:00 UTC",
        "day_source":   "Day 04",
        "phase":        "Exfiltration",
        "actor":        "Attacker",
        "action":       "DNS TXT record exfiltration channel activated — Base64 encoded "
                        "data in subdomain labels every 5th beacon",
        "technique":    "T1048.001",
        "technique_name":"Exfiltration Over Alternative Protocol: DNS",
        "evidence":     "dns_tunnel_detector.py — 20% TXT ratio, entropy > 5.8",
        "significance": "CRITICAL",
    },
    # ── PERSISTENCE ───────────────────────────────────────────────
    {
        "timestamp":    "2025-01-05 – 2025-01-16 (estimated)",
        "day_source":   "Day 06",
        "phase":        "Persistence",
        "actor":        "Attacker",
        "action":       "Persistence mechanisms likely deployed during 11-day dwell: "
                        "Scheduled Task, Registry Run Key, WMI Event Subscription "
                        "(confirmed detectable in purple team exercise — pending "
                        "forensic verification on DESKTOP-FIN-047 image)",
        "technique":    "T1053.005 / T1547.001 / T1546.003",
        "technique_name":"Scheduled Task / Registry Run / WMI Subscription",
        "evidence":     "Day 06 purple team — mechanism fingerprints documented",
        "significance": "CRITICAL",
    },
    # ── CREDENTIAL ACCESS ─────────────────────────────────────────
    {
        "timestamp":    "2025-01-15 ~22:14 UTC",
        "day_source":   "Day 02",
        "phase":        "Credential Access / Initial Access",
        "actor":        "Attacker",
        "action":       "CEO account (j.morrison) successfully authenticated from Ukraine "
                        "— first-ever login from this geography. MFA not enforced. "
                        "Active session to Microsoft 365.",
        "technique":    "T1078.004",
        "technique_name":"Valid Accounts: Cloud Accounts",
        "evidence":     "Azure AD Sign-in log — KQL Query 2, impossible travel detection",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-15 23:47 UTC",
        "day_source":   "Day 02",
        "phase":        "Credential Access",
        "actor":        "Attacker",
        "action":       "Credential stuffing attack: 94 failed auth attempts against "
                        "23 accounts in 15 minutes — 78% overlap with HIBP breach list",
        "technique":    "T1110.004",
        "technique_name":"Brute Force: Credential Stuffing",
        "evidence":     "Splunk SPL Query 1 — Event 4625, source IP 185.220.101.47",
        "significance": "HIGH",
    },
    # ── DETECTION ─────────────────────────────────────────────────
    {
        "timestamp":    "2025-01-16 02:17 UTC",
        "day_source":   "Day 04",
        "phase":        "Detection (Defender)",
        "actor":        "Defender",
        "action":       "Low-confidence EDR alert fires on DNS anomaly for DESKTOP-FIN-047 "
                        "— would have auto-suppressed without active overnight hunt",
        "technique":    "N/A",
        "technique_name":"Detection — Proactive Hunt",
        "evidence":     "EDR alert log, hunt hypothesis: single-domain query frequency",
        "significance": "HIGH",
    },
    {
        "timestamp":    "2025-01-16 02:47 UTC",
        "day_source":   "Day 04",
        "phase":        "Detection (Defender)",
        "actor":        "Defender",
        "action":       "C2 beacon confirmed via IAT statistical analysis — "
                        "CV=0.0018, score 99/100, interval 60.3s",
        "technique":    "N/A",
        "technique_name":"Detection — beacon_analyzer.py",
        "evidence":     "beacon_analysis_results.json",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-16 03:12 UTC",
        "day_source":   "Day 04",
        "phase":        "Detection (Defender)",
        "actor":        "Defender",
        "action":       "DNS tunnel confirmed — 3,160 TXT exfil queries, ~126KB data exfiltrated",
        "technique":    "N/A",
        "technique_name":"Detection — dns_tunnel_detector.py",
        "evidence":     "dns_tunnel_analysis.json",
        "significance": "CRITICAL",
    },
    {
        "timestamp":    "2025-01-16 03:30 UTC",
        "day_source":   "Day 04",
        "phase":        "Containment (Defender)",
        "actor":        "Defender",
        "action":       "DESKTOP-FIN-047 isolated from network. Forensic image initiated.",
        "technique":    "N/A",
        "technique_name":"Containment — host isolation",
        "evidence":     "IR case NVC-IR-2025-004",
        "significance": "HIGH",
    },
    {
        "timestamp":    "2025-01-16 09:00 UTC",
        "day_source":   "Day 07",
        "phase":        "Capstone (Defender)",
        "actor":        "Defender",
        "action":       "Week 1 synthesis complete — full kill chain documented, "
                        "ATT&CK Navigator layer exported, executive brief drafted",
        "technique":    "N/A",
        "technique_name":"Documentation — IR capstone",
        "evidence":     "This report",
        "significance": "HIGH",
    },
]

# ── Print narrative ───────────────────────────────────────────────
print("=" * 70)
print("  NovaCrest Capital Group — Week 1 Kill Chain Timeline")
print("=" * 70)

SIG_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

for event in KILL_CHAIN:
    emoji = SIG_EMOJI.get(event["significance"], "⚪")
    actor_marker = "🔴 ATK" if event["actor"] == "Attacker" else "🔵 DEF"
    print(f"\n  {event['timestamp']}")
    print(f"  {actor_marker} | {event['phase']}")
    print(f"  {emoji} {event['action']}")
    if event["technique"] != "N/A":
        print(f"     ATT&CK: {event['technique']} — {event['technique_name']}")
    print(f"     Source: {event['evidence'][:70]}")

# ── Save as JSON and Markdown ─────────────────────────────────────
with open("artifacts/kill_chain_timeline.json", "w") as f:
    json.dump(KILL_CHAIN, f, indent=2)

with open("artifacts/kill_chain_timeline.md", "w") as f:
    f.write("# Complete Kill Chain Timeline — NovaCrest Capital Group\n")
    f.write("**Week 1 Synthesis | Analyst: Blaakpearl | 2025-01-16**\n\n")
    f.write("| Timestamp | Actor | Phase | Action | ATT&CK | Day |\n")
    f.write("|-----------|-------|-------|--------|--------|-----|\n")
    for e in KILL_CHAIN:
        actor  = "🔴 Attacker" if e["actor"] == "Attacker" else "🔵 Defender"
        tech   = e["technique"] if e["technique"] != "N/A" else "—"
        action = e["action"][:80] + "..." if len(e["action"]) > 80 else e["action"]
        f.write(f"| `{e['timestamp']}` | {actor} | {e['phase']} | "
                f"{action} | {tech} | {e['day_source']} |\n")

print(f"\n\n[+] Kill chain saved:")
print(f"    artifacts/kill_chain_timeline.json")
print(f"    artifacts/kill_chain_timeline.md")
print(f"\n[+] Total events: {len(KILL_CHAIN)}")
print(f"    Attacker actions: {sum(1 for e in KILL_CHAIN if e['actor']=='Attacker')}")
print(f"    Defender actions: {sum(1 for e in KILL_CHAIN if e['actor']=='Defender')}")
print(f"    Days spanned: 12 (Jan 05 – Jan 16, 2025)")
```

```bash
python3 build_kill_chain.py | tee artifacts/kill_chain_summary.txt
```

---

## STEP 2 — ATT&CK Navigator Layer: JSON Export

**Objective:** Generate a complete ATT&CK Navigator layer JSON covering all
techniques confirmed across Days 01–06. Import at attack.mitre.org/navigator
to visualize coverage and gaps.

```python
# Save as: generate_navigator_layer.py
import json
from datetime import datetime

# All confirmed techniques from Week 1 — with source day and confidence
WEEK1_TECHNIQUES = [
    # Reconnaissance
    {"id":"T1590",    "name":"Gather Victim Network Info",        "tactic":"reconnaissance",         "day":"01","confidence":"high",  "color":"#ff4757"},
    {"id":"T1590.001","name":"IP Addresses",                      "tactic":"reconnaissance",         "day":"01","confidence":"high",  "color":"#ff4757"},
    {"id":"T1591",    "name":"Gather Victim Org Info",            "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    {"id":"T1591.002","name":"Business Relationships",            "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    {"id":"T1591.004","name":"Identify Roles",                    "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    {"id":"T1589",    "name":"Gather Victim Identity Info",       "tactic":"reconnaissance",         "day":"02","confidence":"high",  "color":"#ff4757"},
    {"id":"T1589.002","name":"Email Addresses",                   "tactic":"reconnaissance",         "day":"02","confidence":"high",  "color":"#ff4757"},
    {"id":"T1589.003","name":"Employee Names",                    "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    {"id":"T1596",    "name":"Search Open Technical Databases",   "tactic":"reconnaissance",         "day":"01","confidence":"high",  "color":"#ff4757"},
    {"id":"T1593",    "name":"Search Open Websites/Domains",      "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    {"id":"T1593.001","name":"Social Media",                      "tactic":"reconnaissance",         "day":"05","confidence":"high",  "color":"#ff4757"},
    # Resource Development
    {"id":"T1583",    "name":"Acquire Infrastructure",            "tactic":"resource-development",   "day":"03","confidence":"high",  "color":"#ff6b35"},
    {"id":"T1583.001","name":"Domains",                           "tactic":"resource-development",   "day":"03","confidence":"high",  "color":"#ff6b35"},
    {"id":"T1584",    "name":"Compromise Infrastructure",         "tactic":"resource-development",   "day":"03","confidence":"medium","color":"#ff6b35"},
    {"id":"T1587.003","name":"Digital Certificates",              "tactic":"resource-development",   "day":"03","confidence":"high",  "color":"#ff6b35"},
    # Initial Access
    {"id":"T1566",    "name":"Phishing",                          "tactic":"initial-access",         "day":"03","confidence":"high",  "color":"#ffa500"},
    {"id":"T1566.001","name":"Spearphishing Attachment",          "tactic":"initial-access",         "day":"03","confidence":"high",  "color":"#ffa500"},
    {"id":"T1078",    "name":"Valid Accounts",                    "tactic":"initial-access",         "day":"02","confidence":"high",  "color":"#ffa500"},
    {"id":"T1078.004","name":"Cloud Accounts",                    "tactic":"initial-access",         "day":"02","confidence":"high",  "color":"#ffa500"},
    {"id":"T1204.001","name":"User Execution: Malicious Link",    "tactic":"execution",              "day":"03","confidence":"high",  "color":"#ffd700"},
    # Execution
    {"id":"T1059.001","name":"PowerShell",                        "tactic":"execution",              "day":"06","confidence":"high",  "color":"#ffd700"},
    # Persistence
    {"id":"T1053.005","name":"Scheduled Task",                    "tactic":"persistence",            "day":"06","confidence":"high",  "color":"#00ff88"},
    {"id":"T1547.001","name":"Registry Run Keys",                 "tactic":"persistence",            "day":"06","confidence":"high",  "color":"#00ff88"},
    {"id":"T1546.003","name":"WMI Event Subscription",            "tactic":"persistence",            "day":"06","confidence":"high",  "color":"#00ff88"},
    # Defense Evasion
    {"id":"T1036.005","name":"Match Legitimate Name",             "tactic":"defense-evasion",        "day":"03","confidence":"high",  "color":"#a855f7"},
    {"id":"T1112",    "name":"Modify Registry",                   "tactic":"defense-evasion",        "day":"06","confidence":"high",  "color":"#a855f7"},
    {"id":"T1027",    "name":"Obfuscated Files/Info",             "tactic":"defense-evasion",        "day":"04","confidence":"high",  "color":"#a855f7"},
    {"id":"T1562.001","name":"Disable or Modify Tools",           "tactic":"defense-evasion",        "day":"06","confidence":"medium","color":"#a855f7"},
    # Credential Access
    {"id":"T1110",    "name":"Brute Force",                       "tactic":"credential-access",      "day":"02","confidence":"high",  "color":"#00d4ff"},
    {"id":"T1110.003","name":"Password Spraying",                 "tactic":"credential-access",      "day":"02","confidence":"high",  "color":"#00d4ff"},
    {"id":"T1110.004","name":"Credential Stuffing",               "tactic":"credential-access",      "day":"02","confidence":"high",  "color":"#00d4ff"},
    {"id":"T1539",    "name":"Steal Web Session Cookie",          "tactic":"credential-access",      "day":"03","confidence":"high",  "color":"#00d4ff"},
    # Command & Control
    {"id":"T1071.004","name":"DNS",                               "tactic":"command-and-control",    "day":"04","confidence":"high",  "color":"#ff4757"},
    {"id":"T1573.002","name":"Asymmetric Cryptography",           "tactic":"command-and-control",    "day":"04","confidence":"high",  "color":"#ff4757"},
    {"id":"T1008",    "name":"Fallback Channels",                 "tactic":"command-and-control",    "day":"04","confidence":"medium","color":"#ff4757"},
    {"id":"T1132.001","name":"Standard Encoding",                 "tactic":"command-and-control",    "day":"04","confidence":"high",  "color":"#ff4757"},
    # Exfiltration
    {"id":"T1048.001","name":"Exfiltration Over DNS",             "tactic":"exfiltration",           "day":"04","confidence":"high",  "color":"#e17055"},
    {"id":"T1041",    "name":"Exfiltration Over C2 Channel",      "tactic":"exfiltration",           "day":"04","confidence":"medium","color":"#e17055"},
]

# ── Build Navigator Layer ─────────────────────────────────────────
CONFIDENCE_SCORES = {"high": 100, "medium": 60, "low": 30}

layer = {
    "name":        "Blaakpearl — NovaCrest Incident Week 1",
    "versions":    {"attack": "14", "navigator": "4.9"},
    "domain":      "enterprise-attack",
    "description": (
        "MITRE ATT&CK layer generated from Week 1 security investigation "
        "of NovaCrest Capital Group incident (fictional). "
        "Days 01-07 | Analyst: Blaakpearl | 2025-01-16. "
        "Red = Reconnaissance/C2/Exfil | Orange = Initial Access | "
        "Yellow = Execution | Green = Persistence | Purple = Defense Evasion | "
        "Blue = Credential Access"
    ),
    "filters":     {"platforms": ["Windows", "Azure AD", "Office 365", "IaaS"]},
    "sorting":     0,
    "layout":      {"layout": "side", "showID": True, "showName": True},
    "hideDisabled": False,
    "techniques":  [],
    "gradient":    {
        "colors":   ["#444444", "#66b1ff"],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [
        {"label": "Day 01 — External Recon",     "color": "#ff4757"},
        {"label": "Day 02 — Credential Hunt",    "color": "#ffa500"},
        {"label": "Day 03 — Phishing Infra",     "color": "#ff6b35"},
        {"label": "Day 04 — C2 / DNS Tunnel",    "color": "#00d4ff"},
        {"label": "Day 05 — Social Eng Surface", "color": "#ffb700"},
        {"label": "Day 06 — Persistence Hunt",   "color": "#00ff88"},
    ],
    "showTacticRowBackground": True,
    "tacticRowBackground":     "#0f1318",
    "selectTechniquesAcrossTactics": True,
}

for t in WEEK1_TECHNIQUES:
    layer["techniques"].append({
        "techniqueID": t["id"],
        "score":       CONFIDENCE_SCORES[t["confidence"]],
        "color":       t["color"],
        "comment":     f"Day {t['day']} — {t['confidence'].upper()} confidence",
        "enabled":     True,
        "metadata":    [
            {"name": "Day Source",   "value": f"Day {t['day']}"},
            {"name": "Confidence",   "value": t["confidence"]},
            {"name": "Analyst",      "value": "Blaakpearl"},
        ],
    })

# Save layer
with open("artifacts/navigator_layer_week1.json", "w") as f:
    json.dump(layer, f, indent=2)

print("=" * 60)
print("  ATT&CK Navigator Layer Generated — Week 1")
print("=" * 60)
print(f"\n  Total techniques:  {len(WEEK1_TECHNIQUES)}")
print(f"  High confidence:   {sum(1 for t in WEEK1_TECHNIQUES if t['confidence']=='high')}")
print(f"  Medium confidence: {sum(1 for t in WEEK1_TECHNIQUES if t['confidence']=='medium')}")

# Tactic breakdown
from collections import Counter
tactic_counts = Counter(t["tactic"] for t in WEEK1_TECHNIQUES)
print(f"\n  Tactic Coverage:")
for tactic, count in sorted(tactic_counts.items()):
    print(f"    {tactic:<35} {count:>2} technique(s)")

print(f"\n  [+] Layer saved: artifacts/navigator_layer_week1.json")
print(f"\n  Import at: https://mitre-attack.github.io/attack-navigator/")
print(f"  → Open Existing Layer → Upload File → select navigator_layer_week1.json")
```

```bash
python3 generate_navigator_layer.py | tee artifacts/navigator_layer_summary.txt
```

---

## STEP 3 — Unified IOC Master List

**Objective:** Consolidate all indicators from Days 01–06 into a single
deduplicated master list in multiple formats.

```python
# Save as: build_ioc_master.py
import json, csv
from datetime import datetime
from stix2 import (Bundle, Indicator, ThreatActor,
                   KillChainPhase, ExternalReference)

NOW = "2025-01-16T09:00:00Z"

# ── All IOCs from Week 1 ──────────────────────────────────────────
ALL_IOCS = {
    "ips": [
        {"value":"185.220.101.12",  "day":"03","confidence":"high",
         "note":"Phishing hosting — Flyservers AS209588"},
        {"value":"185.220.101.33",  "day":"04","confidence":"high",
         "note":"C2 server — same ASN, updates.cdn-telemetry-svc.net"},
        {"value":"185.220.101.47",  "day":"02","confidence":"high",
         "note":"Credential stuffing source — Tor exit / residential proxy"},
        {"value":"91.108.4.11",     "day":"02","confidence":"high",
         "note":"CEO impossible travel login — Kyiv Ukraine"},
        {"value":"203.0.113.45",    "day":"01","confidence":"medium",
         "note":"NovaCrest primary IP — exposed VPN portal (victim)"},
    ],
    "domains": [
        {"value":"microsoftonline-portal.com",          "day":"03","confidence":"high",
         "note":"Primary phishing domain"},
        {"value":"novacrest-benefits.microsoftonline-portal.com", "day":"03",
         "confidence":"high","note":"Targeted NovaCrest phishing subdomain"},
        {"value":"ms-account-portal.net",               "day":"03","confidence":"high",
         "note":"Related campaign domain — same infrastructure"},
        {"value":"secure-signin.ms-account-portal.com", "day":"03","confidence":"high",
         "note":"Related campaign domain"},
        {"value":"hrportal-login.microsoftonline-portal.com","day":"03",
         "confidence":"high","note":"Related campaign domain"},
        {"value":"updates.cdn-telemetry-svc.net",       "day":"04","confidence":"high",
         "note":"C2 beacon domain — 60.3s interval"},
        {"value":"cdn-telemetry-svc.net",               "day":"04","confidence":"high",
         "note":"C2 parent domain"},
    ],
    "urls": [
        {"value":"hxxps://novacrest-benefits.microsoftonline-portal[.]com/signin",
         "day":"03","confidence":"high","note":"Primary phishing URL — M365 harvester"},
        {"value":"hxxp://185.220.101.33/stage2",        "day":"04","confidence":"high",
         "note":"C2 second stage payload URL — in WMI consumer command"},
    ],
    "email_indicators": [
        {"value":"Subject: Urgent: Benefits Enrollment Update Required",
         "day":"03","confidence":"high","note":"Phishing email subject lure"},
        {"value":"Link pattern: *microsoftonline-[word].com/signin*",
         "day":"03","confidence":"high","note":"Email link pattern for gateway rules"},
    ],
    "network_patterns": [
        {"value":"DNS query: *.cdn-telemetry-svc.net every ~60s",
         "day":"04","confidence":"high","note":"C2 beacon timing pattern"},
        {"value":"DNS TXT records with Base64 encoded labels > 30 chars",
         "day":"04","confidence":"high","note":"DNS tunnel exfil pattern"},
        {"value":"JA3: 72a589da586844d7f0818ce684948eea",
         "day":"04","confidence":"medium","note":"TLS fingerprint — C2 framework"},
    ],
    "host_indicators": [
        {"value":"Scheduled task: MicrosoftEdgeUpdateTaskMachineCore",
         "day":"06","confidence":"high","note":"Persistence Mechanism 1"},
        {"value":"Registry: HKCU\\..\\Run\\OneDriveStandaloneUpdater",
         "day":"06","confidence":"high","note":"Persistence Mechanism 2"},
        {"value":"WMI Filter: SCM_EventLog_Filter",
         "day":"06","confidence":"high","note":"Persistence Mechanism 3 — filter"},
        {"value":"WMI Consumer: SCM_EventLog_Consumer",
         "day":"06","confidence":"high","note":"Persistence Mechanism 3 — consumer"},
        {"value":"Process: powershell.exe -WindowStyle Hidden -EncodedCommand",
         "day":"06","confidence":"high","note":"Common payload execution pattern"},
    ],
    "asns": [
        {"value":"AS209588","name":"Flyservers S.A.","country":"Seychelles",
         "day":"03","confidence":"high","note":"Bulletproof hosting provider"},
    ],
}

# ── Print summary ─────────────────────────────────────────────────
total = sum(len(v) for v in ALL_IOCS.values())
print("=" * 60)
print(f"  Unified IOC Master List — Week 1 ({total} total indicators)")
print("=" * 60)
for category, iocs in ALL_IOCS.items():
    print(f"\n  {category.upper()} ({len(iocs)}):")
    for ioc in iocs:
        print(f"    • {ioc['value'][:60]}")
        print(f"      Day {ioc['day']} | {ioc['confidence'].upper()} | {ioc['note'][:50]}")

# ── Save plain text (defanged) ────────────────────────────────────
with open("artifacts/ioc_master_week1.txt", "w") as f:
    f.write(f"# IOC Master List — NovaCrest Incident Week 1\n")
    f.write(f"# Analyst: Blaakpearl | Date: 2025-01-16 | TLP: AMBER\n")
    f.write(f"# Total indicators: {total}\n\n")
    for category, iocs in ALL_IOCS.items():
        f.write(f"\n## {category.upper()}\n")
        for ioc in iocs:
            val = ioc["value"].replace("https://","hxxps://").replace("http://","hxxp://")
            val = val.replace(".com","[.]com").replace(".net","[.]net") \
                     .replace(".org","[.]org") if "hxxp" not in val and \
                     "Subject" not in val and "pattern" not in val \
                     and "query" not in val and "HKCU" not in val \
                     and "WMI" not in val and "Process" not in val \
                     and "Scheduled" not in val else ioc["value"]
            f.write(f"{val}  # Day {ioc['day']} — {ioc['note']}\n")

# ── Save CSV ──────────────────────────────────────────────────────
with open("artifacts/ioc_master_week1.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["type","value","day","confidence","note"])
    writer.writeheader()
    for category, iocs in ALL_IOCS.items():
        for ioc in iocs:
            writer.writerow({"type":category, **ioc})

# ── Save JSON ─────────────────────────────────────────────────────
with open("artifacts/ioc_master_week1.json", "w") as f:
    json.dump(ALL_IOCS, f, indent=2)

print(f"\n[+] IOC master list saved (3 formats):")
print(f"    artifacts/ioc_master_week1.txt  (plain text defanged)")
print(f"    artifacts/ioc_master_week1.csv  (CSV for SIEM import)")
print(f"    artifacts/ioc_master_week1.json (JSON)")
```

```bash
python3 build_ioc_master.py | tee artifacts/ioc_summary.txt
```

---

## STEP 4 — Detection Coverage Gap Map

**Objective:** Cross-reference all confirmed ATT&CK techniques against
the Sigma rules written in Days 02–06 to identify blind spots.

```python
# Save as: coverage_gap_map.py
import json

# All techniques from Week 1
ALL_TECHNIQUES = [
    "T1590","T1590.001","T1591","T1591.002","T1591.004",
    "T1589","T1589.002","T1589.003","T1596","T1593","T1593.001",
    "T1583","T1583.001","T1584","T1587.003",
    "T1566","T1566.001","T1078","T1078.004","T1204.001",
    "T1059.001","T1110","T1110.003","T1110.004","T1539",
    "T1053.005","T1547.001","T1546.003",
    "T1036.005","T1112","T1027","T1562.001",
    "T1071.004","T1573.002","T1008","T1132.001",
    "T1048.001","T1041",
]

# Sigma rules written during Week 1
SIGMA_COVERAGE = {
    "T1110.004": {"rule":"sigma_credential_stuffing.yml",       "day":"02","level":"high"},
    "T1078.004": {"rule":"kql_impossible_travel.kql",           "day":"02","level":"high"},
    "T1566.001": {"rule":"sigma_phishing_campaign.yml",         "day":"03","level":"high"},
    "T1583.001": {"rule":"sigma_phishing_campaign.yml",         "day":"03","level":"high"},
    "T1053.005": {"rule":"sigma_scheduled_task_persistence.yml","day":"06","level":"high"},
    "T1547.001": {"rule":"sigma_registry_run_key_persistence.yml","day":"06","level":"medium"},
    "T1546.003": {"rule":"sigma_wmi_subscription_persistence.yml","day":"06","level":"critical"},
    "T1071.004": {"rule":"sigma_c2_beacon_dns.yml",             "day":"04","level":"high"},
    "T1048.001": {"rule":"sigma_dns_tunneling.yml",             "day":"04","level":"high"},
}

covered  = [t for t in ALL_TECHNIQUES if t in SIGMA_COVERAGE]
gaps     = [t for t in ALL_TECHNIQUES if t not in SIGMA_COVERAGE]
pct      = len(covered) / len(ALL_TECHNIQUES) * 100

print("=" * 65)
print("  Detection Coverage Gap Map — Week 1 Techniques")
print("=" * 65)
print(f"\n  Total techniques confirmed: {len(ALL_TECHNIQUES)}")
print(f"  Sigma rules covering:       {len(covered)} ({pct:.0f}%)")
print(f"  BLIND SPOTS:                {len(gaps)} ({100-pct:.0f}%)")

print(f"\n  ✅ COVERED TECHNIQUES:")
for t in covered:
    r = SIGMA_COVERAGE[t]
    print(f"    {t:<15} {r['level'].upper():<10} {r['rule']} (Day {r['day']})")

print(f"\n  ❌ GAPS — NO DETECTION RULE:")
TACTIC_MAP = {
    "T1590":"Reconnaissance","T1590.001":"Reconnaissance",
    "T1591":"Reconnaissance","T1591.002":"Reconnaissance","T1591.004":"Reconnaissance",
    "T1589":"Reconnaissance","T1589.002":"Reconnaissance","T1589.003":"Reconnaissance",
    "T1596":"Reconnaissance","T1593":"Reconnaissance","T1593.001":"Reconnaissance",
    "T1583":"Resource Dev",  "T1584":"Resource Dev","T1587.003":"Resource Dev",
    "T1566":"Initial Access","T1078":"Initial Access","T1204.001":"Execution",
    "T1059.001":"Execution","T1110":"Credential Access","T1110.003":"Credential Access",
    "T1539":"Credential Access","T1036.005":"Defense Evasion",
    "T1112":"Defense Evasion","T1027":"Defense Evasion","T1562.001":"Defense Evasion",
    "T1573.002":"C2","T1008":"C2","T1132.001":"C2","T1041":"Exfiltration",
}
gap_priority = [
    ("T1059.001","PowerShell execution","HIGH — common in all 3 persistence mechanisms"),
    ("T1112",    "Modify Registry",     "HIGH — registry writes outside Run keys"),
    ("T1539",    "Steal Web Session Cookie","CRITICAL — MFA bypass kit in phishing"),
    ("T1573.002","Asymmetric Cryptography C2","HIGH — DoH encrypted C2"),
    ("T1204.001","User Execution",      "MEDIUM — requires email gateway telemetry"),
    ("T1027",    "Obfuscated Files/Info","HIGH — Base64 encoded payloads"),
]
for tech_id, tech_name, priority in gap_priority:
    if tech_id in gaps:
        tactic = TACTIC_MAP.get(tech_id, "Unknown")
        print(f"    {tech_id:<15} {tactic:<22} {tech_name}")
        print(f"                   Priority: {priority}")

# Save gap map
gap_data = {
    "coverage_pct": round(pct, 1),
    "covered":      covered,
    "gaps":         gaps,
    "gap_priorities": gap_priority,
    "sigma_rules":  SIGMA_COVERAGE,
}
with open("artifacts/detection_coverage_gaps.json", "w") as f:
    json.dump(gap_data, f, indent=2)

print(f"\n[+] Gap map saved: artifacts/detection_coverage_gaps.json")
print(f"\n  NEXT ACTIONS — Rules to write in Week 2:")
print(f"    1. PowerShell encoded command execution (T1059.001)")
print(f"    2. MFA session cookie theft detection (T1539)")
print(f"    3. Registry modification outside Run keys (T1112)")
```

```bash
python3 coverage_gap_map.py | tee artifacts/coverage_gap_summary.txt
```

---

## STEP 5 — Executive Incident Brief

```bash
cat > artifacts/executive_incident_brief.md << 'EOF'
# Executive Incident Brief
## NovaCrest Capital Group — Active Intrusion — Restricted Distribution

**Date:** January 16, 2025
**Classification:** RESTRICTED — Executive Distribution Only
**Prepared by:** Security Operations — Analyst Blaakpearl
**Case:** NVC-IR-2025-004

---

## What Happened

NovaCrest Capital Group has been targeted by a sophisticated threat actor
in a coordinated attack that began January 5, 2025. The attacker followed
a precise multi-phase playbook:

**Phase 1 (Jan 5–14):** The attacker registered look-alike domains mimicking
Microsoft's login portals, built phishing pages that bypass multi-factor
authentication, and spent 9 days conducting passive research on our employees —
including gathering names, roles, and current business projects from LinkedIn
and public job postings.

**Phase 2 (Jan 14):** 207 phishing emails were sent to NovaCrest employees
impersonating HR benefits notifications. One employee in Fixed Income Trading
clicked the link. Malware was silently installed on their workstation
(DESKTOP-FIN-047) without requiring any further action.

**Phase 3 (Jan 14–16):** The attacker's software ran silently for 11 days,
transmitting encrypted data back to attacker-controlled servers every 60
seconds. An estimated 126 kilobytes of data was exfiltrated during this period.
The content of that data is under forensic investigation.

**Phase 4 (Jan 15):** The CEO's Microsoft 365 account was successfully accessed
from Ukraine — a country from which he has never previously logged in. We believe
this is the same threat actor using credentials obtained from a public data breach.

---

## Current Status

- **DESKTOP-FIN-047 is isolated** — disconnected from the network, forensic
  image captured, active investigation underway
- **CEO account has been secured** — session revoked, password reset, MFA
  enforced, account under enhanced monitoring
- **14 phishing domains are blocked** at email gateway, web proxy, and DNS
- **No other confirmed compromised endpoints** — hunt ongoing across all systems
- **Law enforcement notification** — under assessment pending legal review

---

## What Was at Risk

The Fixed Income analyst whose workstation was compromised had access to:
trading positions, market research, and internal communications. The scope
of data exfiltrated is not yet confirmed — forensic analysis of the 11-day
beacon traffic is in progress and will be reported within 48 hours.

---

## What We Are Doing

**Immediate (complete or in progress):**
- Forensic examination of DESKTOP-FIN-047
- Organization-wide hunt for the same attack pattern on all endpoints
- Forced password resets for all 312 accounts found in the breach dataset
- MFA enforcement for all accounts — executive exemptions removed
- Three new automated detection rules deployed to security monitoring

**This Week:**
- Complete scope assessment — determine all systems accessed
- Legal and compliance review — assess regulatory notification obligations
- Third-party IR firm engagement for independent investigation
- Executive spearphishing awareness briefing — real examples from this case

**This Month:**
- Full detection gap remediation across all 38 identified technique gaps
- FIDO2 hardware security key deployment for C-suite and privileged accounts
- External attack surface reduction — VPN patch, DMARC enforcement, dev env lockdown

---

## Decisions Required from Leadership

1. **Regulatory notification:** Legal team to assess SEC/FINRA/GDPR obligations
   within 72 hours — mandatory breach notification timelines vary by jurisdiction
2. **Third-party IR engagement:** Authorize budget for independent forensic firm
3. **Communication plan:** Determine if and how to notify affected employees
   whose credentials appeared in the breach data

---

*This brief will be updated every 24 hours until the incident is closed.*
*All technical details available from Security Operations on request.*
EOF

echo "[+] Executive brief saved: artifacts/executive_incident_brief.md"
```

---

## STEP 6 — Commit Package Verification

```bash
echo "[*] Week 1 Capstone — Artifact Verification"
echo "=" * 50

echo ""
echo "=== Day 07 Artifacts ==="
ls -lah artifacts/

echo ""
echo "=== Checking GitHub portfolio structure ==="
for day in 01 02 03 04 05 06 07; do
    count=$(ls ~/security-portfolio-30days/days/day-${day}/*.md 2>/dev/null | wc -l)
    if [ "$count" -ge "3" ]; then
        echo "  Day $day: ✅ Complete ($count .md files)"
    else
        echo "  Day $day: ⏳ Pending ($count .md files found)"
    fi
done

echo ""
echo "=== ATT&CK Navigator Layer ==="
python3 -c "
import json
with open('artifacts/navigator_layer_week1.json') as f:
    layer = json.load(f)
print(f'  Layer name:  {layer[\"name\"]}')
print(f'  Techniques:  {len(layer[\"techniques\"])}')
print(f'  Domain:      {layer[\"domain\"]}')
print(f'  Status:      Ready to import at attack.mitre.org/navigator')
"

echo ""
echo "[+] Week 1 Capstone complete"
echo "[+] Commit command:"
echo ""
echo "  cd ~/security-portfolio-30days"
echo "  git add days/day-07/"
echo "  git commit -m \"✅ Day 07 complete — Week 1 Capstone | Full Stack | All T1xxx\""
echo "  git push origin main"
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** How many MITRE ATT&CK techniques were confirmed across the full Week 1 investigation?
- [ ] 🚩 **Flag 2:** What was the attacker's dwell time between first infrastructure registration and detection?
- [ ] 🚩 **Flag 3:** What detection coverage percentage was achieved with the Sigma rules written in Days 02–06?
- [ ] 🚩 **Flag 4:** How many total IOCs are in the unified master list?
- [ ] 🚩 **Flag 5:** What URL do you use to import the ATT&CK Navigator layer JSON?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `kill_chain_timeline.json` | Full kill chain in structured JSON |
| `kill_chain_timeline.md` | Kill chain as Markdown table |
| `kill_chain_summary.txt` | Console output from build_kill_chain.py |
| `navigator_layer_week1.json` | ATT&CK Navigator layer — import this |
| `navigator_layer_summary.txt` | Layer generation summary |
| `ioc_master_week1.txt` | Defanged plain text IOC list |
| `ioc_master_week1.csv` | CSV format for SIEM import |
| `ioc_master_week1.json` | JSON format for tooling |
| `ioc_summary.txt` | IOC consolidation console output |
| `detection_coverage_gaps.json` | Coverage gap map — structured |
| `coverage_gap_summary.txt` | Gap analysis console output |
| `executive_incident_brief.md` | 2-page executive brief |

---

*Next: [REPORT.md](REPORT.md) — Week 1 capstone synthesis report*
