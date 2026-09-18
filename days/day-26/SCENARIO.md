# Day 26 — SCENARIO.md
## Threat Intelligence: Threat Actor Profiling
**NovaCrest Capital Group | Case NCA-2026-06-TI**
**Classification:** TLP:AMBER — Threat Intelligence Restricted Distribution
**Track:** Threat Intelligence
**Tools:** OpenCTI · STIX 2.1 · TAXII · MITRE ATT&CK · VirusTotal Graph

---

## Intelligence Requirement

Eleven days of forensic evidence across Cases NCA-2026-06 and NCA-2026-06-R
has produced a rich set of technical indicators — C2 IP, JA3/JARM fingerprints,
ransomware binary hash, IAM backdoor artifacts, attacker AWS account, ransom
note style, and victim ID format. The question for Day 26 shifts from
**what happened** to **who did it and what do they do next?**

The goal is to build a structured threat actor profile for the group responsible
for the NovaCrest breach — designated **FIN-NC-001** (internal tracking name)
— correlating NovaCrest IOCs against external threat intelligence sources,
published adversary profiles, and open source reporting to answer:

1. **Attribution confidence:** Is this a known threat group? What is the
   confidence level and evidentiary basis?

2. **Targeting profile:** Who else does this actor target? What sector, size,
   and geography? Is NovaCrest a deliberate target or opportunistic?

3. **Operational playbook:** What are their consistent TTPs across incidents?
   What deviates from baseline in the NovaCrest attack?

4. **Infrastructure pattern:** Do they reuse infrastructure? Is 198.51.100.99
   or the .onion domain linked to prior incidents?

5. **Next move prediction:** Given their playbook, what is the likely next
   action if ransom is not paid? What else in the NovaCrest environment is
   at risk?

---

## IOC Pivot Starting Points (from Days 15–25)

| IOC Type | Value | Source Day |
|----------|-------|-----------|
| C2 IPv4 | 198.51.100.99 | Days 15–25 (consistent) |
| JA3 hash (Sliver) | a0e9f5d64349fb13191bc781f81f42e1 | Day 20 |
| JARM (Sliver C2) | 1dd28f00000000000043d43d000000ba86b6e5f1c028a5c19b35dd9e71a15c | Day 20 |
| JA3 hash (Havoc) | f4febc55ea12b31ae17cfb7e614afda8 | Day 20 |
| Ransomware SHA256 | a4b3c2d1e0f9...f5a4b3 | Day 25 |
| Ransom note email | ncrypt-support@protonmail.com | Day 25 |
| Onion site | ncrypt3k4j7mxbwz.onion | Day 25 |
| Attacker AWS account | 987654321099 | Day 24 |
| Backdoor IAM key | AKIAIOSFODNN7BACKDOOR | Day 24 |
| Victim ID format | NOVA-YYYYMMDD-XXXX | Day 25 |
| XMR wallet prefix | 48edfhj3kHJK... | Day 25 |
| Phishing domain | trading-updates[.]novacrest-secure[.]com | Day 16 |

---

## Intelligence Sources

| Source | Type | Access |
|--------|------|--------|
| MITRE ATT&CK Groups | Open source | attack.mitre.org/groups |
| VirusTotal Graph | Commercial | IOC pivot + clustering |
| Mandiant Advantage | Commercial | Threat actor intelligence |
| CrowdStrike Adversary Intelligence | Commercial | Actor profiles |
| OpenCTI (self-hosted) | Open platform | STIX 2.1 structured intel |
| TAXII feeds (CISA, FS-ISAC) | Open/Member | Sector-specific IOCs |
| AlienVault OTX | Community | Community IOC sharing |
| Recorded Future | Commercial | Dark web + infrastructure |
| Ransomwatch | Open source | Ransomware group monitoring |

---

## Intelligence Production Framework

This day uses the **Intelligence Cycle** applied to threat actor analysis:

```
Direction   → What do we need to know? (requirements above)
Collection  → IOC pivoting, OSINT, feed ingestion, dark web monitoring
Processing  → Normalization into STIX 2.1 objects
Analysis    → Correlation, confidence scoring, ATT&CK mapping
Dissemination → OpenCTI report, STIX bundle, executive brief
```

### STIX 2.1 Objects Used

| Object | Purpose |
|--------|---------|
| `threat-actor` | FIN-NC-001 profile |
| `intrusion-set` | Linked campaigns |
| `malware` | ncrypt ransomware + Sliver implant |
| `tool` | Cobalt Strike, Pacu, vssadmin |
| `attack-pattern` | ATT&CK technique references |
| `indicator` | IP, hash, domain, email IOCs |
| `relationship` | Links between objects |
| `report` | NovaCrest incident intelligence report |
| `course-of-action` | Defensive mitigations |

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | OpenCTI setup, TAXII feed config, STIX 2.1 authoring guide |
| `REPORT.md` | Summary findings and STIX bundle |
| `scripts/actor_profiler.py` | Threat actor profile builder + ATT&CK overlay |
| `scripts/stix_builder.py` | STIX 2.1 bundle generator for NovaCrest incident |
| `queries/cti_hunt.spl` | Splunk SPL: IOC feed matching + actor TTP hunt |
| `queries/cti_hunt.kql` | Sentinel KQL: threat intel matching queries |
| `reports/day26_actor_profile.md` | Full FIN-NC-001 threat actor profile |
| `reports/day26_stix_report.md` | STIX 2.1 object documentation |
| `artifacts/fin_nc_001_stix_bundle.json` | Production STIX 2.1 bundle |

---

*Day 26 Scenario | Threat Actor Profiling*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
