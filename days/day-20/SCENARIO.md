# Day 20 — SCENARIO.md
## Purple Team: C2 Beaconing Detection Exercise
**NovaCrest Capital Group | Authorized Purple Team Exercise**
**Classification:** TLP:AMBER — Authorized Participants Only
**Track:** Purple Teaming
**Tools:** Sliver C2 · Havoc · EDR · Zscaler · Zeek · Sigma

---

## Exercise Overview

This is a structured purple team exercise with a defined **detection SLA**.
The red team deploys a live C2 beaconing channel on an isolated lab endpoint.
The blue team must detect it within the agreed SLA window using three
independent detection layers: proxy telemetry (Zscaler), EDR behavioral
analysis, and Zeek network analysis. At exercise close, all teams compare
notes — what fired, what missed, why, and what Sigma rules close the gaps.

**This is not a covert engagement.** Both teams coordinate on the exercise
design; the red team documents every action with timestamps. The goal is to
measure and improve detection capability, not to test secrecy.

---

## Exercise Parameters

| Parameter | Value |
|-----------|-------|
| Target endpoint | LAB-WIN-01 (Windows 11 22H2 — isolated VLAN) |
| Red team SLA | Deploy C2 + 3 evasion variants within 90 minutes |
| Blue team SLA | Detect each variant within 30 minutes of deployment |
| Detection methods | Zscaler proxy, CrowdStrike EDR, Zeek network analysis |
| C2 frameworks | Sliver (primary), Havoc (secondary variant) |
| Exercise window | 4 hours |
| Scoring | 3 pts per detection within SLA; 1 pt late; 0 pts missed |

---

## Scenario Narrative

> *The NovaCrest blue team has deployed Zscaler Internet Access, CrowdStrike Falcon,
> and a Zeek sensor on their network. The red team has been given a clean lab
> endpoint inside an isolated VLAN that allows outbound HTTPS. Their task: establish
> a C2 channel that looks as legitimate as possible, then progressively layer on
> evasion. The blue team watches their dashboards in real time and races to detect
> each variant before the 30-minute SLA expires. At the end, both teams sit together,
> compare what was seen and missed, and build Sigma rules to ensure every variant
> gets caught next time.*

---

## Red Team — C2 Deployment Variants

### Variant 1 — Baseline: Sliver HTTPS Beacon (No Evasion)
```
Framework:     Sliver C2 (open source; CISA advisory CAA23-100)
Transport:     HTTPS (TCP:443)
Beacon type:   Async beacon (not interactive session)
Beacon interval: 60 seconds
Jitter:        0% (predictable — detectable by timing analysis)
Destination:   198.51.100.99:443 (attacker VPS; no fronting)
Certificate:   Let's Encrypt (real cert — not self-signed)
SNI:           evil-c2.novacrest-updates.com (new domain; 3 days old)
User-Agent:    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Payload size:  ~45 KB (encrypted — standard Sliver implant)
Detection goal: Blue team should catch this within 5 min — it's obvious
```

### Variant 2 — Sleep Jitter + Less Obvious Domain
```
Framework:     Sliver C2
Transport:     HTTPS (TCP:443)
Beacon interval: 300 seconds (5 min) with 50% jitter (150–450s range)
Jitter:        50% — harder to detect via timing analysis
Destination:   198.51.100.50:443
Certificate:   DigiCert (purchased legitimate cert)
SNI:           cdn-assets.azureedge-novacrest.com (Azure CDN lookalike)
User-Agent:    Rotates among 5 real browser UAs
Payload size:  Variable (jitter randomizes padding)
Detection goal: Within 15 min — harder; requires content or behavioral detection
```

### Variant 3 — Domain Fronting via Azure CDN
```
Framework:     Sliver C2
Transport:     HTTPS (TCP:443)
Domain fronting: Azure CDN — SNI shows legitimate Azure domain;
                  Host header shows attacker domain
SNI (outer):   legitimate-corp.azureedge.net (real Azure CDN domain)
Host header:   evil-c2.attacker.com (real C2 destination — hidden in encrypted header)
Beacon interval: 600 seconds (10 min) with 30% jitter
Detection goal: Within 20 min — requires HTTP header inspection or JA3
Note:         Domain fronting increasingly blocked by CDN providers;
               this exercises what defenders should still watch for
```

### Variant 4 — Havoc C2 with DNS-over-HTTPS (DoH) Fallback
```
Framework:     Havoc C2 (alternative; different JA3/JARM signatures)
Transport:     HTTPS primary; DNS-over-HTTPS fallback
DoH resolver:  Cloudflare (1.1.1.1:443) — looks like legit DoH traffic
Beacon interval: 900 seconds (15 min)
Jitter:        25%
Detection goal: Within 25 min — DoH fallback is hardest; requires JARM/JA3
```

---

## Blue Team — Detection Layers

### Layer 1: Zscaler Internet Access (Proxy)
```
Controls available:
  - URL categorization (new/uncategorized domains → alert)
  - SSL inspection (decrypt + inspect HTTPS)
  - Cloud Application Control
  - Advanced Threat Protection
  - DNS Security (block DoH to external resolvers)

Expected detections:
  - Variant 1: New domain (3 days old) → URL category alert
  - Variant 2: Azure CDN lookalike → category mismatch
  - Variant 3: Domain fronting → Host header ≠ SNI (TLS inspection required)
  - Variant 4: DoH to external → DNS Security should block
```

### Layer 2: CrowdStrike Falcon EDR
```
Controls available:
  - Behavioral prevention (process chain analysis)
  - Network detection (connection anomalies)
  - Machine learning (unknown binary detection)
  - Threat Graph (correlate across endpoints)
  - Custom IOA rules (custom detection logic)

Expected detections:
  - Variant 1: Known Sliver signature in ML model
  - Variant 2: Beacon timing anomaly (even with jitter, pattern detectable)
  - Variant 3: Process making outbound connections to CDN with unusual timing
  - Variant 4: Havoc implant process behavior; DoH bypass attempt
```

### Layer 3: Zeek Network Analysis
```
Controls available:
  - ssl.log: JA3/JARM fingerprinting
  - conn.log: Beacon timing pattern analysis
  - dns.log: DoH evasion detection
  - http.log: Domain fronting (Host header vs SNI)
  - files.log: Payload size and type patterns

Expected detections:
  - All variants: Periodic connection pattern to external IP
  - Variant 1: Known Sliver JA3 fingerprint
  - Variant 3: Host ≠ SNI in http.log (after TLS inspection)
  - Variant 4: DoH queries to 1.1.1.1:443 with DNS content
```

---

## MITRE ATT&CK Coverage

| Technique | Sub-Technique | Name | Variant |
|-----------|---------------|------|---------|
| T1071 | T1071.001 | Application Layer Protocol: HTTPS | All |
| T1573 | T1573.002 | Encrypted Channel: Asymmetric Cryptography | All |
| T1090 | T1090.004 | Proxy: Domain Fronting | Variant 3 |
| T1008 | — | Fallback Channels (DoH) | Variant 4 |
| T1001 | T1001.001 | Data Obfuscation: Jitter | Variants 2–4 |
| T1071 | T1071.004 | Application Layer Protocol: DNS (DoH) | Variant 4 |
| T1102 | — | Web Service (CDN abuse) | Variants 2–3 |

---

## SLA Scoring Rubric

| Detection Result | Points |
|-----------------|--------|
| Detected within SLA (30 min) | 3 points |
| Detected after SLA, within exercise window | 1 point |
| Not detected (missed entirely) | 0 points |
| False positive triggered (alert on legit traffic) | −1 point |

**Maximum score: 12 points (4 variants × 3 pts)**

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Sliver C2 setup, Zscaler + Zeek configuration, exercise run guide |
| `REPORT.md` | Exercise outcomes, SLA scorecard, detection comparison |
| `scripts/c2_beacon_simulator.py` | Simulate C2 beacon traffic patterns (no live C2) |
| `scripts/beacon_timing_analyzer.py` | Detect periodic beacon patterns in Zeek conn.log |
| `queries/zeek_c2_detection.spl` | Splunk SPL queries for C2 detection |
| `queries/zeek_c2_detection.kql` | Sentinel KQL equivalents |
| `rules/sigma_c2_detection.yml` | Sigma rule library (one rule per variant) |
| `reports/day20_exercise_report.md` | Full exercise findings with SLA scorecard |
| `reports/day20_sigma_tuning.md` | Sigma rule tuning guide and FP analysis |

---

*Day 20 Scenario | Purple Team C2 Detection Exercise*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
