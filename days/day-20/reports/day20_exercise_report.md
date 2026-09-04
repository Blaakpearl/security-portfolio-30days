# Day 20 — C2 Detection Exercise Report
**NovaCrest Capital Group | Purple Team Exercise**
**Classification:** TLP:AMBER — Internal Security Use
**Author:** V. Willis, CISSP — Purple Team Lead
**Exercise Date:** 2026-06-20
**Exercise Window:** 09:00–13:00 UTC

---

## Executive Summary

A four-variant C2 beaconing exercise was conducted across a 4-hour window.
The blue team operated three independent detection layers — Zscaler proxy,
CrowdStrike Falcon EDR, and Zeek network analysis — against Sliver and Havoc
C2 frameworks deploying progressively sophisticated evasion. **Final score:
8/12 points. Two variants detected within SLA; one detected late; one missed.**
Domain fronting (Variant 3) was the most significant gap — requires TLS
inspection to detect, which is not currently deployed. Fourteen Sigma rules
were written during the post-exercise workshop to close remaining gaps.

---

## SLA Scorecard

| Variant | C2 Evasion | SLA (min) | MTTD (min) | Detection Layer | Score |
|---------|-----------|-----------|------------|-----------------|-------|
| V1 — Sliver Baseline | No evasion | 5 | **3:22** | Zeek JA3 + CrowdStrike ML | ✅ **3 pts** |
| V2 — Jitter + CDN SNI | 50% jitter | 15 | **12:44** | Zeek beacon timing CV=0.31 | ✅ **3 pts** |
| V3 — Domain Fronting | Azure CDN front | 20 | **34:10** | Zscaler (post-inspection) | ⚠️ **1 pt** |
| V4 — Havoc + DoH | Alternate C2 + DoH | 25 | **—** | Not detected | ❌ **0 pts** |
| **TOTAL** | | | | | **7/12 pts** |

> **Note:** V3 received 1 point (detected within exercise window, after SLA).
> V4 was not detected — Zscaler DoH blocking was not enabled; Havoc JARM was
> not in the JARM blocklist; beacon timing analysis had insufficient connections
> within the exercise window.

---

## Variant 1 — Sliver Baseline: DETECTED ✅ (T+3:22)

### What Fired
- **Zeek ssl.log (T+3:22):** JA3 `a0e9f5d64349fb13191bc781f81f42e1` matched
  known Sliver fingerprint. Alert fired immediately upon first connection.
- **CrowdStrike ML (T+4:15):** Sliver shellcode injection into `svchost.exe`
  detected by memory scanning. Alert: "Known C2 framework memory signature."
- **Zscaler (T+5:01):** `evil-c2.novacrest-updates.com` categorized as
  "Newly Registered Domain" (3 days old). Alert: URL category policy.

### What Was Not Needed (But Would Have Helped)
- Domain age detection alone would have flagged this without JA3
- Self-signed cert check was not needed (Let's Encrypt cert was valid)

### Lesson Learned — Red Team
Baseline Sliver with no evasion was caught in 3:22 — a realistic MTTD for
a well-instrumented environment. The JA3 blocklist is the single highest-
fidelity C2 detection primitive available — fast, low FP, automatic.

---

## Variant 2 — Jitter + CDN Lookalike: DETECTED ✅ (T+12:44)

### What Fired
- **Zeek beacon timing (T+12:44):** After 6 connections to 198.51.100.50:443,
  the beacon timing analyzer computed IAT coefficient of variation = 0.31,
  below the 0.35 threshold. Alert: "Statistically periodic beacon pattern."
- **CrowdStrike (T+15:22):** Low-prevalence domain connection count threshold
  triggered on `cdn-assets.azureedge-novacrest.com`. Global prevalence: 1 host.

### What Didn't Fire
- Zscaler URL categorization: CDN lookalike domain (`azureedge-novacrest.com`)
  was not in any block category. Domain registered 3 days before exercise but
  Zscaler's domain age feed had not yet indexed it.
- JA3 still matched Sliver — but red team included JA3 rotation in variant 2
  config; Zeek only captured 2 connections with JA3 before rotation started.
  Timing analysis was the actual detection vector.

### Lesson Learned — Blue Team
50% jitter raises detection time from 3 to 13 minutes but doesn't defeat
statistical analysis. IAT CV < 0.35 is robust to 50% jitter. Red team would
need > 80% jitter to push CV above threshold — at which point the interval
becomes too unpredictable to maintain effective C2.

### Lesson Learned — Red Team
CDN lookalike SNI (`cdn-assets.azureedge-novacrest.com`) did not fool Zscaler's
domain age check because the domain was only 3 days old. Purchasing domains
30+ days in advance ("aged domains") is the real adversary countermeasure.

---

## Variant 3 — Domain Fronting: LATE DETECTION ⚠️ (T+34:10)

### What Fired (Late)
- **Zscaler (T+34:10):** After enabling SSL inspection mid-exercise
  (prompted by red team hint), the Host header (`evil-c2.attacker.com`)
  was visible and did not match SNI (`legitimate-corp.azureedge.net`).
  Alert: "Domain fronting detected — Host ≠ SNI."

### What Did NOT Fire
- Zeek ssl.log: SNI showed `legitimate-corp.azureedge.net` (real Azure domain).
  Without the Host header (only visible after TLS decryption), Zeek saw
  a clean connection to a legitimate Azure CDN domain. No alert.
- CrowdStrike: Behavioral analysis saw `svchost.exe` connecting to Azure CDN
  — not inherently suspicious. No alert fired within SLA.
- Zeek beacon timing: V3 used a 600-second interval with 30% jitter.
  Only 4 connections occurred within the SLA window — insufficient for
  CV analysis (minimum 8 required).

### Root Cause of SLA Miss
**TLS inspection was not enabled on the Zscaler tenant** at exercise start.
Without decrypting the HTTPS session, the Host header is hidden inside the
encrypted TLS record. TLS inspection is required to detect domain fronting.

The exercise facilitator provided a hint at T+30:00 ("check proxy decryption
settings"), which prompted the blue team to enable inspection, leading to
detection 4 minutes later.

### Lesson Learned — Critical
Domain fronting is **undetectable without TLS inspection**. Deploying Zscaler
without enabling SSL inspection for newly-registered and uncategorized domains
leaves a complete blind spot. TLS inspection should be enabled at minimum for:
- Newly registered domains (< 30 days)
- Uncategorized / miscellaneous domains
- Any connection with a known-bad JA3 (decrypt to examine Host header)

---

## Variant 4 — Havoc + DoH: MISSED ❌

### What Was Not Configured
- **Zscaler DNS Security:** DoH blocking to external resolvers was not
  enabled. Havoc's DoH fallback to `1.1.1.1:443` went undetected.
  Zeek saw HTTPS to `1.1.1.1:443` with SNI `cloudflare-dns.com` — this
  looks identical to legitimate browser DoH behavior.
- **JARM blocklist:** Havoc's JARM signature (`2ad2ad16...`) was not in the
  Zscaler or Zeek JARM blocklist. Only Sliver's JARM was in the list.
- **Beacon timing:** Havoc's 900-second interval (15 min) meant only 3
  connections occurred in the 45-minute V4 window. Minimum 8 connections
  are needed for reliable CV analysis.

### What Would Have Caught It
1. **Zscaler DNS Security:** Block DoH to `1.1.1.1:443`, `8.8.8.8:443`
   from corporate endpoints (browsers excluded via policy exception)
2. **JARM blocklist update:** Add Havoc JARM to Zscaler + Zeek detection
3. **Extended timing window:** 2-hour observation period would yield
   8 connections (sufficient for CV analysis even at 900s interval)
4. **JARM active scanning:** Periodically JARM-scan destinations with
   multiple connections to build fingerprint database

### Lesson Learned
Havoc is newer than Sliver and less represented in public JA3/JARM lists.
This is the value of JARM active scanning — defenders who periodically
fingerprint destinations they're observing can identify new C2 frameworks
before signatures are published.

---

## Detection Method Comparison

| Method | V1 | V2 | V3 | V4 | Best For |
|--------|----|----|----|----|---------|
| JA3 Fingerprint | ✅ 3:22 | ⚠️ Partial | ❌ (CDN IP) | ❌ (Havoc unknown) | Known framework detection |
| JARM Fingerprint | ✅ | ✅ | ❌ | ❌ | Known framework; server-side |
| Domain Age | ✅ | ⚠️ Partial | ❌ (old domain) | ❌ (Cloudflare) | New C2 infra |
| Beacon Timing CV | — | ✅ 12:44 | ❌ (too few) | ❌ (too few) | Jittered beacons with volume |
| TLS Inspection (Host≠SNI) | — | — | ✅ (late) | — | Domain fronting only |
| DoH Blocking | — | — | — | ✅ (not deployed) | DoH bypass |
| EDR Behavioral | ✅ 4:15 | ✅ 15:22 | ⚠️ | ❌ | Known tool behavior patterns |

**Bottom line:** JA3 + domain age catches ~60% of real-world C2. Beacon
timing extends this to ~75%. TLS inspection + DoH blocking brings coverage
to ~90%. The final 10% (custom-built implants, perfect operational security)
requires threat hunting with anomaly baselines.

---

## Post-Exercise Sigma Rule Workshop

Seven gaps identified; fourteen Sigma rules written (see `rules/sigma_c2_detection.yml`):

| Gap | Rule Written | Estimated FP Rate |
|-----|-------------|------------------|
| Unknown JA3 detection | C2_Beacon_JA3_Fingerprint | Very Low (<0.1%) |
| New domain HTTPS | C2_Beacon_New_Domain | Low (5%) |
| Domain fronting | C2_Beacon_DomainFronting | Low (2%) |
| DoH external resolver | C2_Beacon_DoH_External | Low (3%) |
| Statistical beacon timing | C2_Beacon_TimingCV | Medium (8%) |
| Self-signed cert + bytes | C2_Beacon_SelfSigned | Medium (10%) |
| Consistent payload size | C2_Beacon_PayloadConsistency | Medium (12%) |

---

## Tuning Priorities

### Deploy This Week
1. **Enable TLS inspection in Zscaler** for uncategorized and newly-registered
   domains — closes the domain fronting blind spot completely
2. **Enable Zscaler DNS Security** — blocks DoH to external resolvers;
   eliminates V4 attack path
3. **Add Havoc JARM to blocklist** — immediate improvement on V4 detection

### Deploy This Month
4. **Tune beacon timing alert** — reduce minimum connections from 8 to 5;
   extend observation window to 2 hours; deploy as continuous scheduled search
5. **Add payload size consistency rule** to CrowdStrike custom IOA
6. **JARM active scanning workflow** — scan all external HTTPS destinations
   with > 5 connections/hour; compare against known-bad JARM database

### Strategic
7. **Zeek JARM enrichment** — enable automatic JARM scanning on new connections;
   feed results to SIEM for real-time comparison
8. **Network traffic baseline** — establish 30-day egress baseline per host;
   deploy UEBA for volumetric anomaly (complements timing analysis)

---

*Day 20 — Purple Team C2 Detection Exercise*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
