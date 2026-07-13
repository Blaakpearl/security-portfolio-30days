# Day 10 — Lateral Movement Detection
### Track: Threat Hunting | Difficulty: Advanced | Phase: Lateral Movement

---

## 🎯 Threat Brief

It is Day 16 of the NovaCrest Capital Group incident. The LSASS credential
dump confirmed in Day 08 raised an urgent question that the IR team has been
unable to answer definitively: **did the attacker use the stolen credentials
to move beyond DESKTOP-FIN-047?**

Eleven days of dwell time and a confirmed credential harvesting capability
create a wide window of opportunity. If the attacker successfully pivoted
to other hosts — particularly if they reached a domain controller or a
system with Domain Admin sessions cached — the scope of this incident
changes from "one compromised workstation" to "full domain compromise."

Your task: **hunt for lateral movement** across the entire NovaCrest Windows
environment. You have Windows Security Event Logs, Sysmon telemetry, and
Active Directory data available. You do not yet know if lateral movement
occurred — this is a hypothesis-driven hunt, not a confirmed-finding
investigation. The outcome could go either way, and both outcomes matter
enormously to the scope of remediation required.

---

## 🔍 Lateral Movement: The Attacker's Playbook

Once initial access and credential theft are achieved, attackers pivot
through a network using one of several well-documented techniques. Each
leaves distinct evidence in Windows telemetry — if you know where to look.

```
┌────────────────────────────────────────────────────────────────────┐
│  PASS-THE-HASH (PtH)                                                │
│    Uses stolen NTLM hash directly — no plaintext password needed   │
│    Evidence: Event 4624 Logon Type 3, NTLM auth, no Kerberos ticket │
│                                                                     │
│  PASS-THE-TICKET (PtT)                                              │
│    Uses stolen/forged Kerberos ticket for authentication           │
│    Evidence: Event 4768/4769 anomalies, ticket without pre-auth     │
│                                                                     │
│  DCOM LATERAL MOVEMENT                                              │
│    Abuses Distributed COM objects to execute code remotely          │
│    Evidence: Event 4688 (MMC/DCOM spawned processes), Event 5140    │
│                                                                     │
│  WMI LATERAL MOVEMENT                                               │
│    Uses WMI to execute commands on remote systems                  │
│    Evidence: Event 4688 (WmiPrvSE.exe spawning cmd/powershell)      │
│              WMI-Activity/Operational log entries                   │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🏢 Hunt Context

```
Starting point:    DESKTOP-FIN-047 (confirmed compromised, Day 04/06/08)
Confirmed access:  LSASS credential dump (Day 08) — domain creds at risk
Environment:       Windows Active Directory domain, ~2,400 endpoints
Domain:            NOVACREST.LOCAL
Data sources:      Windows Security Event Logs (all domain controllers)
                    Sysmon (deployed on ~85% of endpoints)
                    Active Directory (for BloodHound path analysis)
Hunt window:       2025-01-14 09:12 UTC (first beacon) through
                    2025-01-16 03:30 UTC (isolation) — 42.3 hour window
Hunt hypothesis:   "Did credentials stolen from FIN-047 authenticate
                    to any other host in the environment during the
                    compromise window?"
```

---

## 🎯 The Hunt Methodology

```
┌────────────────────────────────────────────────────────────────────┐
│  STEP 1: BASELINE                                                   │
│    Establish normal authentication patterns for the compromised     │
│    account(s) — where do they normally log in from/to?              │
│                                                                     │
│  STEP 2: HUNT PASS-THE-HASH                                         │
│    Search Event 4624 for NTLM Type 3 logons from FIN-047 or using   │
│    credentials known to be cached there                             │
│                                                                     │
│  STEP 3: HUNT PASS-THE-TICKET                                       │
│    Search Kerberos events for ticket anomalies — unusual TGT/TGS    │
│    patterns, tickets used from unexpected source IPs                │
│                                                                     │
│  STEP 4: HUNT DCOM/WMI EXECUTION                                     │
│    Search process creation events for remote execution signatures   │
│                                                                     │
│  STEP 5: MAP THE BLAST RADIUS                                       │
│    Use BloodHound to determine what an attacker COULD reach with    │
│    the compromised credentials — worst-case scope assessment        │
│                                                                     │
│  STEP 6: PRODUCE THE PLAYBOOK                                       │
│    Regardless of findings, document a repeatable lateral movement   │
│    hunt playbook for future incidents                               │
└────────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Detection Challenge

Lateral movement is uniquely difficult to detect because:

- **Legitimate admin activity looks identical.** IT staff routinely use
  PsExec, WMI, and remote PowerShell for administration — the same
  techniques attackers use
- **NTLM logons are common.** Distinguishing malicious Pass-the-Hash from
  normal NTLM fallback authentication requires behavioral baselining
- **Kerberos ticket forgery is nearly invisible** without specific
  detection for ticket lifetime anomalies and encryption downgrade
- **Domain controllers generate enormous log volume** — the signal is a
  needle in an extremely large haystack without targeted queries

---

## 📚 Learning Objectives

1. Establish an authentication baseline for a compromised account
2. Hunt for Pass-the-Hash indicators using Windows Event 4624 analysis
3. Hunt for Pass-the-Ticket indicators using Kerberos event correlation
4. Detect DCOM and WMI lateral movement through process creation telemetry
5. Use BloodHound to map attack paths and assess worst-case blast radius
6. Write Splunk correlation queries joining authentication and process data
7. Produce a reusable lateral movement hunt playbook

---

## ✅ Success Criteria

- [ ] Authentication baseline established for compromised account(s)
- [ ] Pass-the-Hash hunt query executed with documented results (positive or negative)
- [ ] Pass-the-Ticket hunt query executed with documented results
- [ ] DCOM/WMI execution hunt query executed with documented results
- [ ] BloodHound attack path analysis completed — blast radius documented
- [ ] Splunk correlation queries saved for future hunts
- [ ] Lateral movement hunt playbook produced

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1550.002** | Use Alternate Authentication: Pass the Hash | Lateral Movement | Primary hunt target |
| **T1550.003** | Use Alternate Authentication: Pass the Ticket | Lateral Movement | Primary hunt target |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Lateral Movement | PsExec-style movement |
| **T1021.003** | Remote Services: Distributed Component Object Model | Lateral Movement | DCOM hunt target |
| **T1021.006** | Remote Services: Windows Remote Management | Lateral Movement | WinRM hunt target |
| **T1047** | Windows Management Instrumentation | Execution | WMI hunt target |
| **T1558** | Steal or Forge Kerberos Tickets | Credential Access | Golden/Silver ticket risk |

---

*Next: [LAB.md](LAB.md) — Step-by-step lateral movement hunt lab guide*
