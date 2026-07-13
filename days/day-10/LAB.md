# Day 10 — Lab Guide: Lateral Movement Detection
### Track: Threat Hunting | Duration: ~3.5 hours | Difficulty: Advanced

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Splunk** | Log correlation across authentication and process data | splunk.com/free-trial |
| **BloodHound** | AD attack path visualization and blast radius analysis | github.com/BloodHoundAD/BloodHound |
| **SharpHound** | BloodHound data collector (run in authorized lab AD only) | github.com/BloodHoundAD/SharpHound |
| **Neo4j** | Graph database backing BloodHound | neo4j.com/download |
| **Windows Event Viewer** | Manual log review | Built-in |
| **PowerShell** | Log extraction and analysis automation | Built-in |
| **Python 3** | Correlation scripting, report generation | Pre-installed |

---

## 🖥 Environment Setup

```powershell
# Run in lab AD environment or against exported event log data

New-Item -Path "C:\SecurityLab\Day10\artifacts" -ItemType Directory -Force
Set-Location "C:\SecurityLab\Day10"

# Confirmed compromised account/host from prior days
$CompromisedHost    = "DESKTOP-FIN-047"
$CompromisedAccount = "NOVACREST\mthompson"
$HuntWindowStart    = "2025-01-14 09:12:00"   # first C2 beacon
$HuntWindowEnd      = "2025-01-16 03:30:00"   # host isolation

Write-Host "[+] Lateral movement hunt environment ready"
Write-Host "[+] Hunt window: $HuntWindowStart to $HuntWindowEnd (42.3 hours)"
Write-Host "[+] Origin host: $CompromisedHost"
```

---

## STEP 1 — Establish Authentication Baseline

**Objective:** Before hunting for anomalies, establish what NORMAL
authentication looks like for the compromised account. Without a baseline,
you cannot distinguish malicious lateral movement from routine IT activity.

```powershell
# Pull 30 days of authentication history BEFORE the compromise window
# to establish baseline behavior

$BaselineStart = (Get-Date "2025-01-14 09:12:00").AddDays(-30)
$BaselineEnd   = Get-Date "2025-01-14 09:12:00"

Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = $BaselineStart
    EndTime   = $BaselineEnd
} | Where-Object { $_.Message -like "*mthompson*" } |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time      = $_.TimeCreated
            LogonType = ($xml.Event.EventData.Data |
                        Where-Object {$_.Name -eq "LogonType"}).'#text'
            SourceIP  = ($xml.Event.EventData.Data |
                        Where-Object {$_.Name -eq "IpAddress"}).'#text'
            TargetHost= ($xml.Event.EventData.Data |
                        Where-Object {$_.Name -eq "WorkstationName"}).'#text'
        }
    } | Group-Object TargetHost |
    Select-Object Name, Count |
    Sort-Object Count -Descending |
    Tee-Object -Variable Baseline |
    Format-Table -AutoSize

$Baseline | ConvertTo-Json | Out-File "artifacts\baseline_auth_pattern.json"
Write-Host "[+] Baseline established — normal login destinations documented"
```

**Expected baseline output:**
```
Name              Count
----              -----
DESKTOP-FIN-047     847   ← normal — user's own workstation
FILESERVER01         12   ← normal — occasional file share access
EXCHANGE01            8   ← normal — occasional OWA fallback
```

**✅ Checkpoint 1:** The baseline shows the account normally authenticates
almost exclusively to its own workstation, with rare access to a file server
and Exchange. Any authentication to a domain controller, a server the user
has no business reason to access, or a peer workstation would be anomalous.

---

## STEP 2 — Hunt Pass-the-Hash (Event 4624 Analysis)

**Objective:** Search for NTLM authentication events during the compromise
window that deviate from the established baseline — particularly Logon
Type 3 (network) authentications using NTLM rather than Kerberos.

```powershell
# Hunt query: NTLM Type 3 logons during compromise window
# involving the compromised account, FROM any source

Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4624
    StartTime = (Get-Date $HuntWindowStart)
    EndTime   = (Get-Date $HuntWindowEnd)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time         = $_.TimeCreated
        TargetUser   = ($data | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
        LogonType    = ($data | Where-Object {$_.Name -eq "LogonType"}).'#text'
        AuthPackage  = ($data | Where-Object {$_.Name -eq "AuthenticationPackageName"}).'#text'
        SourceIP     = ($data | Where-Object {$_.Name -eq "IpAddress"}).'#text'
        WorkstationName = ($data | Where-Object {$_.Name -eq "WorkstationName"}).'#text'
        LogonProcess = ($data | Where-Object {$_.Name -eq "LogonProcessName"}).'#text'
    }
} | Where-Object {
    $_.LogonType -eq "3" -and
    $_.AuthPackage -eq "NTLM" -and
    $_.TargetUser -notlike "*$*"     # exclude machine accounts
} | Tee-Object -Variable NTLMEvents |
    Format-Table -AutoSize

$NTLMEvents | ConvertTo-Json | Out-File "artifacts\ntlm_type3_events.json"

Write-Host "`n[*] NTLM Type 3 logon events found: $($NTLMEvents.Count)"
Write-Host "[*] Flagging any NOT matching baseline destinations..."

$BaselineHosts = $Baseline.Name
$Anomalies = $NTLMEvents | Where-Object { $_.WorkstationName -notin $BaselineHosts }

if ($Anomalies) {
    Write-Host "`n[!!!] ANOMALOUS NTLM AUTHENTICATION DETECTED:"
    $Anomalies | Format-Table -AutoSize
    $Anomalies | ConvertTo-Json | Out-File "artifacts\pth_anomalies.json"
} else {
    Write-Host "`n[+] No NTLM authentications outside baseline pattern"
    Write-Host "[+] No confirmed Pass-the-Hash lateral movement via this method"
}
```

### Splunk Correlation Query — Pass-the-Hash Detection

```splunk
| SPL Query: Pass-the-Hash Hunt
| Detects NTLM Type 3 authentication anomalies for compromised account

index=windows_security EventCode=4624 LogonType=3
    AuthenticationPackageName=NTLM
    TargetUserName="mthompson"
| eval hunt_window=if(_time >= strptime("2025-01-14 09:12:00","%Y-%m-%d %H:%M:%S")
    AND _time <= strptime("2025-01-16 03:30:00","%Y-%m-%d %H:%M:%S"), "IN_WINDOW", "OUTSIDE")
| where hunt_window="IN_WINDOW"
| stats count by WorkstationName, IpAddress, _time
| lookup baseline_hosts.csv WorkstationName OUTPUT is_baseline
| where isnull(is_baseline)
| eval alert="ANOMALOUS PTH CANDIDATE — host not in 30-day baseline"
| table _time, WorkstationName, IpAddress, alert
| sort - _time
```

**✅ Checkpoint 2:** Document the result either way. A negative finding
(no anomalous NTLM auth) is just as important as a positive one — it
narrows the scope of the incident and directs the hunt toward Kerberos-based
techniques instead.

---

## STEP 3 — Hunt Pass-the-Ticket (Kerberos Event Analysis)

**Objective:** Search Kerberos authentication events (4768 TGT request,
4769 TGS request) for anomalies indicating ticket theft or forgery —
tickets used from unexpected locations, unusual encryption types, or
ticket lifetimes inconsistent with legitimate issuance.

```powershell
# Hunt Kerberos TGT requests (4768) for the compromised account
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4768
    StartTime = (Get-Date $HuntWindowStart)
    EndTime   = (Get-Date $HuntWindowEnd)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time           = $_.TimeCreated
        TargetUser     = ($data | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
        IpAddress      = ($data | Where-Object {$_.Name -eq "IpAddress"}).'#text'
        TicketEncType  = ($data | Where-Object {$_.Name -eq "TicketEncryptionType"}).'#text'
        PreAuthType    = ($data | Where-Object {$_.Name -eq "PreAuthType"}).'#text'
        Status         = ($data | Where-Object {$_.Name -eq "Status"}).'#text'
    }
} | Where-Object { $_.TargetUser -like "*mthompson*" } |
    Tee-Object -Variable TGTEvents | Format-Table -AutoSize

$TGTEvents | ConvertTo-Json | Out-File "artifacts\kerberos_tgt_events.json"

# Encryption downgrade check — RC4 (0x17) is weaker and associated with
# Golden/Silver Ticket forgery tools that don't support AES
$WeakEncryption = $TGTEvents | Where-Object { $_.TicketEncType -eq "0x17" }
if ($WeakEncryption) {
    Write-Host "`n[!] WARNING: RC4 encryption tickets found — possible forgery indicator"
    Write-Host "    RC4 tickets: $($WeakEncryption.Count) / $($TGTEvents.Count) total"
    $WeakEncryption | Format-Table -AutoSize
} else {
    Write-Host "`n[+] No RC4-encrypted tickets — no obvious downgrade indicator"
}

# Hunt Kerberos service ticket requests (4769) — look for service access
# patterns that reveal what the attacker attempted to reach
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4769
    StartTime = (Get-Date $HuntWindowStart)
    EndTime   = (Get-Date $HuntWindowEnd)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time        = $_.TimeCreated
        TargetUser  = ($data | Where-Object {$_.Name -eq "TargetUserName"}).'#text'
        ServiceName = ($data | Where-Object {$_.Name -eq "ServiceName"}).'#text'
        IpAddress   = ($data | Where-Object {$_.Name -eq "IpAddress"}).'#text'
        TicketOpts  = ($data | Where-Object {$_.Name -eq "TicketOptions"}).'#text'
    }
} | Where-Object { $_.TargetUser -like "*mthompson*" } |
    Tee-Object -Variable TGSEvents | Format-Table -AutoSize

$TGSEvents | ConvertTo-Json | Out-File "artifacts\kerberos_tgs_events.json"

Write-Host "`n[*] Service tickets requested — what did the account try to access:"
$TGSEvents | Group-Object ServiceName | Select-Object Name, Count |
    Sort-Object Count -Descending | Format-Table -AutoSize
```

### Splunk Correlation Query — Pass-the-Ticket Detection

```splunk
| SPL Query: Kerberos Ticket Anomaly Hunt
| Detects tickets requested from IPs inconsistent with source host

index=windows_security (EventCode=4768 OR EventCode=4769)
    TargetUserName="mthompson"
| eval EventType=if(EventCode=4768,"TGT_Request","TGS_Request")
| stats count values(ServiceName) as services_accessed
    values(IpAddress) as source_ips
    by TargetUserName, EventType
| eval unique_ip_count=mvcount(source_ips)
| where unique_ip_count > 1
| eval alert="MULTIPLE SOURCE IPS FOR SAME ACCOUNT TICKET REQUESTS"
| table TargetUserName, EventType, source_ips, services_accessed, alert
```

**✅ Checkpoint 3:** A single account requesting Kerberos tickets from
multiple distinct source IPs within a short time window is a strong Pass-
the-Ticket indicator — the ticket was extracted from one host's memory and
replayed from another.

---

## STEP 4 — Hunt DCOM and WMI Lateral Movement

**Objective:** DCOM and WMI-based lateral movement (e.g., using tools that
abuse `Win32_Process.Create` via WMI, or DCOM objects like `MMC20.Application`)
leaves distinctive process creation signatures on the target host.

```powershell
# Hunt for WMI-spawned process creation (Event 4688) — classic WMI lateral movement signature
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4688
    StartTime = (Get-Date $HuntWindowStart)
    EndTime   = (Get-Date $HuntWindowEnd)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        Time           = $_.TimeCreated
        NewProcessName = ($data | Where-Object {$_.Name -eq "NewProcessName"}).'#text'
        ParentProcess  = ($data | Where-Object {$_.Name -eq "ParentProcessName"}).'#text'
        CommandLine    = ($data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
        SubjectUser    = ($data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
    }
} | Where-Object {
    $_.ParentProcess -like "*WmiPrvSE.exe*" -or
    $_.ParentProcess -like "*mmc.exe*"
} | Tee-Object -Variable WMIExecEvents | Format-Table -AutoSize

$WMIExecEvents | ConvertTo-Json | Out-File "artifacts\wmi_dcom_execution.json"

Write-Host "`n[*] WMI/DCOM-spawned process events: $($WMIExecEvents.Count)"

# Cross-reference: was any of this activity related to our compromised account?
$RelatedActivity = $WMIExecEvents | Where-Object {
    $_.SubjectUser -like "*mthompson*" -or
    $_.CommandLine -like "*FIN-047*"
}
if ($RelatedActivity) {
    Write-Host "`n[!!!] WMI/DCOM ACTIVITY LINKED TO COMPROMISED ACCOUNT:"
    $RelatedActivity | Format-Table -AutoSize
} else {
    Write-Host "`n[+] No WMI/DCOM lateral movement linked to compromised account"
}
```

### Splunk Correlation Query — WMI/DCOM Lateral Movement

```splunk
| SPL Query: WMI/DCOM Lateral Movement Hunt

index=windows_security EventCode=4688
    ParentProcessName IN ("*WmiPrvSE.exe", "*mmc.exe")
    NewProcessName IN ("*cmd.exe", "*powershell.exe", "*rundll32.exe")
| eval hunt_window=if(_time >= strptime("2025-01-14 09:12:00","%Y-%m-%d %H:%M:%S")
    AND _time <= strptime("2025-01-16 03:30:00","%Y-%m-%d %H:%M:%S"), "IN_WINDOW", "OUTSIDE")
| where hunt_window="IN_WINDOW"
| table _time, host, SubjectUserName, ParentProcessName,
    NewProcessName, CommandLine
| sort - _time
```

---

## STEP 5 — BloodHound: Attack Path & Blast Radius Analysis

**Objective:** Even without confirmed lateral movement, you must assess
what the attacker COULD reach with the compromised credentials. BloodHound
maps Active Directory relationships to reveal privilege escalation and
lateral movement paths — critical for worst-case scope assessment.

```bash
# Run SharpHound collector (in authorized lab AD environment)
# This collects AD relationship data — group memberships, session data,
# ACLs, trust relationships — WITHOUT any exploitation

# On a domain-joined system with appropriate read access:
SharpHound.exe -c All --domain novacrest.local --outputdirectory C:\SecurityLab\Day10\artifacts

echo "[+] SharpHound collection complete — ZIP file generated"
echo "[+] Import into BloodHound GUI for analysis"
```

```
BloodHound Analysis Steps:
==========================

1. Start Neo4j database:
   neo4j console

2. Launch BloodHound GUI, connect to Neo4j (default: bolt://localhost:7687)

3. Upload the SharpHound collection ZIP file

4. Run pre-built queries:

   Query A: "Find Shortest Paths to Domain Admins"
     Mark 'mthompson' as start node
     → Reveals if compromised account has ANY path to Domain Admin
       via group nesting, ACL abuse, or session presence

   Query B: "Find Computers where user has admin rights"
     Search: mthompson
     → Shows every machine this account can log into as local admin

   Query C: "Find all Domain Admins"
     → Identify high-value targets the attacker would seek

   Query D: "Shortest path from Owned principals"
     Mark FIN-047 as "Owned" (compromised)
     → Reveals the shortest theoretical path from this foothold
       to Domain Admin — even if not yet exploited

5. Document findings in artifacts/bloodhound_analysis.md
```

```python
# Save as: bloodhound_findings_documenter.py
# Documents BloodHound analysis results in structured format

import json

# Populate with actual BloodHound query results
BLOODHOUND_FINDINGS = {
    "compromised_principal": "mthompson@novacrest.local",
    "compromised_host":      "DESKTOP-FIN-047",
    "direct_admin_rights": [
        # Hosts where mthompson has local admin — NONE expected for standard user
    ],
    "group_memberships": [
        "Domain Users",
        "Fixed Income Traders",
        "VPN Users",
    ],
    "shortest_path_to_da": {
        "path_exists": False,
        "hops": None,
        "path_detail": "No direct or nested path found from mthompson to "
                       "Domain Admins group through standard analysis. "
                       "Account is a standard domain user with no unusual "
                       "ACL grants or group nesting anomalies.",
    },
    "session_exposure": {
        "note": "BloodHound session data shows which OTHER privileged "
                "accounts had active sessions on FIN-047 historically — "
                "if a Domain Admin ever logged into FIN-047 (e.g. for "
                "IT support), their credentials would have been cached "
                "in memory and exposed to the LSASS dump (Day 08).",
        "privileged_sessions_on_host": [
            # Populate from actual BloodHound HasSession edge data
            {"account": "NOVACREST\\svc_backup", "privilege": "Backup Operators",
             "last_seen": "2025-01-10", "risk": "MEDIUM — cached during compromise window"},
        ],
    },
    "blast_radius_assessment": {
        "worst_case": "If svc_backup credentials were cached and captured by "
                      "the LSASS dump, Backup Operators group membership "
                      "grants the ability to read/write any file on domain "
                      "controllers via backup privileges — a well-known "
                      "path to Domain Admin equivalent access.",
        "confidence": "MEDIUM — requires confirmation that svc_backup "
                      "actually authenticated to FIN-047 during the "
                      "11-day compromise window (Jan 5-16), not just "
                      "historically.",
    },
}

print("=" * 65)
print("  BloodHound Attack Path Analysis — Findings Summary")
print("=" * 65)

print(f"\n  Compromised principal: {BLOODHOUND_FINDINGS['compromised_principal']}")
print(f"  Compromised host:      {BLOODHOUND_FINDINGS['compromised_host']}")

print(f"\n  Direct Admin Rights (mthompson → other hosts):")
if BLOODHOUND_FINDINGS["direct_admin_rights"]:
    for host in BLOODHOUND_FINDINGS["direct_admin_rights"]:
        print(f"    • {host}")
else:
    print(f"    None — standard user has no local admin elsewhere")

print(f"\n  Shortest Path to Domain Admin:")
sp = BLOODHOUND_FINDINGS["shortest_path_to_da"]
print(f"    Path exists: {sp['path_exists']}")
print(f"    Detail: {sp['path_detail']}")

print(f"\n  Privileged Sessions Historically Seen on {BLOODHOUND_FINDINGS['compromised_host']}:")
for sess in BLOODHOUND_FINDINGS["session_exposure"]["privileged_sessions_on_host"]:
    print(f"    ⚠ {sess['account']} ({sess['privilege']}) "
          f"— last seen {sess['last_seen']} — Risk: {sess['risk']}")

print(f"\n  BLAST RADIUS ASSESSMENT:")
print(f"    {BLOODHOUND_FINDINGS['blast_radius_assessment']['worst_case']}")
print(f"    Confidence: {BLOODHOUND_FINDINGS['blast_radius_assessment']['confidence']}")

with open("artifacts/bloodhound_analysis.json", "w") as f:
    json.dump(BLOODHOUND_FINDINGS, f, indent=2)

print(f"\n[+] Analysis saved: artifacts/bloodhound_analysis.json")
```

```bash
python3 bloodhound_findings_documenter.py | tee artifacts/bloodhound_summary.txt
```

**✅ Checkpoint 4:** The svc_backup finding is the critical output of this
step. Even if no confirmed lateral movement occurred, the THEORETICAL blast
radius through a cached privileged session is the worst-case scope the IR
team must plan remediation around.

---

## STEP 6 — Lateral Movement Hunt Playbook

```bash
cat > artifacts/lateral_movement_hunt_playbook.md << 'EOF'
# Lateral Movement Hunt Playbook
**For future incidents — reusable methodology**

---

## When to Run This Playbook

Trigger this hunt whenever:
- Credential access (LSASS dump, Mimikatz-style tooling) is confirmed on any host
- A compromised account has known privileged group membership or historical sessions
- An incident dwell time exceeds 24 hours (sufficient window for pivot attempts)

## Pre-Hunt Requirements

- [ ] Confirmed compromised account name(s)
- [ ] Confirmed compromised host(s)
- [ ] Confirmed compromise time window (start/end)
- [ ] 30-day baseline authentication data for comparison
- [ ] Splunk or equivalent SIEM access with Windows Security + Sysmon indexed
- [ ] BloodHound collection access (SharpHound run against target AD domain)

## Hunt Sequence

1. **Baseline** — Pull 30 days of Event 4624 for the compromised account.
   Document normal login destinations, times, and source hosts.

2. **Pass-the-Hash** — Query Event 4624, LogonType=3, AuthPackage=NTLM,
   within compromise window. Flag any destination NOT in baseline.

3. **Pass-the-Ticket** — Query Events 4768/4769 for the account. Flag:
   - Multiple source IPs for same account ticket requests
   - RC4 (0x17) encryption tickets (downgrade indicator)
   - TGS requests for services the account has no business reason to access

4. **DCOM/WMI Execution** — Query Event 4688 for processes spawned by
   WmiPrvSE.exe or mmc.exe. Cross-reference against compromised account.

5. **BloodHound Blast Radius** — Regardless of confirmed lateral movement,
   run BloodHound shortest-path analysis from the compromised account to
   Domain Admins. Document the theoretical worst case.

6. **Session History Check** — Use BloodHound HasSession data to identify
   ANY privileged account that historically logged into the compromised
   host — these credentials must be considered at-risk even without
   confirmed exfiltration.

## Decision Tree

```
Lateral movement CONFIRMED (positive finding in Steps 2-4)?
├── YES → Escalate to full domain compromise IR procedure
│         Isolate all affected hosts, force KRBTGT reset,
│         assume Domain Admin compromise until proven otherwise
│
└── NO  → Proceed with Step 5-6 blast radius assessment
          Rotate credentials for ANY account with historical session
          exposure on compromised host, regardless of confirmed use
          Document negative finding — still valuable intelligence
```

## Output Deliverables (every hunt, regardless of outcome)

1. Documented baseline
2. Query results for all 3 lateral movement techniques (positive or negative)
3. BloodHound blast radius assessment
4. Updated remediation scope based on findings
5. This playbook, refined with lessons learned
EOF

echo "[+] Playbook saved: artifacts/lateral_movement_hunt_playbook.md"
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What Windows Event ID indicates a Kerberos TGT request?
- [ ] 🚩 **Flag 2:** What encryption type value (hex) is associated with Kerberos ticket forgery risk?
- [ ] 🚩 **Flag 3:** What two parent processes are the classic signature of WMI/DCOM lateral movement?
- [ ] 🚩 **Flag 4:** What BloodHound edge type reveals historical privileged account logins on a compromised host?
- [ ] 🚩 **Flag 5:** In the decision tree, what AD remediation action is recommended if lateral movement is confirmed?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `baseline_auth_pattern.json` | 30-day authentication baseline for compromised account |
| `ntlm_type3_events.json` | All NTLM Type 3 logons in hunt window |
| `pth_anomalies.json` | Pass-the-Hash anomalies (if any found) |
| `kerberos_tgt_events.json` | Kerberos TGT request events |
| `kerberos_tgs_events.json` | Kerberos service ticket request events |
| `wmi_dcom_execution.json` | WMI/DCOM-spawned process events |
| `bloodhound_analysis.json` | Structured BloodHound findings |
| `bloodhound_summary.txt` | BloodHound analysis console output |
| `lateral_movement_hunt_playbook.md` | Reusable hunt methodology |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Event 4768/4769 not logging | Enable "Audit Kerberos Authentication Service" GPO |
| SharpHound flagged by AV | Expected — add exclusion in isolated lab AD only |
| Neo4j connection refused | Check Neo4j service running: `neo4j status` |
| No baseline data available | Use 7-day window minimum if 30-day unavailable — document limitation |

---

*Next: [REPORT.md](REPORT.md) — Lateral movement hunt findings report*
