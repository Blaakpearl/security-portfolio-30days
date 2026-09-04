# Day 17 — LAB.md
## Privilege Escalation Hunt Lab Setup
**NovaCrest Capital Group | Threat Hunt Week**

---

## Overview

This lab replicates the detection environment needed to hunt privilege
escalation artifacts across a mixed Windows/Linux estate. You will ingest
Sysmon and auditd telemetry into Splunk or Sentinel, then execute hunt
queries against both real and simulated log data.

---

## Windows Lab Setup (Sysmon)

### Step 1: Install Sysmon with Hunt-Grade Config

```powershell
# Download Sysmon (Sysinternals)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
    -OutFile C:\Tools\Sysmon.zip
Expand-Archive C:\Tools\Sysmon.zip -DestinationPath C:\Tools\Sysmon

# Download SwiftOnSecurity config (includes privesc coverage)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile C:\Tools\sysmonconfig.xml

# Install with config
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml

# Verify
Get-Service Sysmon64
```

### Step 2: Enable Critical Windows Security Audit Policies

```powershell
# Enable all relevant audit subcategories
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Token Right Adjusted" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Verify
auditpol /get /category:"Privilege Use"
auditpol /get /category:"Account Logon"
```

### Step 3: Simulate Privilege Escalation Artifacts (Safe Lab Only)

```powershell
# H1: Token impersonation indicator — access LSASS with non-system process
# (Safe simulation — read-only; adjust in lab VM only)
# Sysmon will log Event 10 (ProcessAccess to lsass.exe)

# H5: UAC bypass indicator — write to common UAC bypass registry key
# (Safe; no actual bypass — writes to HKCU only)
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" `
    /ve /d "cmd.exe" /f
reg add "HKCU\Software\Classes\ms-settings\shell\open\command" `
    /v "DelegateExecute" /d "" /f
# Clean up after testing:
# reg delete "HKCU\Software\Classes\ms-settings" /f

# H4: Kerberoasting simulation — request TGS for SPN
# Generates Security Event 4769 with RC4 encryption (0x17)
Add-Type -AssemblyName System.IdentityModel
$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken `
    -ArgumentList "MSSQLSvc/sqlserver.novacrest.local:1433"

# H6: Check current token privileges
whoami /priv
```

### Step 4: Forward Windows Events to Splunk

```powershell
# Install Splunk Universal Forwarder
# Download from: https://www.splunk.com/en_us/download/universal-forwarder.html

# Configure inputs.conf
$inputs = @"
[WinEventLog://Security]
disabled = false
index = wineventlog
whitelist = 4624,4625,4634,4648,4669,4672,4673,4688,4769,4771

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = sysmon
renderXml = true
"@
$inputs | Out-File "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"

Restart-Service SplunkForwarder
```

---

## Linux Lab Setup (auditd)

### Step 1: Install and Configure auditd

```bash
# Install auditd
sudo apt-get install -y auditd audispd-plugins

# Deploy privilege escalation hunt rules
sudo tee /etc/audit/rules.d/privesc-hunt.rules << 'EOF'
# Execution of sudo
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k sudo_exec
-a always,exit -F arch=b32 -S execve -F path=/usr/bin/sudo -k sudo_exec

# SUID/SGID binary execution
-a always,exit -F arch=b64 -S execve -F perm=u+s -k suid_exec
-a always,exit -F arch=b32 -S execve -F perm=u+s -k suid_exec

# Privilege escalation via setuid/setgid syscalls
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privesc_syscall
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privesc_syscall

# Writing to /etc/passwd, /etc/shadow, /etc/sudoers
-w /etc/passwd -p wa -k sensitive_file_write
-w /etc/shadow -p wa -k sensitive_file_write
-w /etc/sudoers -p wa -k sensitive_file_write
-w /etc/sudoers.d/ -p wa -k sensitive_file_write

# Cron jobs (persistence via cron; often accompanies privesc)
-w /var/spool/cron/ -p wa -k cron_write
-w /etc/cron.d/ -p wa -k cron_write

# SSH authorized_keys modification
-w /root/.ssh/ -p wa -k root_ssh_write
EOF

# Load rules and restart
sudo augenrules --load
sudo systemctl restart auditd
sudo auditctl -l  # Verify rules loaded
```

### Step 2: Simulate Linux Privilege Escalation Artifacts (Lab Only)

```bash
# H2: Sudo abuse simulation
# Check sudo rules (attacker enumeration step — auditd logs this)
sudo -l

# H3: SUID binary discovery (attacker enumeration)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null  # SGID

# H2: Abuse NOPASSWD sudo rule (if misconfigured in lab)
# Lab setup: add misconfigured rule to /etc/sudoers.d/lab-test:
# echo "labuser ALL=(ALL) NOPASSWD: /usr/bin/find" | sudo tee /etc/sudoers.d/lab-test
# Then execute privilege escalation via GTFOBins:
# sudo find . -exec /bin/bash \; -quit  # Spawns root shell

# H3: SUID GTFOBin (if present in lab)
# Example with python3 if SUID set (lab only):
# chmod u+s /usr/bin/python3  # Set SUID (lab only)
# python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Step 3: Forward auditd to Splunk

```bash
# Install Splunk Universal Forwarder for Linux
wget -O splunk-uf.tgz "https://download.splunk.com/products/universalforwarder/releases/9.2.0/linux/splunkforwarder-9.2.0-Linux-x86_64.tgz"
tar xvzf splunk-uf.tgz -C /opt

# Configure to forward auditd logs
cat >> /opt/splunkforwarder/etc/system/local/inputs.conf << 'EOF'
[monitor:///var/log/audit/audit.log]
index = linux_audit
sourcetype = linux_auditd

[monitor:///var/log/auth.log]
index = linux_auth
sourcetype = syslog
EOF

/opt/splunkforwarder/bin/splunk start --accept-license
```

---

## Generating Sample Hunt Data

```bash
# Run the hunt simulator to generate synthetic log events
python3 scripts/privilege_escalation_hunter.py --generate-logs --output /tmp/hunt-logs/

# Run the SUID scanner against the local filesystem
python3 scripts/suid_audit_scanner.py --scan / --report /tmp/suid-report.json

# Load synthetic logs into Splunk via HEC
HEC_TOKEN="your-hec-token"
for f in /tmp/hunt-logs/*.json; do
    curl -k -H "Authorization: Splunk $HEC_TOKEN" \
         -H "Content-Type: application/json" \
         -d @$f \
         https://localhost:8088/services/collector/event
done
```

---

## Hunt Validation Checklist

After lab setup, verify each hunt query returns expected results:

```
□ SPL Query 1 (Token Impersonation): Returns LSASS access from j.henderson process
□ SPL Query 2 (Special Privileges at Logon): Returns SeDebugPrivilege assignment
□ SPL Query 3 (Kerberoasting): Returns RC4 TGS requests (0x17 encryption)
□ SPL Query 4 (UAC Registry Bypass): Returns ms-settings key write
□ SPL Query 5 (UAC Bypass Process Chain): Returns fodhelper → cmd parent-child
□ SPL Query 6 (Sudo Abuse): Returns sudo execution by non-admin user
□ SPL Query 7 (SUID Execution): Returns known GTFOBin execution
□ SPL Query 8 (setuid Syscall): Returns privilege syscall from unexpected process
□ KQL equivalents: Mirror SPL coverage across all 8 hypotheses
```

---

*Day 17 Lab Guide | Threat Hunt: Privilege Escalation*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
