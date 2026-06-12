---
title: "Active Directory Incident Response & Hardening"
description: "Complete AD IR playbook: post-incident investigation checklist, remediation procedures (krbtgt double reset, privilege cleanup, GPO audit), and hardening best practices from a Microsoft expert perspective."
date: "2026-06-12 10:30"
category: "Active Directory"
tags:
  - Active Directory
  - Incident Response
  - Hardening
  - Threat Hunting
  - Blue Team
published: true
archived: false
pinned: true
featured: false
author: "Luca Manfrin"
readingTime: true
---

## Overview

This post is a field reference for Active Directory incident response and hardening. It covers three phases:

1. **Investigation** — what to collect and examine after a suspected AD compromise
2. **Remediation** — the specific actions required to evict an attacker and restore integrity
3. **Hardening** — the structural changes that prevent recurrence

Every command is tested against Windows Server 2016+ and Windows 10/11 domain environments. Where something has a known compatibility caveat or gotcha, it is called out explicitly.

---

## Part 1: Post-Incident Investigation Checklist

The goal of the investigation phase is to understand **blast radius**: what was compromised, what accounts have been touched, and what persistence mechanisms may have been planted.

Run everything below from a clean, trusted machine — ideally a Privileged Access Workstation (PAW) with a freshly provisioned, domain-joined account created specifically for the investigation.

### 1.1 — Domain Functional Level and Schema Version

The domain and forest functional level (DFL/FFL) determines which security features are available. A low functional level is both a risk indicator and a technical constraint.

```powershell
# Domain and Forest functional level
Get-ADDomain  | Select-Object Name, DomainMode, DomainSID
Get-ADForest  | Select-Object Name, ForestMode, RootDomain, Domains, GlobalCatalogs

# Schema version (maps to OS versions — useful to understand what security features exist)
$schemaDN = (Get-ADForest).SchemaNamingContext
(Get-ADObject $schemaDN -Properties objectVersion).objectVersion
# Common values: 44=2003, 47=2008, 56=2012, 69=2016, 87=2019, 88=2022
```

Ideally: Windows Server 2016 DFL or higher, to support Protected Users Group features and Kerberos Armoring (FAST).

### 1.2 — Domain Admin Enumeration

```powershell
# All members of Domain Admins (recursive — catches nested group membership)
Get-ADGroupMember 'Domain Admins' -Recursive |
  Select-Object SamAccountName, objectClass, DistinguishedName |
  Sort-Object objectClass, SamAccountName

# Other privileged groups to audit
$privilegedGroups = @(
  'Domain Admins',
  'Enterprise Admins',
  'Schema Admins',
  'Administrators',
  'Account Operators',
  'Backup Operators',
  'Server Operators',
  'Print Operators',
  'Group Policy Creator Owners',
  'Dns Admins',         # can load arbitrary DLL on DC via DNS service
  'DHCP Administrators',
  'Remote Management Users',
  'Protected Users'
)

foreach ($group in $privilegedGroups) {
  $members = Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue
  if ($members) {
    Write-Host "`n=== $group ===`n"
    $members | Select-Object SamAccountName, objectClass | Format-Table -AutoSize
  }
}
```

> [!WARNING]
> **DnsAdmins** is frequently overlooked. Any member of DnsAdmins can execute arbitrary code on a DC by loading a malicious DLL via the DNS service. This is a Tier 0 equivalent privilege. Audit it every time.

### 1.3 — Accounts with AdminCount = 1

`AdminCount = 1` is set automatically by the SDProp process on accounts that are (or ever were) members of protected groups. It means the SDProp process took ownership of the ACL. Many organizations have ghost accounts with AdminCount=1 from long-removed group memberships — attackers know this and look for them.

```powershell
# All user accounts with AdminCount=1
Get-ADUser -Filter { AdminCount -eq 1 } `
  -Properties AdminCount, Enabled, PasswordLastSet, MemberOf, LastLogonDate |
  Select-Object SamAccountName, Enabled, PasswordLastSet, LastLogonDate,
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    } |
  Sort-Object LastLogonDate -Descending

# Compare: accounts with AdminCount=1 but NOT in any privileged group
# These are ghost accounts with lingering elevated ACLs
$currentPrivMembers = foreach ($g in $privilegedGroups) {
  Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty SamAccountName
}

Get-ADUser -Filter { AdminCount -eq 1 } | Where-Object {
  $_.SamAccountName -notin $currentPrivMembers
} | Select-Object SamAccountName, DistinguishedName
```

### 1.4 — Accounts with Sensitive Privileges

```powershell
# Accounts with "Password Not Required" flag (PASSWD_NOTREQD, UAC bit 0x20)
Get-ADUser -Filter { PasswordNotRequired -eq $true } `
  -Properties PasswordNotRequired, Enabled, PasswordLastSet |
  Select-Object SamAccountName, Enabled, PasswordLastSet

# Accounts with passwords that never expire
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
  -Properties PasswordNeverExpires, PasswordLastSet, MemberOf |
  Select-Object SamAccountName, PasswordLastSet,
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    } |
  Sort-Object PasswordLastSet

# Accounts with preauthentication disabled (AS-REP Roasting target)
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
  -Properties DoesNotRequirePreAuth, Enabled, PasswordLastSet |
  Select-Object SamAccountName, Enabled, PasswordLastSet

# Accounts allowed to delegate (unconstrained delegation — very dangerous)
Get-ADUser -Filter { TrustedForDelegation -eq $true } `
  -Properties TrustedForDelegation, ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName

Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
  -Properties TrustedForDelegation |
  Select-Object Name, DistinguishedName

# Accounts with constrained delegation
Get-ADUser -Filter { TrustedToAuthForDelegation -eq $true } `
  -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo |
  Select-Object SamAccountName, 'msDS-AllowedToDelegateTo'
```

> [!IMPORTANT]
> **Unconstrained delegation** (`TrustedForDelegation = $true`) is extremely dangerous. Any computer or user with unconstrained delegation can receive and reuse TGTs from connecting users. If a DC connects to a service running on an unconstrained delegation host, the DC's krbtgt-signed TGT is cached there. DCs should never connect to servers with unconstrained delegation — yet this is common in many environments.

### 1.5 — Accounts with Non-Empty Description Fields

Attackers look for password hints or sensitive information stored in the Description attribute. This is embarrassingly common.

```powershell
# Find users with non-empty descriptions
Get-ADUser -Filter { Description -like "*" } `
  -Properties Description, Enabled, PasswordLastSet |
  Select-Object SamAccountName, Enabled, PasswordLastSet, Description |
  Where-Object { $_.Description -ne $null -and $_.Description -ne '' }
```

Look specifically for:
- `Password123`, `Summer2024!`, `Welcome1` — literal passwords
- `Admin account for X` — service role descriptions that hint at privilege
- IP addresses, server names, connection strings

### 1.6 — Service Principal Names (Kerberoasting Surface)

```powershell
# All kerberoastable accounts with password age and group membership
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires,
              AdminCount, Enabled, Description, MemberOf |
  Select-Object SamAccountName, Enabled, AdminCount, Description, PasswordLastSet,
    PasswordNeverExpires,
    @{ n = 'PasswordAgeDays'; e = {
        if ($_.PasswordLastSet) {
          [int](((Get-Date) - $_.PasswordLastSet).TotalDays)
        } else { 99999 }
      }
    },
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    },
    @{ n = 'SPN'; e = { $_.ServicePrincipalName -join ' | ' } } |
  Sort-Object PasswordAgeDays -Descending

# Any SPN-bearing account in a privileged group = critical risk
# (already covered in 1.3 cross-reference — repeat here for clarity)
```

### 1.7 — Orphan SIDs and Stale Objects

Orphan SIDs appear in group memberships when the referenced account has been deleted. They can indicate lateral cleanup by an attacker who deleted their account but left SID artifacts.

```powershell
# Find groups with member SIDs that don't resolve to valid objects
Get-ADGroup -Filter * -Properties Members |
  ForEach-Object {
    $group = $_
    foreach ($member in $group.Members) {
      try {
        Get-ADObject -Identity $member -ErrorAction Stop | Out-Null
      } catch {
        [PSCustomObject]@{
          Group     = $group.SamAccountName
          OrphanDN  = $member
          Error     = $_.Exception.Message
        }
      }
    }
  }

# Find disabled accounts that still have group memberships (common cleanup gap)
Get-ADUser -Filter { Enabled -eq $false } -Properties MemberOf |
  Where-Object { $_.MemberOf.Count -gt 0 } |
  Select-Object SamAccountName,
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    }

# Find computer accounts that haven't logged in for 90+ days (stale, zombie machines)
$staleDate = (Get-Date).AddDays(-90)
Get-ADComputer -Filter { LastLogonDate -lt $staleDate -and Enabled -eq $true } `
  -Properties LastLogonDate |
  Select-Object Name, LastLogonDate |
  Sort-Object LastLogonDate
```

### 1.8 — ACL Analysis (Delegation and Backdoors)

Attackers frequently plant ACL backdoors — granting themselves or a controlled account persistent rights over privileged objects without being group members.

```powershell
# Check ACLs on the domain object itself (DCSync, GPO link manipulation)
$domainDN = (Get-ADDomain).DistinguishedName
(Get-ACL "AD:\$domainDN").Access |
  Where-Object {
    $_.IdentityReference -notmatch 'Domain Controllers|Enterprise Domain Controllers|' +
                                    'Administrators|System|Creator Owner|ENTERPRISE ADMINS|' +
                                    'MSOL_|AADConnect|ADFS'
  } | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
  Sort-Object IdentityReference

# Check ACLs on privileged groups (Domain Admins, etc.)
foreach ($group in @('Domain Admins','Enterprise Admins','krbtgt')) {
  $dn = (Get-ADGroup $group -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty DistinguishedName)
  if (-not $dn) {
    $dn = (Get-ADUser $group -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty DistinguishedName)
  }
  if ($dn) {
    Write-Host "`n=== ACL on $group ===`n"
    (Get-ACL "AD:\$dn").Access |
      Where-Object { $_.IdentityReference -notmatch 'System|Administrators|Domain Admins|CREATOR' } |
      Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType |
      Format-Table -AutoSize
  }
}

# BloodHound-style: find all objects where a specific account has WriteDACL, WriteOwner,
# GenericAll, or GenericWrite
# Best done via BloodHound + SharpHound — native PowerShell is slow at scale
```

> [!TIP]
> **BloodHound** (with the SharpHound collector) is the most effective tool for mapping ACL attack paths. Run it as part of every AD IR to visualize the full privilege graph — manual ACL review misses chained delegation paths.

### 1.9 — Recently Modified GPOs

Attackers modify GPOs to push persistence (scheduled tasks, logon scripts, registry keys, user rights assignments):

```powershell
# GPOs modified in the last 30 days
$cutoff = (Get-Date).AddDays(-30)
Get-GPO -All | Where-Object { $_.ModificationTime -gt $cutoff } |
  Select-Object DisplayName, Id, ModificationTime, GpoStatus |
  Sort-Object ModificationTime -Descending

# Dump GPO settings for any recently modified GPO
$suspectGPO = "Default Domain Policy"   # replace with flagged GPO name
Get-GPOReport -Name $suspectGPO -ReportType HTML -Path "C:\Temp\$suspectGPO.html"
```

### 1.10 — Recently Modified AD Objects

```powershell
# All AD objects (users, groups, computers, GPOs) modified in the last 7 days
$cutoff = (Get-Date).AddDays(-7)
Get-ADObject -Filter { WhenChanged -gt $cutoff } `
  -Properties WhenChanged, WhenCreated, ObjectClass, Description |
  Select-Object Name, ObjectClass, WhenChanged, WhenCreated, DistinguishedName |
  Sort-Object WhenChanged -Descending

# New accounts created in last 30 days — look for rogue accounts
Get-ADUser -Filter { WhenCreated -gt $cutoff } `
  -Properties WhenCreated, Enabled, MemberOf, AdminCount |
  Select-Object SamAccountName, Enabled, WhenCreated, AdminCount,
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    }
```

### 1.11 — krbtgt Account Status

```powershell
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, PasswordNeverExpires,
  WhenCreated, Enabled, SID |
  Select-Object SamAccountName, Enabled, PasswordLastSet, PasswordNeverExpires,
    WhenCreated, SID

$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet, WhenCreated
$daysSinceCreation = [int](((Get-Date) - $krbtgt.WhenCreated).TotalDays)
$daysSinceReset    = [int](((Get-Date) - $krbtgt.PasswordLastSet).TotalDays)
Write-Host "krbtgt: domain created $daysSinceCreation days ago | password last changed $daysSinceReset days ago"
# If daysSinceReset ≈ daysSinceCreation → krbtgt has NEVER been rotated
```

### 1.12 — Domain Trusts

```powershell
# Enumerate all trusts — each trust is a potential lateral movement path
Get-ADTrust -Filter * |
  Select-Object Name, TrustType, TrustDirection, TrustAttributes, IntraForest

# TrustDirection: BiDirectional is highest risk
# TrustAttributes check:
# 0x8  = FOREST_TRANSITIVE (cross-forest, high value)
# 0x20 = WITHIN_FOREST (intra-forest, parent/child)
# 0x40 = TREAT_AS_EXTERNAL (quarantine)
```

### 1.13 — Security Event Log Health

```powershell
# Verify audit policy is configured correctly on all DCs
auditpol /get /category:* | Select-String "Account Logon|Logon|DS Access|Privilege Use|Policy"

# Check max event log size and retention
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, RecordCount

# Check if logs have been cleared recently (Event ID 1102 = security log cleared, 104 = system)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -MaxEvents 20 |
  Select-Object TimeCreated, Message

Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -MaxEvents 20 |
  Select-Object TimeCreated, Message
```

---

## Part 2: Remediation Procedures

### 2.1 — krbtgt Double Password Reset

This is the single most important remediation action after a domain compromise. It invalidates all outstanding Golden Tickets and forces all users to reauthenticate.

**Why two resets?**
The KDC maintains the current AND previous krbtgt password. TGTs encrypted with either are accepted until `MaxTicketAge` expires. One reset makes the old key the "previous" key (still valid). The second reset removes the "previous" key, invalidating all tickets signed with the old material.

**Impact**: All authenticated sessions expire. Users will need to log out and back in. Some applications and services with long-lived tickets may break until they reauthenticate.

```powershell
# Step 0: Document current krbtgt state before touching anything
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
$beforeHash = (Get-ADUser krbtgt -Properties 'msDS-KeyVersionNumber').'msDS-KeyVersionNumber'
Write-Host "krbtgt KVNO before Phase 1: $beforeHash"

# Use Microsoft's official rotation script
# Download: https://github.com/microsoft/New-KrbtgtKeys.ps1

# Step 1: Simulation — verify no issues before executing
.\New-KrbtgtKeys.ps1 -Mode Simulation -Scope AllDCsInForest

# Step 2: Phase 1 rotation — execute during change window
.\New-KrbtgtKeys.ps1 -Mode Reset -Scope AllDCsInForest

# Verify Phase 1 completed on all DCs
.\New-KrbtgtKeys.ps1 -Mode Audit -Scope AllDCsInForest

# !! WAIT: minimum 10 hours (default MaxTicketAge) before Phase 2 !!
# Communicate: users may need to reauthenticate
# Monitor for service disruptions during this window

# Step 3: Phase 2 rotation — 10+ hours after Phase 1
.\New-KrbtgtKeys.ps1 -Mode Reset -Scope AllDCsInForest

$afterHash = (Get-ADUser krbtgt -Properties 'msDS-KeyVersionNumber').'msDS-KeyVersionNumber'
Write-Host "krbtgt KVNO after Phase 2: $afterHash"
# KVNO should have incremented by 2
```

> [!WARNING]
> If you have RODC (Read-Only Domain Controllers), each RODC has its own krbtgt account (e.g., `krbtgt_12345`). These must also be rotated separately. The New-KrbtgtKeys.ps1 script handles this with `-Scope AllDCsInForest`.

### 2.2 — Domain Admin and Privileged Account Password Resets

After a compromise, assume all credentials for privileged accounts are known to the attacker.

```powershell
# Reset ALL Domain Admin passwords
$newPassword = Read-Host "New password for all DA accounts" -AsSecureString

Get-ADGroupMember 'Domain Admins' -Recursive |
  Where-Object { $_.objectClass -eq 'user' } |
  ForEach-Object {
    Set-ADAccountPassword -Identity $_.SamAccountName `
      -NewPassword $newPassword -Reset
    Set-ADUser -Identity $_.SamAccountName -ChangePasswordAtLogon $true
    Write-Output "Reset: $($_.SamAccountName)"
  }

# Repeat for: Enterprise Admins, Schema Admins, Administrators (local on DCs)
foreach ($group in @('Enterprise Admins','Schema Admins')) {
  Get-ADGroupMember $group -Recursive |
    Where-Object { $_.objectClass -eq 'user' } |
    ForEach-Object {
      Set-ADAccountPassword -Identity $_.SamAccountName `
        -NewPassword $newPassword -Reset
      Write-Output "Reset: $($_.SamAccountName)"
    }
}
```

### 2.3 — Reset All Domain User Passwords (Full Compromise Scenario)

If the NTDS.dit was extracted (all hashes compromised), every domain user password must be reset:

```powershell
# Reset all enabled user accounts — this is a major operational event
# Notify users, prepare helpdesk, plan for a full reauthentication wave

$allUsers = Get-ADUser -Filter { Enabled -eq $true } |
  Where-Object { $_.SamAccountName -ne 'krbtgt' }

foreach ($user in $allUsers) {
  # Option 1: Set a temporary password and force change at next logon
  $tempPwd = ConvertTo-SecureString "Temp$(Get-Random -Minimum 1000 -Maximum 9999)!Change" `
    -AsPlainText -Force
  Set-ADAccountPassword -Identity $user -NewPassword $tempPwd -Reset
  Set-ADUser -Identity $user -ChangePasswordAtLogon $true
}

Write-Host "Reset $($allUsers.Count) user accounts"
```

> [!IMPORTANT]
> Before bulk-resetting all user passwords: notify management, HR, and helpdesk. Prepare for an influx of locked-out calls. Consider staggering the reset by OU (workstations first, then servers, then privileged accounts). Have out-of-band communication ready for users who cannot receive their new credentials.

### 2.4 — Service Account Password Rotation

```powershell
# Identify service accounts (SPN-bearing)
$svcAccounts = Get-ADUser -Filter { ServicePrincipalName -ne "$null" } |
  Where-Object { $_.SamAccountName -ne 'krbtgt' }

# Coordinate with application owners before resetting
# Service account resets require updating the password in the application/service config

foreach ($svc in $svcAccounts) {
  Write-Output "Needs rotation: $($svc.SamAccountName) | SPN: $($svc.ServicePrincipalName -join ', ')"
}

# For each one, after coordinating with the app team:
Set-ADAccountPassword -Identity "svc_sql" `
  -NewPassword (ConvertTo-SecureString "NewSecure!P@ssw0rd2026" -AsPlainText -Force) -Reset
```

### 2.5 — NTLM Hash Invalidation for Local Accounts

LAPS should be deployed for machine-specific password management, but existing local account passwords must be rotated:

```powershell
# If LAPS is deployed — force immediate rotation on all machines
Get-ADComputer -Filter * | ForEach-Object {
  # Trigger LAPS password rotation via registry flag
  Set-ItemProperty `
    -Path "\\$($_.Name)\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" `
    -Name "LastPolicyTime" -Value 0
}

# Or use Windows LAPS cmdlet
Get-LapsADPassword -Identity "WORKSTATION01" -AsPlainText
Reset-LapsPassword -Identity "WORKSTATION01"
```

### 2.6 — GPO Audit and Remediation

```powershell
# 1. Export and review all recently modified GPOs
$cutoff = (Get-Date).AddDays(-30)
$modifiedGPOs = Get-GPO -All | Where-Object { $_.ModificationTime -gt $cutoff }

foreach ($gpo in $modifiedGPOs) {
  $path = "C:\GPOAudit\$($gpo.DisplayName -replace '[\\/:*?"<>|]','_').html"
  Get-GPOReport -Guid $gpo.Id -ReportType HTML -Path $path
  Write-Output "Exported: $($gpo.DisplayName) → $path"
}

# 2. Look for suspicious settings in GPO XML
# Startup/shutdown scripts, logon scripts, scheduled tasks in GPOs
Get-GPO -All | ForEach-Object {
  $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($_.Id)}"
  Get-ChildItem -Path $gpoPath -Recurse -Include "*.xml" -ErrorAction SilentlyContinue |
    Select-String "ScheduledTasks|Scripts|Services" |
    Where-Object { $_ } |
    ForEach-Object {
      Write-Output "Check GPO $($_.Filename): $($_.Line)"
    }
}

# 3. Check SYSVOL for rogue scripts
Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse `
  -Include "*.ps1","*.vbs","*.bat","*.cmd","*.exe" `
  -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime, Length |
  Sort-Object LastWriteTime -Descending
```

### 2.7 — Revoke Suspicious ACL Permissions

```powershell
# Remove DCSync rights from non-DC accounts on the domain NC
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-ACL -Path "AD:\$domainDN"

$replicationGUIDs = @(
  '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',  # DS-Replication-Get-Changes-All
  '89e95b76-444d-4c62-991a-0facbeda640c'   # DS-Replication-Get-Changes-In-Filtered-Set
)

$legitPrincipals = @(
  'NT AUTHORITY\SYSTEM',
  'DOMAIN\Domain Controllers',
  'DOMAIN\Enterprise Domain Controllers',
  'DOMAIN\Administrators',
  'DOMAIN\MSOL_*',
  'DOMAIN\AADConnect*'
)

$acl.Access | Where-Object {
  $_.ObjectType -in $replicationGUIDs -and
  $_.AccessControlType -eq 'Allow' -and
  $legitPrincipals -notcontains $_.IdentityReference.Value
} | ForEach-Object {
  Write-Warning "Suspicious DCSync ACE: $($_.IdentityReference)"
  # $acl.RemoveAccessRule($_)  # uncomment after review
}
```

### 2.8 — Remove Rogue Accounts and Unauthorized Group Members

```powershell
# Review and remove unrecognized accounts from privileged groups
$domainAdmins = Get-ADGroupMember 'Domain Admins' | Select-Object SamAccountName

# Present the list — remove any that are not authorized
foreach ($member in $domainAdmins) {
  $confirm = Read-Host "Is $($member.SamAccountName) authorized in Domain Admins? [y/n]"
  if ($confirm -eq 'n') {
    Remove-ADGroupMember -Identity 'Domain Admins' -Members $member.SamAccountName -Confirm:$false
    Write-Warning "REMOVED from Domain Admins: $($member.SamAccountName)"
  }
}

# Disable or delete rogue accounts
Disable-ADAccount -Identity "suspicioususer"
# Or permanently delete (only after forensic preservation)
Remove-ADUser -Identity "suspicioususer" -Confirm:$false
```

### 2.9 — Check and Remediate Unconstrained Delegation

```powershell
# Remove unconstrained delegation from user accounts
Get-ADUser -Filter { TrustedForDelegation -eq $true } |
  ForEach-Object {
    Write-Warning "Removing unconstrained delegation from: $($_.SamAccountName)"
    Set-ADAccountControl $_ -TrustedForDelegation $false
  }

# For computer accounts — requires application owner coordination
Get-ADComputer -Filter { TrustedForDelegation -eq $true } |
  Where-Object { $_.Name -notmatch 'DC\d+|EXCHANGE|LYNC' } |  # adjust exclusions
  Select-Object Name, DistinguishedName
```

---

## Part 3: Hardening Best Practices

### 3.1 — Migrate Service Accounts to gMSA

Group Managed Service Accounts eliminate the service account password management problem entirely. The password is 240 characters, randomly generated, and automatically rotated.

```powershell
# Prerequisites
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))  # production-safe (wait propagation)
# or
Add-KdsRootKey -EffectiveImmediately  # lab only

# Create gMSA
New-ADServiceAccount `
  -Name "gmsa_iis" `
  -DNSHostName "webserver.domain.local" `
  -ServicePrincipalNames "HTTP/webserver.domain.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "WebServers_Group"

# On the target server
Install-ADServiceAccount -Identity "gmsa_iis"
Test-ADServiceAccount   -Identity "gmsa_iis"

# Configure IIS app pool to use gMSA
# In IIS Manager: Application Pools → Identity → Custom Account → DOMAIN\gmsa_iis$
# Leave password blank
```

### 3.2 — Implement Microsoft Tiering Model (PAW)

The Tier model separates administrative credentials so that Tier 0 credentials (Domain Admin, DC admin) never touch Tier 1 or Tier 2 machines.

| Tier | Scope | Examples |
|---|---|---|
| Tier 0 | AD Control Plane | DCs, ADCS, AAD Connect, ADFS |
| Tier 1 | Server Workloads | Member servers, applications |
| Tier 2 | User Workstations | Laptops, desktops |

```powershell
# Enforce via GPO: prevent Tier 0 accounts from logging onto Tier 1/2 machines
# Apply to all non-PAW computers OU:
# Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → User Rights Assignment:
#   "Deny log on locally" → Add: Domain Admins, Enterprise Admins
#   "Deny log on through Remote Desktop Services" → Add: same groups

# Enforce via GPO: prevent Tier 0 accounts from authenticating to Tier 1/2 via network
# "Deny access to this computer from the network" → Domain Admins

# Create separate admin accounts for each tier
# T0Admin_Username — only usable on DCs/PAWs (Tier 0)
# T1Admin_Username — only usable on servers (Tier 1)
# T2Admin_Username — only usable on workstations (Tier 2)
```

### 3.3 — Enable Protected Users for All Tier 0 Accounts

```powershell
# Add all privileged accounts to Protected Users
$tier0Groups = @('Domain Admins','Enterprise Admins','Schema Admins')

foreach ($group in $tier0Groups) {
  Get-ADGroupMember $group -Recursive |
    Where-Object { $_.objectClass -eq 'user' } |
    ForEach-Object {
      Add-ADGroupMember -Identity 'Protected Users' -Members $_
      Write-Output "Added to Protected Users: $($_.SamAccountName)"
    }
}
```

**Protected Users enforces:**
- No NTLM authentication
- No DES or RC4 Kerberos
- No credential caching
- TGT lifetime: 4 hours, no renewal

> [!WARNING]
> Service accounts using NTLM, any account that needs NTLM authentication, and accounts that use DES/RC4-dependent applications must NOT be added to Protected Users. Test each account individually before bulk-adding.

### 3.4 — Disable RC4 / Enforce AES Kerberos

```powershell
# Enforce AES on all service accounts (prioritize kerberoastable accounts)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } |
  ForEach-Object {
    Set-ADUser $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }  # AES128+AES256
  }

# Domain-wide via GPO:
# Computer Configuration → Windows Settings → Security Settings →
#   Account Policies → Kerberos Policy →
#   Configure encryption types allowed for Kerberos:
#   ✅ AES128_HMAC_SHA1
#   ✅ AES256_HMAC_SHA1
#   ❌ RC4_HMAC_MD5
#   ❌ DES_CBC_CRC
#   ❌ DES_CBC_MD5

# Check which accounts still support RC4 only
Get-ADUser -Filter * -Properties 'msDS-SupportedEncryptionTypes' |
  Where-Object { $_.'msDS-SupportedEncryptionTypes' -eq 0 -or
                 $_.'msDS-SupportedEncryptionTypes' -eq $null } |
  Select-Object SamAccountName, 'msDS-SupportedEncryptionTypes'
```

### 3.5 — Enable Microsoft Entra Password Protection (formerly Azure AD Password Protection)

Entra Password Protection prevents the use of known-weak passwords and organization-specific banned terms, even in on-premises AD.

```powershell
# Deploy the proxy service on member servers (not DCs)
# Then deploy the DC agent on all DCs

# Install DC agent (on each DC)
Install-Module -Name AzureADPasswordProtection -Force
Register-AzureADPasswordProtectionAgent

# Configure via Azure portal:
# Microsoft Entra ID → Security → Authentication Methods → Password Protection
# Set: Enable password protection on Windows Server Active Directory → Yes
# Set: Mode → Enforced (after testing in Audit mode)
# Add custom banned password list (company name variants, common local terms)
```

### 3.6 — Deploy LAPS for All Machines

```powershell
# Windows LAPS (built into Windows 11 22H2+ / Server 2022+)
Update-LapsADSchema

# Set permissions for target OUs
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=domain,DC=local"
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=domain,DC=local"

# Configure via GPO:
# Computer Configuration → Administrative Templates → System → LAPS
# - Enable local admin password management → Enabled
# - Configure password backup directory → Active Directory
# - Password Settings: Length=20, Complexity=Large+Small+Numbers+Special
# - Maximum password age → 30 days

# Verify deployment
Get-ADComputer -Filter * -Properties msLAPS-Password, msLAPS-PasswordExpirationTime |
  Where-Object { -not $_.msLAPS-Password } |
  Select-Object Name   # machines not yet reporting LAPS passwords
```

### 3.7 — Audit Policy — Enable All Relevant Categories

```powershell
# Configure comprehensive audit policy via auditpol
# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# DS Access
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Verify
auditpol /get /category:*
```

### 3.8 — Sysmon Deployment on All Machines

Sysmon provides process creation, network connection, LSASS access, and file creation telemetry that native Windows audit logs do not.

```powershell
# Deploy Sysmon with a community-maintained config
# Reference config: https://github.com/SwiftOnSecurity/sysmon-config
.\sysmon64.exe -accepteula -i sysmonconfig-export.xml

# Update Sysmon config
.\sysmon64.exe -c sysmonconfig-export.xml

# Verify
Get-Service Sysmon64
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} -MaxEvents 5
```

### 3.9 — Disable WDigest Credential Caching

WDigest stores plaintext credentials in LSASS memory on older systems. It should be disabled everywhere:

```powershell
# Disable WDigest
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -Name "UseLogonCredential" -Value 0 -Type DWord

# Via GPO:
# Computer Configuration → Windows Settings → Security Settings →
#   Registry →
#   HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
#   Value: 0

# Verify on all machines
Invoke-Command -ComputerName (Get-ADComputer -Filter *).Name -ScriptBlock {
  Get-ItemPropertyValue `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -ErrorAction SilentlyContinue
}
```

### 3.10 — Enable LSA Protection and Credential Guard

```powershell
# LSA Protection (PPL)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1 -Type DWord

# Credential Guard (requires UEFI + Secure Boot + VT-x)
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LsaCfgFlags" -Value 2 -Type DWord  # 2 = enabled with UEFI lock

# Deploy via GPO:
# Computer Configuration → Administrative Templates → System → Device Guard →
#   Turn On Virtualization Based Security:
#   Select Platform Security Level: Secure Boot and DMA Protection
#   Virtualization Based Protection of Code Integrity: Enabled with UEFI lock
#   Credential Guard Configuration: Enabled with UEFI lock
```

### 3.11 — Restrict NTLM

```powershell
# Phase 1: Enable NTLM auditing (do not block yet)
# Group Policy: Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → Security Options:
#   "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" → Audit All
#   "Network security: Restrict NTLM: Audit NTLM authentication in this domain" → Enable All

# Review NTLM usage after 30 days of auditing
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 8004
} | Group-Object { $_.Properties[2].Value } |
  Sort-Object Count -Descending |
  Select-Object -First 20 Name, Count

# Phase 2: After remediating NTLM-dependent apps, restrict:
# "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers" → Deny All
# (Apply to workstation OU GPO first, then server OU)
```

### 3.12 — Enable Kerberos Armoring (FAST)

Kerberos Flexible Authentication Secure Tunneling (FAST) protects the AS-REQ exchange from interception and tampering. Requires Windows Server 2012+ DFL.

```powershell
# Enable via GPO:
# Computer Configuration → Administrative Templates → System → KDC →
#   KDC support for claims, compound authentication and Kerberos armoring → Enabled
#   Options: Supported or Required

# Client-side:
# Computer Configuration → Administrative Templates → System → Kerberos →
#   Support Compound Authentication → Enabled (Automatic)
#   Kerberos client support for claims, compound authentication and Kerberos armoring → Enabled
```

### 3.13 — Deploy Microsoft Defender for Identity

MDI is the definitive detection tool for Golden Ticket, DCSync, Pass-the-Hash, Pass-the-Ticket, and reconnaissance attacks.

```powershell
# Install MDI sensor on every DC, ADCS server, ADFS server
# Download from Microsoft 365 Defender portal: Settings → Identities → Sensors

# Post-install health check
Get-Service -Name "AATPSensor" -ComputerName dc01.domain.local

# Configure in the portal:
# - Add sensitive groups (custom to your environment)
# - Configure honeytoken accounts (accounts that should never log on)
# - Set entity tags for sensitive accounts/computers/groups
```

---

## Conclusion

AD incident response is a race: the attacker is counting on you not knowing the blast radius, and remediation actions like krbtgt rotation disrupt their persistence. The investigation checklist above should be executable in the first 2-4 hours of an IR. Remediation follows in priority order: krbtgt rotation first (neutralizes Golden Tickets), then privileged account resets, then service accounts. Hardening closes the gaps that allowed the initial access. None of these steps is optional — an IR that resets all passwords but doesn't rotate krbtgt has evicted the attacker from one door while leaving another unlocked.
