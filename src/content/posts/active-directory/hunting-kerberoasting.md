---
title: "Hunting Kerberoasting Without Drowning in 4769s"
description: "A practical, signal-first approach to detecting Kerberoasting using service ticket telemetry, encryption downgrades, and behavioural baselines."
date: "2026-06-05 09:15"
category: "Active Directory"
tags:
  - Active Directory
  - Threat Hunting
  - Kerberos
published: true
archived: false
pinned: true
featured: true
author: "Luca Manfrin"
readingTime: true
---

## Scenario

Kerberoasting is old, noisy on paper, and still works. An attacker requests
service tickets (TGS) for accounts with a Service Principal Name, then cracks
the ciphertext offline. The classic detection — alert on Event ID `4769` — drowns
you in false positives because every normal logon generates them too.

## The signal that actually matters

Stop counting `4769`s. Filter for the *shape* of the abuse instead:

- Ticket encryption type `0x17` (RC4) when your domain should be issuing AES.
- A single principal requesting tickets for **many distinct SPNs** in a short window.
- Service accounts whose tickets are requested by a workstation that never touches them.

```powershell
# Surface RC4 service tickets (encryption downgrade) from the Security log
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4769 } |
  Where-Object { $_.Properties[8].Value -eq '0x17' } |
  Select-Object TimeCreated,
    @{ n = 'Account';     e = { $_.Properties[0].Value } },
    @{ n = 'ServiceName'; e = { $_.Properties[2].Value } }
```

> [!NOTE]
> `0x17` is RC4-HMAC. If you have already enforced AES across the domain, an
> RC4 request is by itself worth a second look.

## Baseline first, alert second

The win is behavioural. Build a 30-day baseline of *which principals request
tickets for which SPNs*, then alert only on new pairs. Kerberoasting lights up
because the attacker reaches for SPNs the source account has never touched.

> [!TIP]
> Pair this with a honeypot service account: a fake SPN, a strong password, and
> zero legitimate users. **Any** TGS request for it is high-fidelity.

## Conclusion

Kerberoasting detection isn't about more events — it's about fewer, sharper
ones. Encryption downgrades plus per-principal SPN baselines plus one honey-SPN
will catch the vast majority of real attempts without burying your analysts.
s.
