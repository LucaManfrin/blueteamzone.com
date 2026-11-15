---
title: "Anomalous connection from Windows process"
description: "Threat Hunting query for identifying anomalous connections from legitimate Windows process."
date: 2026-11-15T19:00:00
category: Threat-Hunting
tags:
  - Network
  - Threat Hunting
  - C2
author: "Luca Manfrin"
published: true
archived: false
pinned: false
---

# Scenario

Command and control (C2) is one of the most critical stages of the attack chain. After initial access, an attacker needs a channel to issue commands, exfiltrate data, download additional tools or maintain persistence.

In many cases, C2 traffic does not use exotic protocols. Attackers often rely on HTTPS, DNS or other common communication methods, making it harder to distinguish from legitimate business traffic.

This article presents a threat-hunting query for Microsoft Defender XDR/Sentinel designed to identify potential beaconing from unexpected Windows processes, such as Office applications, `rundll32.exe`, `mshta.exe` or Windows script hosts.

The primary technique is **MITRE ATT&CK T1071 — Application Layer Protocol**.

## Why Hunt for Beaconing

A beacon is a periodic or near-periodic communication between a compromised endpoint and an attacker-controlled server. It can be used to:

- Receive commands and payloads.
- Send discovery results or stolen credentials.
- Download additional tools.
- Maintain an active session.
- Exfiltrate data in small chunks.

There's no universal beacon. The interval may vary, the traffic may use HTTPS, DNS, HTTP or custom protocols and attackers can introduce jitter to reduce regularity.

However, repeated connections from processes that normally should not communicate with the internet are an excellent starting point for threat hunting.

MITRE describes detection of C2 over application-layer protocols as identifying abnormal use of common protocols — including HTTP, HTTPS, DNS and SMB — by unexpected processes, high outbound traffic or beacon-like communication patterns.

## Hunting Hypothesis

**Hypothesis:** A Windows endpoint is repeatedly communicating with external infrastructure through an unexpected process, potentially to maintain a C2 channel or exfiltrate data.

The focus is on processes such as:

- `winword.exe`, `excel.exe`, `powerpnt.exe` and `outlook.exe`
- `acrord32.exe` and `acrord64.exe`
- `rundll32.exe`
- `regsvr32.exe`
- `mshta.exe`
- `wscript.exe` and `cscript.exe`

These processes may have legitimate reasons to generate network traffic, but repeated connections to public IP addresses, especially with a relatively regular cadence, deserve deeper investigation.

## KQL Query

The query uses the `DeviceNetworkEvents` table in Microsoft Defender XDR, which contains network connection and related event information, including `RemoteIP`, `RemoteUrl`, `LocalIP` and `ActionType`.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrord32.exe",
    "acrord64.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe"
  )
| summarize
    Connections = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    IntervalMinutes = datetime_diff("minute", max(Timestamp), min(Timestamp)),
    RemoteIPs = make_set(RemoteIP, 20),
    RemoteURLs = make_set(RemoteUrl, 20)
    by
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemotePort
| where Connections >= 20
| extend Regularity = round(IntervalMinutes * 1.0 / Connections, 2)
| where Regularity between (0.5 .. 30)
| project
    FirstSeen,
    LastSeen,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemotePort,
    Connections,
    UniqueRemoteIPs,
    Regularity,
    RemoteIPs,
    RemoteURLs
| order by Connections desc
```

## How to Interpret Results

The query aggregates connections by device, user, initiating process, command line and remote port. It then calculates an approximate regularity indicator:

```text
Regularity = Total interval in minutes / Number of connections
```

A low value indicates many connections in a short period. A value between 0.5 and 30 minutes may suggest repetitive communication, but it's not proof of C2.

| Field | What to review |
|---|---|
| `Connections` | A high number of repeated connections |
| `UniqueRemoteIPs` | A small number of repeated IPs may indicate beaconing; many IPs may indicate CDNs, advertising or scanning |
| `Regularity` | Relatively consistent intervals deserve higher priority |
| `InitiatingProcessFileName` | Office, `rundll32`, `mshta` and script hosts are more suspicious than browsers |
| `RemoteURLs` | New, low-reputation, DGA-like or business-unrelated domains are relevant |
| `RemotePort` | Unusual ports for the process can increase priority |

The `DeviceNetworkEvents` table exposes both the remote IP and the reached URL or FQDN, which are useful for correlating activity with DNS, proxy, firewall and threat-intelligence data.

## Investigative Pivots

### 1. Identify the Process and User

Review who launched the process, from which device and with which command line.

An Office process generating dozens of connections to the same public IP is much more interesting if the user did not open documents or if the activity occurred outside normal business hours.

### 2. Reconstruct the Process Chain

Search for the process-creation event and trace the parent process chain. A sequence like this should be treated as high priority:

```text
WINWORD.EXE -> cmd.exe -> mshta.exe -> rundll32.exe
```

Or:

```text
OUTLOOK.EXE -> wscript.exe -> powershell.exe
```

These chains may indicate phishing, malicious macros, script droppers or LOLBin abuse.

### 3. Analyze DNS and URLs

Correlate the IPs and URLs with:

- DNS and proxy logs.
- Threat intelligence.
- TLS certificates and JA3/JA4 fingerprints, if available.
- Domain reputation.
- The presence of the same domain across other endpoints.

A single domain contacted by multiple endpoints, especially with the same process or command line, is a strong candidate for C2 infrastructure.

### 4. Search for Files and Persistence

Check whether the process created, modified or downloaded files. Pay attention to executables, DLLs, scripts and files in writable locations such as:

```text
%TEMP%
%APPDATA%
%LOCALAPPDATA%
C:\Users\Public\
C:\ProgramData\
```

Then look for scheduled tasks, services, Run keys and WMI modifications that could provide persistence.

### 5. Check for Exfiltration

Compare outbound and inbound traffic. A C2 beacon may have low volume, while exfiltration may show an unbalanced outbound-to-inbound ratio.

MITRE highlights the importance of observing abnormal protocols, high outbound traffic and beacon-like patterns to identify C2 or exfiltration activity.

## Expected False Positives

Beaconing is a useful pattern, but it's not deterministic. Many legitimate services communicate periodically with the internet.

| Common false positive | Why it appears | How to reduce noise |
|---|---|---|
| Browser and telemetry | Browsers, extensions and cloud services generate many connections | Baseline browsers rather than excluding them by default |
| Office and OneDrive | Office may sync files, telemetry and updates | Baseline by tenant, user and process |
| PDF readers | Some readers perform updates or telemetry | Allowlist known publishers and versions |
| Monitoring tools | EDR, RMM and backup agents communicate regularly | Baseline by process, endpoint and destination |
| CDNs and advertising | Third-party domains may be contacted repeatedly | Correlate with DNS, category and reputation |

Do not exclude entire processes without first understanding which destinations, users and hosts are involved. A browser may be normal for most users, but anomalous on a server, a service account or an endpoint that should not have internet access.

## Operational Recommendations

- Start with a 7-day time window and expand to 30 days to build a baseline.
- Prioritize non-browser processes with repeated connections to public IP addresses.
- Always correlate process, user, DNS, URL, IP, files and persistence.
- Use threat intelligence as enrichment, not as the sole decision criterion.
- Convert the query into a detection only after tuning it against your real environment.

## Conclusion

Beaconing is not absolute proof of compromise, but it's one of the most useful signals for identifying potential C2 channels.

The key is context: an unexpected process, an unusual external destination, a repeated cadence and an abnormal process-execution chain together significantly increase the likelihood that
