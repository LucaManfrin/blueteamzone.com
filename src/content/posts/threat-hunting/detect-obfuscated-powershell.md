---
title: "Finding Obfuscated PowerShell on Windows hosts"
description: "Threat Hunting query for detecting anomalous obfuscated PowerShell command that can be related to malicious activities."
date: 2026-09-15T18:40:00
category: Threat-Hunting
tags:
  - Threat Hunting
  - PowerShell
  - C2
author: "Luca Manfrin"
published: true
archived: false
pinned: true
---

# Scenario

PowerShell remains one of the most abused execution techniques by threat actors because it's native, powerful and commonly available in Windows environments. This article presents a threat-hunting query for Microsoft Defender XDR/Sentinel designed to identify suspicious PowerShell activity, with a focus on encoded commands, payload downloads and dynamic code execution.

The primary technique is **MITRE ATT&CK T1059.001 - Command and Scripting Interpreter: PowerShell**.

## Why PowerShell Is a Key Signal

After gaining initial access, an attacker may use PowerShell to enumerate the environment, download additional tools, execute code in memory, manipulate processes or collect credentials.

The most interesting patterns aren't simply “PowerShell was executed.” PowerShell is a legitimate administrative tool. The objective is to identify unusual combinations of:

- Base64-encoded commands, such as `-EncodedCommand`, `-enc` or `-e`.
- Remote downloads using `Invoke-WebRequest`, `iwr`, `DownloadString` or `DownloadFile`.
- Dynamic execution using `Invoke-Expression`, `IEX` or .NET assembly loading.
- Unexpected parent processes, such as Office applications, browsers or scripting tools.
- Commands attempting to bypass or interfere with security controls, including AMSI.

The `-EncodedCommand` parameter allows an attacker to pass a Base64 payload to PowerShell, reducing the immediate readability of the command line and making simple string-based matching less effective.

## Hunting Hypothesis

**Hypothesis:** A compromised user or process is using PowerShell to download, decode or execute potentially malicious code.

The query looks for signs of obfuscated execution and behaviors commonly associated with loaders, droppers and post-exploitation activity. It's not a final detection rule: it's a hunting query that produces candidates requiring context from identity, parent process, network activity and files.

## KQL Query

The following query is designed for **Microsoft Defender XDR Advanced Hunting** and uses the `DeviceProcessEvents` table.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any(
    "-enc",
    "-EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "DownloadFile",
    "Invoke-Expression",
    "IEX",
    "iwr",
    "Invoke-WebRequest",
    "Start-Process",
    "amsiInitFailed",
    "AmsiUtils",
    "System.Reflection.Assembly"
  )
| extend SuspiciousScore = case(
    ProcessCommandLine has_any("-enc", "-EncodedCommand"), 3,
    ProcessCommandLine has_any("FromBase64String", "System.Reflection.Assembly"), 3,
    ProcessCommandLine has_any("DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr"), 2,
    ProcessCommandLine has_any("Invoke-Expression", "IEX"), 2,
    ProcessCommandLine has_any("amsiInitFailed", "AmsiUtils"), 3,
    1
  )
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName,
    ReportId,
    SuspiciousScore
| order by SuspiciousScore desc, Timestamp desc
```

## How to Interpret Results

The `SuspiciousScore` field is a prioritization aid, not a verdict. It assigns a higher score to patterns more strongly associated with evasion or remote execution.

| Score | Pattern | Operational interpretation |
|---:|---|---|
| 3 | `-EncodedCommand`, `FromBase64String`, AMSI manipulation, assembly loading | High priority: possible obfuscation, loader or evasion |
| 2 | Remote download or `Invoke-Expression` | Medium-high priority: possible payload download and execution |
| 1 | Other suspicious patterns | Validate in the context of the host and user |

The command line is the central field for analysis. For example, Sysmon Event ID 1 records the newly created process along with its full command line, parent process, user and file hashes.

## Investigative Pivots

A hit should always be investigated as a chain of events, not as an isolated event.

### 1. Identify Who Ran PowerShell

Review `AccountName`, the timestamp, the device and whether the activity is consistent with the user’s role.

A service account running PowerShell may be normal. The same behavior from a standard user account, especially outside business hours, deserves closer attention.

### 2. Identify Where PowerShell Came From

Analyze `InitiatingProcessFileName`, `InitiatingProcessCommandLine` and `InitiatingProcessParentFileName`.

A chain like this is significantly more suspicious:

```text
WINWORD.EXE -> cmd.exe -> powershell.exe -enc <Base64>
```

Compared with a legitimate administrative console:

```text
powershell_ise.exe -> powershell.exe -Command Get-Process
```

Office applications, browsers, PDF readers and archive utilities are common parent processes in phishing and initial-access chains.

### 3. Determine What PowerShell Did

Decode the Base64 payload **in an isolated environment**. Do not execute it on a production endpoint.

Look for URLs, file names, discovery commands, process creation, registry modifications, security-control tampering or references to command-and-control infrastructure.

### 4. Check for Internet Communication

Correlate the event with `DeviceNetworkEvents`, searching for outbound connections from the same device during the same time window.

Review IP addresses, domains, ports and URLs associated with the PowerShell process.

### 5. Check for Persistence

Look for scheduled tasks, services, Run keys, executable files in writable locations and WMI modifications.

A PowerShell command may be only the first step in a chain that ends with persistence or lateral movement.

## Network Correlation

After identifying a suspicious hit, use the following query to review network connections generated by the same process:

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| where RemoteIPType == "Public"
| summarize
    Connections = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    RemoteIPs = make_set(RemoteIP, 20),
    RemoteURLs = make_set(RemoteUrl, 20)
    by DeviceName, AccountName, InitiatingProcessFileName,
       InitiatingProcessCommandLine, RemotePort
| order by Connections desc
```

This correlation helps distinguish a one-time download from a possible C2 beacon or data-exfiltration activity.

## Expected False Positives

PowerShell is widely used by administrators, deployment tools, management agents and automation scripts. Therefore, not every result represents an incident.

| Common false positive | Why it appears | How to reduce noise |
|---|---|---|
| Deployment scripts | `Invoke-WebRequest`, `Start-Process` and downloads are common in pipelines | Baseline by host, user and time |
| RMM tools | Some remote-management agents use PowerShell | Use targeted allowlists for publishers and paths |
| Administrative scripts | Administrators may use `Invoke-Expression` or encoded commands for automation | Validate repositories and change-management processes |
| Development software | Developers may execute scripts and download dependencies | Exclude only previously approved hosts and identities |

Avoid overly broad exclusions. Excluding all PowerShell processes or all administrative accounts can hide exactly the activity you are trying to find.

## Operational Recommendations

- Start with a 7-day time window, then expand to 30 or 90 days to build a baseline.
- Treat `-EncodedCommand`, AMSI bypass and dynamic assembly loading as high-priority candidates.
- Do not decode payloads on production endpoints; use an isolated VM or dedicated analysis environment.
- Always correlate process creation, identity, network, files and persistence.
- Convert a pattern into a detection only after tuning it against your real environment.

## Conclusion

The goal of this query is not to declare “PowerShell = malicious.” Instead, it aims to identify PowerShell execution in an unusual context: obfuscation, downloads, dynamic execution and unexpected parent processes.

This combination is often more predictive than a single static indicator.
