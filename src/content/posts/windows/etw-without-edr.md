---
title: "Reading ETW Like an EDR (Without Buying One)"
description: "Tap directly into Event Tracing for Windows to get process, network and DNS telemetry that rivals commercial endpoint agents."
date: "2026-05-28 16:20"
category: "Windows"
tags:
  - Windows
  - Threat Hunting
  - ETW
published: true
archived: false
pinned: false
author: "Your Name"
readingTime: true
---

## Scenario

Event Tracing for Windows (ETW) is the firehose that commercial EDRs drink
from. You can drink from it too. The `Microsoft-Windows-Threat-Intelligence`,
`-Kernel-Process` and `-DNS-Client` providers expose a remarkable amount.

## A minimal trace session

```powershell
# Capture process + DNS provider events for 60 seconds
$session = New-EtwTraceSession -Name "hunt" -LogFileMode 0x00000100
Add-EtwTraceProvider -SessionName "hunt" `
  -Guid "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}"  # DNS-Client
Start-Sleep 60
Remove-EtwTraceSession -Name "hunt"
```

> [!IMPORTANT]
> Some providers (notably Threat-Intelligence) require Protected Process Light
> or a signed ELAM driver to subscribe. Plan for that before you rely on them.

## What to hunt

DNS-Client events tie a *process* to the domains it resolves — that mapping is
gold for catching malware phoning home. Kernel-Process events give you parent/
child lineage to spot `winword.exe → cmd.exe → powershell.exe` chains.

## Conclusion

ETW won't replace a mature EDR's correlation and response, but for detection
engineering and incident triage it gives you the same raw telemetry for the
price of writing a trace session.
