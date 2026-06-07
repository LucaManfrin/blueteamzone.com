---
title: "Velociraptor for 5-Minute Endpoint Triage"
description: "Spin up Velociraptor and run a fleet-wide hunt for suspicious persistence in minutes — no agent rollout required."
date: "2026-06-01 11:00"
category: "Security Tools"
tags:
  - tool
  - Threat Hunting
  - Velociraptor
published: true
archived: false
pinned: true
author: "Luca Manfrin"
readingTime: true
---

## Why Velociraptor

When something is on fire you don't have time to deploy an EDR. Velociraptor
gives you a single binary that can act as server, client, or a standalone
collector, and a query language (VQL) that reaches into the live endpoint.

## Standalone collection

Build a collector that grabs autoruns, scheduled tasks, and recent prefetch,
hand it to the user, get a zip back:

```bash
velociraptor collector \
  --artifacts Windows.Sys.StartupItems,Windows.System.TaskScheduler \
  --output triage.zip
```

> [!TIP]
> The collector needs no server and no install. It runs from a USB stick and
> leaves nothing behind — ideal for "just look at this one box" requests.

## Fleet hunt with VQL

If you do have clients connected, a hunt across the whole fleet is one query:

```sql
SELECT Name, CommandLine, Hash
FROM Artifact.Windows.System.TaskScheduler()
WHERE CommandLine =~ "powershell.*-enc"
```

> [!NOTE]
> `=~` is a case-insensitive regex match in VQL. Encoded PowerShell in a
> scheduled task is a reliable persistence smell.

## Conclusion

Velociraptor's superpower is *time to first answer*. A standalone collector for
one box, a VQL hunt for the fleet — either way you're triaging in minutes, not
after a week-long agent rollout.
