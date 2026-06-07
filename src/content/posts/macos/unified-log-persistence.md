---
title: "Catching macOS Persistence in the Unified Log"
description: "Use macOS Unified Logging and FSEvents to detect launch agents, login items and other persistence the moment they're planted."
date: "2026-05-14 13:30"
category: "MacOS"
tags:
  - macos
  - Threat Hunting
  - persistence
published: true
archived: false
pinned: false
author: "Luca Manfrin"
readingTime: true
---

## Scenario

On macOS, persistence almost always touches a small set of locations: `Launch
Agents`, `Launch Daemons`, login items, and configuration profiles. The Unified
Log sees the daemons that manage them.

## Querying the Unified Log

```bash
# Surface launchd loading a new agent/daemon in the last hour
log show --last 1h --predicate \
  'process == "launchd" && eventMessage CONTAINS "Service only ran"' \
  --info
```

> [!NOTE]
> Unified Logging is ephemeral and lossy by design. For real detection, stream
> it to a collector with `log stream` rather than relying on `log show` after
> the fact.

## Watch the paths directly

Pair the log with FSEvents (or an `eslogger`/Endpoint Security client) on the
persistence directories:

```bash
ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons
```

> [!TIP]
> A new `.plist` whose `ProgramArguments` points at `/tmp`, a hidden path, or a
> user-writable directory is persistence until proven otherwise.

## Conclusion

You don't need a third-party agent to catch most macOS persistence — streamed
Unified Logging plus Endpoint Security on a handful of directories covers the
techniques real intrusions actually use.
