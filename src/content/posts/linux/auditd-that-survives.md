---
title: "An auditd Baseline That Survives Contact With Production"
description: "A lean, high-signal auditd ruleset that catches real attacker behaviour on Linux without flooding your SIEM or melting the host."
date: "2026-05-22 08:05"
category: "Linux"
tags:
  - Linux
  - Threat Hunting
  - auditd
published: true
archived: false
pinned: false
author: "Luca Manfrin"
readingTime: true
---

## Scenario

The default reaction to "we need Linux visibility" is to paste a 400-rule
auditd config from the internet. The host slows down, the SIEM bill explodes,
and analysts ignore the noise. Less is more.

## The core rules

Watch the things attackers actually touch: credential files, persistence
locations, and privilege escalation.

```bash
# /etc/audit/rules.d/baseline.rules
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/sudoers -p wa -k privesc
-w /etc/cron.d  -p wa -k persistence
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
```

> [!WARNING]
> The `execve` rule on every root command is powerful but chatty. Scope it with
> `-F auid>=1000` to ignore daemon noise and focus on interactive sessions.

## Make it queryable

Tag everything with `-k` keys so `ausearch -k privesc` becomes a one-liner.
Ship to your SIEM by key, and you get clean, named detections instead of a wall
of syscalls.

## Conclusion

A dozen well-chosen rules beats four hundred copied ones. Watch identity,
persistence and privilege escalation, key everything, and your auditd config
will still be running — and still be read — six months from now.
