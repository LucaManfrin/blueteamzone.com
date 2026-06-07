---
title: "Finding C2 Beacons Hiding Behind Jitter"
description: "How to detect command-and-control beaconing in proxy and netflow logs even when malware randomises its callback interval."
date: "2026-06-03 18:40"
category: "Threat Hunting"
tags:
  - Threat Hunting
  - Network
  - C2
published: true
archived: false
pinned: true
author: "Your Name"
readingTime: true
---

## Scenario

Modern implants add *jitter* — they randomise the sleep between callbacks so a
naive "same interval every N seconds" detection misses them. Good news: jitter
hides the mean, not the *distribution*.

## Connection-interval analysis

Group outbound connections by `(src, dst, dport)`, compute the deltas between
successive connection times, then look at the coefficient of variation. Human
traffic is bursty and irregular; beacons cluster tightly even with ±30% jitter.

```python
import numpy as np

def beacon_score(timestamps):
    t = np.sort(np.asarray(timestamps, dtype=float))
    if len(t) < 8:
        return 0.0
    deltas = np.diff(t)
    cv = deltas.std() / (deltas.mean() + 1e-9)
    # Low CV + high connection count = strong beacon candidate
    return float(len(t) / (cv + 0.1))
```

> [!WARNING]
> Don't alert on a single high score. CDNs, software updaters and telemetry
> agents all beacon legitimately. Allow-list them, then triage the rest.

## Enrich, then decide

Rank destinations by score, then enrich: domain age, ASN reputation, JA3/JA4
hash, and whether the process making the calls is signed. A two-day-old domain
contacted every ~58s (±20%) by an unsigned binary is not a software updater.

## Conclusion

Jitter defeats interval matching, not statistics. Coefficient-of-variation
scoring over connection deltas, plus destination enrichment, turns "too noisy
to hunt" into a short, rankable list.
