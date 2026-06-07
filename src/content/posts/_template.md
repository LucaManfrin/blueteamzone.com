---
title: "Article Title"
description: "A concise, SEO-friendly description (max ~160 chars)."
date: "2026-05-31 14:30"
category: "Active Directory" # Windows | Active Directory | Linux | MacOS | Threat Hunting | Security Tools
tags:
  - Active Directory
  - Windows

# --- visibility controls ---
published: true # false => hidden everywhere + out of sitemap (draft)
archived: false # true  => unreachable by URL, hidden from all listings
pinned: false # true  => also shown in the homepage "Pinned" section
featured: false # reserved flag for future use
draft: false # alias for published:false behaviour

author: "Luca Manfrin"
coverImage: "" # e.g. "/images/posts/example.webp" (optional)
readingTime: true
---

# Introduction

Article introduction goes here. The first H1 is optional — the layout already
renders the title from frontmatter, so you can start with prose or an H2.

## Scenario

Describe the scenario.

## Analysis

Explain the analysis.

```powershell
Get-ADUser -Filter * -Properties servicePrincipalName |
  Where-Object { $_.servicePrincipalName }
```

> [!NOTE]
> This renders as a styled "note" callout.

> [!WARNING]
> This renders as a "warning" callout. TIP, IMPORTANT, CAUTION and DANGER also work.

> A blockquote without a marker stays a normal quote.

## Conclusion

Wrap up.
