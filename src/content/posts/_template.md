---
# ============================================================
#  NEW POST TEMPLATE  —  copy this file into a category folder
#  e.g.  src/content/posts/windows/my-new-post.md
#  (the folder is just organisation; the `category` field below
#   is what actually files the post)
# ============================================================

title: "Your Article Title"
description: "A concise, SEO-friendly summary (max ~160 characters)."
date: "2026-06-07 14:30"              # YYYY-MM-DD HH:MM  (sorted newest-first)
category: "Windows"                    # Windows | Active Directory | Linux | MacOS | Threat Hunting | Security Tools
tags:
  - Windows
  - Threat Hunting

# ---- visibility controls ----
published: true     # false  -> hidden everywhere + excluded from sitemap (draft)
archived: false     # true   -> no public URL, hidden from all listings
pinned: false       # true   -> also shown in the homepage "Pinned" section
draft: false        # alias for published:false
featured: false     # reserved flag for future use

author: "Luca Manfrin"
coverImage: ""      # optional, e.g. "/images/posts/my-cover.webp"
readingTime: true
---

# Introduction

Open with the problem or scenario. The first H1 is optional — the page already
renders the title from the frontmatter, so you can start with prose or an H2.

## Scenario

Describe the situation.

## Analysis

Explain what you found. Fenced code blocks get syntax highlighting:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4769 } |
  Select-Object TimeCreated, Id
```

> [!NOTE]
> Renders as a styled "note" callout.

> [!TIP]
> Also available: TIP, IMPORTANT, WARNING, CAUTION, DANGER.

> [!WARNING]
> Use this for gotchas and risky steps.

## Conclusion

Wrap up with the takeaway.
