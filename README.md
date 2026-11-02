# Blue Team Zone

A clean, professional cybersecurity blog built with Astro 4 and designed for Cloudflare Pages.

## Features

- 🌓 Dark/Light mode toggle
- 🔍 Client-side search with Fuse.js
- 📁 Category-based organization
- 📝 Markdown-based posts
- 📊 RSS feed
- 🚀 Optimized for Cloudflare Pages
- ♿ Accessible and responsive
- ⚡ Fast static generation

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Run locally
```bash
npm run dev
```

Visit `http://localhost:4321`

### 3. Build for production
```bash
npm run build
```

## Project Structure

```
src/
├── components/        # Reusable components
├── content/
│   └── posts/        # Your markdown articles (14 migrated)
├── layouts/          # Base layout
├── lib/              # Utility functions
├── pages/            # Route pages (homepage, posts, categories, search)
└── site.config.ts    # Site configuration

public/              # Static assets
```

## Site Config

Edit `src/site.config.ts`:

```typescript
export const SITE: SiteConfig = {
  url: "https://blueteamzone.com",
  title: "0xLuca // notes",
  description: "...",
  author: "Luca Manfrin",
  authorTitle: "Cyber Security Specialist",
  lang: "en",
};

export const CATEGORIES = [
  { slug: "windows", label: "Windows" },
  { slug: "Active-Directory", label: "Active Directory" },
  // ... all 6 categories pre-configured
];
```

## Deployment

### Cloudflare Pages (Recommended)

1. Push to GitHub
2. Go to Cloudflare Pages → "Create a project"
3. Connect your repo
4. Build settings:
   - Framework: Astro
   - Build command: `npm run build`
   - Build output: `dist`

## Features

### Dark/Light Mode
- Automatically persists preference in localStorage
- Toggle in header (moon/sun icons)
- GitHub-inspired color scheme

### Search
- Real-time client-side search using Fuse.js
- Search `/search` page
- Index generated at build time

### Categories
- 6 built-in categories (windows, Active-Directory, Linux, macOS, Threat-Hunting, tools)
- Category pages at `/category/<slug>`
- Related posts shown on each post detail page

### RSS Feed
- Available at `/rss.xml`
- Includes all published posts
- Subscribe in any RSS reader

### SEO
- Automatic sitemap at `/sitemap.xml`
- Open Graph tags
- Twitter card support
- Canonical URLs

## Post Frontmatter Format

```yaml
---
title: "Your Post Title"
description: "Short description for cards and meta"
date: 2026-01-20T10:30:00
category: "Active-Directory"  # Slug format
tags:
  - tag1
  - tag2
author: "Luca Manfrin"
published: true
archived: false
pinned: false
featured: false
---

Your content here...
```

**Required fields:**
- `title`, `description`, `date`, `category`

**Optional fields:**
- `author` (defaults to SITE.author)
- `tags` (empty array by default)
- `published`, `archived`, `pinned`, `featured` (all false by default)

## Performance

- **Pages**: < 1s load time (Cloudflare CDN)
- **Build**: ~2-3s for full rebuild
- **Size**: ~ 50KB per page (gzipped)

## Security

Headers configured in `public/_headers`:
- CSP (Content Security Policy)
- X-Frame-Options: SAMEORIGIN
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
