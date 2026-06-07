# Final security review

Scope: this static, database-free, login-free Astro blog deployed via GitHub →
Netlify, fronted by Cloudflare. The review covers CSP, security headers,
routing, information disclosure, build/deploy config, SEO leakage, and the
visibility (draft/archived) controls. Verified against a production build.

## Summary

The attack surface is intentionally tiny: no server-side code at runtime, no
forms, no authentication, no user input persisted anywhere, no public API. The
main residual risks for a site like this are (1) header/CSP misconfiguration,
(2) accidental publication of unpublished/archived content, and (3) supply-chain
risk in build dependencies. All three are addressed below.

## What was verified on the built output

- **Unpublished/archived content does not leak.** A production build was
  inspected: `published:false` (draft) and `archived:true` posts produce **no
  HTML page, no URL, no sitemap entry, and no search-index entry**. Confirmed by
  string-searching `dist/` for their titles (zero hits) and by enumerating
  generated routes.
- **Sitemap contains only published, non-archived pages** (homepage, category
  pages, and the 6 listable posts). Drafts/archived are absent.
- **Search index** (`/search-index.json`) contains only listable posts.
- **No inline scripts and no inline event handlers** exist in the output, so the
  strict `script-src 'self'` CSP holds without `'unsafe-inline'`. JSON-LD blocks
  are `type="application/ld+json"` (data, not executable) and the theme
  bootstrap is an external same-origin file.
- **Canonical URLs** are emitted on every page and point at the configured site
  origin.

## Identified risks & mitigations

| # | Risk | Severity | Mitigation (in place) |
|---|------|----------|-----------------------|
| 1 | XSS via injected markup | Medium | Strict CSP: `default-src 'self'`, `script-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`. Content is authored Markdown rendered at build time; no runtime user input. |
| 2 | Clickjacking | Medium | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. |
| 3 | Protocol downgrade / MITM | Medium | HSTS (2y, `includeSubDomains`, `preload`) + Cloudflare *Always Use HTTPS* + *Full (strict)* TLS + `upgrade-insecure-requests`. |
| 4 | MIME sniffing | Low | `X-Content-Type-Options: nosniff`. |
| 5 | Referrer leakage | Low | `Referrer-Policy: strict-origin-when-cross-origin`. |
| 6 | Browser feature abuse | Low | `Permissions-Policy` disables camera, mic, geolocation, USB, payment, etc. |
| 7 | Cross-origin data exposure | Low | `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`. |
| 8 | Draft/archived content disclosure | Medium | Visibility enforced centrally in `src/lib/posts.ts`; non-listable posts are never routed, sitemapped, or indexed (verified). |
| 9 | Information disclosure (paths, infra, secrets) | Medium | No secrets in repo; `.env*` gitignored. No server/stack details exposed. 404 page shows no stack traces. Build logs contain no secrets (none used). |
| 10 | Supply-chain (malicious/compromised deps) | Medium | Lockfile committed; pinned/minimal dependency set; CI uses `npm ci`. Run `npm audit` periodically. Dependabot recommended. |
| 11 | Dependency in build only | Low | All JS runs at build time; nothing from `node_modules` ships to the client except the small bundled site scripts and Fuse.js. |
| 12 | DoS / scraping | Low | Static origin behind Cloudflare DDoS protection, Bot Fight Mode, WAF. No origin compute to exhaust. |

## Remaining recommendations

1. **Set `SITE.url`** to the real domain before launch so canonical URLs,
   sitemap and RSS are correct.
2. **Enable Dependabot** (or Renovate) on the GitHub repo and review
   `npm audit` output before each deploy.
3. **Submit HSTS to the preload list** only after confirming every subdomain is
   HTTPS-only.
4. **Verify headers on the live origin** with
   [securityheaders.com](https://securityheaders.com) and the Mozilla Observatory
   after the first deploy; target an A/A+.
5. **Keep Cloudflare from injecting scripts** — leave Rocket Loader and Auto
   Minify off (they conflict with the strict `script-src 'self'`). See
   `docs/CLOUDFLARE.md`.
6. **Protect the production branch** on GitHub (require PR review) so only
   contributors can publish — this is the publishing access control.
7. If you ever add a comment system, analytics, or embeds, **update the CSP**
   `connect-src`/`script-src`/`frame-src` deliberately rather than loosening to
   `*`.

## OWASP ASVS — applicable checklist (static site)

Most ASVS controls assume server-side state, sessions, and accounts, which this
site does not have (marked **N/A**). The applicable subset:

### V1 Architecture
- [x] Components and trust boundaries documented (README + this doc).
- [x] No secrets in source control; `.env*` ignored.

### V5 Validation, Sanitization & Encoding
- [x] Output encoding: content is build-time Markdown→HTML; search results are
      HTML-escaped before insertion into the DOM.
- [x] `object-src 'none'`, no `eval`, no dynamic script injection.
- [N/A] Server-side input validation (no server input).

### V7 Error Handling & Logging
- [x] Custom 404 with no stack traces or technical details.
- [x] No verbose errors or framework banners exposed to clients.
- [N/A] Centralized server logging.

### V9 Communications
- [x] TLS enforced everywhere (HSTS + Always Use HTTPS + Full strict).
- [x] Modern TLS only (≥1.2, 1.3 enabled); `upgrade-insecure-requests`.

### V12 Files & Resources
- [x] No file upload functionality.
- [x] Static assets served with correct `Content-Type`; `nosniff` set.
- [x] No user-controlled file paths.

### V13 API & Web Service
- [N/A] No public API endpoints. `/search-index.json` is a static, public,
        read-only index of already-public content and is `Disallow`ed in robots.

### V14 Configuration
- [x] Strict CSP without `'unsafe-inline'`/`'unsafe-eval'` for scripts.
- [x] Full security header set (HSTS, XFO, nosniff, Referrer-Policy,
      Permissions-Policy, COOP/CORP/COEP).
- [x] Dependencies pinned via lockfile; minimal footprint; reproducible build.
- [x] No debug/admin endpoints; no CMS; no login.
- [x] Least privilege: nothing writes at runtime; deploy is read-only static.

### Sessions / Authentication / Access Control (V2, V3, V4)
- [N/A] No accounts, sessions, passwords, or authorization logic exist. Publish
        access is governed by GitHub repository permissions + branch protection.

---

_Re-run this review whenever you add third-party scripts, embeds, analytics, a
comment system, or any dynamic functionality — each of those changes the CSP and
the threat model._
