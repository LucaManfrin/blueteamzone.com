# Retro Sec Blog

A retro, security-hardened, static cyber-security blog. Dark-first **90s
desktop-OS** aesthetic (beveled windows, title bars, a subtly bouncing logo) —
deliberately none of the usual matrix / green-terminal clichés. Markdown
in, fast static HTML out. No CMS, no database, no login, no public API.

Built with **[Astro](https://astro.build)** + TypeScript.

---

## Features

- 100% static output, Git-driven publishing (write Markdown → commit → deploy).
- Content visibility controls: `published`, `archived`, `pinned`, `draft`.
- Homepage shows the **latest 3** and **pinned 3** posts.
- Category pages with **9 posts/page** + prev/next pagination, SEO-friendly URLs.
- Per-article table of contents, syntax highlighting, note/tip/warning callouts,
  related posts, reading time.
- Client-side search (Fuse.js) over a prebuilt index — no server, no tracking.
- Dark/light theme with `localStorage` persistence (dark is default).
- SEO: sitemap, robots.txt, canonical URLs, Open Graph, Twitter cards,
  Schema.org `BlogPosting`, RSS feed.
- Security: strict CSP and a full set of hardening headers via `netlify.toml`.
- Accessible: semantic HTML, keyboard nav, skip link, visible focus, reduced-
  motion support.

---

## Requirements

- Node.js **20+** (22 recommended; CI/Netlify pinned to 22).
- npm (or pnpm/yarn — examples use npm).

---

## Local development

```bash
npm install
npm run dev        # http://localhost:4321
```

Other scripts:

```bash
npm run build        # type-check + production build into dist/
npm run preview      # serve the built site locally
npm run lint         # ESLint
npm run format       # Prettier (write)
npm run format:check # Prettier (check only)
```

---

## Configuration

Everything personal lives in **`src/site.config.ts`** — it's the only file you
need to edit:

- `SITE.url` — your production URL (update before launch; powers canonical URLs,
  sitemap and RSS).
- `SITE.title`, `SITE.tagline`, `SITE.description`.
- `SITE.authorName`, `SITE.authorTitle`, `SITE.defaultAuthor`.
- `SOCIAL.github`, `SOCIAL.linkedin`, `SOCIAL.credly` — set any to `""` to hide.
- `CATEGORIES` — order + friendly labels for the built-in nav.

No secrets, API keys or environment variables are required anywhere.

---

## Writing an article

1. Copy the template `src/content/posts/_template.md`.
2. Save it as `src/content/posts/<category-folder>/<your-slug>.md`.
   The folder is organisational; the **`category`** frontmatter field is what
   actually files the post.
3. Fill in the frontmatter, write your Markdown, commit and push.

Frontmatter reference:

| Field         | Type    | Effect                                                             |
| ------------- | ------- | ----------------------------------------------------------------- |
| `title`       | string  | Post title.                                                       |
| `description` | string  | SEO/meta description (~160 chars).                                |
| `date`        | date    | Publication date/time. Sorting is newest-first.                  |
| `category`    | string  | One of the categories (or a brand-new one — see below).          |
| `tags`        | list    | Free-form tags.                                                  |
| `published`   | bool    | `false` = hidden everywhere + out of sitemap (draft).            |
| `archived`    | bool    | `true` = no URL, hidden from every listing.                      |
| `pinned`      | bool    | `true` = also shown in the homepage "Pinned" section.            |
| `draft`       | bool    | Same effect as `published: false`.                              |
| `featured`    | bool    | Reserved flag for future use.                                    |
| `author`      | string  | Optional; falls back to `SITE.defaultAuthor`.                   |
| `coverImage`  | string  | Optional path, e.g. `/images/posts/foo.webp`.                   |
| `readingTime` | bool    | Show estimated reading time.                                     |

`yes`/`no` strings are accepted for the boolean fields too.

### Callouts

```markdown
> [!NOTE]
> Renders as a note block.

> [!TIP]
> Tip. (TIP, IMPORTANT, WARNING, CAUTION, DANGER supported.)
```

---

## Adding a category

The architecture reads categories from post frontmatter, so a brand-new
category works **with zero code changes** — just publish a post with a new
`category` value and its `/category/<slug>` page is generated automatically.

To give it a friendly label/description and a fixed spot in the nav, add an
entry to `CATEGORIES` in `src/site.config.ts`.

---

## Image management

- Put images in `public/images/` and reference them by absolute path, e.g.
  `/images/posts/my-cover.webp`.
- Prefer **WebP/AVIF**, size them to their display width, and always provide
  meaningful `alt` text.
- Files in `public/` are served as-is at the site root.

---

## Deployment (GitHub → Netlify → Cloudflare)

1. **GitHub** — push this repo to GitHub.
2. **Netlify** — "Add new site → Import from Git", pick the repo. Netlify reads
   `netlify.toml`: build command `npm run build`, publish dir `dist`. Every push
   to the production branch triggers a deploy automatically.
3. **Cloudflare** — point DNS at Netlify and apply the settings in
   [`docs/CLOUDFLARE.md`](docs/CLOUDFLARE.md).

Before launch, set `SITE.url` in `src/site.config.ts` to your real domain.

---

## Project structure

```text
src/
  components/      UI components (Header, Footer, cards, TOC, pagination…)
  content/
    config.ts      content collection schema + visibility coercion
    posts/         your Markdown articles, organised in category folders
  layouts/Base.astro
  lib/             posts logic, remark plugins (callouts, reading time)
  pages/
    index.astro            homepage (latest 3 + pinned 3)
    category/[slug]/[...page].astro   category pages + pagination
    posts/[...slug].astro             article pages
    404.astro
    rss.xml.ts / robots.txt.ts / search-index.json.ts
  scripts/         small client modules (theme, search, TOC, bouncer)
  styles/global.css
public/            static assets (logo, favicon, theme-init.js, images)
netlify.toml       build + strict security headers + cache rules
docs/              security review + Cloudflare recommendations
```

---

## Troubleshooting

- **A new post isn't showing.** Check `published: true`, `archived: false`,
  `draft: false`, and that the `date` is not in the future relative to build
  time if you later add future-date filtering. Re-run `npm run build`.
- **Type errors on build.** `npm run build` runs `astro check`; fix the
  reported frontmatter/type issue. The schema lives in
  `src/content/posts`'s `config.ts`.
- **Syntax highlighting looks unstyled.** That's expected if you strip
  `'unsafe-inline'` from `style-src`; Shiki emits inline color styles. Keep it,
  or switch to a class-based highlighter.
- **Search returns nothing.** Ensure the build emitted `dist/search-index.json`
  and that you have at least one listable post.

---

## License

Add your preferred license here (e.g. MIT for code). Article content is yours.
