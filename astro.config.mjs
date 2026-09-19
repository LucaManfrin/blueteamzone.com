// @ts-check
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";
import { remarkReadingTime } from "./src/lib/remark-reading-time.mjs";
import { remarkCallouts } from "./src/lib/remark-callouts.mjs";
import { SITE } from "./src/site.config.ts";

// https://astro.build/config
export default defineConfig({
  site: SITE.url,
  trailingSlash: "ignore",
  build: {
    // Emit clean directory-style URLs: /category/linux/ -> .../linux/index.html
    format: "directory",
  },
  integrations: [
    sitemap({
      // Drafts / unpublished / archived pages are never emitted as routes,
      // so they can never reach the sitemap. We additionally filter defensively.
      filter: (page) =>
        !page.includes("/404") && !page.includes("/search-index.json"),
    }),
  ],
  markdown: {
    remarkPlugins: [remarkReadingTime, remarkCallouts],
    shikiConfig: {
      // Dark-first, retro-leaning theme that still reads well in light mode.
      themes: {
        dark: "github-dark",
        light: "github-light",
      },
      wrap: true,
    },
    gfm: true,
  },
});
