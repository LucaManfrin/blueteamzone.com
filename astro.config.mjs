import { defineConfig } from "astro/config";
import { SITE } from "./src/site.config.ts";

export default defineConfig({
  output: "static",
  site: SITE.url,
  trailingSlash: "always",
  build: {
    format: "directory",
  },
  integrations: [],
  markdown: {
    shikiConfig: {
      themes: {
        dark: "github-dark",
        light: "github-light",
      },
      wrap: true,
    },
    gfm: false,
  },
});