import type { APIRoute } from "astro";
import { SITE } from "@/site.config";

// Generated so the sitemap URL always matches the configured production URL.
export const GET: APIRoute = () => {
  const body = `# ${SITE.title}
User-agent: *
Allow: /

# Keep machine endpoints out of the index
Disallow: /search-index.json

Sitemap: ${SITE.url}/sitemap-index.xml
`;
  return new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
};
