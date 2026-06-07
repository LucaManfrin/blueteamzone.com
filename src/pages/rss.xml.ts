import rss from "@astrojs/rss";
import type { APIContext } from "astro";
import { SITE } from "@/site.config";
import { getListablePosts, postPath } from "@/lib/posts";

export async function GET(context: APIContext) {
  const posts = await getListablePosts();
  return rss({
    title: SITE.title,
    description: SITE.description,
    site: context.site ?? SITE.url,
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      pubDate: post.data.date,
      link: postPath(post),
      categories: [post.data.category, ...post.data.tags],
    })),
    customData: `<language>${SITE.lang}</language>`,
  });
}
