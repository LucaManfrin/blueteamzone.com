import rss from "@astrojs/rss";
import { getAllPosts } from "../lib/posts";
import { SITE } from "../site.config";

export async function GET(context: { site?: URL }) {
  const posts = await getAllPosts();

  return rss({
    title: SITE.title,
    description: SITE.description,
    site: context.site ?? SITE.url,
    items: posts.map((post) => ({
      title: post.data.title,
      description: post.data.description,
      pubDate: post.data.date,
      link: `/posts/${post.id}/`,
    })),
  });
}