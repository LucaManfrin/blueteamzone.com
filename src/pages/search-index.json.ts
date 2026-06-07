import type { APIRoute } from "astro";
import { getListablePosts, postPath } from "@/lib/posts";
import { categorySlug, categoryBySlug } from "@/site.config";

/**
 * Builds the client-side search index. Only LISTABLE posts are included, so
 * drafts / unpublished / archived content can never be discovered via search.
 * Body text is truncated to keep the index small and fast.
 */
export const GET: APIRoute = async () => {
  const posts = await getListablePosts();
  const docs = posts.map((post) => {
    const slug = categorySlug(post.data.category);
    return {
      title: post.data.title,
      description: post.data.description,
      category: categoryBySlug(slug)?.name ?? post.data.category,
      tags: post.data.tags,
      url: postPath(post),
      body: post.body
        .replace(/```[\s\S]*?```/g, " ") // drop code fences
        .replace(/[#>*`_\-]/g, " ") // drop md punctuation
        .replace(/\s+/g, " ")
        .slice(0, 1200),
    };
  });

  return new Response(JSON.stringify(docs), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "public, max-age=300",
    },
  });
};
