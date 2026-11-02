import type { APIRoute } from "astro";
import { getAllPosts } from "../lib/posts";
import type { CollectionEntry } from "astro:content";

type Post = CollectionEntry<"posts">;

export const GET: APIRoute = async () => {
  const posts = await getAllPosts();

  const index = posts
    .filter((post: Post) => post.data.published && !post.data.archived)
    .map((post: Post) => ({
      slug: post.id,
      title: post.data.title,
      description: post.data.description,
      category: post.data.category,
      tags: post.data.tags
    }));

  return new Response(JSON.stringify(index), {
    headers: {
      "Content-Type": "application/json"
    }
  });
};