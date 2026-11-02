import { getCollection } from "astro:content";
import type { CollectionEntry } from "astro:content";
import { CATEGORIES } from "../site.config";

export type Post = CollectionEntry<"posts">;

export async function getAllPosts(): Promise<Post[]> {
  const posts = await getCollection("posts");

  return posts
    .filter((post: Post) => {
      return post.data.published === true && post.data.archived !== true;
    })
    .sort(
      (a: Post, b: Post) =>
        b.data.date.getTime() - a.data.date.getTime()
    );
}

export async function getCategoryLabel(slug: string): Promise<string> {
  const category = CATEGORIES.find((item) => item.slug === slug);
  return category?.label ?? slug;
}

export function getCategorySlug(name: string): string {
  const category = CATEGORIES.find(
    (item) => item.label.toLowerCase() === name.toLowerCase()
  );

  if (category) {
    return category.slug;
  }

  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}