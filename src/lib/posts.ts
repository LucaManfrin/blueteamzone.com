import { getCollection, type CollectionEntry } from "astro:content";
import { categorySlug } from "@/site.config";

export type Post = CollectionEntry<"posts">;

/**
 * A post is PUBLICLY VISIBLE in listings only when it is:
 *   - published: true
 *   - archived:  false
 *   - draft:     false
 * Archived posts are also unreachable by direct URL (see [...slug].astro),
 * and unpublished/draft posts are never built into a route at all.
 */
export function isListable(post: Post): boolean {
  const d = post.data;
  return d.published === true && d.archived === false && d.draft === false;
}

/** Sort newest-first by publication date. */
export function byDateDesc(a: Post, b: Post): number {
  return b.data.date.getTime() - a.data.date.getTime();
}

/** All listable posts, newest first. */
export async function getListablePosts(): Promise<Post[]> {
  const posts = await getCollection("posts", isListable);
  return posts.sort(byDateDesc);
}

/** The N most recent listable posts. */
export async function getLatest(n: number): Promise<Post[]> {
  return (await getListablePosts()).slice(0, n);
}

/** The N most recent pinned + listable posts. */
export async function getPinned(n: number): Promise<Post[]> {
  return (await getListablePosts())
    .filter((p) => p.data.pinned === true)
    .slice(0, n);
}

/** Listable posts belonging to a category (matched by slug). */
export async function getPostsByCategorySlug(slug: string): Promise<Post[]> {
  return (await getListablePosts()).filter(
    (p) => categorySlug(p.data.category) === slug
  );
}

/** Distinct category slugs that actually have at least one listable post. */
export async function getActiveCategorySlugs(): Promise<string[]> {
  const posts = await getListablePosts();
  return [...new Set(posts.map((p) => categorySlug(p.data.category)))];
}

/**
 * Related posts: same category first, then shared tags, newest first,
 * excluding the current post. Always listable.
 */
export async function getRelated(post: Post, n: number): Promise<Post[]> {
  const all = (await getListablePosts()).filter((p) => p.id !== post.id);
  const tagSet = new Set(post.data.tags.map((t) => t.toLowerCase()));
  const score = (p: Post): number => {
    let s = 0;
    if (categorySlug(p.data.category) === categorySlug(post.data.category)) {
      s += 5;
    }
    s += p.data.tags.filter((t) => tagSet.has(t.toLowerCase())).length;
    return s;
  };
  return all
    .map((p) => ({ p, s: score(p) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || byDateDesc(a.p, b.p))
    .slice(0, n)
    .map((x) => x.p);
}

/** Rough reading time (words / 200), min 1, computed from raw body. */
export function readingMinutes(post: Post): number {
  const words = post.body.trim().split(/\s+/).length;
  return Math.max(1, Math.round(words / 200));
}

/**
 * Build the canonical URL path for a post.
 * `post.slug` includes the content sub-folder (e.g. "windows/foo"), so URLs
 * are collision-free across categories: /posts/windows/foo/.
 */
export function postPath(post: Post): string {
  return `/posts/${post.slug}/`;
}
