import { defineCollection } from "astro:content";
import { z } from "astro/zod";
import { glob } from "astro/loaders";

const postsCollection = defineCollection({
  loader: glob({
    pattern: "**/[^_]*.{md,mdx}",
    base: "./src/content/posts"
  }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()).default([]),
    author: z.string().optional(),
    published: z.boolean().default(true),
    archived: z.boolean().default(false),
    pinned: z.boolean().default(false),
    featured: z.boolean().default(false)
  })
});

export const collections = {
  posts: postsCollection
};