import { defineCollection, z } from "astro:content";

/**
 * Coerce loose YAML truthiness ("yes"/"no"/"true"/true/...) into a boolean.
 * This lets the article template use either `pinned: true` or `pinned: "no"`.
 */
const looseBool = (fallback: boolean) =>
  z
    .union([z.boolean(), z.string()])
    .optional()
    .transform((val) => {
      if (typeof val === "boolean") return val;
      if (typeof val === "string") {
        return ["true", "yes", "y", "1"].includes(val.trim().toLowerCase());
      }
      return fallback;
    });

const posts = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    description: z.string(),
    // Accept "2026-05-31 14:30" or full ISO; coerce to a Date.
    date: z.coerce.date(),
    category: z.string(),
    tags: z.array(z.string()).default([]),

    // Visibility controls (see README for full behaviour).
    published: looseBool(true),
    archived: looseBool(false),
    pinned: looseBool(false),
    featured: looseBool(false),
    draft: looseBool(false),

    author: z.string().optional(),
    coverImage: z.string().optional(),
    readingTime: looseBool(true),
  }),
});

export const collections = { posts };
