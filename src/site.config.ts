/**
 * =====================================================================
 *  SITE CONFIGURATION  --  edit this file to make the blog yours.
 * =====================================================================
 *  This is the ONLY file you need to touch for personal details.
 *  Nothing here exposes secrets: it is all public, build-time data.
 * ---------------------------------------------------------------------
 */

export interface SiteConfig {
  /** Canonical production URL. No trailing slash. */
  url: string;
  /** Short site title (used in <title>, header, OG). */
  title: string;
  /** One-line tagline shown in the header. */
  tagline: string;
  /** Longer blog description for the homepage + meta description. */
  description: string;
  /** Display name shown in the header. */
  authorName: string;
  /** Professional title shown under the name. */
  authorTitle: string;
  /** Default author used when a post omits the `author` field. */
  defaultAuthor: string;
  /** Default language tag, e.g. "en". */
  lang: string;
  /** Default Open Graph image (in /public). */
  defaultOgImage: string;
}

export const SITE: SiteConfig = {
  url: "https://lucamanfrin.it",
  title: "0xLuca // notes",
  tagline: "field notes from the blue & red side",
  description:
    "A personal cyber security notebook: practical write-ups on Windows, " +
    "Active Directory, Linux, macOS, threat hunting and the tools that " +
    "make it all tick. No fluff, no trackers, just signal.",
  authorName: "Luca Manfrin",
  authorTitle: "Cyber Security Specialist",
  defaultAuthor: "Luca Manfrin",
  lang: "en",
  defaultOgImage: "/images/website-logo.png",
};

/**
 * Social / external links shown in the footer / taskbar tray.
 * Leave a value as an empty string ("") to hide that link.
 * Only these three link types are exposed -- no email, phone or address.
 */
export const SOCIAL = {
  github: "https://github.com/LucaManfrin",
  linkedin: "https://www.linkedin.com/in/lucamanfrin--",
  credly: "https://www.credly.com/users/luca-manfrin.600e2ebe",
} as const;

/**
 * Categories. The architecture reads categories from each post's frontmatter,
 * so a brand-new category works just by writing a post with a new `category`.
 * This list only controls ORDER and the friendly labels for the built-in nav.
 */
export interface Category {
  slug: string;
  name: string;
  description: string;
}

export const CATEGORIES: Category[] = [
  {
    slug: "windows",
    name: "Windows",
    description: "Windows internals, hardening, logging and exploitation.",
  },
  {
    slug: "active-directory",
    name: "Active Directory",
    description: "AD attacks, defenses, Kerberos, and identity security.",
  },
  {
    slug: "linux",
    name: "Linux",
    description: "Linux hardening, forensics, and offensive tradecraft.",
  },
  {
    slug: "macos",
    name: "macOS",
    description: "macOS security, endpoint telemetry, and persistence.",
  },
  {
    slug: "threat-hunting",
    name: "Threat Hunting",
    description: "Hypotheses, detections, and hunting across telemetry.",
  },
  {
    slug: "tools",
    name: "Security Tools",
    description: "Tooling deep-dives, reviews, and how to build your own.",
  },
];

export const POSTS_PER_PAGE = 9;
export const HOME_LATEST_COUNT = 3;
export const HOME_PINNED_COUNT = 3;
export const RELATED_COUNT = 3;

export function categorySlug(name: string): string {
  const known = CATEGORIES.find(
    (c) => c.name.toLowerCase() === name.toLowerCase()
  );
  if (known) return known.slug;
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export function categoryBySlug(slug: string): Category | undefined {
  return CATEGORIES.find((c) => c.slug === slug);
}
