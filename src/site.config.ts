export interface SiteConfig {
  url: string;
  title: string;
  description: string;
  author: string;
  authorTitle: string;
  lang: string;
}

export const SITE: SiteConfig = {
  url: "https://blueteamzone.com",
  title: "BLUE TEAM ZONE",
  description:
    "A personal cyber security notebook: practical write-ups on Windows, AD, Linux, macOS, Threat Hunting and Security Tools.",
  author: "Luca Manfrin",
  authorTitle: "Cyber Security Specialist",
  lang: "en",
};

export const SOCIAL = {
  github: "https://github.com/LucaManfrin",
  linkedin: "https://www.linkedin.com/in/lucamanfrin--",
  credly: "https://www.credly.com/users/luca-manfrin.600e2ebe",
  mail: "hello@blueteamzone.com",
};

export const CATEGORIES = [
  { slug: "Windows", label: "Windows" },
  { slug: "Active-Directory", label: "Active Directory" },
  { slug: "Linux", label: "Linux" },
  { slug: "macOS", label: "macOS" },
  { slug: "Threat-Hunting", label: "Threat Hunting" },
  { slug: "Tools", label: "Security Tools" },
];

export const POSTS_PER_PAGE = 10;
