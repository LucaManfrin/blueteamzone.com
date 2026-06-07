import getReadingTime from "reading-time";
import { toString } from "mdast-util-to-string";

/**
 * Injects `minutesRead` into each Markdown file's frontmatter so it can be
 * read via `post.data.astro.frontmatter.minutesRead` and surfaced in the UI.
 */
export function remarkReadingTime() {
  return function (tree, { data }) {
    const textOnPage = toString(tree);
    const readingTime = getReadingTime(textOnPage);
    data.astro.frontmatter.minutesRead = Math.max(
      1,
      Math.round(readingTime.minutes)
    );
  };
}
