// Client-side full-text search over a prebuilt JSON index using Fuse.js.
// No network calls beyond the same-origin index; no analytics.
import Fuse from "fuse.js";

interface Doc {
  title: string;
  description: string;
  category: string;
  tags: string[];
  url: string;
  body: string;
}

const input = document.getElementById("search-input") as HTMLInputElement | null;
const results = document.getElementById("search-results");
// Prevent the search form from submitting/reloading (replaces the inline
// onsubmit handler so the page can run under a strict, inline-free CSP).
input
  ?.closest("form")
  ?.addEventListener("submit", (e) => e.preventDefault());
if (input && results) {
  let fuse: Fuse<Doc> | null = null;
  let docs: Doc[] = [];
  let activeIndex = -1;

  async function ensureIndex() {
    if (fuse) return;
    try {
      const res = await fetch("/search-index.json");
      docs = (await res.json()) as Doc[];
      fuse = new Fuse(docs, {
        keys: [
          { name: "title", weight: 0.5 },
          { name: "tags", weight: 0.2 },
          { name: "description", weight: 0.2 },
          { name: "body", weight: 0.1 },
        ],
        threshold: 0.38,
        ignoreLocation: true,
        minMatchCharLength: 2,
      });
    } catch {
      docs = [];
    }
  }

  function close() {
    results!.classList.remove("open");
    results!.innerHTML = "";
    activeIndex = -1;
  }

  function render(matches: Doc[]) {
    if (!input!.value.trim()) {
      close();
      return;
    }
    if (matches.length === 0) {
      results!.innerHTML =
        '<div class="search__empty">No matching notes found.</div>';
      results!.classList.add("open");
      return;
    }
    const items = matches
      .slice(0, 8)
      .map(
        (m) =>
          `<li><a href="${m.url}"><span class="r-cat">${escapeHtml(
            m.category
          )}</span><div class="r-title">${escapeHtml(m.title)}</div></a></li>`
      )
      .join("");
    results!.innerHTML = `<div class="window"><ul role="listbox">${items}</ul></div>`;
    results!.classList.add("open");
    activeIndex = -1;
  }

  function escapeHtml(s: string) {
    return s.replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c] as string
    );
  }

  async function onInput() {
    await ensureIndex();
    const q = input!.value.trim();
    if (!q || !fuse) {
      close();
      return;
    }
    render(fuse.search(q).map((r) => r.item));
  }

  let t: number | undefined;
  input.addEventListener("input", () => {
    window.clearTimeout(t);
    t = window.setTimeout(onInput, 120);
  });
  input.addEventListener("focus", ensureIndex);

  input.addEventListener("keydown", (e) => {
    const links = results!.querySelectorAll<HTMLAnchorElement>("a");
    if (e.key === "Escape") {
      close();
      input!.blur();
    } else if (e.key === "ArrowDown" && links.length) {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, links.length - 1);
      updateActive(links);
    } else if (e.key === "ArrowUp" && links.length) {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      updateActive(links);
    } else if (e.key === "Enter" && activeIndex >= 0 && links[activeIndex]) {
      window.location.href = links[activeIndex].href;
    }
  });

  function updateActive(links: NodeListOf<HTMLAnchorElement>) {
    links.forEach((l, i) => l.classList.toggle("active", i === activeIndex));
    links[activeIndex]?.scrollIntoView({ block: "nearest" });
  }

  document.addEventListener("click", (e) => {
    if (!(e.target as Element)?.closest(".search")) close();
  });

  // Keyboard shortcut: "/" focuses search.
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== input) {
      e.preventDefault();
      input!.focus();
    }
  });
}
