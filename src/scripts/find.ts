// Search for the Find: Notes window. Uses the prebuilt same-origin index.
import Fuse from "fuse.js";

interface Doc {
  title: string;
  description: string;
  category: string;
  tags: string[];
  url: string;
  body: string;
}

const input = document.getElementById("find-input") as HTMLInputElement | null;
const out = document.getElementById("find-results");
const form = input?.closest("form");
form?.addEventListener("submit", (e) => e.preventDefault());

if (input && out) {
  let fuse: Fuse<Doc> | null = null;

  function esc(s: string) {
    return s.replace(
      /[&<>"']/g,
      (c) =>
        (({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        }) as Record<string, string>)[c]
    );
  }

  async function ensure() {
    if (fuse) return;
    try {
      const res = await fetch("/search-index.json");
      const docs = (await res.json()) as Doc[];
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
      out!.innerHTML =
        '<div class="search-empty">Could not load the search index.</div>';
    }
  }

  function render(items: Doc[]) {
    if (!input!.value.trim()) {
      out!.innerHTML =
        '<div class="search-empty">Start typing to search…</div>';
      return;
    }
    if (!items.length) {
      out!.innerHTML =
        '<div class="search-empty">No notes match your search.</div>';
      return;
    }
    const rows = items
      .slice(0, 30)
      .map(
        (m) =>
          `<tr data-href="${m.url}"><td><span class="name"><img src="/icons/doc.svg" alt="" width="16" height="16"><a href="${m.url}">${esc(
            m.title
          )}</a></span></td><td class="col-hide-sm col-cat">${esc(
            m.category
          )}</td></tr>`
      )
      .join("");
    out!.innerHTML = `<table class="explorer"><thead><tr><th>Name</th><th class="col-hide-sm">Category</th></tr></thead><tbody>${rows}</tbody></table>`;
    out!.querySelectorAll<HTMLElement>("tr[data-href]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if ((e.target as Element).closest("a")) return;
        window.location.href = tr.getAttribute("data-href")!;
      });
    });
  }

  let t: number | undefined;
  async function run() {
    await ensure();
    if (!fuse) return;
    const q = input!.value.trim();
    render(q ? fuse.search(q).map((r) => r.item) : []);
  }
  input.addEventListener("input", () => {
    window.clearTimeout(t);
    t = window.setTimeout(run, 110);
  });
  input.addEventListener("focus", ensure);

  // Pre-fill from ?q= and run.
  const q = new URLSearchParams(location.search).get("q");
  if (q) {
    input.value = q;
    run();
  }
}
