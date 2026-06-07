// Table-of-contents scroll-spy: highlights the heading currently in view.
const tocLinks = Array.from(
  document.querySelectorAll<HTMLAnchorElement>(".toc a")
);
if (tocLinks.length) {
  const map = new Map<string, HTMLAnchorElement>();
  tocLinks.forEach((l) => {
    const id = decodeURIComponent(l.hash.slice(1));
    if (id) map.set(id, l);
  });
  const headings = tocLinks
    .map((l) => document.getElementById(decodeURIComponent(l.hash.slice(1))))
    .filter((h): h is HTMLElement => Boolean(h));

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          tocLinks.forEach((l) => l.classList.remove("active"));
          map.get(entry.target.id)?.classList.add("active");
        }
      });
    },
    { rootMargin: "-90px 0px -70% 0px", threshold: 0 }
  );
  headings.forEach((h) => observer.observe(h));
}
