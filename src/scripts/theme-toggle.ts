// Theme toggle. Persists choice in localStorage; default is dark (set by
// /theme-init.js before paint). Kept as a same-origin module for CSP.
const root = document.documentElement;
const btn = document.getElementById("theme-toggle");

function setTheme(theme: "dark" | "light") {
  root.setAttribute("data-theme", theme);
  try {
    localStorage.setItem("theme", theme);
  } catch {
    /* storage may be unavailable; ignore */
  }
  btn?.setAttribute("aria-pressed", String(theme === "light"));
}

btn?.addEventListener("click", () => {
  const current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
  setTheme(current === "light" ? "dark" : "light");
});
