
(() => {
  const THEME_KEY = "theme";
  const root = document.documentElement;

  // Apply the saved theme immediately.
  let theme = "dark";

  try {
    if (localStorage.getItem(THEME_KEY) === "light") {
      theme = "light";
    }
  } catch {
    // Keep dark mode if localStorage is unavailable.
  }

  root.dataset.theme = theme;

  function updateButton(button) {
    const isDark = root.dataset.theme === "dark";

    button.textContent = isDark ? "☀️" : "🌙";

    const label = isDark
      ? "Switch to light mode"
      : "Switch to dark mode";

    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.setAttribute("aria-pressed", String(!isDark));
  }

  function initThemeToggle() {
    const button = document.getElementById("theme-toggle");

    if (!button) return;

    updateButton(button);

    button.addEventListener("click", () => {
      const nextTheme =
        root.dataset.theme === "dark" ? "light" : "dark";

      root.dataset.theme = nextTheme;

      try {
        localStorage.setItem(THEME_KEY, nextTheme);
      } catch {
        // Theme switching still works without storage.
      }

      updateButton(button);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initThemeToggle,
      { once: true }
    );
  } else {
    initThemeToggle();
  }
})();
