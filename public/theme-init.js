/* Anti-FOUC theme bootstrap. Loaded as a blocking, same-origin script in
   <head> so the correct theme is applied before first paint.
   Kept external (not inline) so the Content-Security-Policy can stay strict:
   script-src 'self'  (no 'unsafe-inline', no hashes to maintain). */
(function () {
  try {
    var stored = localStorage.getItem("theme");
    // Authentic Win98/XP look is light by default; "dark" is night mode.
    var theme = stored === "light" || stored === "dark" ? stored : "light";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();
