// Subtle always-on "DVD logo" bouncer. Low opacity, behind content,
// pointer-events:none. Honors prefers-reduced-motion (hidden via CSS).
const el = document.getElementById("dvd-bouncer");
if (
  el &&
  !window.matchMedia("(prefers-reduced-motion: reduce)").matches
) {
  const accents = ["#f2a65a", "#4ec9b0", "#c792ea", "#9ad36b", "#ef6f6f"];
  let x = Math.random() * (window.innerWidth - 120);
  let y = Math.random() * (window.innerHeight - 120);
  let vx = 0.55;
  let vy = 0.55;

  function recolor() {
    if (!el) return;
    const c = accents[Math.floor(Math.random() * accents.length)];
    el.style.setProperty("--bounce-color", c);
    const paths = el.querySelectorAll<SVGElement>("[data-tint]");
    paths.forEach((p) => (p.style.stroke = c));
    const fills = el.querySelectorAll<SVGElement>("[data-fill]");
    fills.forEach((p) => (p.style.fill = c));
  }
  recolor();

  function frame() {
    if (!el) return;
    const w = el.offsetWidth;
    const h = el.offsetHeight;
    const maxX = window.innerWidth - w;
    const maxY = window.innerHeight - h;
    x += vx;
    y += vy;
    let hit = false;
    if (x <= 0) {
      x = 0;
      vx = Math.abs(vx);
      hit = true;
    } else if (x >= maxX) {
      x = maxX;
      vx = -Math.abs(vx);
      hit = true;
    }
    if (y <= 0) {
      y = 0;
      vy = Math.abs(vy);
      hit = true;
    } else if (y >= maxY) {
      y = maxY;
      vy = -Math.abs(vy);
      hit = true;
    }
    if (hit) recolor();
    el.style.transform = `translate(${x}px, ${y}px)`;
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}
