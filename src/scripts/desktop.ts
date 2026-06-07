/* =====================================================================
   Desktop environment: window manager (light), Start menu, clock,
   theme toggle, UI sounds, idle screensaver, menu actions.
   All same-origin, no inline handlers -> works under strict CSP.
   ===================================================================== */

const root = document.documentElement;
const reduceMotion = window.matchMedia(
  "(prefers-reduced-motion: reduce)"
).matches;

/* ---------------- Theme ---------------- */
function applyTheme(theme: "light" | "dark") {
  root.setAttribute("data-theme", theme);
  try {
    localStorage.setItem("theme", theme);
  } catch {
    /* ignore */
  }
  document
    .querySelectorAll<HTMLElement>("#theme-toggle")
    .forEach((b) => b.setAttribute("aria-pressed", String(theme === "dark")));
}
function toggleTheme() {
  applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
}

/* ---------------- UI sounds (off by default) ---------------- */
let soundOn = false;
try {
  soundOn = localStorage.getItem("ui-sounds") === "on";
} catch {
  /* ignore */
}
let audioCtx: AudioContext | null = null;
function beep(freq: number, ms: number, vol = 0.04) {
  if (!soundOn || reduceMotion) return;
  try {
    audioCtx =
      audioCtx ||
      new (window.AudioContext || (window as any).webkitAudioContext)();
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    o.type = "square";
    o.frequency.value = freq;
    g.gain.value = vol;
    o.connect(g).connect(audioCtx.destination);
    o.start();
    g.gain.exponentialRampToValueAtTime(
      0.0001,
      audioCtx.currentTime + ms / 1000
    );
    o.stop(audioCtx.currentTime + ms / 1000);
  } catch {
    /* ignore */
  }
}
function updateMuteUI() {
  const btn = document.getElementById("mute-toggle");
  if (!btn) return;
  btn.setAttribute("aria-pressed", String(!soundOn));
  const span = btn.querySelector("span");
  if (span)
    span.textContent =
      span.getAttribute(soundOn ? "data-on" : "data-off") ||
      (soundOn ? "🔊" : "🔈");
  btn.setAttribute(
    "title",
    soundOn ? "Sound: on (click to mute)" : "Sound: off (click to enable)"
  );
}
document.getElementById("mute-toggle")?.addEventListener("click", () => {
  soundOn = !soundOn;
  try {
    localStorage.setItem("ui-sounds", soundOn ? "on" : "off");
  } catch {
    /* ignore */
  }
  updateMuteUI();
  beep(880, 60);
});
updateMuteUI();

/* ---------------- Clock ---------------- */
const clockEl = document.getElementById("clock");
function tick() {
  if (!clockEl) return;
  clockEl.textContent = new Date().toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}
tick();
setInterval(tick, 15000);

/* ---------------- Start menu ---------------- */
const startBtn = document.getElementById("start-button");
const startMenu = document.getElementById("start-menu");
function setStart(open: boolean) {
  if (!startMenu || !startBtn) return;
  startMenu.classList.toggle("open", open);
  startBtn.setAttribute("aria-expanded", String(open));
  if (open) beep(660, 40);
}
startBtn?.addEventListener("click", (e) => {
  e.stopPropagation();
  setStart(!startMenu?.classList.contains("open"));
});
document.addEventListener("click", (e) => {
  if (
    startMenu?.classList.contains("open") &&
    !(e.target as Element).closest("#start-menu, #start-button")
  )
    setStart(false);
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") setStart(false);
});

/* ---------------- Menu bar (close other dropdowns) ---------------- */
const menus = Array.from(
  document.querySelectorAll<HTMLDetailsElement>(".menubar details.menu")
);
menus.forEach((d) => {
  d.addEventListener("toggle", () => {
    if (d.open) menus.forEach((o) => o !== d && (o.open = false));
  });
});
document.addEventListener("click", (e) => {
  if (!(e.target as Element).closest(".menubar"))
    menus.forEach((d) => (d.open = false));
});

/* ---------------- Window manager ---------------- */
interface WinState {
  el: HTMLElement;
  id: string;
  title: string;
  icon: string | null;
  taskBtn: HTMLButtonElement | null;
  minimized: boolean;
}
const taskWrap = document.getElementById("task-windows");
const wins: WinState[] = [];
let zTop = 20;

function focusWin(w: WinState) {
  wins.forEach((o) => {
    o.el.classList.toggle("is-focused", o === w);
    o.el.classList.toggle("is-inactive", o !== w);
    o.taskBtn?.classList.toggle("active", o === w && !o.minimized);
  });
  if (w.el.classList.contains("floating")) {
    w.el.style.zIndex = String(++zTop);
  }
}
function showWin(w: WinState) {
  w.minimized = false;
  w.el.style.display = "";
  focusWin(w);
}
function minimizeWin(w: WinState) {
  w.minimized = true;
  w.el.style.display = "none";
  w.taskBtn?.classList.remove("active");
  beep(440, 50);
}
function closeWin(w: WinState) {
  const action = w.el.getAttribute("data-close");
  beep(330, 70);
  if (action === "back") {
    if (history.length > 1) history.back();
    else window.location.href = "/";
    return;
  }
  w.el.style.display = "none";
  w.taskBtn?.remove();
  w.taskBtn = null;
}

document.querySelectorAll<HTMLElement>(".win[data-win]").forEach((el) => {
  const w: WinState = {
    el,
    id: el.getAttribute("data-win") || "win",
    title: el.getAttribute("data-title") || "Window",
    icon: el.getAttribute("data-icon"),
    taskBtn: null,
    minimized: false,
  };

  // taskbar button
  if (el.hasAttribute("data-taskbar") && taskWrap) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "task-btn active";
    b.innerHTML =
      (w.icon ? `<img src="${w.icon}" alt="" width="16" height="16">` : "") +
      `<span>${w.title}</span>`;
    b.addEventListener("click", () => {
      if (w.minimized) showWin(w);
      else if (el.classList.contains("is-focused")) minimizeWin(w);
      else showWin(w);
    });
    taskWrap.appendChild(b);
    w.taskBtn = b;
  }

  // controls
  el.querySelectorAll<HTMLElement>(".win__btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const act = btn.getAttribute("data-act");
      if (act === "min") minimizeWin(w);
      else if (act === "max") {
        el.classList.toggle("win--max");
        if (el.classList.contains("win--max")) {
          el.style.cssText +=
            ";position:fixed;inset:0 0 40px 0;width:auto;max-width:none;max-height:none;z-index:" +
            ++zTop;
        } else {
          el.style.position = "";
          el.style.inset = "";
          el.style.width = "";
          el.style.maxWidth = "";
          el.style.maxHeight = "";
        }
      } else if (act === "close") closeWin(w);
    });
  });

  el.addEventListener("mousedown", () => focusWin(w));
  wins.push(w);

  // dragging (floating windows only)
  const bar = el.querySelector<HTMLElement>(".win__titlebar.draggable");
  if (bar) enableDrag(el, bar);
});

// focus first window initially
if (wins.length) focusWin(wins[0]);

function enableDrag(el: HTMLElement, handle: HTMLElement) {
  let sx = 0,
    sy = 0,
    ox = 0,
    oy = 0,
    dragging = false;
  const onMove = (e: PointerEvent) => {
    if (!dragging) return;
    const x = Math.max(
      0,
      Math.min(window.innerWidth - 80, ox + (e.clientX - sx))
    );
    const y = Math.max(
      0,
      Math.min(window.innerHeight - 70, oy + (e.clientY - sy))
    );
    el.style.left = x + "px";
    el.style.top = y + "px";
  };
  const onUp = (e: PointerEvent) => {
    dragging = false;
    el.classList.remove("is-dragging");
    handle.releasePointerCapture?.(e.pointerId);
    window.removeEventListener("pointermove", onMove);
    window.removeEventListener("pointerup", onUp);
  };
  handle.addEventListener("pointerdown", (e) => {
    if ((e.target as Element).closest(".win__btn")) return;
    dragging = true;
    el.classList.add("is-dragging");
    const r = el.getBoundingClientRect();
    ox = r.left;
    oy = r.top;
    sx = e.clientX;
    sy = e.clientY;
    el.style.left = ox + "px";
    el.style.top = oy + "px";
    handle.setPointerCapture?.(e.pointerId);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  });
}

/* ---------------- Menu / button actions ([data-act]) ---------------- */
document.addEventListener("click", (e) => {
  const t = (e.target as Element).closest<HTMLElement>("[data-act]");
  if (!t) return;
  const act = t.getAttribute("data-act");
  if (act === "theme") {
    toggleTheme();
    setStart(false);
    menus.forEach((d) => (d.open = false));
  } else if (act === "print") {
    window.print();
  } else if (act === "selectall") {
    const doc = document.querySelector(".doc");
    if (doc) {
      const r = document.createRange();
      r.selectNodeContents(doc);
      const s = getSelection();
      s?.removeAllRanges();
      s?.addRange(r);
    }
  }
});

/* ---------------- Explorer row clicks ---------------- */
document.querySelectorAll<HTMLElement>("tr[data-href]").forEach((tr) => {
  tr.addEventListener("click", (e) => {
    if ((e.target as Element).closest("a")) return; // let real links work
    const href = tr.getAttribute("data-href");
    if (href) window.location.href = href;
  });
});

/* ---------------- small click sound on buttons ---------------- */
document.addEventListener("click", (e) => {
  if ((e.target as Element).closest("button, .btn, .dicon, .task-btn"))
    beep(720, 25);
});

/* ---------------- "/" focuses Find ---------------- */
document.addEventListener("keydown", (e) => {
  const tag = (document.activeElement?.tagName || "").toLowerCase();
  if (e.key === "/" && tag !== "input" && tag !== "textarea") {
    const find = document.getElementById("find-input") as HTMLInputElement;
    if (find) {
      e.preventDefault();
      find.focus();
    } else {
      window.location.href = "/find";
    }
  }
});

/* ---------------- Idle screensaver (bouncing logo) ---------------- */
const saver = document.getElementById("screensaver");
const saverImg = saver?.querySelector("img") as HTMLImageElement | null;
if (saver && saverImg && !reduceMotion) {
  const IDLE_MS = 60000;
  let idleTimer: number | undefined;
  let raf = 0;
  let x = 60,
    y = 60,
    vx = 1.6,
    vy = 1.6;

  function start() {
    saver!.classList.add("on");
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(loop);
  }
  function stop() {
    saver!.classList.remove("on");
    cancelAnimationFrame(raf);
  }
  function loop() {
    const w = saverImg!.offsetWidth || 130;
    const h = saverImg!.offsetHeight || 70;
    x += vx;
    y += vy;
    if (x <= 0) {
      x = 0;
      vx = Math.abs(vx);
    } else if (x >= window.innerWidth - w) {
      x = window.innerWidth - w;
      vx = -Math.abs(vx);
    }
    if (y <= 0) {
      y = 0;
      vy = Math.abs(vy);
    } else if (y >= window.innerHeight - h) {
      y = window.innerHeight - h;
      vy = -Math.abs(vy);
    }
    saverImg!.style.transform = `translate(${x}px, ${y}px)`;
    raf = requestAnimationFrame(loop);
  }
  function resetIdle() {
    if (saver!.classList.contains("on")) stop();
    window.clearTimeout(idleTimer);
    idleTimer = window.setTimeout(start, IDLE_MS);
  }
  ["mousemove", "keydown", "pointerdown", "wheel", "touchstart"].forEach((ev) =>
    window.addEventListener(ev, resetIdle, { passive: true })
  );
  resetIdle();
}

export {};
