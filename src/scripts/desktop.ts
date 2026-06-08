/* =====================================================================
   Desktop environment: window manager (light), Start menu, clock,
   theme toggle, UI sounds, menu actions.
   All same-origin, no inline handlers -> works under strict CSP.
   ===================================================================== */

const root = document.documentElement;
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function updateThemeUI() {
  const dark = root.getAttribute("data-theme") === "dark";
  document
    .querySelectorAll<HTMLElement>("#theme-toggle")
    .forEach((b) => b.setAttribute("aria-pressed", String(dark)));
  document
    .querySelectorAll<HTMLElement>("[data-theme-label]")
    .forEach((el) => (el.textContent = dark ? "Light Mode" : "Night Mode"));
  const ico = document.getElementById("theme-ico");
  if (ico) ico.textContent = dark ? "◑" : "◐";
}
function applyTheme(theme: "light" | "dark") {
  root.setAttribute("data-theme", theme);
  try {
    localStorage.setItem("theme", theme);
  } catch {
    /* ignore */
  }
  updateThemeUI();
}
function toggleTheme() {
  applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
}
updateThemeUI();

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
    audioCtx = audioCtx || new (window.AudioContext || (window as any).webkitAudioContext)();
    const o = audioCtx.createOscillator();
    const g = audioCtx.createGain();
    o.type = "square";
    o.frequency.value = freq;
    g.gain.value = vol;
    o.connect(g).connect(audioCtx.destination);
    o.start();
    g.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + ms / 1000);
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
      span.getAttribute(soundOn ? "data-on" : "data-off") || (soundOn ? "🔊" : "🔈");
  btn.setAttribute("title", soundOn ? "Sound: on (click to mute)" : "Sound: off (click to enable)");
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

const menus = Array.from(
  document.querySelectorAll<HTMLDetailsElement>(".menubar details.menu")
);
menus.forEach((d) => {
  d.addEventListener("toggle", () => {
    if (d.open) menus.forEach((o) => o !== d && (o.open = false));
  });
});
document.addEventListener("click", (e) => {
  if (!(e.target as Element).closest(".menubar")) menus.forEach((d) => (d.open = false));
});

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
  if (w.el.classList.contains("floating") && !w.el.classList.contains("win--max")) {
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
  // Desktop windows: hide but keep the taskbar button so it can be reopened.
  minimizeWin(w);
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

  if (el.hasAttribute("data-taskbar") && taskWrap) {
    // Build the taskbar button with safe DOM APIs (no innerHTML) so a window
    // title can never inject markup.
    const b = document.createElement("button");
    b.type = "button";
    b.className = "task-btn active";
    if (w.icon) {
      const img = document.createElement("img");
      img.src = w.icon;
      img.alt = "";
      img.width = 16;
      img.height = 16;
      b.appendChild(img);
    }
    const span = document.createElement("span");
    span.textContent = w.title;
    b.appendChild(span);
    b.addEventListener("click", () => {
      if (w.minimized) showWin(w);
      else if (el.classList.contains("is-focused")) minimizeWin(w);
      else showWin(w);
    });
    taskWrap.appendChild(b);
    w.taskBtn = b;
  }

  // Windows that start hidden (e.g. the cmd.exe toy) open via their icon.
  if (el.style.display === "none") {
    w.minimized = true;
    w.taskBtn?.classList.remove("active");
  }

  el.querySelectorAll<HTMLElement>(".win__btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const act = btn.getAttribute("data-act");
      if (act === "min") minimizeWin(w);
      else if (act === "max") {
        // Fullscreen is handled purely by the .win--max CSS class, so the
        // window's original inline left/top/width are preserved and restored
        // exactly when un-maximized (no jumping behind the desktop icons).
        const maxed = el.classList.toggle("win--max");
        if (!maxed) focusWin(w);
      } else if (act === "close") closeWin(w);
    });
  });

  el.addEventListener("mousedown", () => focusWin(w));
  wins.push(w);

  const bar = el.querySelector<HTMLElement>(".win__titlebar.draggable");
  if (bar) enableDrag(el, bar);
});

if (wins.length) {
  const firstVisible = wins.find((w) => !w.minimized) || wins[0];
  focusWin(firstVisible);
}

// Icons / buttons that open a desktop window (e.g. the Profile icon).
document.querySelectorAll<HTMLElement>("[data-open]").forEach((a) => {
  a.addEventListener("click", (e) => {
    const id = a.getAttribute("data-open");
    const w = wins.find((x) => x.id === id);
    if (w) {
      e.preventDefault();
      showWin(w);
      setStart(false);
    }
  });
});

function enableDrag(el: HTMLElement, handle: HTMLElement) {
  let sx = 0,
    sy = 0,
    ox = 0,
    oy = 0,
    dragging = false;
  const onMove = (e: PointerEvent) => {
    if (!dragging) return;
    const x = Math.max(0, Math.min(window.innerWidth - 80, ox + (e.clientX - sx)));
    const y = Math.max(0, Math.min(window.innerHeight - 70, oy + (e.clientY - sy)));
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
    if (el.classList.contains("win--max")) return;
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

document.querySelectorAll<HTMLElement>("tr[data-href]").forEach((tr) => {
  tr.addEventListener("click", (e) => {
    if ((e.target as Element).closest("a")) return;
    const href = tr.getAttribute("data-href");
    if (href) window.location.href = href;
  });
});

document.addEventListener("click", (e) => {
  if ((e.target as Element).closest("button, .btn, .dicon, .task-btn")) beep(720, 25);
});

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

export {};
