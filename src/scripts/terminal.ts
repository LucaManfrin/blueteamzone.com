/* =====================================================================
   Fake cmd.exe — a harmless, static, client-side terminal toy.
   No eval, no real shell, no network writes. All commands are canned
   lookups, so this adds ZERO attack surface and works under the strict
   `script-src 'self'` CSP (no inline handlers, DOM built with safe APIs).
   ===================================================================== */
import { SITE, SOCIAL, CATEGORIES } from "@/site.config";

const term = document.querySelector<HTMLElement>("[data-terminal]");
const out = document.querySelector<HTMLElement>("[data-term-out]");
const input = document.querySelector<HTMLInputElement>("[data-term-in]");

if (term && out && input) {
  const PROMPT = "C:\\Users\\luca>";
  const history: string[] = [];
  let hIdx = -1;

  /* ---- output helpers (no innerHTML) ---------------------------------- */
  function line(text = "", cls?: string): HTMLDivElement {
    const d = document.createElement("div");
    d.className = "term__row" + (cls ? " " + cls : "");
    d.textContent = text;
    out!.appendChild(d);
    return d;
  }
  function lines(arr: string[], cls?: string) {
    arr.forEach((t) => line(t, cls));
  }
  function linkLine(label: string, href: string, prefix = "") {
    const d = document.createElement("div");
    d.className = "term__row";
    if (prefix) d.appendChild(document.createTextNode(prefix));
    const a = document.createElement("a");
    a.href = href;
    a.textContent = label;
    a.className = "term__link";
    d.appendChild(a);
    out!.appendChild(d);
  }
  function blank() {
    line("");
  }
  function scroll() {
    out!.scrollTop = out!.scrollHeight;
  }

  /* ---- command table -------------------------------------------------- */
  type Cmd = (args: string[], raw: string) => void | Promise<void>;

  const commands: Record<string, Cmd> = {
    help() {
      lines([
        "Available commands:",
        "",
        "  whoami        display the current user",
        "  about         who runs this notebook",
        "  hostname      show the machine name",
        "  ipconfig      show network configuration",
        "  uname         print system information",
        "  ver           show the OS version",
        "  date          show the current date/time",
        "  echo <text>   print text back",
        "  ls | dir      list the notebook sections",
        "  posts         list the latest notes",
        "  open <cat>    open a category (e.g. open linux)",
        "  contact       show external profiles",
        "  banner        reprint the welcome banner",
        "  clear | cls   clear the screen",
        "  exit          close this window",
        "",
        "Tip: up/down arrows cycle command history.",
      ]);
    },

    whoami() {
      line("luca");
      line("uid=1337(luca) gid=1337(analysts) groups=blueteam,redteam", "term__dim");
    },

    about() {
      lines([
        `${SITE.title}`,
        `${SITE.authorName} — ${SITE.authorTitle}`,
        SITE.tagline,
        "",
      ]);
      // wrap the long description nicely
      wrap(SITE.description, 64).forEach((l) => line(l, "term__dim"));
    },

    hostname() {
      line("WORKSTATION-0XLUCA");
    },

    ipconfig() {
      lines([
        "Windows IP Configuration",
        "",
        "Ethernet adapter Notebook:",
        "",
        "   Connection-specific DNS Suffix  . : lan",
        "   IPv4 Address. . . . . . . . . . . : 10.0.0.13",
        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0",
        "   Default Gateway . . . . . . . . . : 10.0.0.1",
      ]);
    },

    uname(args) {
      if (args[0] === "-a")
        line("Linux 0xluca 6.8.0-blueteam #1 SMP x86_64 GNU/Coffee");
      else line("Linux");
    },

    ver() {
      blank();
      line("0xLuca Notebook OS [Version 13.37] — no telemetry, no trackers");
      blank();
    },

    date() {
      line(
        new Date().toLocaleString(undefined, {
          weekday: "short",
          year: "numeric",
          month: "short",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        })
      );
    },

    echo(_args, raw) {
      line(raw.slice(raw.indexOf("echo") + 4).trim());
    },

    ls() {
      line("Directory of C:\\notebook");
      blank();
      CATEGORIES.forEach((c) =>
        linkLine(c.name, `/category/${c.slug}`, "  <DIR>   ")
      );
      linkLine("Find Notes", "/find", "  <DIR>   ");
      blank();
    },

    async posts() {
      line("Fetching latest notes...", "term__dim");
      try {
        const res = await fetch("/search-index.json", { headers: { Accept: "application/json" } });
        const docs: { title: string; url: string; category: string }[] = await res.json();
        // index is already listable-only and date-sorted upstream
        if (!docs.length) {
          line("No published notes yet.");
          return;
        }
        docs.slice(0, 8).forEach((d) => linkLine(d.title, d.url, "  * "));
        blank();
        line(`${Math.min(docs.length, 8)} of ${docs.length} note(s) shown. Type 'open <category>' to browse.`, "term__dim");
      } catch {
        line("Could not load notes. Try the 'ls' command instead.", "term__err");
      }
    },

    open(args) {
      const q = (args[0] || "").toLowerCase();
      if (!q) {
        line("Usage: open <category>  (try: open linux)", "term__err");
        return;
      }
      const cat = CATEGORIES.find(
        (c) => c.slug === q || c.name.toLowerCase().replace(/\s+/g, "") === q.replace(/\s+/g, "")
      );
      if (cat) {
        line(`Opening ${cat.name}...`);
        window.location.href = `/category/${cat.slug}`;
      } else {
        line(`No such section: ${q}`, "term__err");
        line("Type 'ls' to list sections.", "term__dim");
      }
    },

    contact() {
      line("External profiles:");
      blank();
      if (SOCIAL.github) linkLine("GitHub", SOCIAL.github, "  ");
      if (SOCIAL.linkedin) linkLine("LinkedIn", SOCIAL.linkedin, "  ");
      if (SOCIAL.credly) linkLine("Credly", SOCIAL.credly, "  ");
      blank();
    },

    banner() {
      printBanner();
    },

    clear() {
      out!.replaceChildren();
    },
    cls() {
      out!.replaceChildren();
    },

    exit() {
      line("Closing...");
      const win = term!.closest<HTMLElement>(".win");
      const close = win?.querySelector<HTMLElement>('.win__btn[data-act="close"]');
      if (close) setTimeout(() => close.click(), 250);
    },

    /* ---- easter eggs --------------------------------------------------- */
    hack() {
      lines([
        "Initializing exploit kit...",
        "[####################] 100%",
        "Bypassing mainframe firewall...    OK",
        "Rerouting through 7 proxies...     OK",
        "ACCESS GRANTED.",
        "",
        "Just kidding. The only thing compromised here is your free time. :)",
      ]);
    },
    matrix() {
      const cols = 40;
      const charset = "01<>/$#@*";
      for (let i = 0; i < 6; i++) {
        let s = "";
        for (let j = 0; j < cols; j++) s += charset[Math.floor(Math.random() * charset.length)];
        line(s, "term__matrix");
      }
      line("Wake up, analyst...", "term__dim");
    },
    coffee() {
      line("HTTP 418: I'm a teapot. ☕ No coffee for you.");
    },
  };

  /* ---- helpers -------------------------------------------------------- */
  function wrap(text: string, width: number): string[] {
    const words = text.split(/\s+/);
    const res: string[] = [];
    let cur = "";
    for (const w of words) {
      if ((cur + " " + w).trim().length > width) {
        res.push(cur.trim());
        cur = w;
      } else cur += " " + w;
    }
    if (cur.trim()) res.push(cur.trim());
    return res;
  }

  function printBanner() {
    lines([
      `${SITE.title} — cmd.exe`,
      "0xLuca Notebook OS [Version 13.37]",
      "(c) Notebook. Not a real shell. All output is canned & harmless.",
      "",
      "Type 'help' for a list of commands.",
      "",
    ], "term__dim");
  }

  function echoPrompt(cmd: string) {
    const d = document.createElement("div");
    d.className = "term__row term__cmd";
    d.textContent = `${PROMPT} ${cmd}`;
    out!.appendChild(d);
  }

  async function run(raw: string) {
    const trimmed = raw.trim();
    echoPrompt(trimmed);
    if (trimmed) {
      history.push(trimmed);
      if (history.length > 50) history.shift();
    }
    hIdx = history.length;
    if (trimmed) {
      const parts = trimmed.split(/\s+/);
      const name = parts[0].toLowerCase();
      const args = parts.slice(1);
      const fn = commands[name];
      if (fn) {
        try {
          await fn(args, trimmed);
        } catch {
          line("Command failed.", "term__err");
        }
      } else {
        line(`'${parts[0]}' is not recognized as an internal or external command,`, "term__err");
        line("operable program or batch file.", "term__err");
      }
    }
    blank();
    scroll();
  }

  /* ---- input handling ------------------------------------------------- */
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const v = input.value;
      input.value = "";
      void run(v);
    } else if (e.key === "ArrowUp") {
      if (history.length) {
        hIdx = Math.max(0, hIdx - 1);
        input.value = history[hIdx] || "";
        e.preventDefault();
      }
    } else if (e.key === "ArrowDown") {
      if (history.length) {
        hIdx = Math.min(history.length, hIdx + 1);
        input.value = history[hIdx] || "";
        e.preventDefault();
      }
    } else if (e.key === "l" && e.ctrlKey) {
      out!.replaceChildren();
      e.preventDefault();
    }
  });

  // Click anywhere in the terminal focuses the prompt (unless selecting a link).
  term.addEventListener("mousedown", (e) => {
    if ((e.target as Element).closest("a")) return;
    setTimeout(() => input.focus(), 0);
  });

  // Focus the prompt whenever the cmd window is opened.
  document.querySelectorAll<HTMLElement>('[data-open="terminal"]').forEach((el) =>
    el.addEventListener("click", () => setTimeout(() => input.focus(), 60))
  );
  term.closest<HTMLElement>(".win")?.addEventListener("click", (e) => {
    if ((e.target as Element).closest(".win__titlebar, a")) return;
    setTimeout(() => input.focus(), 0);
  });

  printBanner();
  scroll();
}

export {};
