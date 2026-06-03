// KI-Bot Zugriffs-Analyzer – Server-Funktion (läuft auf Vercel)
// Prüft für eine gegebene Website, ob die wichtigsten KI-Bots sie lesen dürfen.
import dns from "node:dns/promises";

// --- Die KI-Bots, die wir prüfen ---------------------------------------------
// "token" = der Name, unter dem der Bot in der robots.txt angesprochen wird.
// "ua"    = der echte User-Agent, den der Bot beim Besuch sendet.
const BOTS = [
  {
    name: "GPTBot",
    vendor: "OpenAI",
    token: "GPTBot",
    ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
  },
  {
    name: "ChatGPT-User",
    vendor: "OpenAI",
    token: "ChatGPT-User",
    ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
  },
  {
    name: "OAI-SearchBot",
    vendor: "OpenAI",
    token: "OAI-SearchBot",
    ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
  },
  {
    name: "ClaudeBot",
    vendor: "Anthropic",
    token: "ClaudeBot",
    ua: "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
  },
  {
    name: "Claude-User",
    vendor: "Anthropic",
    token: "Claude-User",
    ua: "Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
  },
  {
    name: "PerplexityBot",
    vendor: "Perplexity",
    token: "PerplexityBot",
    ua: "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
  },
  {
    name: "Perplexity-User",
    vendor: "Perplexity",
    token: "Perplexity-User",
    ua: "Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
  },
];

// --- robots.txt: einlesen und auswerten --------------------------------------
function parseRobots(txt) {
  const groups = [];
  let current = null;
  for (const raw of txt.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (field === "user-agent") {
      // Eine neue User-agent-Zeile nach Regeln beginnt eine neue Gruppe.
      if (current && current.rules.length > 0) {
        groups.push(current);
        current = null;
      }
      if (!current) current = { agents: [], rules: [] };
      current.agents.push(value.toLowerCase());
    } else if (field === "allow" || field === "disallow") {
      if (!current) current = { agents: ["*"], rules: [] };
      current.rules.push({ type: field, path: value });
    }
  }
  if (current) groups.push(current);
  return groups;
}

function rulesForAgent(groups, token) {
  if (!groups) return null;
  const t = token.toLowerCase();
  let exact = null;
  let star = null;
  for (const g of groups) {
    if (g.agents.includes(t) && !exact) exact = g;
    if (g.agents.includes("*") && !star) star = g;
  }
  return exact || star || null;
}

// Wandelt ein robots.txt-Muster (mit * und $) in einen Regex um.
function matchPattern(pattern, path) {
  if (!pattern) return false; // leeres Muster blockt nichts
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") re += ".*";
    else if (c === "$" && i === pattern.length - 1) re += "$";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  try {
    return new RegExp("^" + re).test(path);
  } catch {
    return path.startsWith(pattern);
  }
}

// Längste Übereinstimmung gewinnt; bei Gleichstand gewinnt "Allow".
function isAllowed(rules, path) {
  if (!rules) return true;
  let best = null;
  for (const r of rules.rules) {
    if (matchPattern(r.path, path)) {
      const len = r.path.length;
      if (
        !best ||
        len > best.len ||
        (len === best.len && r.type === "allow")
      ) {
        best = { len, type: r.type };
      }
    }
  }
  return best ? best.type === "allow" : true;
}

// --- Meta-Robots-Tag aus dem HTML lesen --------------------------------------
function extractMeta(html, botToken) {
  if (!html) return "";
  for (const name of [botToken.toLowerCase(), "robots"]) {
    const re = new RegExp(
      '<meta[^>]*name=["\']' + name + '["\'][^>]*>',
      "i"
    );
    const m = html.match(re);
    if (m) {
      const cm = m[0].match(/content=["\']([^"\']*)["\']/i);
      if (cm) return cm[1].trim();
    }
  }
  return "";
}

// --- Eine Website mit einem bestimmten User-Agent abrufen --------------------
async function fetchAs(url, ua, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const start = Date.now();
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": ua,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "de,en;q=0.8",
      },
      redirect: "follow",
      signal: ctrl.signal,
    });
    const ct = res.headers.get("content-type") || "";
    let body = "";
    if (ct.startsWith("text/") || ct.includes("html") || ct.includes("xml") || ct === "") {
      try {
        body = (await res.text()).slice(0, 250000);
      } catch {
        body = "";
      }
    }
    return {
      ok: true,
      status: res.status,
      body,
      xrobots: res.headers.get("x-robots-tag") || "",
      elapsed: Date.now() - start,
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      error: e.name === "AbortError" ? "timeout" : "fetch_failed",
      elapsed: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

// --- Sicherheit: keine internen / privaten Adressen abfragen (SSRF-Schutz) ---
function isPrivateIp(ip) {
  if (ip === "::1") return true;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local / Cloud-Metadaten
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // IPv6 privat
  if (lower.startsWith("fe80")) return true; // IPv6 link-local
  return false;
}

async function isSafeUrl(u) {
  if (!/^https?:$/.test(u.protocol)) return false;
  const host = u.hostname.toLowerCase();
  if (["localhost", "0.0.0.0"].includes(host)) return false;
  if (host.endsWith(".local") || host.endsWith(".internal")) return false;
  if (isPrivateIp(host)) return false;
  try {
    const addrs = await dns.lookup(host, { all: true });
    for (const a of addrs) {
      if (isPrivateIp(a.address)) return false;
    }
  } catch {
    /* DNS-Fehler: dann scheitert fetch ohnehin gleich */
  }
  return true;
}

// --- Haupt-Funktion ----------------------------------------------------------
export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  const send = (status, obj) => {
    res.statusCode = status;
    res.end(JSON.stringify(obj));
  };

  // URL aus der Anfrage lesen und normalisieren.
  let raw;
  try {
    const parsed = new URL(req.url, "http://localhost");
    raw = (parsed.searchParams.get("url") || "").trim();
  } catch {
    return send(400, { error: "Ungültige Anfrage." });
  }
  if (!raw) return send(400, { error: "Bitte eine Website-Adresse angeben." });
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;

  let target;
  try {
    target = new URL(raw);
  } catch {
    return send(400, { error: "Das sieht nicht wie eine gültige Web-Adresse aus." });
  }

  if (!(await isSafeUrl(target))) {
    return send(400, {
      error: "Diese Adresse kann nicht geprüft werden (interne oder ungültige Adresse).",
    });
  }

  // robots.txt einmalig laden.
  let robotsGroups = null;
  let robotsTxtFound = false;
  try {
    const robotsUrl = new URL("/robots.txt", target.origin).toString();
    const r = await fetchAs(robotsUrl, BOTS[0].ua, 8000);
    if (r.ok && r.status >= 200 && r.status < 300 && r.body) {
      robotsTxtFound = true;
      robotsGroups = parseRobots(r.body);
    }
  } catch {
    /* keine robots.txt -> alles erlaubt */
  }

  const path = target.pathname || "/";

  // Alle Bots parallel prüfen.
  const results = await Promise.all(
    BOTS.map(async (bot) => {
      const robotsAllowed = isAllowed(rulesForAgent(robotsGroups, bot.token), path);
      const page = await fetchAs(target.toString(), bot.ua);

      let status; // "allowed" | "blocked" | "error"
      if (!page.ok) status = "error";
      else if (!robotsAllowed) status = "blocked";
      else if (page.status === 403 || page.status === 401 || page.status === 429)
        status = "blocked";
      else if (page.status >= 400) status = "error";
      else status = "allowed";

      let meta = "";
      let xrobots = "";
      if (page.ok) {
        meta = extractMeta(page.body, bot.token);
        xrobots = page.xrobots || "";
      }

      return {
        name: bot.name,
        vendor: bot.vendor,
        status,
        http: page.status || null,
        robotsTxt: robotsAllowed,
        robotsMeta: meta,
        xRobotsTag: xrobots,
        responseTime: page.ok ? (page.elapsed / 1000).toFixed(2) + "s" : null,
        error: page.ok ? null : page.error,
      };
    })
  );

  send(200, {
    url: target.toString(),
    robotsTxtFound,
    testedAt: new Date().toISOString(),
    results,
  });
}
