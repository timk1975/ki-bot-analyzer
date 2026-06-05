// KI-Bot Zugriffs-Analyzer + GEO-Check – erweiterter Server-Endpoint (Vercel)
// - Prüft Bot-Zugriffe wie bisher
// - Zusätzlich: 11 GEO-Merkmale + Bonus-Check auf llms.txt
import dns from "node:dns/promises";

const BOTS = [
  { name: "GPTBot",          vendor: "OpenAI",     token: "GPTBot",          ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot" },
  { name: "ChatGPT-User",    vendor: "OpenAI",     token: "ChatGPT-User",    ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot" },
  { name: "OAI-SearchBot",   vendor: "OpenAI",     token: "OAI-SearchBot",   ua: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot" },
  { name: "ClaudeBot",       vendor: "Anthropic",  token: "ClaudeBot",       ua: "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)" },
  { name: "Claude-User",     vendor: "Anthropic",  token: "Claude-User",     ua: "Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)" },
  { name: "PerplexityBot",   vendor: "Perplexity", token: "PerplexityBot",   ua: "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)" },
  { name: "Perplexity-User", vendor: "Perplexity", token: "Perplexity-User", ua: "Mozilla/5.0 (compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)" },
];

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
      if (current && current.rules.length > 0) { groups.push(current); current = null; }
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
  let exact = null, star = null;
  for (const g of groups) {
    if (g.agents.includes(t) && !exact) exact = g;
    if (g.agents.includes("*") && !star) star = g;
  }
  return exact || star || null;
}

function matchPattern(pattern, path) {
  if (!pattern) return false;
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") re += ".*";
    else if (c === "$" && i === pattern.length - 1) re += "$";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  try { return new RegExp("^" + re).test(path); } catch { return path.startsWith(pattern); }
}

function isAllowed(rules, path) {
  if (!rules) return true;
  let best = null;
  for (const r of rules.rules) {
    if (matchPattern(r.path, path)) {
      const len = r.path.length;
      if (!best || len > best.len || (len === best.len && r.type === "allow")) {
        best = { len, type: r.type };
      }
    }
  }
  return best ? best.type === "allow" : true;
}

function extractMeta(html, botToken) {
  if (!html) return "";
  for (const name of [botToken.toLowerCase(), "robots"]) {
    const re = new RegExp('<meta[^>]*name=["\']' + name + '["\'][^>]*>', "i");
    const m = html.match(re);
    if (m) {
      const cm = m[0].match(/content=["\']([^"\']*)["\']/i);
      if (cm) return cm[1].trim();
    }
  }
  return "";
}

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
      try { body = (await res.text()).slice(0, 500000); } catch { body = ""; }
    }
    return {
      ok: true,
      status: res.status,
      body,
      finalUrl: res.url || url,
      xrobots: res.headers.get("x-robots-tag") || "",
      elapsed: Date.now() - start,
    };
  } catch (e) {
    return {
      ok: false, status: 0,
      error: e.name === "AbortError" ? "timeout" : "fetch_failed",
      elapsed: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

function isPrivateIp(ip) {
  if (ip === "::1") return true;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  const lower = ip.toLowerCase();
  if (lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80")) return true;
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
    for (const a of addrs) if (isPrivateIp(a.address)) return false;
  } catch {}
  return true;
}

function stripTags(s) { return String(s || "").replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim(); }

function findAttr(tag, attr) {
  const re = new RegExp(attr + '\\s*=\\s*["\']([^"\']*)["\']', "i");
  const m = tag.match(re);
  return m ? m[1].trim() : "";
}

function findAllTags(html, tagName) {
  const re = new RegExp("<" + tagName + "\\b[^>]*>([\\s\\S]*?)</" + tagName + ">", "gi");
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) out.push({ full: m[0], inner: m[1] });
  return out;
}

function findAllMeta(html, key, value) {
  const re = new RegExp('<meta[^>]*' + key + '\\s*=\\s*["\']' + value + '["\'][^>]*>', "gi");
  const out = [];
  let m;
  while ((m = re.exec(html)) !== null) out.push(m[0]);
  return out;
}

function getMetaContent(html, key, value) {
  const tags = findAllMeta(html, key, value);
  if (!tags.length) return "";
  return findAttr(tags[0], "content");
}

function getTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return m ? stripTags(m[1]) : "";
}

function getLang(html) {
  const m = html.match(/<html[^>]*lang\s*=\s*["']([^"']+)["']/i);
  return m ? m[1].trim() : "";
}

function getCanonical(html) {
  const m = html.match(/<link[^>]*rel\s*=\s*["']canonical["'][^>]*>/i);
  if (!m) return "";
  return findAttr(m[0], "href");
}

function getJsonLd(html) {
  const re = /<script[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  const blocks = [];
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const cleaned = m[1].trim().replace(/^﻿/, "");
      const parsed = JSON.parse(cleaned);
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of arr) {
        if (item && item["@graph"] && Array.isArray(item["@graph"])) {
          for (const g of item["@graph"]) blocks.push(g);
        } else {
          blocks.push(item);
        }
      }
    } catch {}
  }
  return blocks;
}

function schemaTypes(blocks) {
  const types = new Set();
  for (const b of blocks) {
    if (!b) continue;
    const t = b["@type"];
    if (typeof t === "string") types.add(t);
    else if (Array.isArray(t)) t.forEach(x => types.add(String(x)));
  }
  return [...types];
}

function wordCount(html) {
  let scope = html;
  const main = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i)
            || html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i);
  if (main) scope = main[1];
  scope = scope.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ");
  return stripTags(scope).split(/\s+/).filter(Boolean).length;
}

function runGeoChecks(html, finalUrl) {
  const checks = [];
  const add = (key, label, status, value, recommendation) =>
    checks.push({ key, label, status, value, recommendation });

  {
    const title = getTitle(html);
    const len = title.length;
    if (!title) {
      add("title", "Title-Tag", "fail", "nicht vorhanden",
        "Ohne Title-Tag fehlt KIs der wichtigste Zusammenfassungs-Anker. Füge <title>...</title> mit 30–65 Zeichen hinzu, das das Hauptthema klar benennt.");
    } else if (len < 30 || len > 65) {
      add("title", "Title-Tag", "warn", `vorhanden, ${len} Zeichen: „${title.slice(0, 80)}"`,
        `Ideallänge sind 30–65 Zeichen (aktuell ${len}). Zu kurz wirkt unspezifisch, zu lang wird gekürzt. Optimiere den Titel, sodass das Kernthema in den ersten 60 Zeichen steht.`);
    } else {
      add("title", "Title-Tag", "pass", `„${title}" (${len} Z.)`,
        "Sehr gut. KIs nutzen diesen Titel oft direkt als Zitations-Überschrift.");
    }
  }

  {
    const desc = getMetaContent(html, "name", "description");
    const len = desc.length;
    if (!desc) {
      add("description", "Meta-Description", "fail", "nicht vorhanden",
        "Fehlt — KIs müssen sich aus dem Fließtext selbst eine Zusammenfassung bauen. Setze eine prägnante Meta-Description mit 50–160 Zeichen, die den Mehrwert klar formuliert.");
    } else if (len < 50 || len > 160) {
      add("description", "Meta-Description", "warn", `vorhanden, ${len} Zeichen`,
        `Ideallänge sind 50–160 Zeichen (aktuell ${len}). Zu kurz vermittelt wenig, zu lang wird abgeschnitten.`);
    } else {
      add("description", "Meta-Description", "pass", `${len} Zeichen: „${desc.slice(0, 100)}…"`,
        "KIs verwenden diese Beschreibung häufig 1:1 in Antwort-Snippets.");
    }
  }

  {
    const h1s = findAllTags(html, "h1").map(x => stripTags(x.inner)).filter(Boolean);
    if (h1s.length === 0) {
      add("h1", "H1-Überschrift", "fail", "keine H1 gefunden",
        "Ohne H1 fehlt das Haupt-Thema-Signal. Jede Seite sollte genau eine H1 haben, die ihren Inhalt klar benennt.");
    } else if (h1s.length > 1) {
      add("h1", "H1-Überschrift", "warn", `${h1s.length} H1-Tags gefunden`,
        "Mehrere H1 verwirren die thematische Hierarchie. Reduziere auf genau eine H1; nutze H2/H3 für Unterabschnitte.");
    } else {
      add("h1", "H1-Überschrift", "pass", `„${h1s[0].slice(0, 100)}"`,
        "Klare Hauptüberschrift — hilft KIs, das Hauptthema sofort zu erfassen.");
    }
  }

  {
    const blocks = getJsonLd(html);
    const types = schemaTypes(blocks);
    const valuable = ["Article", "BlogPosting", "NewsArticle", "Organization", "LocalBusiness", "Person", "FAQPage", "HowTo", "Product", "Service", "WebSite", "WebPage", "BreadcrumbList"];
    const found = types.filter(t => valuable.includes(t));
    if (blocks.length === 0) {
      add("schema", "Strukturierte Daten (Schema.org)", "fail", "keine JSON-LD-Markierungen gefunden",
        "Schema.org/JSON-LD ist eines der wichtigsten GEO-Signale. KIs lesen strukturierte Daten bevorzugt. Mindestens Organization (für Firmen) oder Person (für Personenmarken) sowie Article/BlogPosting für Inhalte einbinden.");
    } else if (found.length === 0) {
      add("schema", "Strukturierte Daten (Schema.org)", "warn", `vorhanden, aber ohne Kerntypen (${types.slice(0,5).join(", ") || "—"})`,
        "Schema vorhanden, aber ohne die für KI besonders relevanten Typen wie Organization, Person, Article oder FAQPage. Ergänze passende Typen mit Beschreibung, Autor, Datum und Verknüpfungen.");
    } else {
      add("schema", "Strukturierte Daten (Schema.org)", "pass", `${blocks.length} Block(s), Typen: ${found.join(", ")}`,
        "Sehr gut. Diese Markierungen helfen KIs, dich korrekt einzuordnen und zu zitieren.");
    }
  }

  {
    const ogTitle = getMetaContent(html, "property", "og:title");
    const ogDesc  = getMetaContent(html, "property", "og:description");
    const ogImg   = getMetaContent(html, "property", "og:image");
    const present = [ogTitle && "og:title", ogDesc && "og:description", ogImg && "og:image"].filter(Boolean);
    if (present.length === 0) {
      add("og", "Open Graph", "fail", "keine OG-Tags vorhanden",
        "Open Graph steuert Vorschauen in Social Media und vielen KI-Tools. Setze mindestens og:title, og:description und og:image.");
    } else if (present.length < 3) {
      add("og", "Open Graph", "warn", `nur ${present.join(", ")}`,
        "Open Graph ist teilweise vorhanden. Ergänze die fehlenden Tags für vollständige, ansprechende Vorschauen.");
    } else {
      add("og", "Open Graph", "pass", "og:title, og:description, og:image vorhanden",
        "Saubere Vorschau-Konfiguration für KI- und Social-Snippets.");
    }
  }

  {
    const c = getCanonical(html);
    if (!c) {
      add("canonical", "Canonical-URL", "warn", "kein <link rel=\"canonical\"> gefunden",
        "Ohne Canonical riskierst du, dass KIs verschiedene URL-Varianten als getrennte Quellen behandeln. Setze auf jeder Seite einen Canonical-Verweis auf die kanonische Adresse.");
    } else {
      add("canonical", "Canonical-URL", "pass", c,
        "Verhindert Duplicate-Content-Verwirrung für KIs.");
    }
  }

  {
    const blocks = getJsonLd(html);
    const hasAuthorSchema = blocks.some(b => b && (b.author || b["@type"] === "Person" || (Array.isArray(b["@type"]) && b["@type"].includes("Person"))));
    const hasDateSchema = blocks.some(b => b && (b.datePublished || b.dateModified));
    const metaAuthor = getMetaContent(html, "name", "author");
    const articlePub = getMetaContent(html, "property", "article:published_time");
    const hasAuthor = hasAuthorSchema || !!metaAuthor;
    const hasDate = hasDateSchema || !!articlePub;
    if (hasAuthor && hasDate) {
      add("authorDate", "Autor & Datum", "pass", "beides erkannt",
        "E-E-A-T-Signale: KIs gewichten Inhalte mit erkennbarem Autor und Datum als vertrauenswürdiger.");
    } else if (hasAuthor || hasDate) {
      add("authorDate", "Autor & Datum", "warn", hasAuthor ? "nur Autor erkannt" : "nur Datum erkannt",
        "Für stärkere E-E-A-T-Signale (Expertise/Erfahrung) sollten beide vorhanden sein. Ergänze das fehlende Element in Schema.org oder als Meta-Tag.");
    } else {
      add("authorDate", "Autor & Datum", "fail", "weder Autor noch Datum erkannt",
        "KIs trauen anonymen, undatierten Inhalten weniger. Ergänze Autor (Schema Person oder meta name=\"author\") und Datum (datePublished/dateModified).");
    }
  }

  {
    const has = {
      main: /<main\b[^>]*>/i.test(html),
      article: /<article\b[^>]*>/i.test(html),
      section: /<section\b[^>]*>/i.test(html),
      header: /<header\b[^>]*>/i.test(html),
      nav: /<nav\b[^>]*>/i.test(html),
    };
    const count = Object.values(has).filter(Boolean).length;
    const list = Object.entries(has).filter(([,v]) => v).map(([k]) => `<${k}>`).join(", ");
    if (count >= 3) {
      add("semantic", "Semantisches HTML", "pass", list || "—",
        "Klare Struktur hilft KIs, Hauptinhalt von Navigation und Beiwerk zu trennen.");
    } else if (count >= 1) {
      add("semantic", "Semantisches HTML", "warn", `nur ${list}`,
        "Wenige semantische Tags. Nutze zusätzlich <main>, <article> und <section>, um den Hauptinhalt klar abzugrenzen.");
    } else {
      add("semantic", "Semantisches HTML", "fail", "keine semantischen Tags",
        "Die Seite verwendet ausschließlich <div>. KIs müssen raten, was Inhalt und was Beiwerk ist. Strukturiere mit <main>, <article>, <section>, <header>, <nav>.");
    }
  }

  {
    const lang = getLang(html);
    if (!lang) {
      add("lang", "Sprache deklariert", "fail", "kein lang-Attribut",
        "Ohne lang=\"...\" können deutsche KIs deine Seite eventuell falsch einordnen. Setze lang=\"de\" (oder z.B. \"de-DE\") am <html>-Element.");
    } else {
      add("lang", "Sprache deklariert", "pass", `lang=\"${lang}\"`,
        "Klare Sprachzuordnung. KIs können dich korrekt einer Sprachversion zuordnen.");
    }
  }

  {
    const wc = wordCount(html);
    const hasFaq = getJsonLd(html).some(b => b && (b["@type"] === "FAQPage" || (Array.isArray(b["@type"]) && b["@type"].includes("FAQPage"))));
    const hasList = /<ul\b|<ol\b/i.test(html);
    const hasTable = /<table\b/i.test(html);
    const features = [hasFaq && "FAQ-Schema", hasList && "Listen", hasTable && "Tabellen"].filter(Boolean);
    if (wc < 150) {
      add("substance", "Inhalts-Substanz", "fail", `nur ${wc} Wörter`,
        "Sehr dünner Inhalt. KIs bevorzugen substanzielle Seiten mit ≥300 Wörtern und klarer Struktur (Listen, Tabellen, FAQ).");
    } else if (wc < 300 || features.length === 0) {
      add("substance", "Inhalts-Substanz", "warn", `${wc} Wörter${features.length ? ", " + features.join(", ") : ", keine Listen/Tabellen/FAQ"}`,
        "Mehr Substanz oder strukturierte Formate (Listen, Tabellen, FAQPage-Schema) erhöhen die Wahrscheinlichkeit, dass KIs deine Inhalte zitieren.");
    } else {
      add("substance", "Inhalts-Substanz", "pass", `${wc} Wörter, ${features.join(", ")}`,
        "Substanzieller, gut strukturierter Inhalt — gute Zitations-Voraussetzungen für KI-Antworten.");
    }
  }

  return checks;
}

const ABOUT_PATHS = ["/about", "/about-us", "/ueber-uns", "/ueber-mich", "/about-me", "/team", "/company", "/uber-uns", "/uber-mich"];

async function detectGroundingPage(originUrl, mainHtml) {
  const homeBlocks = getJsonLd(mainHtml);
  const hasStrongHome = homeBlocks.some(b => {
    if (!b) return false;
    const t = b["@type"];
    const types = Array.isArray(t) ? t : [t];
    const isOrgOrPerson = types.some(x => ["Organization", "Person", "LocalBusiness"].includes(String(x)));
    if (!isOrgOrPerson) return false;
    const richness = ["description", "sameAs", "address", "founder", "employee", "knowsAbout", "jobTitle"].filter(k => b[k]).length;
    return richness >= 2;
  });
  if (hasStrongHome) {
    return { found: true, url: originUrl, where: "Startseite", types: schemaTypes(homeBlocks).join(", ") };
  }

  const origin = new URL(originUrl).origin;
  const checks = await Promise.all(ABOUT_PATHS.map(async (p) => {
    try {
      const r = await fetchAs(origin + p, BOTS[0].ua, 6000);
      if (!r.ok || r.status >= 400 || !r.body) return null;
      const blocks = getJsonLd(r.body);
      const hasStrong = blocks.some(b => {
        if (!b) return false;
        const t = b["@type"];
        const types = Array.isArray(t) ? t : [t];
        return types.some(x => ["Organization", "Person", "LocalBusiness", "AboutPage"].includes(String(x)));
      });
      return { path: p, status: r.status, hasStrong, types: schemaTypes(blocks) };
    } catch { return null; }
  }));
  const hits = checks.filter(Boolean).filter(c => c.status >= 200 && c.status < 400);
  const strong = hits.find(h => h.hasStrong);
  if (strong) {
    return { found: true, url: origin + strong.path, where: strong.path, types: strong.types.join(", ") };
  }
  const weak = hits[0];
  if (weak) {
    return { found: "weak", url: origin + weak.path, where: weak.path, types: weak.types.join(", ") };
  }
  return { found: false };
}

function groundingPageCheck(detection) {
  if (detection.found === true) {
    return {
      key: "grounding", label: "Grounding-Seite", status: "pass",
      value: `erkannt unter ${detection.where}${detection.types ? " (Schema: " + detection.types + ")" : ""}`,
      recommendation: "Sehr gut. Diese Seite hilft KIs, dich als Entity (Person/Unternehmen) eindeutig zu verankern.",
    };
  }
  if (detection.found === "weak") {
    return {
      key: "grounding", label: "Grounding-Seite", status: "warn",
      value: `Über-uns-Seite gefunden (${detection.where}), aber ohne Organization/Person-Schema`,
      recommendation: "Du hast eine Über-uns-Seite, aber ohne strukturierte Daten. Ergänze dort ein JSON-LD-Block mit Organization (für Firmen) oder Person (für Personenmarken) inklusive description, sameAs (Social-Profile), founder, knowsAbout etc. Damit wird die Seite zur kanonischen Quelle für KIs.",
    };
  }
  return {
    key: "grounding", label: "Grounding-Seite", status: "fail",
    value: "keine erkennbare Über-uns-Seite mit Entity-Schema",
    recommendation: "Lege eine dedizierte Grounding-Seite an (z. B. /ueber-mich oder /ueber-uns) und versehe sie mit Organization- oder Person-Schema. So liefern KIs konsistente, korrekte Aussagen über dich/dein Unternehmen.",
  };
}

async function detectLlmsTxt(originUrl) {
  const origin = new URL(originUrl).origin;
  const paths = ["/llms.txt", "/llms-full.txt", "/ai.txt"];
  const results = await Promise.all(paths.map(async (p) => {
    const r = await fetchAs(origin + p, BOTS[0].ua, 5000);
    if (!r.ok || r.status < 200 || r.status >= 300 || !r.body || r.body.length < 20) return null;
    if (/<html|<!doctype/i.test(r.body.slice(0, 200))) return null;
    return { path: p, size: r.body.length, lines: r.body.split(/\r?\n/).length };
  }));
  return results.filter(Boolean);
}

function llmsTxtCheck(hits) {
  if (!hits.length) {
    return {
      key: "llmstxt", label: "llms.txt (Bonus)", status: "info",
      value: "nicht vorhanden",
      recommendation: "llms.txt ist ein junger, optionaler Standard (Jeremy Howard, 2024): eine Markdown-Datei, die KIs eine kuratierte Inhalts-Landkarte gibt. Wer das hat, signalisiert KI-Vorausschau. Anleitung: llmstxt.org",
    };
  }
  const main = hits[0];
  return {
    key: "llmstxt", label: "llms.txt (Bonus)", status: "pass",
    value: `${main.path} vorhanden (${main.lines} Zeilen, ${(main.size/1024).toFixed(1)} KB)`,
    recommendation: "Stark! Du signalisierst aktiv KI-Vorausschau — ein klares Differenzierungsmerkmal gegenüber Wettbewerbern.",
  };
}

function calcScore(geoChecks, groundingCheck) {
  const all = [...geoChecks, groundingCheck];
  let earned = 0;
  for (const c of all) {
    if (c.status === "pass") earned += 1;
    else if (c.status === "warn") earned += 0.5;
  }
  return { earned: Math.round(earned * 10) / 10, max: all.length };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method === "OPTIONS") { res.statusCode = 204; res.end(); return; }
  const send = (status, obj) => { res.statusCode = status; res.end(JSON.stringify(obj)); };

  let raw;
  try {
    const parsed = new URL(req.url, "http://localhost");
    raw = (parsed.searchParams.get("url") || "").trim();
  } catch { return send(400, { error: "Ungültige Anfrage." }); }
  if (!raw) return send(400, { error: "Bitte eine Website-Adresse angeben." });
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  let target;
  try { target = new URL(raw); } catch { return send(400, { error: "Das sieht nicht wie eine gültige Web-Adresse aus." }); }
  if (!(await isSafeUrl(target))) {
    return send(400, { error: "Diese Adresse kann nicht geprüft werden (interne oder ungültige Adresse)." });
  }

  let robotsGroups = null, robotsTxtFound = false;
  try {
    const robotsUrl = new URL("/robots.txt", target.origin).toString();
    const r = await fetchAs(robotsUrl, BOTS[0].ua, 8000);
    if (r.ok && r.status >= 200 && r.status < 300 && r.body) {
      robotsTxtFound = true;
      robotsGroups = parseRobots(r.body);
    }
  } catch {}

  const path = target.pathname || "/";

  const botPromise = Promise.all(BOTS.map(async (bot) => {
    const robotsAllowed = isAllowed(rulesForAgent(robotsGroups, bot.token), path);
    const page = await fetchAs(target.toString(), bot.ua);
    let status;
    if (!page.ok) status = "error";
    else if (!robotsAllowed) status = "blocked";
    else if (page.status === 403 || page.status === 401 || page.status === 429) status = "blocked";
    else if (page.status >= 400) status = "error";
    else status = "allowed";
    let meta = "", xrobots = "";
    if (page.ok) { meta = extractMeta(page.body, bot.token); xrobots = page.xrobots || ""; }
    return {
      name: bot.name, vendor: bot.vendor, status,
      http: page.status || null,
      robotsTxt: robotsAllowed,
      robotsMeta: meta,
      xRobotsTag: xrobots,
      responseTime: page.ok ? (page.elapsed / 1000).toFixed(2) + "s" : null,
      error: page.ok ? null : page.error,
      _body: page.ok ? page.body : "",
      _finalUrl: page.ok ? page.finalUrl : null,
    };
  }));

  const [botResults, llmsHits] = await Promise.all([botPromise, detectLlmsTxt(target.toString())]);

  const reference = botResults.find(b => b.name === "GPTBot" && b._body) || botResults.find(b => b._body);
  const mainHtml = reference ? reference._body : "";
  const finalUrl = reference?._finalUrl || target.toString();

  let geoChecks = [], groundingCheck = null, score = null;
  if (mainHtml) {
    geoChecks = runGeoChecks(mainHtml, finalUrl);
    const detection = await detectGroundingPage(finalUrl, mainHtml);
    groundingCheck = groundingPageCheck(detection);
    score = calcScore(geoChecks, groundingCheck);
  }
  const llmsCheck = llmsTxtCheck(llmsHits);

  const cleanedBots = botResults.map(b => {
    const { _body, _finalUrl, ...rest } = b;
    return rest;
  });

  send(200, {
    url: target.toString(),
    finalUrl,
    robotsTxtFound,
    testedAt: new Date().toISOString(),
    results: cleanedBots,
    geo: {
      score,
      checks: geoChecks,
      grounding: groundingCheck,
      llmstxt: llmsCheck,
    },
  });
}
