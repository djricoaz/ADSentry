// ADSentry – console web de l'appliance. Sans dépendance ; tout texte issu de l'API passe par textContent.
"use strict";

// ---------------------------------------------------------------------------- référentiels
const CATS = {
  stale_objects: "Objets obsolètes", privileged_accounts: "Comptes à privilèges", trusts: "Approbations",
  anomalies: "Anomalies", pki: "Certificats (ADCS)", entra_id: "Entra ID",
};
const CAT_HINT = {
  stale_objects: "Comptes, OS et configurations hérités", privileged_accounts: "Administrateurs, délégations, ACL",
  trusts: "Domaines et forêts approuvés", anomalies: "Kerberos, GPO, protocoles, DNS",
  pki: "Autorités et modèles de certificats", entra_id: "Tenant, rôles, applications, accès conditionnel",
};
const SEV = { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible", info: "Info" };
const SEV_ORDER = Object.keys(SEV);
const SOURCES = { ldap: "Annuaire (LDAP)", gpo: "GPO (SYSVOL)", probe: "Sondes réseau", dns: "DNS", graph: "Microsoft Graph" };
const TACTICS_FR = {
  "reconnaissance": "Reconnaissance", "resource-development": "Développement de ressources",
  "initial-access": "Accès initial", "execution": "Exécution", "persistence": "Persistance",
  "privilege-escalation": "Élévation de privilèges", "stealth": "Furtivité",
  "defense-impairment": "Neutralisation des défenses", "credential-access": "Accès aux identifiants",
  "discovery": "Découverte", "lateral-movement": "Mouvement latéral", "collection": "Collecte",
  "command-and-control": "Commande et contrôle", "exfiltration": "Exfiltration", "impact": "Impact",
};
const MATURITY = { 1: "Initial", 2: "Fragile", 3: "Défini", 4: "Maîtrisé", 5: "Optimisé" };
const VIEWS = {
  dashboard: { title: "Tableau de bord", group: "pilotage" },
  maturity: { title: "Évolution de la maturité", group: "pilotage" },
  compare: { title: "Comparer des rapports", group: "pilotage" },
  overview: { title: "Vue d'ensemble du scan", group: "scan" },
  findings: { title: "Constats", group: "scan" },
  pki: { title: "Certificats (ADCS)", group: "scan" },
  entra: { title: "Entra ID", group: "scan" },
  mitre: { title: "MITRE ATT&CK", group: "scan" },
  report: { title: "Synthèse", group: "scan" },
  topology: { title: "Topologie", group: "scan" },
  scans: { title: "Historique des scans", group: "ref" },
  rules: { title: "Catalogue de règles", group: "ref" },
  help: { title: "Guide de lecture", group: "ref" },
  targets: { title: "Cibles d'audit", group: "admin", admin: true },
  jobs: { title: "Tâches", group: "admin", admin: true },
  users: { title: "Comptes et rôles", group: "admin", admin: true },
  audit: { title: "Journal d'audit", group: "admin", admin: true },
  ai: { title: "IA locale", group: "admin", admin: true },
};

const state = { scans: [], scanId: null, scan: null, domain: null, rules: null, mitre: null, filters: {}, user: null, minPassword: 12, period: "" };
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------- utilitaires
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}
const SVGNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const c of children.flat()) if (c) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}
async function api(path, options = {}) {
  const headers = { "X-ADSentry": "1", ...(options.headers || {}) };
  if (typeof options.body === "string") headers["Content-Type"] = "application/json";
  const r = await fetch(`/api${path}`, { credentials: "same-origin", ...options, headers });
  if (r.status === 401 && !path.startsWith("/auth/")) {
    showAuth("login", { message: "Votre session a expiré ; reconnectez-vous." });
    throw new Error("Session expirée");
  }
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch { /* corps non JSON */ }
    throw new Error(msg);
  }
  return r.json();
}
const fmtDate = (iso, opts = { day: "2-digit", month: "2-digit", year: "numeric" }) =>
  iso ? new Date(iso).toLocaleDateString("fr-FR", opts) : "—";
const fmtShort = (iso) => new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
const plural = (n, one, many) => `${n} ${n > 1 ? many : one}`;
const sev = (s) => el("span", { class: `sev sev-${s}` }, SEV[s] || s);
function level(score) {
  return score >= 75 ? "Critique" : score >= 50 ? "Élevé" : score >= 25 ? "Modéré" : "Faible";
}
function deltaEl(value, { lowerIsBetter = true, unit = "", suffix = "vs scan précédent" } = {}) {
  if (value === null || value === undefined) return el("span", { class: "delta" }, "Premier scan");
  if (value === 0) return el("span", { class: "delta" }, `Stable ${suffix}`);
  const good = lowerIsBetter ? value < 0 : value > 0;
  return el("span", { class: `delta ${good ? "good" : "bad"}` }, `${value > 0 ? "+" : "−"}${Math.abs(value)}${unit} ${suffix}`);
}
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2600);
}
function section(title, sub, ...body) {
  return el("section", { class: "section" },
    el("div", { class: "section-head" }, el("h2", {}, title), sub ? el("p", {}, sub) : null), ...body);
}
function emptyState(title, text, action) {
  return el("div", { class: "empty" }, el("h2", {}, title), el("p", {}, text), action || null);
}

// ---------------------------------------------------------------------------- infobulle des graphiques
const tip = {
  show(evt, title, rows) {
    const t = $("tooltip");
    t.replaceChildren(el("b", {}, title), ...rows.map(([label, value, color]) => el("div", { class: "row" },
      el("span", {}, color ? el("i", { class: "swatch", style: `--c:${color}` }) : null, label), el("span", {}, value))));
    t.style.display = "block";
    const x = Math.min(evt.clientX + 14, window.innerWidth - t.offsetWidth - 8);
    const y = Math.max(8, evt.clientY - t.offsetHeight - 12);
    t.style.left = `${x}px`;
    t.style.top = `${y}px`;
  },
  hide() { $("tooltip").style.display = "none"; },
};

// ---------------------------------------------------------------------------- graphiques SVG
// Courbe unique (score, maturité). Pas de légende : le titre du bloc nomme la série.
function lineChart(points, { yMin = 0, yMax = 100, ticks = [0, 25, 50, 75, 100], tickLabel = (v) => v,
  step = false, height = 220, fmt = (v) => v, compact = false, onPick = null } = {}) {
  const W = 640, H = height, m = compact ? { t: 8, r: 12, b: 18, l: 8 } : { t: 12, r: 44, b: 26, l: 34 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const x = (i) => m.l + (points.length < 2 ? iw / 2 : (i * iw) / (points.length - 1));
  const y = (v) => m.t + ih - ((v - yMin) / (yMax - yMin)) * ih;
  let d = "";
  points.forEach((p, i) => {
    if (i === 0) d += `M${x(i)},${y(p.y)}`;
    else d += step ? `H${x(i)}V${y(p.y)}` : `L${x(i)},${y(p.y)}`;
  });
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  if (!compact) {
    root.append(svg("g", { class: "grid" }, ticks.map((t) => svg("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t) }))));
    root.append(svg("g", { class: "axis" },
      ticks.map((t) => svg("text", { x: m.l - 8, y: y(t) + 4, "text-anchor": "end" }, tickLabel(t))),
      points.map((p, i) => (points.length <= 8 || i % Math.ceil(points.length / 8) === 0)
        ? svg("text", { x: x(i), y: H - 6, "text-anchor": "middle" }, fmtShort(p.x)) : null)));
  } else {
    root.append(svg("g", { class: "grid" }, svg("line", { x1: m.l, x2: W - m.r, y1: y(yMin), y2: y(yMin) })));
  }
  root.append(svg("path", { class: "series", d }));
  const last = points[points.length - 1];
  if (last) {
    root.append(svg("circle", { class: "dot", cx: x(points.length - 1), cy: y(last.y), r: compact ? 4 : 4.5 }));
    if (!compact) root.append(svg("text", { class: "end-label", x: x(points.length - 1) + 9, y: y(last.y) + 4 }, fmt(last.y)));
  }
  const cross = svg("line", { class: "cross", y1: m.t, y2: m.t + ih, style: "display:none" });
  const marker = svg("circle", { class: "dot", r: 4.5, style: "display:none" });
  root.append(cross, marker);
  const hit = svg("rect", { class: `hit${onPick ? " pickable" : ""}`, x: m.l, y: 0, width: iw, height: H });
  const indexAt = (evt) => {
    const box = root.getBoundingClientRect();
    const px = ((evt.clientX - box.left) / box.width) * W;
    return Math.max(0, Math.min(points.length - 1, Math.round(((px - m.l) / iw) * (points.length - 1))));
  };
  if (onPick) hit.addEventListener("click", (evt) => { tip.hide(); onPick(points[indexAt(evt)]); });
  hit.addEventListener("mousemove", (evt) => {
    const i = indexAt(evt);
    const p = points[i];
    cross.setAttribute("x1", x(i)); cross.setAttribute("x2", x(i)); cross.style.display = "";
    marker.setAttribute("cx", x(i)); marker.setAttribute("cy", y(p.y)); marker.style.display = "";
    tip.show(evt, fmtDate(p.x), p.rows || [["Valeur", fmt(p.y)]]);
  });
  hit.addEventListener("mouseleave", () => { cross.style.display = "none"; marker.style.display = "none"; tip.hide(); });
  root.append(hit);
  return el("div", { class: "chart" }, root);
}

// Barres empilées par sévérité (rampe séquentielle), écart de 2px entre segments.
function stackedBars(timeline, keys = ["critical", "high", "medium", "low"], W = 440) {
  const H = 260, m = { t: 12, r: 12, b: 26, l: 34 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const totals = timeline.map((t) => keys.reduce((s, k) => s + t.severity[k], 0));
  const max = Math.max(10, ...totals);
  const niceMax = Math.ceil(max / 50) * 50;
  const y = (v) => m.t + ih - (v / niceMax) * ih;
  const band = iw / Math.max(timeline.length, 1);
  const bw = Math.min(42, band * 0.56);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  const ticks = [0, niceMax / 2, niceMax];
  root.append(svg("g", { class: "grid" }, ticks.map((t) => svg("line", { x1: m.l, x2: W - m.r, y1: y(t), y2: y(t) }))));
  root.append(svg("g", { class: "axis" }, ticks.map((t) => svg("text", { x: m.l - 8, y: y(t) + 4, "text-anchor": "end" }, t))));
  const styles = getComputedStyle(document.documentElement);
  timeline.forEach((t, i) => {
    const cx = m.l + band * i + band / 2;
    let acc = 0;
    const g = svg("g");
    keys.forEach((k) => {
      const v = t.severity[k];
      if (!v) return;
      const y0 = y(acc), y1 = y(acc + v);
      const h = Math.max(1, y0 - y1 - 2);
      g.append(svg("rect", { x: cx - bw / 2, y: y1, width: bw, height: h, rx: 1, fill: styles.getPropertyValue(`--sev-${k}`) }));
      acc += v;
    });
    root.append(g);
    root.append(svg("text", { class: "axis", x: cx, y: H - 6, "text-anchor": "middle", style: "font-size:11px;fill:var(--ink-3)" }, fmtShort(t.analyzed_at)));
    const hit = svg("rect", { class: "bar-hit", x: cx - band / 2, y: m.t, width: band, height: ih });
    hit.addEventListener("mousemove", (evt) => tip.show(evt, fmtDate(t.analyzed_at),
      [...keys.map((k) => [SEV[k], t.severity[k], styles.getPropertyValue(`--sev-${k}`)]), ["Total", totals[i]]]));
    hit.addEventListener("mouseleave", tip.hide);
    root.append(hit);
  });
  const legend = el("div", { class: "legend", style: "padding:0 0 .6rem" },
    keys.map((k) => el("span", {}, el("i", { class: "swatch", style: `--c:var(--sev-${k})` }), SEV[k])));
  return el("div", { class: "chart" }, legend, root);
}

// ---------------------------------------------------------------------------- tableau des constats
function findingsTable(findings, { onOpen = openFinding, showCategory = true } = {}) {
  const rows = findings.map((f) => el("tr", { class: "clickable", tabindex: "0", onclick: () => onOpen(f),
    onkeydown: (e) => { if (e.key === "Enter") onOpen(f); } },
  el("td", {}, sev(f.severity)),
  el("td", { class: "rule-id" }, f.rule_id),
  el("td", {}, f.title),
  showCategory ? el("td", { class: "hide-sm" }, CATS[f.category]) : null,
  el("td", { class: "num" }, f.affected.length),
  el("td", { class: "num hide-sm" }, f.points)));
  return el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Sévérité"), el("th", {}, "Règle"), el("th", {}, "Constat"),
      showCategory ? el("th", { class: "hide-sm" }, "Catégorie") : null, el("th", { class: "num" }, "Objets"),
      el("th", { class: "num hide-sm" }, "Points"))),
    el("tbody", {}, rows)));
}
const bySeverity = (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.points - a.points;

// ---------------------------------------------------------------------------- panneau de détail
async function openFinding(f) {
  const rules = await getRules();
  const rule = rules.find((r) => r.id === f.rule_id) || {};
  const ref = await getMitre();
  $("drawer-id").textContent = `${f.rule_id}  ·  ${CATS[f.category]}`;
  $("drawer-title").textContent = f.title;
  const max = 200;
  $("drawer-body").replaceChildren(el("div", {},
    el("div", { class: "kv" }, sev(f.severity), el("span", {}, `${f.points} points`),
      el("span", {}, plural(f.affected.length, "objet concerné", "objets concernés")),
      rule.source ? el("span", {}, SOURCES[rule.source] || rule.source) : null),
    el("h3", {}, "Risque"), el("p", {}, f.description),
    el("h3", {}, "Correction"), el("p", {}, f.remediation),
    f.detection ? [el("h3", {}, "Détection"), el("p", {}, f.detection)] : null,
    el("h3", {}, "Objets concernés"),
    el("ul", { class: "objects" }, f.affected.slice(0, max).map((o) => el("li", {}, o))),
    f.affected.length > max ? el("p", { class: "muted" }, `et ${f.affected.length - max} autres`) : null,
    f.mitre.length ? [el("h3", {}, "MITRE ATT&CK"), el("ul", { class: "objects" }, f.mitre.map((m) =>
      el("li", {}, el("a", { href: `https://attack.mitre.org/techniques/${m.technique.replace(".", "/")}/`, target: "_blank", rel: "noopener" },
        m.technique), " ", ref?.techniques[m.technique]?.name || "")))] : null,
    rule.references?.length ? [el("h3", {}, "Références"), el("ul", { class: "objects" },
      rule.references.map((u) => el("li", {}, el("a", { href: u, target: "_blank", rel: "noopener" }, new URL(u).hostname))))] : null,
  ));
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-close").focus();
}
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
}

// ---------------------------------------------------------------------------- données partagées
async function getRules() { return state.rules ||= await api("/rules"); }
async function getMitre() {
  if (state.mitre === null) { try { state.mitre = await api("/mitre"); } catch { state.mitre = undefined; } }
  return state.mitre;
}
async function loadScan(id) {
  if (!id) return null;
  if (state.scanId !== id || !state.scan) {
    state.scan = await api(`/scans/${id}`);
    state.scanId = id;
  }
  $("side-target").textContent = state.scan.domain;
  $("side-date").textContent = `Collecté le ${fmtDate(state.scan.collected_at, { day: "2-digit", month: "long", year: "numeric", hour: "2-digit", minute: "2-digit" })}`;
  $("nav-findings").textContent = state.scan.findings.length;
  $("scan-select").value = id;
  return state.scan;
}
async function refreshScans(selectId) {
  state.scans = await api("/scans");
  const sel = $("scan-select");
  sel.replaceChildren(...state.scans.map((s) => el("option", { value: s.id }, `${s.domain} — ${fmtDate(s.collected_at || s.analyzed_at)}`)));
  const domains = [...new Set(state.scans.map((s) => s.domain))];
  $("domain-select").replaceChildren(...domains.map((d) => el("option", { value: d }, d)));
  state.domain = state.domain && domains.includes(state.domain) ? state.domain : domains[0] || null;
  if (state.domain) $("domain-select").value = state.domain;
  const id = selectId || state.scanId || state.scans[0]?.id;
  if (id) await loadScan(id);
  $("side-foot").textContent = `${state.scans.length} rapport(s) conservé(s) sur l'appliance`;
}

// ---------------------------------------------------------------------------- vues : pilotage
// ---------------------------------------------------------------------------- aides à la lecture
const LEVELS = [
  { min: 75, key: "critical", label: "Critique", text: "Des failles permettent probablement de prendre le contrôle du domaine. Une action immédiate est nécessaire." },
  { min: 50, key: "high", label: "Élevé", text: "Des faiblesses importantes facilitent une attaque. Elles doivent être traitées en priorité dans les prochaines semaines." },
  { min: 25, key: "medium", label: "Modéré", text: "Le socle est correct mais plusieurs points de configuration restent à durcir." },
  { min: 0, key: "low", label: "Faible", text: "Peu de faiblesses détectées. Il s'agit de maintenir ce niveau dans la durée." },
];
const levelOf = (score) => LEVELS.find((l) => score >= l.min);
const MATURITY_TEXT = {
  1: "au moins un point critique reste ouvert",
  2: "plus de point critique, mais des points élevés restent ouverts",
  3: "seuls des points moyens ou faibles restent ouverts",
  4: "seuls des points faibles ou informatifs restent ouverts",
  5: "aucun constat ouvert",
};
const SEV_HELP = {
  critical: "Peut mener directement à la compromission du domaine. Délai indicatif : immédiat.",
  high: "Facilite fortement une attaque. Délai indicatif : sous 30 jours.",
  medium: "Affaiblit la défense en profondeur. Délai indicatif : sous 90 jours.",
  low: "Bonne pratique non appliquée. À planifier.",
  info: "Information utile, sans risque direct.",
};
const KPI_HELP = {
  score: "Note de 0 à 100 : plus elle est haute, plus le risque est élevé. C'est la note du domaine d'analyse le plus exposé, car le maillon le plus faible suffit à un attaquant.",
  maturity: "Niveau de 1 (Initial) à 5 (Optimisé), déterminé par le constat le plus grave encore ouvert.",
  critical: "Nombre de constats critiques dans le dernier scan : ce sont les premiers à corriger.",
  open: "Nombre de problèmes distincts détectés dans le dernier scan, toutes sévérités confondues.",
  objects: "Total des comptes, ordinateurs, GPO, modèles de certificats… concernés par au moins un constat.",
  rate: "Part des problèmes déjà vus sur la période qui ont disparu depuis (corrigés).",
  mttr: "Nombre moyen de jours entre la première détection d'un problème et le scan où il a disparu.",
};
function help(text) {
  return el("span", { class: "help", tabindex: "0", role: "img", "aria-label": text, "data-tip": text }, "?");
}
const daysAgo = (iso) => Math.max(0, Math.round((Date.now() - new Date(iso)) / 86400000));
const agoText = (iso) => { const d = daysAgo(iso); return d === 0 ? "aujourd'hui" : d === 1 ? "hier" : `il y a ${d} jours`; };
function sparkline(values, { invert = false } = {}) {
  if (values.length < 2) return el("span", { class: "spark-empty" });
  const W = 120, H = 28, min = Math.min(...values), max = Math.max(...values), span = max - min || 1;
  const pts = values.map((v, i) => `${(i * W) / (values.length - 1)},${H - 3 - ((v - min) / span) * (H - 6)}`);
  const trend = values.at(-1) - values[0];
  const good = invert ? trend > 0 : trend < 0;
  return svg("svg", { class: `spark ${trend === 0 ? "" : good ? "good" : "bad"}`, viewBox: `0 0 ${W} ${H}`, "aria-hidden": "true", preserveAspectRatio: "none" },
    svg("polyline", { points: pts.join(" ") }));
}
function gauge(score) {
  const lv = levelOf(score);
  const r = 70, cx = 90, cy = 86, a = Math.PI * (1 - Math.min(score, 100) / 100);
  const arc = (from, to) => {
    const p = (t) => [cx + r * Math.cos(Math.PI * (1 - t)), cy - r * Math.sin(Math.PI * (1 - t))];
    const [x1, y1] = p(from), [x2, y2] = p(to);
    return `M${x1},${y1} A${r},${r} 0 0 1 ${x2},${y2}`;
  };
  return el("div", { class: "gauge" }, svg("svg", { viewBox: "0 0 180 100", role: "img", "aria-label": `Score de risque ${score} sur 100, niveau ${lv.label}` },
    svg("path", { class: "gauge-track", d: arc(0, 1) }),
    score > 0 ? svg("path", { class: `gauge-fill sevfill-${lv.key}`, d: arc(0, Math.min(score, 100) / 100) }) : null,
    svg("circle", { class: "gauge-needle", cx: cx + r * Math.cos(a), cy: cy - r * Math.sin(a), r: 5 })),
  el("div", { class: "gauge-value" }, el("strong", {}, score), el("small", {}, "/100")),
  el("div", { class: `gauge-level lvl-${lv.key}` }, `Risque ${lv.label.toLowerCase()}`));
}
const scanCache = new Map();
async function getScan(id) {
  if (state.scanId === id && state.scan) return state.scan;
  if (!scanCache.has(id)) scanCache.set(id, await api(`/scans/${id}`));
  return scanCache.get(id);
}
function goFindings(params = {}) {
  state.filters = { q: params.q || "", category: params.category || "", severity: params.severity || "" };
  const id = params.scan;
  const nav = () => { location.hash = "#/findings"; };
  if (id && id !== state.scanId) loadScan(id).then(nav); else nav();
}

// ---------------------------------------------------------------------------- vue : tableau de bord
const PERIODS = [["", "Tout l'historique"], ["365", "12 derniers mois"], ["180", "6 derniers mois"], ["90", "3 derniers mois"], ["30", "30 derniers jours"]];
async function viewDashboard() {
  if (!state.domain) return noScan();
  const d = await api(`/dashboard?domain=${encodeURIComponent(state.domain)}${state.period ? `&days=${state.period}` : ""}`);
  const k = d.kpis, tl = d.timeline;
  const latest = await getScan(k.last_scan_id);
  const findings = [...latest.findings].sort(bySeverity);
  const lv = levelOf(k.global_score);
  const lastEvent = d.events.find((e) => !e.first);
  const lastScores = tl.at(-1).scores;
  const driver = Object.keys(CATS).reduce((a, c) => ((lastScores[c] ?? 0) > (lastScores[a] ?? 0) ? c : a));
  const driverFindings = findings.filter((f) => f.category === driver);
  // Score élevé sans constat critique ni élevé : il vient du cumul de constats de moindre gravité
  const cumulative = lv.min >= 50 && !k.severity.critical && !k.severity.high;
  const heroText = cumulative
    ? `Aucune faille critique ou élevée isolée, mais le cumul de ${plural(driverFindings.length, "constat", "constats")} de moindre gravité dans « ${CATS[driver]} » porte le score à ${k.global_score}/100. Les traiter par lots fera baisser le score rapidement.`
    : lv.text;

  // Barre d'outils : période, impression
  const period = el("select", { "aria-label": "Période analysée" }, PERIODS.map(([v, l]) => el("option", { value: v, selected: (state.period || "") === v }, l)));
  period.addEventListener("change", () => { state.period = period.value; softRender(); });
  const toolbar = el("div", { class: "dash-toolbar" },
    el("label", { class: "field-inline" }, el("span", {}, "Période"), period),
    el("span", { class: "muted small" }, `${plural(k.scans, "scan", "scans")} retenu(s) sur ${k.scans_total}`),
    el("span", { class: "live", title: "Le tableau de bord se met à jour dès qu'un nouveau rapport est disponible" }, el("i"), "Mise à jour automatique"),
    el("button", { class: "btn btn-secondary", onclick: () => window.print() }, "Imprimer / PDF"));

  // Synthèse en langage clair
  const stale = daysAgo(k.last_collected_at) > 35;
  const facts = [
    k.critical ? el("li", { class: "bad" }, el("strong", {}, plural(k.critical, "point critique", "points critiques")), " à traiter en priorité.")
      : el("li", { class: "good" }, el("strong", {}, "Aucun point critique"), " dans le dernier scan."),
    el("li", {}, `${plural(k.open, "problème détecté", "problèmes détectés")}, concernant ${plural(k.objects, "objet", "objets")} de l'annuaire.`),
    lastEvent ? el("li", { class: lastEvent.resolved >= lastEvent.new ? "good" : "bad" },
      `Depuis le scan précédent : ${plural(lastEvent.resolved, "problème corrigé", "problèmes corrigés")}, ${plural(lastEvent.new, "nouveau", "nouveaux")}.`)
      : el("li", {}, "Premier scan de la période : il sert de référence pour mesurer les progrès."),
    k.global_score ? el("li", {}, "Domaine le plus exposé : ", el("a", { href: "#/findings", onclick: (e) => { e.preventDefault(); goFindings({ category: driver, scan: k.last_scan_id }); } },
      CATS[driver]), ` (${lastScores[driver]}/100), qui détermine le score global.`) : null,
    el("li", {}, `Maturité ${k.maturity}/5 (${k.maturity_label}) : ${MATURITY_TEXT[k.maturity]}.`),
  ];
  const hero = el("section", { class: `section hero lvl-border-${lv.key}` },
    gauge(k.global_score),
    el("div", { class: "hero-text" },
      el("p", { class: "eyebrow" }, `${d.domain} · dernière évaluation ${agoText(k.last_collected_at)} (${fmtDate(k.last_collected_at)})`),
      el("h2", {}, `Niveau de risque ${lv.label.toLowerCase()}`),
      el("p", {}, heroText),
      el("ul", { class: "facts-list" }, facts),
      stale ? el("p", { class: "note small" }, "Ce rapport a plus d'un mois : la situation réelle a pu évoluer. Demandez un nouveau scan à un administrateur.") : null,
      el("div", { class: "actions" },
        el("a", { class: "btn btn-primary", href: "#priorities", onclick: (e) => { e.preventDefault(); $("priorities")?.scrollIntoView({ behavior: "smooth" }); } }, "Voir les priorités"),
        el("a", { class: "btn btn-secondary", href: "#/report", onclick: () => loadScan(k.last_scan_id) }, "Synthèse du dernier scan"),
        el("a", { class: "btn btn-link", href: "#/help" }, "Comment lire ce tableau de bord ?"))));

  // Indicateurs cliquables
  const series = (fn) => tl.map(fn);
  const tile = ({ label, value, unit, delta, helpText, spark, go, title }) => el("button", { class: "kpi", type: "button", title, onclick: go },
    el("span", { class: "k" }, label, help(helpText)),
    el("span", { class: "v" }, value ?? "—", unit && value !== null && value !== undefined ? el("small", {}, unit) : null),
    el("span", { class: "kpi-foot" }, delta, spark));
  const toLife = () => $("lifecycle")?.scrollIntoView({ behavior: "smooth" });
  const tiles = el("section", { class: "kpi-grid", "aria-label": "Indicateurs clés" },
    tile({ label: "Score de risque", value: k.global_score, unit: "/100", delta: deltaEl(k.global_score_delta), helpText: KPI_HELP.score,
      spark: sparkline(series((t) => t.global_score)), go: () => { loadScan(k.last_scan_id).then(() => { location.hash = "#/overview"; }); }, title: "Ouvrir la vue d'ensemble du dernier scan" }),
    tile({ label: "Maturité", value: k.maturity, unit: `/5 ${k.maturity_label}`, delta: deltaEl(k.maturity_delta, { lowerIsBetter: false, suffix: "niveau" }),
      helpText: KPI_HELP.maturity, spark: sparkline(series((t) => t.maturity), { invert: true }), go: () => { location.hash = "#/maturity"; }, title: "Voir l'évolution de la maturité" }),
    tile({ label: "Points critiques", value: k.critical, delta: deltaEl(k.critical_delta), helpText: KPI_HELP.critical,
      spark: sparkline(series((t) => t.severity.critical)), go: () => goFindings({ severity: "critical", scan: k.last_scan_id }), title: "Lister les constats critiques" }),
    tile({ label: "Constats ouverts", value: k.open, delta: deltaEl(tl.length > 1 ? tl.at(-1).findings - tl.at(-2).findings : null), helpText: KPI_HELP.open,
      spark: sparkline(series((t) => t.findings)), go: () => goFindings({ scan: k.last_scan_id }), title: "Lister tous les constats" }),
    tile({ label: "Objets concernés", value: k.objects, delta: deltaEl(tl.length > 1 ? tl.at(-1).objects - tl.at(-2).objects : null), helpText: KPI_HELP.objects,
      spark: sparkline(series((t) => t.objects)), go: () => goFindings({ scan: k.last_scan_id }), title: "Lister les constats et leurs objets" }),
    tile({ label: "Taux de correction", value: k.remediation_rate, unit: " %", delta: el("span", { class: "delta" }, `${k.resolved_total} corrigés`), helpText: KPI_HELP.rate,
      spark: null, go: toLife, title: "Voir le suivi des corrections" }),
    tile({ label: "Délai moyen de correction", value: k.mttr_days, unit: " j", helpText: KPI_HELP.mttr, spark: null, go: toLife, title: "Voir le suivi des corrections",
      delta: el("span", { class: "delta" }, k.oldest_critical_days !== null ? `Critique le plus ancien : ${k.oldest_critical_days} j` : "Aucun critique ouvert") }));

  // Répartition par sévérité (cliquable)
  const maxSev = Math.max(1, ...SEV_ORDER.map((s) => k.severity[s] || 0));
  const sevBars = el("div", { class: "sev-bars" }, SEV_ORDER.map((s) => el("button", { type: "button", class: "sev-bar", onclick: () => goFindings({ severity: s, scan: k.last_scan_id }),
    title: `${SEV[s]} : ${SEV_HELP[s]}`, disabled: !k.severity[s] },
  el("span", { class: "sev-bar-label" }, sev(s)),
  el("span", { class: "sev-bar-track" }, el("i", { class: `sevfill-${s}`, style: `width:${(100 * (k.severity[s] || 0)) / maxSev}%` })),
  el("span", { class: "sev-bar-n" }, k.severity[s] || 0))));

  const scoreChart = lineChart(tl.map((t) => ({ x: t.collected_at, y: t.global_score, id: t.id,
    rows: [["Score", `${t.global_score}/100 (${levelOf(t.global_score).label})`], ["Maturité", `${t.maturity} ${t.maturity_label}`], ["Constats", t.findings], ["", "Cliquer pour ouvrir"]] })),
  { fmt: (v) => `${v}`, onPick: (p) => loadScan(p.id).then(() => { location.hash = "#/overview"; }) });

  // Domaines d'analyse (cliquables)
  const byCat = Object.fromEntries(Object.keys(CATS).map((c) => [c, findings.filter((f) => f.category === c)]));
  const cards = el("div", { class: "cat-grid" }, Object.keys(CATS).map((c) => {
    const pts = tl.map((t) => t.scores[c] ?? 0);
    const last = pts.at(-1) ?? 0, prev = pts.at(-2);
    const cl = levelOf(last), crit = byCat[c].filter((f) => f.severity === "critical").length;
    return el("button", { type: "button", class: "cat-card", onclick: () => goFindings({ category: c, scan: k.last_scan_id }), title: `Lister les constats : ${CATS[c]}` },
      el("span", { class: "cat-head" }, el("strong", {}, CATS[c]), el("span", { class: `pill lvl-${cl.key}` }, `${last}/100`)),
      el("span", { class: "muted small" }, CAT_HINT[c]),
      el("span", { class: "cat-stats" }, byCat[c].length ? `${plural(byCat[c].length, "constat", "constats")}${crit ? ` dont ${crit} critique${crit > 1 ? "s" : ""}` : ""}` : "Aucun constat",
        deltaEl(prev === undefined ? null : last - prev)),
      sparkline(pts));
  }));

  // Priorités d'action
  // Sévérité d'abord, puis points, puis domaine le plus exposé (c'est lui qui fait baisser le score global)
  const top = findings.filter((f) => f.severity !== "info")
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.points - a.points
      || (lastScores[b.category] ?? 0) - (lastScores[a.category] ?? 0) || b.affected.length - a.affected.length)
    .slice(0, 6);
  const priorities = top.length ? el("ol", { class: "priorities" }, top.map((f, i) => el("li", {},
    el("span", { class: "rank" }, i + 1),
    el("div", { class: "prio-body" },
      el("div", { class: "prio-head" }, sev(f.severity), el("strong", {}, f.title)),
      el("p", { class: "muted" }, f.description.split(/(?<=\.)\s/)[0]),
      el("span", { class: "small muted" }, `${plural(f.affected.length, "objet concerné", "objets concernés")} · ${CATS[f.category]} · ${SEV_HELP[f.severity].split(". ")[1] || ""}`)),
    el("button", { class: "btn btn-secondary", onclick: () => openFinding(f) }, "Comment corriger")))) :
    emptyState("Rien à corriger en priorité", "Aucun constat de sévérité faible ou supérieure dans le dernier scan.");

  // Suivi des corrections (onglets, recherche, tri)
  const groups = {
    open: { label: "Ouverts", list: d.lifecycle.filter((x) => !x.resolved_at) },
    fixed: { label: "Corrigés", list: d.lifecycle.filter((x) => x.resolved_at) },
    reopened: { label: "Réapparus", list: d.lifecycle.filter((x) => x.reopened) },
  };
  let tab = "open", sortKey = "severity", q = "", limit = 10;
  const lifeBody = el("div");
  const tabs = el("div", { class: "tabs", role: "tablist" });
  const search = el("input", { type: "search", placeholder: "Filtrer", "aria-label": "Filtrer le suivi" });
  search.addEventListener("input", () => { q = search.value.toLowerCase(); renderLife(); });
  const sortSel = el("select", { "aria-label": "Trier" }, el("option", { value: "severity" }, "Trier par sévérité"), el("option", { value: "age" }, "Trier par ancienneté"), el("option", { value: "objects" }, "Trier par nombre d'objets"));
  sortSel.addEventListener("change", () => { sortKey = sortSel.value; renderLife(); });
  function renderLife() {
    tabs.replaceChildren(...Object.entries(groups).map(([key, g]) => el("button", { type: "button", role: "tab", class: key === tab ? "active" : null, "aria-selected": String(key === tab),
      onclick: () => { tab = key; limit = 10; renderLife(); } }, g.label, el("span", { class: "count" }, g.list.length))));
    const list = groups[tab].list.filter((x) => !q || `${x.rule_id} ${x.title}`.toLowerCase().includes(q))
      .sort((a, b) => sortKey === "age" ? b.age_days - a.age_days : sortKey === "objects" ? (b.objects || 0) - (a.objects || 0)
        : SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.age_days - a.age_days);
    const current = new Map(findings.map((f) => [f.rule_id, f]));
    lifeBody.replaceChildren(list.length ? el("div", { class: "table-wrap" }, el("table", { class: "data" },
      el("thead", {}, el("tr", {}, el("th", {}, "Sévérité"), el("th", {}, "Constat"), el("th", { class: "num hide-sm" }, "Objets"),
        el("th", { class: "hide-sm" }, "Détecté le"), el("th", { class: "num" }, tab === "fixed" ? "Corrigé le" : "Ouvert depuis"))),
      el("tbody", {}, list.slice(0, limit).map((x) => {
        const f = current.get(x.rule_id);
        return el("tr", { class: f ? "clickable" : null, tabindex: f ? "0" : null, onclick: f ? () => openFinding(f) : null, onkeydown: f ? (e) => { if (e.key === "Enter") openFinding(f); } : null },
          el("td", {}, sev(x.severity)),
          el("td", {}, x.title, x.reopened ? el("span", { class: "pill lvl-high", title: "Corrigé puis réapparu" }, `réapparu ${x.reopened}×`) : null, el("div", { class: "rule-id small" }, x.rule_id)),
          el("td", { class: "num hide-sm" }, x.objects ?? "—"),
          el("td", { class: "hide-sm" }, fmtDate(x.first_seen)),
          el("td", { class: "num" }, tab === "fixed" ? fmtDate(x.resolved_at) : `${x.age_days} j`));
      }))), list.length > limit ? el("div", { class: "section-body more" }, el("button", { class: "btn btn-link", type: "button",
        onclick: () => { limit += 15; renderLife(); } }, `Afficher plus (${list.length - limit} restants)`)) : null)
      : el("div", { class: "empty" }, el("p", {}, tab === "fixed" ? "Aucune correction constatée sur la période." : tab === "reopened" ? "Aucun problème n'est réapparu après correction." : "Aucun constat ouvert.")));
  }
  renderLife();

  const changes = el("ul", { class: "events" }, d.events.slice(0, 6).map((e, i) => {
    const prev = d.events[i + 1];
    return el("li", {},
      el("span", { class: "when" }, fmtDate(e.date)), el("span", { class: "rail" }, el("i")),
      el("div", { class: "what" }, el("strong", {}, e.first ? "Scan de référence" : `${e.resolved} corrigé(s), ${e.new} nouveau(x)`),
        el("p", {}, `Score ${e.global_score}/100, maturité ${e.maturity} ${MATURITY[e.maturity]}`),
        prev ? el("a", { href: `#/compare?base=${prev.id}&target=${e.id}` }, "Voir le détail des changements") : null));
  }));

  return [
    welcomeBanner(), toolbar, hero, tiles,
    el("div", { class: "grid-2" },
      section("Évolution du score de risque", "Cliquez sur un point pour ouvrir le rapport de cette date", el("div", { class: "section-body" }, scoreChart)),
      section("Constats du dernier scan par sévérité", "Cliquez pour lister les constats", el("div", { class: "section-body" }, sevBars,
        el("div", { class: "sev-history" }, el("p", { class: "muted small" }, "Évolution sur la période"), stackedBars(tl))))),
    el("div", { style: "height:1.25rem" }),
    section("Domaines d'analyse", "Note de 0 (sain) à 100 (exposé) ; cliquez pour voir les constats du domaine", cards),
    el("section", { class: "section", id: "priorities" },
      el("div", { class: "section-head" }, el("div", {}, el("h2", {}, "Priorités d'action"), el("p", {}, "Les constats les plus graves du dernier scan, avec la correction recommandée")),
        el("a", { href: "#/findings", onclick: () => goFindings({ scan: k.last_scan_id }) }, "Tous les constats")),
      el("div", { class: "section-body" }, priorities)),
    el("div", { class: "grid-2" },
      el("section", { class: "section", id: "lifecycle" },
        el("div", { class: "section-head" }, el("div", {}, el("h2", {}, "Suivi des corrections"), el("p", {}, "Cycle de vie des problèmes sur la période"))),
        el("div", { class: "toolbar" }, tabs, search, sortSel), lifeBody),
      section("Derniers changements", null, changes)),
  ];
}

function welcomeBanner() {
  const key = `adsentry.welcome.${state.user?.username}`;
  if (localStorage.getItem(key)) return null;
  const box = el("div", { class: "welcome" },
    el("div", {},
      el("strong", {}, `Bienvenue ${state.user.display_name}.`),
      el("p", {}, state.user.role === "admin"
        ? "Ce tableau de bord résume la sécurité de vos annuaires. Les cibles, les scans et les comptes se gèrent dans la section Administration."
        : "Ce tableau de bord résume la sécurité de l'annuaire en langage clair : niveau de risque, points à corriger en priorité et progrès réalisés. Chaque indicateur est cliquable, et le symbole « ? » en explique le sens."),
      el("a", { href: "#/help" }, "Lire le guide (3 minutes)")),
    el("button", { class: "icon-btn", "aria-label": "Masquer ce message", onclick: () => { localStorage.setItem(key, "1"); box.remove(); } }, svg("svg", {}, svg("use", { href: "#i-close" }))));
  return box;
}

// ---------------------------------------------------------------------------- vue : guide de lecture
function viewHelp() {
  const table = (head, rows) => el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, head.map((h) => el("th", {}, h)))), el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c)))))));
  const block = (title, ...body) => section(title, null, el("div", { class: "section-body prose" }, ...body));
  return el("div", { class: "help-page" },
    el("p", { class: "lead" }, "ADSentry vérifie régulièrement la configuration de l'annuaire Active Directory, de l'infrastructure de certificats (ADCS) et du tenant Entra ID, sans rien modifier. Ce guide explique comment lire les résultats."),
    block("1. Le score de risque (0 à 100)",
      el("p", {}, "Chaque problème détecté ajoute des points à son domaine d'analyse (plafonné à 100). Le score global est celui du domaine le plus exposé : il suffit d'un maillon faible pour qu'un attaquant progresse. ", el("strong", {}, "Plus le score est bas, mieux c'est.")),
      table(["Score", "Niveau", "Signification"], LEVELS.map((l, i) => [`${l.min} – ${i ? LEVELS[i - 1].min - 1 : 100}`, el("span", { class: `pill lvl-${l.key}` }, l.label), l.text]))),
    block("2. La maturité (1 à 5)",
      el("p", {}, "La maturité résume où en est la sécurisation, selon le constat le plus grave encore ouvert. Elle progresse quand les points les plus graves sont corrigés."),
      table(["Niveau", "Nom", "Condition"], Object.entries(MATURITY).map(([n, name]) => [n, name, MATURITY_TEXT[n].replace(/^./, (c) => c.toUpperCase())]))),
    block("3. Les sévérités",
      table(["Sévérité", "Ce que cela veut dire"], SEV_ORDER.map((s) => [sev(s), SEV_HELP[s]])),
      el("p", { class: "muted small" }, "Les délais sont indicatifs ; votre politique de sécurité peut en fixer d'autres.")),
    block("4. Les domaines d'analyse",
      table(["Domaine", "Ce qui est vérifié"], Object.keys(CATS).map((c) => [el("strong", {}, CATS[c]), CAT_HINT[c]]))),
    block("5. Lire un constat",
      el("p", {}, "Cliquez sur un constat (tableau de bord, liste des constats) pour ouvrir sa fiche :"),
      el("ul", {},
        el("li", {}, el("strong", {}, "Risque"), " : ce qu'un attaquant pourrait faire et pourquoi c'est important."),
        el("li", {}, el("strong", {}, "Correction"), " : l'action recommandée, à transmettre à l'équipe qui administre l'annuaire."),
        el("li", {}, el("strong", {}, "Détection"), " : comment repérer une tentative d'exploitation (journaux, alertes)."),
        el("li", {}, el("strong", {}, "Objets concernés"), " : les comptes, ordinateurs, GPO ou certificats en cause."),
        el("li", {}, el("strong", {}, "MITRE ATT&CK"), " : la technique d'attaque correspondante dans le référentiel public MITRE, utile aux équipes de détection."))),
    block("6. Suivre les progrès",
      el("ul", {},
        el("li", {}, el("strong", {}, "Taux de correction"), " : part des problèmes rencontrés qui ont disparu."),
        el("li", {}, el("strong", {}, "Délai moyen de correction"), " : temps moyen entre la détection et la correction."),
        el("li", {}, el("strong", {}, "Réapparus"), " : problèmes corrigés puis revenus, souvent le signe d'un processus à fiabiliser."),
        el("li", {}, el("strong", {}, "Comparer des rapports"), " : liste précise de ce qui a été corrigé, ce qui est nouveau et ce qui a changé entre deux dates."))),
    block("7. Questions fréquentes",
      el("dl", { class: "faq" },
        el("dt", {}, "Le score est élevé : sommes-nous attaqués ?"), el("dd", {}, "Non. Le score mesure des faiblesses de configuration, pas une attaque en cours. Il indique ce qu'un attaquant pourrait exploiter."),
        el("dt", {}, "Pourquoi un constat n'apparaît-il pas alors que je pense le problème présent ?"), el("dd", {}, "Une donnée qui n'a pas pu être collectée n'est jamais considérée comme vulnérable. Les règles concernées sont alors indiquées comme non évaluées dans la vue d'ensemble."),
        el("dt", {}, "Comment obtenir un rapport à jour ?"), el("dd", {}, state.user?.role === "admin" ? "Administration > Cibles d'audit > Lancer le scan." : "Les scans sont lancés par les administrateurs de l'appliance, à la demande ou selon une planification. Le tableau de bord se met à jour seul dès qu'un nouveau rapport est disponible."),
        el("dt", {}, "Puis-je partager un rapport ?"), el("dd", {}, "Oui : « Imprimer / PDF » sur le tableau de bord, ou « Exporter (CSV) » dans la liste des constats. Ces documents décrivent des faiblesses de sécurité : diffusez-les avec précaution."))));
}

// ---------------------------------------------------------------------------- nouveaux rapports (tous les rôles)
let scansTimer = null;
async function watchScans() {
  clearTimeout(scansTimer);
  if (!state.user) return;
  try {
    const known = new Set(state.scans.map((s) => s.id));
    const list = await api("/scans");
    const fresh = list.filter((s) => !known.has(s.id));
    if (fresh.length && known.size) {
      await refreshScans();
      toast(`Nouveau rapport disponible : ${fresh[0].domain} (score ${fresh[0].global_score}/100)`);
      if (["dashboard", "scans", "maturity"].includes(currentView())) softRender();
    } else if (list.length !== state.scans.length) await refreshScans();
  } catch { /* réessai au prochain passage */ }
  scansTimer = setTimeout(watchScans, 60000);
}

// ---------------------------------------------------------------------------- export CSV des constats
function exportCsv(list, scan) {
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = ["Sévérité", "Règle", "Constat", "Catégorie", "Points", "Nombre d'objets", "Objets", "Risque", "Correction", "MITRE ATT&CK"];
  const rows = list.map((f) => [SEV[f.severity], f.rule_id, f.title, CATS[f.category], f.points, f.affected.length,
    f.affected.join(" ; "), f.description, f.remediation, f.mitre.map((m) => m.technique).join(" ")]);
  const csv = "﻿" + [head, ...rows].map((r) => r.map(esc).join(";")).join("\r\n");
  const a = el("a", { href: URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" })),
    download: `adsentry-${scan.domain.replace(/[^a-z0-9.-]+/gi, "_")}-${scan.collected_at.slice(0, 10)}.csv` });
  document.body.append(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
}

async function viewMaturity() {
  if (!state.domain) return noScan();
  const d = await api(`/dashboard?domain=${encodeURIComponent(state.domain)}`);
  const tl = d.timeline;
  const chart = lineChart(tl.map((t) => ({ x: t.collected_at, y: t.maturity,
    rows: [["Niveau", `${t.maturity} ${t.maturity_label}`], ["Score", `${t.global_score}/100`]] })),
  { yMin: 1, yMax: 5, ticks: [1, 2, 3, 4, 5], tickLabel: (v) => v, step: true, fmt: (v) => MATURITY[v], height: 240 });
  const byId = Object.fromEntries(tl.map((t) => [t.id, t]));
  const list = el("ul", { class: "events" }, d.events.map((e, i) => {
    const t = byId[e.id];
    const older = d.events[i + 1];
    return el("li", {}, el("span", { class: "when" }, fmtDate(e.date)), el("span", { class: "rail" }, el("i")),
      el("div", { class: "what" },
        el("strong", {}, `Niveau ${e.maturity} – ${MATURITY[e.maturity]}`),
        el("p", {}, e.first ? `Scan de référence : ${plural(t.findings, "constat", "constats")}, score ${e.global_score}/100`
          : `${plural(e.resolved, "constat corrigé", "constats corrigés")}, ${plural(e.new, "nouveau constat", "nouveaux constats")}, score ${e.global_score}/100`),
        older ? el("a", { href: `#/compare?base=${older.id}&target=${e.id}` }, "Voir les changements") : null));
  }));
  const levels = el("table", { class: "data" }, el("tbody", {}, Object.entries(MATURITY).reverse().map(([n, name]) =>
    el("tr", {}, el("td", { class: "num" }, n), el("td", {}, name), el("td", { class: "muted" }, {
      5: "Aucun constat", 4: "Seulement des constats faibles ou informatifs", 3: "Au moins un constat moyen",
      2: "Au moins un constat élevé", 1: "Au moins un constat critique" }[n])))));
  return [
    el("div", { class: "grid-2" },
      section("Niveau de maturité dans le temps", state.domain, el("div", { class: "section-body" }, chart)),
      section("Échelle de maturité", "Calculée à partir de la sévérité la plus haute encore ouverte", levels)),
    el("div", { style: "height:1.25rem" }),
    section("Chronologie des scans", "Du plus récent au plus ancien", list),
  ];
}

async function viewCompare(params) {
  const scans = state.scans.filter((s) => s.domain === state.domain)
    .sort((a, b) => new Date(a.collected_at) - new Date(b.collected_at));
  if (scans.length < 2) return emptyState("Comparaison impossible", "Il faut au moins deux scans du même périmètre.");
  const base = params.get("base") || scans.at(-2).id, target = params.get("target") || scans.at(-1).id;
  const pick = (id, value) => el("select", { id }, scans.map((s) => el("option", { value: s.id, selected: s.id === value }, fmtDate(s.collected_at))));
  const pickers = el("div", { class: "pickers" },
    el("label", {}, "Rapport de référence", pick("cmp-base", base)),
    el("label", {}, "Rapport comparé", pick("cmp-target", target)),
    el("button", { class: "btn btn-primary", onclick: () => {
      location.hash = `#/compare?base=${$("cmp-base").value}&target=${$("cmp-target").value}`;
    } }, "Comparer"));
  const c = await api(`/compare?base=${base}&target=${target}`);
  const diff = (before, after, lowerIsBetter = true) => deltaEl(after - before, { lowerIsBetter, suffix: "" });
  const head = el("div", { class: "compare-head" },
    el("div", {}, el("div", { class: "k muted" }, "Score de risque"), el("div", { class: "v" }, `${c.base.global_score} → ${c.target.global_score}`),
      diff(c.base.global_score, c.target.global_score)),
    el("div", {}, el("div", { class: "k muted" }, "Maturité"),
      el("div", { class: "v" }, `${MATURITY[c.base.maturity]} → ${MATURITY[c.target.maturity]}`),
      diff(c.base.maturity, c.target.maturity, false)),
    el("div", {}, el("div", { class: "k muted" }, "Mouvements"),
      el("div", { class: "v" }, `${c.resolved.length} corrigés, ${c.new.length} nouveaux`),
      el("span", { class: "delta" }, `${c.changed.length} constats modifiés`)));
  const catTable = el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Domaine"), el("th", { class: "num" }, fmtDate(c.base.date)),
      el("th", { class: "num" }, fmtDate(c.target.date)), el("th", { class: "num" }, "Écart"))),
    el("tbody", {},
      Object.entries(c.scores).map(([k, v]) => el("tr", {}, el("td", {}, CATS[k]), el("td", { class: "num" }, v.before),
        el("td", { class: "num" }, v.after), el("td", { class: "num" }, diff(v.before, v.after)))),
      SEV_ORDER.slice(0, 4).map((s) => el("tr", {}, el("td", {}, sev(s), " constats"), el("td", { class: "num" }, c.severity.before[s]),
        el("td", { class: "num" }, c.severity.after[s]), el("td", { class: "num" }, diff(c.severity.before[s], c.severity.after[s]))))));
  const simple = (items, empty) => items.length ? el("table", { class: "data" }, el("tbody", {}, items.map((x) =>
    el("tr", {}, el("td", {}, sev(x.severity)), el("td", { class: "rule-id" }, x.rule_id), el("td", {}, x.title),
      el("td", { class: "num" }, plural(x.objects, "objet", "objets")))))) : el("div", { class: "empty" }, el("p", {}, empty));
  const changed = c.changed.length ? el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Règle"), el("th", {}, "Constat"), el("th", { class: "num" }, "Objets"), el("th", {}, "Détail"))),
    el("tbody", {}, c.changed.map((x) => el("tr", {}, el("td", { class: "rule-id" }, x.rule_id), el("td", {}, x.title),
      el("td", { class: "num" }, `${x.before} → ${x.after}`),
      el("td", {}, x.added.length ? el("div", { class: "diff-added" }, `Ajoutés : ${x.added.slice(0, 5).join(", ")}${x.added.length > 5 ? "…" : ""}`) : null,
        x.removed.length ? el("div", { class: "diff-removed" }, `Retirés : ${x.removed.slice(0, 5).join(", ")}${x.removed.length > 5 ? "…" : ""}`) : null)))))
    : el("div", { class: "empty" }, el("p", {}, "Aucun constat modifié."));
  return [
    section("Rapports comparés", state.domain, el("div", { class: "section-body" }, pickers)),
    el("section", { class: "section" }, head),
    section("Évolution par domaine et par sévérité", null, el("div", { class: "table-wrap" }, catTable)),
    section(`Nouveaux constats (${c.new.length})`, "Présents dans le rapport comparé, absents de la référence", simple(c.new, "Aucun nouveau constat.")),
    section(`Constats corrigés (${c.resolved.length})`, "Présents dans la référence, disparus depuis", simple(c.resolved, "Aucun constat corrigé.")),
    section(`Constats modifiés (${c.changed.length})`, "Objets concernés ajoutés ou retirés", changed),
  ];
}

// ---------------------------------------------------------------------------- vues : résultats du scan
function noScan() {
  if (state.user?.role === "admin") {
    return emptyState("Aucun scan disponible",
      "Déclarez un domaine ou un tenant dans « Cibles d'audit » puis lancez le scan, ou importez un snapshot JSON.",
      el("a", { class: "btn btn-primary", href: "#/targets" }, "Gérer les cibles d'audit"));
  }
  return emptyState("Aucune évaluation disponible",
    "Aucun rapport n'a encore été produit. Un administrateur de l'appliance doit lancer un premier scan.");
}

async function viewOverview() {
  const s = state.scan;
  if (!s) return noScan();
  const counts = Object.fromEntries(SEV_ORDER.map((k) => [k, s.findings.filter((f) => f.severity === k).length]));
  const posture = el("section", { class: "section" }, el("div", { class: "posture" },
    el("div", {}, el("div", { class: "k" }, "Score de risque"), el("div", { class: "v" }, s.global_score, el("small", {}, " /100")),
      el("div", { class: "sub" }, el("span", { class: "level" }, `Risque ${level(s.global_score).toLowerCase()}`),
        `, ${plural(s.findings.length, "constat", "constats")}`)),
    ...["critical", "high", "medium", "low"].map((k) => el("div", {}, el("div", { class: "k" }, sev(k)),
      el("div", { class: "v" }, counts[k]), el("div", { class: "sub" }, `${s.findings.filter((f) => f.severity === k)
        .reduce((n, f) => n + f.affected.length, 0)} objets`)))));

  const ledgerRows = Object.keys(CATS).map((cat) => {
    const fs = s.findings.filter((f) => f.category === cat);
    const total = fs.reduce((n, f) => n + f.points, 0) || 1;
    const evaluated = !(cat === "entra_id" && s.not_evaluated.some((r) => r.startsWith("E-")));
    return el("tr", { class: "clickable", onclick: () => { state.filters = { category: cat }; location.hash = "#/findings"; } },
      el("td", { class: "cat" }, CATS[cat], el("span", {}, CAT_HINT[cat])),
      el("td", {}, evaluated ? el("div", { class: "composition", title: "Longueur = score ; segments = part de chaque sévérité" },
        el("div", { class: "fill", style: `width:${s.scores[cat] ?? 0}%` }, SEV_ORDER.map((k) => {
          const pts = fs.filter((f) => f.severity === k).reduce((n, f) => n + f.points, 0);
          return pts ? el("i", { style: `width:${(pts / total) * 100}%;background:var(--sev-${k})` }) : null;
        }))) : el("span", { class: "muted" }, "Non évalué dans ce scan")),
      el("td", { class: "num hide-sm" }, fs.length),
      el("td", { class: "num score-cell" }, evaluated ? `${s.scores[cat] ?? 0}/100` : "—"));
  });
  const ledger = section("Risque par domaine d'analyse", null,
    el("div", { class: "section-body", style: "padding-bottom:0" }, el("div", { class: "legend" },
      SEV_ORDER.slice(0, 4).map((k) => el("span", {}, el("i", { class: "swatch", style: `--c:var(--sev-${k})` }), SEV[k])))),
    el("div", { class: "table-wrap" }, el("table", { class: "ledger" },
      el("thead", {}, el("tr", {}, el("th", {}, "Domaine"), el("th", {}, "Score et répartition par sévérité"), el("th", { class: "num hide-sm" }, "Constats"), el("th", { class: "num" }, "Score"))),
      el("tbody", {}, ledgerRows))));

  const top = [...s.findings].sort(bySeverity).slice(0, 8);
  const priorities = section("À traiter en priorité", null, el("ul", { class: "priority-list" }, top.map((f) =>
    el("li", { tabindex: "0", onclick: () => openFinding(f), onkeydown: (e) => { if (e.key === "Enter") openFinding(f); } },
      sev(f.severity), el("span", {}, f.title, el("span", { class: "rule-id sub-id" }, f.rule_id)),
      el("span", { class: "objs" }, plural(f.affected.length, "objet", "objets"))))),
  el("div", { class: "section-body" }, el("a", { href: "#/findings" }, `Voir les ${s.findings.length} constats`)));

  const rules = await getRules();
  const scope = section("Périmètre du contrôle", null, el("div", { class: "section-body" }, el("dl", { class: "facts" },
    el("dt", {}, "Règles du catalogue"), el("dd", {}, rules.length),
    el("dt", {}, "Règles évaluées"), el("dd", {}, rules.length - s.not_evaluated.length - s.manual_checks.length),
    el("dt", {}, "Hors périmètre"), el("dd", {}, s.not_evaluated.length),
    el("dt", {}, "Vérifications manuelles"), el("dd", {}, s.manual_checks.length),
    el("dt", {}, "Modèles de certificats classés"), el("dd", {}, s.pki_classification.length),
    el("dt", {}, "Collecte"), el("dd", {}, fmtDate(s.collected_at)))));
  return [posture, ledger, el("div", { class: "grid-2" }, priorities, scope)];
}

function viewFindings() {
  const s = state.scan;
  if (!s) return noScan();
  const f = state.filters;
  const search = el("input", { type: "search", placeholder: "Rechercher une règle, un constat, un objet", value: f.q || "", "aria-label": "Rechercher" });
  const cat = el("select", { "aria-label": "Catégorie" }, el("option", { value: "" }, "Toutes les catégories"),
    Object.entries(CATS).map(([k, v]) => el("option", { value: k, selected: f.category === k }, v)));
  const sv = el("select", { "aria-label": "Sévérité" }, el("option", { value: "" }, "Toutes les sévérités"),
    SEV_ORDER.map((k) => el("option", { value: k, selected: f.severity === k }, SEV[k])));
  const count = el("span", { class: "result-count" });
  const holder = el("div");
  let current = [];
  const reset = el("button", { class: "btn btn-link", type: "button" }, "Réinitialiser");
  reset.addEventListener("click", () => { search.value = ""; cat.value = ""; sv.value = ""; render(); });
  const csv = el("button", { class: "btn btn-secondary", type: "button", onclick: () => exportCsv(current, s) }, "Exporter (CSV)");
  const render = () => {
    state.filters = { q: search.value, category: cat.value, severity: sv.value };
    reset.hidden = !(search.value || cat.value || sv.value);
    const q = search.value.toLowerCase();
    const list = s.findings.filter((x) => (!cat.value || x.category === cat.value) && (!sv.value || x.severity === sv.value))
      .filter((x) => !q || `${x.rule_id} ${x.title} ${x.affected.join(" ")} ${x.mitre.map((m) => m.technique).join(" ")}`.toLowerCase().includes(q))
      .sort(bySeverity);
    current = list;
    count.textContent = plural(list.length, "constat", "constats");
    holder.replaceChildren(list.length ? findingsTable(list) : el("div", { class: "empty" }, el("p", {}, "Aucun constat ne correspond à ces filtres.")));
  };
  search.addEventListener("input", render);
  cat.addEventListener("change", render);
  sv.addEventListener("change", render);
  render();
  return [
    el("p", { class: "muted intro" }, `Rapport ${s.domain} du ${fmtDate(s.collected_at)}. Cliquez sur un constat pour lire le risque, la correction recommandée et les objets concernés.`),
    el("section", { class: "section" }, el("div", { class: "toolbar" }, search, cat, sv, reset, count, csv), holder),
  ];
}

function viewPki() {
  const s = state.scan;
  if (!s) return noScan();
  const fs = s.findings.filter((f) => f.category === "pki").sort(bySeverity);
  const classes = el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Modèle"), el("th", {}, "Classe"), el("th", {}, "Exposition"), el("th", {}, "Risque"),
      el("th", {}, "Escalades (ESC)"), el("th", { class: "hide-sm" }, "Caractéristiques"))),
    el("tbody", {}, s.pki_classification.map((c) => el("tr", {},
      el("td", { class: "rule-id" }, c.template), el("td", {}, c.classe), el("td", {}, c.exposition), el("td", {}, sev(c.risque)),
      el("td", {}, c.esc.length ? c.esc.map((e) => el("span", { class: "tech" }, e)) : el("span", { class: "muted" }, "Aucune")),
      el("td", { class: "hide-sm muted" }, c.raisons.join(" ; ")))))));
  return [
    section("Classification des modèles de certificats", "Ce que permet un certificat émis et qui peut l'obtenir", classes),
    section("Constats ADCS", `Score ${s.scores.pki ?? 0}/100`, fs.length ? findingsTable(fs, { showCategory: false })
      : el("div", { class: "empty" }, el("p", {}, "Aucun constat sur l'infrastructure de certificats."))),
  ];
}

function viewEntra() {
  const s = state.scan;
  if (!s) return noScan();
  if (s.not_evaluated.some((r) => r.startsWith("E-"))) {
    return el("section", { class: "section" }, emptyState("Entra ID non audité dans ce scan",
      "Ajoutez un bloc « entra » à la cible dans /etc/adsentry/targets.yaml (procédure : docs/ENTRA.md), puis relancez le scan."));
  }
  const fs = s.findings.filter((f) => f.category === "entra_id").sort(bySeverity);
  return section("Constats Entra ID", `Score ${s.scores.entra_id ?? 0}/100`, fs.length ? findingsTable(fs, { showCategory: false })
    : el("div", { class: "empty" }, el("p", {}, "Aucun constat sur le tenant.")));
}

async function viewMitre() {
  const s = state.scan;
  if (!s) return noScan();
  const ref = await getMitre();
  const byTech = {};
  for (const f of s.findings) for (const m of f.mitre) (byTech[m.technique] ||= []).push(f);
  const worst = (fs) => fs.map((f) => f.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0];
  const exportBtn = el("a", { class: "btn btn-secondary", href: `/api/scans/${state.scanId}/navigator`, download: "attack-layer.json" },
    svg("svg", { class: "ico" }, svg("use", { href: "#i-download" })), "Exporter pour ATT&CK Navigator");
  if (!ref) {
    return section("Techniques observées", "Référentiel ATT&CK absent : lancer « adsentry mitre-check »", el("div", { class: "section-body" },
      Object.keys(byTech).sort().map((t) => el("span", { class: "tech" }, t))));
  }
  const columns = ref.tactics.map((tac) => {
    const techs = Object.keys(byTech).filter((t) => ref.techniques[t]?.tactics.includes(tac.id)).sort();
    return el("div", { class: `tactic${techs.length ? "" : " empty"}` },
      el("h3", {}, TACTICS_FR[tac.id] || tac.name, el("span", {}, plural(techs.length, "technique", "techniques"))),
      techs.map((t) => el("button", { class: "tcell", style: `--c:var(--sev-${worst(byTech[t])})`,
        title: `${byTech[t].length} constat(s) – sévérité maximale : ${SEV[worst(byTech[t])]}`,
        onclick: () => { state.filters = { q: t }; location.hash = "#/findings"; } },
      el("b", {}, t), ref.techniques[t].name, el("em", {}, ` · ${byTech[t].length}`))));
  });
  return section("Techniques ATT&CK exploitables dans ce périmètre", `ATT&CK v${ref.version} – couleur = sévérité la plus haute`,
    el("div", { class: "section-body", style: "display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;padding-bottom:0" },
      el("div", { class: "legend" }, SEV_ORDER.slice(0, 4).map((k) => el("span", {}, el("i", { class: "swatch", style: `--c:var(--sev-${k})` }), SEV[k]))),
      exportBtn),
    el("div", { class: "matrix" }, columns));
}

async function viewReport() {
  const s = state.scan;
  if (!s) return noScan();
  const box = el("div", { class: "section-body" });
  const button = el("button", { class: "btn btn-primary" }, "Générer la synthèse");
  const render = (a) => {
    box.replaceChildren(el("div", { class: "report" },
      el("p", { class: "meta" }, `Niveau de risque : ${a.niveau_risque}`),
      el("p", {}, a.resume_executif),
      el("h3", {}, "Risques prioritaires"),
      el("ol", {}, (a.top_risques || []).map((r) => el("li", {}, el("strong", {}, r.rule_id), " – ", r.pourquoi_prioritaire,
        el("div", { class: "meta" }, `Scénario : ${r.scenario_attaque}`), el("div", { class: "meta" }, `Détection : ${r.detection}`)))),
      el("h3", {}, "Plan de remédiation"),
      el("ol", {}, (a.plan_remediation || []).map((p) => el("li", {}, el("strong", {}, `${p.horizon} : `), p.action,
        el("div", { class: "meta" }, `Règles ${(p.regles || []).join(", ")}, effort ${String(p.effort).toLowerCase()}`)))),
      a.questions_a_verifier?.length ? [el("h3", {}, "Points à vérifier"), el("ul", {}, a.questions_a_verifier.map((q) => el("li", {}, q)))] : null,
      a._controle_qualite && !a._controle_qualite.fiable
        ? el("p", { class: "note" }, `Références écartées car absentes des constats : ${a._controle_qualite.regles_inventees_retirees.join(", ")}`) : null));
    button.textContent = "Régénérer la synthèse";
  };
  const isAdmin = state.user?.role === "admin";
  const pending = isAdmin && jobsState.list.find((j) => j.kind === "ai" && j.scan_id === state.scanId);
  const waiting = () => {
    button.disabled = true;
    button.textContent = "Rédaction en cours…";
    box.replaceChildren(el("p", { class: "muted" }, "Le modèle local rédige la synthèse à partir des constats. Comptez une à cinq minutes ; la page se met à jour d'elle-même."));
  };
  button.addEventListener("click", async () => {
    try { await api(`/scans/${state.scanId}/ai-analysis`, { method: "POST" }); waiting(); pollJobs(); }
    catch (e) { toast(e.message); }
  });
  if (!isAdmin) button.hidden = true;
  if (pending?.active) waiting();
  else {
    try { render(await api(`/scans/${state.scanId}/ai-analysis`)); }
    catch {
      box.replaceChildren(pending?.status === "failed"
        ? el("p", { class: "note" }, `La synthèse n'a pas pu être générée : ${pending.error}. Vérifiez que le service ollama est démarré.`)
        : el("p", { class: "muted" }, isAdmin ? "Aucune synthèse pour ce scan." : "Aucune synthèse pour ce scan ; un administrateur peut la générer."));
    }
  }
  return el("section", { class: "section" },
    el("div", { class: "section-head" }, el("div", {}, el("h2", {}, "Synthèse de l'audit"),
      el("p", {}, "Rédigée sur l'appliance par le modèle local à partir des seuls constats ; aucune donnée ne sort.")), button),
    box);
}

// ---------------------------------------------------------------------------- vues : administration
function viewScans() {
  if (!state.scans.length) return noScan();
  const sorted = [...state.scans].sort((a, b) => new Date(b.collected_at) - new Date(a.collected_at));
  return section("Rapports conservés", plural(sorted.length, "rapport", "rapports"), el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Collecte"), el("th", {}, "Périmètre"), el("th", { class: "num" }, "Score"),
      el("th", { class: "num" }, "Constats"), el("th", { class: "hide-sm" }, "Synthèse"), el("th", {}, ""))),
    el("tbody", {}, sorted.map((s) => {
      const prev = sorted.find((x) => x.domain === s.domain && new Date(x.collected_at) < new Date(s.collected_at));
      return el("tr", { class: s.id === state.scanId ? "selected" : null },
        el("td", {}, fmtDate(s.collected_at, { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" })),
        el("td", {}, s.domain), el("td", { class: "num" }, s.global_score), el("td", { class: "num" }, s.findings),
        el("td", { class: "hide-sm" }, s.ai ? "Disponible" : el("span", { class: "muted" }, "—")),
        el("td", { class: "num" }, el("a", { href: "#/overview", onclick: () => loadScan(s.id) }, "Ouvrir"),
          prev ? [" ", el("a", { href: `#/compare?base=${prev.id}&target=${s.id}`, onclick: () => { state.domain = s.domain; } }, "Comparer")] : null,
          state.user?.role === "admin" ? [" ", el("button", { class: "btn btn-link danger", onclick: () => deleteScan(s) }, "Supprimer")] : null));
    })))));
}

async function deleteScan(s) {
  if (!confirm(`Supprimer le rapport ${s.domain} du ${fmtDate(s.collected_at)} ? Cette action est définitive.`)) return;
  try {
    await api(`/scans/${s.id}`, { method: "DELETE" });
    if (state.scanId === s.id) { state.scanId = null; state.scan = null; }
    await refreshScans();
    toast("Rapport supprimé");
    softRender();
  } catch (e) { toast(e.message); }
}

async function viewRules() {
  const rules = await getRules();
  const stats = await api("/catalog-stats");
  const search = el("input", { type: "search", placeholder: "Rechercher une règle", "aria-label": "Rechercher" });
  const cat = el("select", { "aria-label": "Catégorie" }, el("option", { value: "" }, "Toutes les catégories"),
    Object.entries(CATS).map(([k, v]) => el("option", { value: k }, v)));
  const src = el("select", { "aria-label": "Source" }, el("option", { value: "" }, "Toutes les sources"),
    Object.entries(SOURCES).map(([k, v]) => el("option", { value: k }, v)));
  const count = el("span", { class: "result-count" });
  const holder = el("div", { class: "table-wrap" });
  const render = () => {
    const q = search.value.toLowerCase();
    const list = rules.filter((r) => (!cat.value || r.category === cat.value) && (!src.value || r.source === src.value))
      .filter((r) => !q || `${r.id} ${r.title}`.toLowerCase().includes(q));
    count.textContent = plural(list.length, "règle", "règles");
    holder.replaceChildren(el("table", { class: "data" },
      el("thead", {}, el("tr", {}, el("th", {}, "Règle"), el("th", {}, "Contrôle"), el("th", {}, "Sévérité"),
        el("th", { class: "hide-sm" }, "Source"), el("th", { class: "hide-sm" }, "MITRE ATT&CK"))),
      el("tbody", {}, list.map((r) => el("tr", {}, el("td", { class: "rule-id" }, r.id), el("td", {}, r.title),
        el("td", {}, sev(r.severity)), el("td", { class: "hide-sm" }, SOURCES[r.source] || r.source),
        el("td", { class: "hide-sm muted" }, r.mitre.map((m) => m.technique).join(", ") || "—"))))));
  };
  [search, cat, src].forEach((x) => x.addEventListener(x === search ? "input" : "change", render));
  render();
  return [
    el("section", { class: "section" }, el("div", { class: "compare-head" },
      el("div", {}, el("div", { class: "k muted" }, "Règles au catalogue"), el("div", { class: "v" }, stats.rules)),
      el("div", {}, el("div", { class: "k muted" }, "Escalades ADCS couvertes"), el("div", { class: "v" }, `ESC1 à ESC${stats.adcs_escalations}`)),
      el("div", {}, el("div", { class: "k muted" }, "Règles Entra ID"), el("div", { class: "v" }, stats.by_category.entra_id || 0)))),
    el("section", { class: "section" }, el("div", { class: "toolbar" }, search, cat, src, count), holder),
  ];
}

// ---------------------------------------------------------------------------- formulaires
function field(label, input, hint) {
  const id = input.id || `f-${Math.random().toString(36).slice(2, 9)}`;
  input.id = id;
  return el("div", { class: "field" }, el("label", { for: id }, label), input, hint ? el("p", { class: "hint" }, hint) : null);
}
const input = (attrs = {}) => el("input", { type: "text", autocomplete: "off", spellcheck: "false", ...attrs });
function check(label, checked, hint) {
  const box = el("input", { type: "checkbox", checked });
  return { box, node: el("label", { class: "check" }, box, el("span", {}, label, hint ? el("small", {}, hint) : null)) };
}
function formError() { return el("p", { class: "form-error", role: "alert", hidden: true }); }
function showError(node, msg) { node.textContent = msg; node.hidden = !msg; }
async function busy(btn, label, fn) {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  try { return await fn(); } finally { btn.disabled = false; btn.textContent = old; }
}
function openPanel(kicker, title, body) {
  $("drawer-id").textContent = kicker;
  $("drawer-title").textContent = title;
  $("drawer-body").replaceChildren(body);
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  setTimeout(() => body.querySelector("input:not([disabled]), select, textarea")?.focus(), 50);
}
const fmtDateTime = (iso) => fmtDate(iso, { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
function fmtDuration(a, b) {
  if (!a) return "—";
  const s = Math.max(0, Math.round(((b ? new Date(b) : new Date()) - new Date(a)) / 1000));
  return s < 60 ? `${s} s` : s < 3600 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

// ---------------------------------------------------------------------------- planification
const DAYS = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"];
const isNum = (v) => /^\d+$/.test(v);
function describeCron(c) {
  if (!c) return "Lancement manuel uniquement";
  const [m, h, dom, mon, dow] = c.split(" ");
  const at = isNum(m) && isNum(h) ? `${h.padStart(2, "0")}:${m.padStart(2, "0")}` : null;
  if (at && mon === "*" && dom === "*" && dow === "*") return `Chaque jour à ${at}`;
  if (at && mon === "*" && dom === "*" && dow === "1-5") return `Du lundi au vendredi à ${at}`;
  if (at && mon === "*" && dom === "*" && /^[0-6]$/.test(dow)) return `Chaque ${DAYS[+dow]} à ${at}`;
  if (at && mon === "*" && isNum(dom) && dow === "*") return `Le ${dom} de chaque mois à ${at}`;
  return `Planification personnalisée (${c})`;
}
function scheduleEditor(cron) {
  const freq = el("select", {},
    el("option", { value: "manual" }, "Manuel (pas de planification)"), el("option", { value: "daily" }, "Chaque jour"),
    el("option", { value: "weekdays" }, "Du lundi au vendredi"), el("option", { value: "weekly" }, "Chaque semaine"),
    el("option", { value: "monthly" }, "Chaque mois"), el("option", { value: "custom" }, "Personnalisée (cron)"));
  const time = el("input", { type: "time", value: "02:17", "aria-label": "Heure" });
  const day = el("select", { "aria-label": "Jour" }, DAYS.map((d, i) => el("option", { value: i }, d)));
  const dom = el("input", { type: "number", min: 1, max: 28, value: 1, "aria-label": "Jour du mois", class: "narrow" });
  const custom = input({ placeholder: "17 2 * * *", "aria-label": "Expression cron" });
  const preview = el("p", { class: "hint" });
  const [m, h, d, , w] = (cron || "").split(" ");
  if (!cron) freq.value = "manual";
  else {
    if (isNum(m) && isNum(h)) time.value = `${h.padStart(2, "0")}:${m.padStart(2, "0")}`;
    const simple = isNum(m) && isNum(h) && cron.split(" ")[3] === "*";
    if (simple && d === "*" && w === "*") freq.value = "daily";
    else if (simple && d === "*" && w === "1-5") freq.value = "weekdays";
    else if (simple && d === "*" && /^[0-6]$/.test(w)) { freq.value = "weekly"; day.value = w; }
    else if (simple && isNum(d) && w === "*") { freq.value = "monthly"; dom.value = d; }
    else { freq.value = "custom"; custom.value = cron; }
  }
  const value = () => {
    const [hh, mm] = (time.value || "02:17").split(":").map((x) => String(+x));
    return { manual: "", daily: `${mm} ${hh} * * *`, weekdays: `${mm} ${hh} * * 1-5`, weekly: `${mm} ${hh} * * ${day.value}`,
      monthly: `${mm} ${hh} ${dom.value} * *`, custom: custom.value.trim() }[freq.value];
  };
  const sync = () => {
    const f = freq.value;
    time.hidden = f === "manual" || f === "custom";
    day.hidden = f !== "weekly";
    dom.hidden = f !== "monthly";
    custom.hidden = f !== "custom";
    preview.textContent = f === "custom" ? "Format : minute heure jour mois jour_semaine (heure de l'appliance)" : describeCron(value());
  };
  [freq, time, day, dom, custom].forEach((x) => x.addEventListener("input", sync));
  sync();
  return { value, node: el("div", { class: "field" }, el("label", {}, "Planification"),
    el("div", { class: "inline-fields" }, freq, day, dom, time, custom), preview) };
}

// ---------------------------------------------------------------------------- tâches : suivi en direct
const KIND = { scan: "Scan", test: "Test de connexion", ai: "Synthèse IA", ai_setup: "Installation du modèle IA", ai_index: "Indexation de la base de connaissances" };
const STATUS = { queued: "En attente", running: "En cours", succeeded: "Terminé", failed: "Échec", cancelled: "Annulé" };
const jobsState = { list: [], worker: null, timer: null, known: new Map() };
const statusBadge = (s) => el("span", { class: `status status-${s}` }, STATUS[s] || s);
function progressBar(job) {
  return el("div", { class: "progress", role: "progressbar", "aria-valuemin": 0, "aria-valuemax": 100, "aria-valuenow": job.progress },
    el("i", { style: `width:${job.status === "queued" ? 0 : job.progress}%` }));
}
async function pollJobs() {
  clearTimeout(jobsState.timer);
  if (state.user?.role !== "admin") return;
  let data;
  try { data = await api("/jobs?limit=100"); } catch { jobsState.timer = setTimeout(pollJobs, 10000); return; }
  jobsState.list = data.jobs;
  jobsState.worker = data.worker;
  let finishedScan = false;
  for (const j of data.jobs) {
    const before = jobsState.known.get(j.id);
    if (before && before !== j.status && !j.active) {
      if (j.kind === "scan" && j.status === "succeeded") {
        finishedScan = true;
        toast(`Scan « ${j.target} » terminé : score ${j.result.global_score}/100, ${plural(j.result.findings, "constat", "constats")}`);
      } else if (j.kind === "test") toast(j.status === "succeeded" ? `Connexion à « ${j.target} » réussie` : `Test de « ${j.target} » en échec`);
      else if (j.kind === "ai" && j.status === "succeeded") toast("Synthèse IA disponible");
      else if (j.kind === "ai_setup" && j.status === "succeeded") toast("Modèle IA installé et prêt");
      else if (j.kind === "ai_index" && j.status === "succeeded") toast(`Base de connaissances indexée (${j.result.chunks} extraits)`);
      else if (j.status === "failed") toast(`${KIND[j.kind]} en échec : ${j.error || ""}`);
    }
    jobsState.known.set(j.id, j.status);
  }
  const active = data.jobs.filter((j) => j.active);
  const pill = $("job-indicator");
  pill.hidden = !active.length;
  pill.querySelector("span").textContent = active.length ? `${plural(active.length, "tâche", "tâches")} en cours` : "";
  if (finishedScan) await refreshScans();
  const view = currentView();
  if (view === "ai" && state.liveUpdate) state.liveUpdate();
  if (["targets", "jobs"].includes(view) || (view === "report" && active.some((j) => j.kind === "ai"))) softRender();
  if (finishedScan && ["dashboard", "scans", "overview"].includes(view)) softRender();
  jobsState.timer = setTimeout(pollJobs, active.length || ["targets", "jobs", "ai"].includes(view) ? 2500 : 15000);
}
function workerBanner() {
  const w = jobsState.worker;
  if (!w || w.online) return null;
  return el("div", { class: "banner" }, el("strong", {}, "Le planificateur ne répond pas. "),
    "Les scans demandés restent en attente tant qu'il n'est pas démarré : service « worker » de l'appliance, ",
    "ou « adsentry serve --worker » en installation simple.");
}

// ---------------------------------------------------------------------------- vue : cibles d'audit
async function viewTargets() {
  const [targets] = await Promise.all([api("/targets"), jobsState.worker ? null : pollJobs()]);
  const add = el("button", { class: "btn btn-primary", onclick: () => openTargetForm() }, "Ajouter une cible");
  const head = el("div", { class: "page-actions" },
    el("p", { class: "muted" }, "Domaines Active Directory et tenants Entra ID audités par l'appliance. Les mots de passe, secrets et certificats sont chiffrés sur l'appliance et ne sont jamais réaffichés."),
    add);
  if (!targets.length) {
    return [workerBanner(), el("section", { class: "section" }, emptyState("Aucune cible d'audit",
      "Déclarez un domaine Active Directory (compte standard en lecture seule) et/ou un tenant Entra ID (application d'audit en lecture seule), puis lancez le premier scan.", add))];
  }
  return [workerBanner(), head, el("div", { class: "cards" }, targets.map(targetCard))];
}
function targetCard(t) {
  const job = t.active_job, last = t.last_scan;
  const sources = [
    t.ad ? el("div", {}, el("span", { class: "tag" }, "Active Directory"), ` ${t.ad.domain} via ${t.ad.dc}`, el("span", { class: "muted" }, ` · ${t.ad.username}${t.ad.ldaps ? " · LDAPS" : ""}`)) : null,
    t.entra ? el("div", {}, el("span", { class: "tag" }, "Entra ID"), ` tenant ${t.entra.tenant_id}`, el("span", { class: "muted" }, ` · ${t.entra.auth === "secret" ? "secret client" : "certificat"}`)) : null,
  ];
  const scanBtn = el("button", { class: "btn btn-primary", disabled: !!job }, "Lancer le scan");
  scanBtn.addEventListener("click", () => busy(scanBtn, "Envoi…", async () => {
    try { await api(`/targets/${t.name}/scan`, { method: "POST" }); toast(`Scan de « ${t.name} » demandé`); pollJobs(); }
    catch (e) { toast(e.message); }
  }));
  const testBtn = el("button", { class: "btn btn-secondary", disabled: !!job }, "Tester la connexion");
  testBtn.addEventListener("click", () => busy(testBtn, "Envoi…", async () => {
    try { await api(`/targets/${t.name}/test`, { method: "POST" }); pollJobs(); } catch (e) { toast(e.message); }
  }));
  const del = el("button", { class: "btn btn-link danger" }, "Supprimer");
  del.addEventListener("click", async () => {
    if (!confirm(`Supprimer la cible « ${t.name} » et ses secrets ? Les rapports déjà produits sont conservés.`)) return;
    try { await api(`/targets/${t.name}`, { method: "DELETE" }); toast("Cible supprimée"); softRender(); } catch (e) { toast(e.message); }
  });
  let lastLine;
  if (last) {
    const scan = last.scan_id && state.scans.find((s) => s.id === last.scan_id);
    lastLine = el("div", {}, statusBadge(last.status), " ", fmtDateTime(last.finished_at || last.created_at),
      last.status === "succeeded" && last.result?.global_score !== undefined ? ` · score ${last.result.global_score}/100 · ${plural(last.result.findings, "constat", "constats")}` : "",
      last.status === "failed" ? el("div", { class: "note small" }, last.error) : null,
      scan ? [" · ", el("a", { href: "#/overview", onclick: () => loadScan(scan.id) }, "Ouvrir le rapport")] : null);
  } else lastLine = el("span", { class: "muted" }, "Jamais scannée");
  const lastTest = jobsState.list.find((j) => j.target === t.name && j.kind === "test" && !j.active);
  return el("section", { class: "section card" },
    el("div", { class: "section-head" }, el("h2", {}, t.name),
      el("div", { class: "actions" }, el("button", { class: "btn btn-link", onclick: () => openTargetForm(t) }, "Modifier"), del)),
    el("div", { class: "section-body" },
      el("div", { class: "sources" }, sources),
      el("dl", { class: "facts" },
        el("dt", {}, "Planification"), el("dd", {}, describeCron(t.schedule)),
        el("dt", {}, "Synthèse IA"), el("dd", {}, t.ai_analysis ? "Générée après chaque scan" : "Sur demande"),
        el("dt", {}, "Dernier scan"), el("dd", {}, lastLine),
        lastTest ? [el("dt", {}, "Dernier test"), el("dd", {}, statusBadge(lastTest.status), " ", fmtDateTime(lastTest.finished_at),
          lastTest.status === "failed" ? el("div", { class: "note small" }, lastTest.error) : null)] : null),
      job ? el("div", { class: "job-live" },
        el("div", { class: "job-live-head" }, el("strong", {}, `${KIND[job.kind]} — ${STATUS[job.status]}`), el("span", {}, `${job.progress} %`)),
        progressBar(job), el("p", { class: "muted small" }, job.step)) : null,
      el("div", { class: "actions" }, scanBtn, testBtn)));
}

function openTargetForm(t = null) {
  const err = formError();
  const name = input({ value: t?.name || "", disabled: !!t, placeholder: "corp", maxlength: 40, required: true });
  // Active Directory
  const adOn = check("Auditer un domaine Active Directory", t ? !!t.ad : true);
  const ad = t?.ad || {};
  const domain = input({ value: ad.domain || "", placeholder: "corp.local" });
  const dc = input({ value: ad.dc || "", placeholder: "10.0.0.10 ou dc01.corp.local" });
  const user = input({ value: ad.username || "", placeholder: "svc-adsentry" });
  const pwd = el("input", { type: "password", autocomplete: "new-password",
    placeholder: ad.password_set ? "Enregistré — laisser vide pour conserver" : "" });
  const ldaps = check("LDAPS (636)", !!ad.ldaps, "Recommandé si le DC présente un certificat valide");
  const sysvol = check("Lire les GPO dans SYSVOL (SMB 445)", ad.sysvol ?? true);
  const probes = check("Sondes réseau sur les DC", ad.probes ?? true, "Signature LDAP/SMB, channel binding, services exposés");
  const adBox = el("fieldset", { class: "sub" },
    el("div", { class: "grid-fields" }, field("Domaine DNS", domain), field("Contrôleur de domaine", dc),
      field("Compte d'audit", user, "Utilisateur standard, sans privilège ; « compte », « DOMAINE\\compte » ou « compte@domaine »"), field("Mot de passe", pwd)),
    ldaps.node, sysvol.node, probes.node);
  // Entra ID
  const en = t?.entra || {};
  const enOn = check("Auditer un tenant Entra ID", !!t?.entra);
  const tenant = input({ value: en.tenant_id || "", placeholder: "00000000-0000-0000-0000-000000000000" });
  const client = input({ value: en.client_id || "", placeholder: "ID de l'application d'audit" });
  const authSel = el("select", {}, el("option", { value: "certificate" }, "Certificat (recommandé)"), el("option", { value: "secret" }, "Secret client"));
  authSel.value = en.auth || "certificate";
  let pem = null;
  const pemFile = el("input", { type: "file", accept: ".pem,.crt,.key" });
  pemFile.addEventListener("change", async () => { pem = pemFile.files[0] ? await pemFile.files[0].text() : null; });
  const thumb = input({ value: en.thumbprint || "", placeholder: "Empreinte SHA-1 du certificat" });
  const secret = el("input", { type: "password", autocomplete: "new-password", placeholder: en.client_secret_set ? "Enregistré — laisser vide pour conserver" : "" });
  const connect = input({ value: en.connect_version || "", placeholder: "2.4.27.0 (facultatif)" });
  const certFields = el("div", { class: "grid-fields" },
    field("Fichier PEM (clé privée + certificat)", pemFile, en.certificate_set ? "Un certificat est enregistré ; choisir un fichier pour le remplacer" : null),
    field("Empreinte", thumb));
  const secretFields = el("div", { class: "grid-fields" }, field("Secret client", secret));
  const enBox = el("fieldset", { class: "sub" },
    el("div", { class: "grid-fields" }, field("ID du tenant", tenant), field("ID de l'application", client),
      field("Authentification", authSel), field("Version d'Entra Connect", connect, "Non exposée par Microsoft Graph")),
    certFields, secretFields, el("p", { class: "hint" }, "Permissions Graph en lecture seule : voir docs/ENTRA.md."));
  const sched = scheduleEditor(t ? t.schedule : "17 2 * * *");
  const ai = check("Générer la synthèse IA après chaque scan", !!t?.ai_analysis, "Modèle local ; 1 à 5 minutes sur CPU");
  const sync = () => {
    adBox.hidden = !adOn.box.checked;
    enBox.hidden = !enOn.box.checked;
    certFields.hidden = authSel.value !== "certificate";
    secretFields.hidden = authSel.value !== "secret";
  };
  [adOn.box, enOn.box, authSel].forEach((x) => x.addEventListener("change", sync));
  sync();

  const payload = () => ({
    name: name.value.trim(), schedule: sched.value() || null, ai_analysis: ai.box.checked,
    ad: adOn.box.checked ? { domain: domain.value.trim(), dc: dc.value.trim(), username: user.value.trim(), password: pwd.value || null,
      ldaps: ldaps.box.checked, sysvol: sysvol.box.checked, probes: probes.box.checked } : null,
    entra: enOn.box.checked ? { tenant_id: tenant.value.trim(), client_id: client.value.trim(), auth: authSel.value,
      client_secret: secret.value || null, certificate_pem: pem, thumbprint: thumb.value.trim() || null,
      connect_version: connect.value.trim() || null } : null,
  });
  const save = el("button", { class: "btn btn-primary", type: "submit" }, t ? "Enregistrer" : "Créer la cible");
  const saveTest = el("button", { class: "btn btn-secondary", type: "button" }, "Enregistrer et tester");
  const submit = async (thenTest) => {
    showError(err, "");
    const body = payload();
    try {
      await api(t ? `/targets/${t.name}` : "/targets", { method: t ? "PUT" : "POST", body: JSON.stringify(body) });
      if (thenTest) await api(`/targets/${body.name}/test`, { method: "POST" });
      closeDrawer();
      toast(thenTest ? "Cible enregistrée ; test de connexion lancé" : "Cible enregistrée");
      pollJobs();
      softRender();
    } catch (e) { showError(err, e.message); }
  };
  const form = el("form", { class: "form", novalidate: true },
    field("Nom de la cible", name, "Minuscules, chiffres et tirets ; sert à nommer les rapports"),
    adOn.node, adBox, enOn.node, enBox, sched.node, ai.node, err,
    el("div", { class: "actions" }, save, saveTest));
  form.addEventListener("submit", (e) => { e.preventDefault(); busy(save, "Enregistrement…", () => submit(false)); });
  saveTest.addEventListener("click", () => busy(saveTest, "Enregistrement…", () => submit(true)));
  openPanel(t ? "Modifier la cible" : "Nouvelle cible d'audit", t ? t.name : "Ajouter une cible", form);
}

// ---------------------------------------------------------------------------- vue : tâches
async function viewJobs() {
  await pollJobs();
  const list = jobsState.list;
  if (!list.length) return [workerBanner(), el("section", { class: "section" }, emptyState("Aucune tâche", "Les scans, tests de connexion et synthèses IA lancés depuis la console apparaîtront ici avec leur avancement."))];
  return [workerBanner(), section("Tâches récentes", "Conservées 30 jours", el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Demandée"), el("th", {}, "Tâche"), el("th", {}, "Cible"),
      el("th", { class: "hide-sm" }, "Par"), el("th", {}, "État"), el("th", { class: "hide-sm" }, "Étape"), el("th", { class: "num hide-sm" }, "Durée"))),
    el("tbody", {}, list.map((j) => el("tr", { class: "clickable", tabindex: "0", onclick: () => openJob(j), onkeydown: (e) => { if (e.key === "Enter") openJob(j); } },
      el("td", {}, fmtDateTime(j.created_at)), el("td", {}, KIND[j.kind]),
      el("td", {}, j.target || state.scans.find((s) => s.id === j.scan_id)?.domain || j.scan_id || "—"),
      el("td", { class: "hide-sm" }, j.trigger === "schedule" ? el("span", { class: "muted" }, "Planification") : j.requested_by),
      el("td", {}, j.active ? el("div", { class: "cell-progress" }, statusBadge(j.status), progressBar(j)) : statusBadge(j.status)),
      el("td", { class: "hide-sm muted" }, j.status === "failed" ? j.error : j.step),
      el("td", { class: "num hide-sm" }, fmtDuration(j.started_at, j.finished_at))))))))];
}
function openJob(j) {
  const cancel = j.status === "queued" ? el("button", { class: "btn btn-secondary" }, "Annuler la tâche") : null;
  cancel?.addEventListener("click", () => busy(cancel, "Annulation…", async () => {
    try { await api(`/jobs/${j.id}/cancel`, { method: "POST" }); closeDrawer(); pollJobs(); } catch (e) { toast(e.message); }
  }));
  const scan = j.scan_id && j.kind === "scan" && state.scans.find((s) => s.id === j.scan_id);
  openPanel(`${KIND[j.kind]} · ${j.id}`, j.target || j.scan_id || "", el("div", {},
    el("div", { class: "kv" }, statusBadge(j.status), el("span", {}, `Demandée le ${fmtDateTime(j.created_at)}`),
      el("span", {}, j.trigger === "schedule" ? "par la planification" : `par ${j.requested_by}`), el("span", {}, `Durée ${fmtDuration(j.started_at, j.finished_at)}`)),
    j.active ? [el("h3", {}, j.step), progressBar(j)] : null,
    j.error ? [el("h3", {}, "Erreur"), el("p", { class: "note" }, j.error)] : null,
    j.kind === "test" && Object.keys(j.result || {}).length ? [el("h3", {}, "Résultat"), el("ul", { class: "plain" },
      Object.entries(j.result).map(([k, v]) => el("li", {}, statusBadge(v.ok ? "succeeded" : "failed"), ` ${k === "ad" ? "Active Directory" : "Entra ID"} : ${v.detail}`)))] : null,
    scan ? el("p", {}, el("a", { href: "#/overview", onclick: () => { closeDrawer(); loadScan(scan.id); } }, "Ouvrir le rapport produit")) : null,
    el("h3", {}, "Journal"),
    el("ol", { class: "log" }, j.log.map((l) => el("li", { class: `log-${l.level}` }, el("time", {}, new Date(l.at).toLocaleTimeString("fr-FR")), l.msg))),
    cancel));
}

// ---------------------------------------------------------------------------- vue : comptes
const ROLES = { admin: "Administrateur", viewer: "Lecteur" };
async function viewUsers() {
  const list = await api("/users");
  const add = el("button", { class: "btn btn-primary", onclick: () => openUserForm() }, "Ajouter un compte");
  const rows = list.map((u) => {
    const me = u.username.toLowerCase() === state.user.username.toLowerCase();
    const role = el("select", { "aria-label": `Rôle de ${u.username}`, disabled: me }, Object.entries(ROLES).map(([k, v]) => el("option", { value: k }, v)));
    role.value = u.role;
    role.addEventListener("change", async () => {
      try { await api(`/users/${u.username}`, { method: "PATCH", body: JSON.stringify({ role: role.value }) }); toast("Rôle modifié ; les sessions du compte ont été fermées"); }
      catch (e) { toast(e.message); role.value = u.role; }
    });
    const toggle = el("button", { class: "btn btn-link", disabled: me }, u.disabled ? "Réactiver" : "Désactiver");
    toggle.addEventListener("click", async () => {
      try { await api(`/users/${u.username}`, { method: "PATCH", body: JSON.stringify({ disabled: !u.disabled }) }); softRender(); } catch (e) { toast(e.message); }
    });
    const del = el("button", { class: "btn btn-link danger", disabled: me }, "Supprimer");
    del.addEventListener("click", async () => {
      if (!confirm(`Supprimer le compte « ${u.username} » ?`)) return;
      try { await api(`/users/${u.username}`, { method: "DELETE" }); toast("Compte supprimé"); softRender(); } catch (e) { toast(e.message); }
    });
    return el("tr", { class: u.disabled ? "disabled" : null },
      el("td", {}, el("strong", {}, u.username), me ? el("span", { class: "muted" }, " (vous)") : null, el("div", { class: "muted small" }, u.display_name)),
      el("td", {}, role),
      el("td", { class: "hide-sm" }, u.last_login ? fmtDateTime(u.last_login) : el("span", { class: "muted" }, "Jamais")),
      el("td", {}, el("span", { class: `status status-${u.disabled ? "cancelled" : "succeeded"}` }, u.disabled ? "Désactivé" : "Actif")),
      el("td", { class: "num" }, el("button", { class: "btn btn-link", onclick: () => openUserForm(u) }, "Mot de passe"), toggle, del));
  });
  return [
    el("div", { class: "page-actions" }, el("p", { class: "muted" },
      "Administrateur : cibles, secrets, scans et comptes. Lecteur : consultation des évaluations, tableaux de bord et rapports."), add),
    section("Comptes de la console", plural(list.length, "compte", "comptes"), el("div", { class: "table-wrap" }, el("table", { class: "data" },
      el("thead", {}, el("tr", {}, el("th", {}, "Compte"), el("th", {}, "Rôle"), el("th", { class: "hide-sm" }, "Dernière connexion"), el("th", {}, "État"), el("th", {}, ""))),
      el("tbody", {}, rows)))),
  ];
}
function passwordFields(minLen) {
  const pwd = el("input", { type: "password", autocomplete: "new-password", minlength: minLen, required: true });
  const confirmPwd = el("input", { type: "password", autocomplete: "new-password", required: true });
  return { pwd, confirmPwd, nodes: [field("Mot de passe", pwd, `${minLen} caractères minimum, 3 types de caractères parmi minuscules, majuscules, chiffres et symboles`), field("Confirmation", confirmPwd)],
    check: () => pwd.value === confirmPwd.value ? "" : "Les deux mots de passe diffèrent" };
}
function openUserForm(u = null) {
  const err = formError();
  const pf = passwordFields(state.minPassword);
  const username = input({ autocomplete: "off", maxlength: 64 });
  const display = input({ maxlength: 80 });
  const role = el("select", {}, Object.entries(ROLES).map(([k, v]) => el("option", { value: k }, v)));
  role.value = "viewer"; // moindre privilège par défaut
  const save = el("button", { class: "btn btn-primary", type: "submit" }, u ? "Réinitialiser" : "Créer le compte");
  const form = el("form", { class: "form" },
    u ? el("p", { class: "muted" }, "Les sessions ouvertes de ce compte seront fermées.") : [field("Identifiant", username), field("Nom affiché", display), field("Rôle", role)],
    pf.nodes, err, el("div", { class: "actions" }, save));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    showError(err, pf.check());
    if (pf.check()) return;
    busy(save, "Enregistrement…", async () => {
      try {
        if (u) await api(`/users/${u.username}`, { method: "PATCH", body: JSON.stringify({ password: pf.pwd.value }) });
        else await api("/users", { method: "POST", body: JSON.stringify({ username: username.value.trim(), display_name: display.value, role: role.value, password: pf.pwd.value }) });
        closeDrawer();
        toast(u ? "Mot de passe réinitialisé" : "Compte créé");
        softRender();
      } catch (e2) { showError(err, e2.message); }
    });
  });
  openPanel(u ? "Réinitialiser le mot de passe" : "Nouveau compte", u ? u.username : "Ajouter un compte", form);
}
function openPasswordForm() {
  const err = formError();
  const current = el("input", { type: "password", autocomplete: "current-password", required: true });
  const pf = passwordFields(state.minPassword);
  const save = el("button", { class: "btn btn-primary", type: "submit" }, "Changer le mot de passe");
  const form = el("form", { class: "form" }, field("Mot de passe actuel", current), pf.nodes, err, el("div", { class: "actions" }, save));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    showError(err, pf.check());
    if (pf.check()) return;
    busy(save, "Enregistrement…", async () => {
      try { await api("/auth/password", { method: "POST", body: JSON.stringify({ current: current.value, new: pf.pwd.value }) }); closeDrawer(); toast("Mot de passe changé"); }
      catch (e2) { showError(err, e2.message); }
    });
  });
  openPanel("Mon compte", state.user.display_name, form);
}

// ---------------------------------------------------------------------------- vue : journal d'audit
const EVENTS = {
  setup: "Initialisation de l'appliance", login: "Connexion", logout: "Déconnexion", login_failed: "Échec de connexion", login_locked: "Compte temporairement bloqué",
  password_changed: "Changement de mot de passe", user_created: "Compte créé", user_updated: "Compte modifié", user_deleted: "Compte supprimé",
  target_created: "Cible créée", target_updated: "Cible modifiée", target_deleted: "Cible supprimée", job_scan: "Scan demandé",
  job_test: "Test de connexion demandé", job_ai: "Synthèse IA demandée", job_cancelled: "Tâche annulée",
  snapshot_imported: "Snapshot importé", scan_deleted: "Rapport supprimé", job_ai_setup: "Installation du modèle IA",
  job_ai_index: "Indexation de la base de connaissances", ai_settings_updated: "Réglages IA modifiés", knowledge_saved: "Document enregistré",
  knowledge_deleted: "Document supprimé", ai_question: "Question à l'analyste", ai_dataset_downloaded: "Jeu d'entraînement téléchargé",
};
async function viewAudit() {
  const list = await api("/audit?limit=500");
  if (!list.length) return el("section", { class: "section" }, emptyState("Journal vide", "Les actions de la console sont journalisées ici."));
  const details = (e) => Object.entries(e).filter(([k]) => !["at", "event", "user"].includes(k))
    .map(([k, v]) => `${k} : ${Array.isArray(v) ? v.join(", ") : v}`).join(" · ");
  return section("Journal d'audit de la console", "500 derniers événements", el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Date"), el("th", {}, "Compte"), el("th", {}, "Événement"), el("th", { class: "hide-sm" }, "Détails"))),
    el("tbody", {}, list.map((e) => el("tr", { class: e.event.startsWith("login_") ? "warn" : null },
      el("td", {}, fmtDateTime(e.at)), el("td", {}, e.user || "—"), el("td", {}, EVENTS[e.event] || e.event),
      el("td", { class: "hide-sm muted" }, details(e))))))));
}

// ---------------------------------------------------------------------------- connexion
function showAuth(mode, info = {}) {
  clearTimeout(jobsState.timer);
  state.user = null;
  document.body.dataset.role = "";
  const err = formError();
  if (info.message) showError(err, info.message);
  const username = input({ autocomplete: "username", required: true, maxlength: 64 });
  let form;
  if (mode === "setup") {
    const token = input({ required: true, autocomplete: "off" });
    const display = input({ maxlength: 80 });
    const pf = passwordFields(info.min_password || 12);
    const go = el("button", { class: "btn btn-primary", type: "submit" }, "Créer l'administrateur");
    form = el("form", { class: "form" },
      el("h1", {}, "Première configuration"),
      el("p", { class: "muted" }, "Créez le compte administrateur de la console. Le jeton d'installation est affiché dans le journal du service API et enregistré dans le fichier setup-token du dossier de données (sur l'appliance : sudo cat /var/lib/adsentry/setup-token)."),
      field("Jeton d'installation", token), field("Identifiant", username), field("Nom affiché", display), pf.nodes, err, go);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      showError(err, pf.check());
      if (pf.check()) return;
      busy(go, "Création…", async () => {
        try {
          const user = await api("/auth/setup", { method: "POST", body: JSON.stringify({ token: token.value, username: username.value.trim(), display_name: display.value, password: pf.pwd.value }) });
          startApp(user, { first: true });
        } catch (e2) { showError(err, e2.message); }
      });
    });
  } else {
    const pwd = el("input", { type: "password", autocomplete: "current-password", required: true });
    const go = el("button", { class: "btn btn-primary", type: "submit" }, "Se connecter");
    form = el("form", { class: "form" }, el("h1", {}, "Connexion"), field("Identifiant", username), field("Mot de passe", pwd), err, go);
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      busy(go, "Connexion…", async () => {
        try { startApp(await api("/auth/login", { method: "POST", body: JSON.stringify({ username: username.value.trim(), password: pwd.value }) })); }
        catch (e2) { showError(err, e2.message); pwd.value = ""; pwd.focus(); }
      });
    });
  }
  $("auth").replaceChildren(el("div", { class: "auth-card" },
    el("div", { class: "brand" }, el("span", {}, "ADSentry")), form,
    el("p", { class: "muted small" }, "Audit Active Directory, PKI et Entra ID en lecture seule.")));
  document.body.classList.add("signed-out");
  setTimeout(() => form.querySelector("input")?.focus(), 30);
}
async function startApp(user, { first = false } = {}) {
  state.user = user;
  document.body.dataset.role = user.role;
  document.body.classList.remove("signed-out");
  $("auth").replaceChildren();
  $("user-name").textContent = user.display_name;
  $("user-role").textContent = user.role_label;
  await refreshScans();
  if (first) location.hash = "#/targets";
  else if (user.role === "admin" && !state.scans.length && !location.hash) location.hash = "#/targets";
  route();
  pollJobs();
  watchScans();
}
async function logout() {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* déjà déconnecté */ }
  state.scans = []; state.scan = null; state.scanId = null;
  jobsState.known.clear();
  clearTimeout(scansTimer);
  scanCache.clear();
  closeDrawer();
  $("drawer-body").replaceChildren();
  $("view").replaceChildren();
  showAuth("login");
}

// ---------------------------------------------------------------------------- vue : topologie
const TOPO_TYPES = { user: "Utilisateur", group: "Groupe", computer: "Ordinateur", domain: "Domaine", object: "Objet" };
const TOPO_FAMILIES = { membership: "Appartenance", acl: "Droits (ACL)", delegation: "Délégation", sidhistory: "Historique SID" };
const TOPO_FLAGS = {
  spn: ["SPN", "Compte de service avec SPN : son mot de passe peut être attaqué hors ligne (Kerberoasting)."],
  asrep: ["Sans pré-auth.", "Pré-authentification Kerberos désactivée : le mot de passe peut être attaqué hors ligne."],
  unconstrained: ["Délégation", "Délégation non contrainte : les tickets des comptes qui s'y connectent sont réutilisables."],
  sid_history: ["Hist. SID", "Historique SID renseigné : le compte hérite des droits d'un autre SID."],
  pwd_never_expires: ["Mdp permanent", "Compte à privilèges dont le mot de passe n'expire jamais."],
  rbcd: ["RBCD", "Délégation basée sur la ressource configurée sur cet ordinateur."],
  dc: ["DC", "Contrôleur de domaine."],
  disabled: ["Désactivé", "Compte désactivé."],
};
const topoState = { tab: "paths", families: new Set(Object.keys(TOPO_FAMILIES)), onlyPaths: false, simFrom: "" };

async function viewTopology(params) {
  const s = state.scan;
  if (!s) return noScan();
  let t;
  try { t = await api(`/scans/${state.scanId}/topology`); }
  catch (e) { return el("section", { class: "section" }, emptyState("Topologie indisponible", e.message)); }
  if (params?.get("tab")) topoState.tab = params.get("tab");
  const tabs = el("div", { class: "tabs topo-tabs", role: "tablist" }, [["paths", "Comptes et groupes : chemins vers le Tier 0"], ["trusts", "Domaines et forêts : approbations"]]
    .map(([k, l]) => el("button", { type: "button", role: "tab", class: topoState.tab === k ? "active" : null, "aria-selected": String(topoState.tab === k),
      onclick: () => { topoState.tab = k; softRender(); } }, l)));
  return [el("div", { class: "topo-head" }, tabs, el("span", { class: "muted small" }, `Rapport ${s.domain} du ${fmtDate(s.collected_at)}`)),
    topoState.tab === "trusts" ? trustView(t.trust_map) : pathsView(t.graph, s)].flat(Infinity);
}

// --- graphe des chemins ----------------------------------------------------------
function pathsView(g, scan) {
  const st = g.stats;
  const kpi = (label, value, cls, hint) => el("div", { class: `topo-kpi ${cls || ""}` }, el("span", { class: "k" }, label, help(hint)), el("strong", {}, value));
  const band = el("section", { class: "section topo-kpis" },
    kpi("Comptes et groupes Tier 0", st.tier0, "", "Administrateurs du domaine, contrôleurs de domaine et objets qui en contrôlent la sécurité."),
    kpi("Objets pouvant atteindre le Tier 0", st.exposed, st.exposed ? "warn" : "ok", "Comptes, groupes et ordinateurs non administrateurs qui ont un chemin (appartenance, droit, délégation) jusqu'au Tier 0."),
    kpi("Chemins ouverts à tous les utilisateurs", st.low_priv_paths, st.low_priv_paths ? "bad" : "ok", "Chemins qui partent de « Tout le monde », « Utilisateurs authentifiés » ou « Utilisateurs du domaine » : n'importe quel compte peut devenir administrateur."),
    kpi("Comptes à risque", st.risky_accounts, st.risky_accounts ? "warn" : "ok", "Comptes avec SPN, sans pré-authentification Kerberos, avec délégation non contrainte ou historique SID."));
  if (!g.nodes.length) return [band, el("section", { class: "section" }, emptyState("Aucune relation à afficher", "Aucun groupe Tier 0 ni compte à risque n'a été trouvé dans les données collectées."))];

  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const famBoxes = el("div", { class: "topo-filters" }, Object.entries(TOPO_FAMILIES).map(([k, l]) => {
    const box = el("input", { type: "checkbox", checked: topoState.families.has(k) });
    box.addEventListener("change", () => { box.checked ? topoState.families.add(k) : topoState.families.delete(k); draw(); });
    return el("label", { class: `chip fam-${k}` }, box, el("i"), l);
  }));
  const only = el("input", { type: "checkbox", checked: topoState.onlyPaths });
  only.addEventListener("change", () => { topoState.onlyPaths = only.checked; draw(); });
  const search = el("input", { type: "search", placeholder: "Trouver un compte ou un groupe", "aria-label": "Rechercher dans le graphe", list: "topo-names" });
  const names = el("datalist", { id: "topo-names" }, g.nodes.map((n) => el("option", { value: n.label })));
  search.addEventListener("change", () => {
    const n = g.nodes.find((x) => x.label.toLowerCase() === search.value.trim().toLowerCase());
    if (n) { focusNode(n.id); openNode(n); } else if (search.value) toast("Aucun objet de ce nom dans le graphe");
  });
  const resetBtn = el("button", { class: "btn btn-secondary", type: "button" }, "Recentrer");
  const toolbar = el("div", { class: "toolbar topo-toolbar" }, famBoxes,
    el("label", { class: "check inline" }, only, el("span", {}, "Seulement les chemins vers le Tier 0")), search, names, resetBtn);

  const svgEl = svg("svg", { class: "topo-svg", role: "img", "aria-label": "Graphe des relations vers le Tier 0" });
  const wrap = el("div", { class: "topo-canvas" }, svgEl,
    el("div", { class: "topo-legend" },
      el("span", {}, el("i", { class: "lg tier0" }), "Tier 0"), el("span", {}, el("i", { class: "lg exposed" }), "Peut atteindre le Tier 0"),
      el("span", {}, el("i", { class: "lg lowpriv" }), "Tous les utilisateurs"), el("span", {}, el("i", { class: "lg risky" }), "Compte à risque"),
      el("span", { class: "muted" }, "Molette : zoom · glisser : déplacer · clic : détails")));

  // Liste des chemins
  const pathList = el("ol", { class: "topo-paths" }, g.paths.map((p, i) => {
    const start = byId.get(p.nodes[0]);
    return el("li", { tabindex: "0", class: start?.low_priv ? "lowpriv" : null,
      onclick: () => highlightPath(p), onkeydown: (e) => { if (e.key === "Enter") highlightPath(p); } },
    el("div", { class: "path-head" }, el("strong", {}, start?.label || "?"), el("span", { class: "muted small" }, `${p.length} étape${p.length > 1 ? "s" : ""} → ${p.target}`)),
    el("div", { class: "path-steps small" }, p.kinds.map((k, j) => [el("span", { class: "step-kind" }, g.edge_labels[k] || k), " ", byId.get(p.nodes[j + 1])?.label, j < p.kinds.length - 1 ? " · " : ""])),
    start?.low_priv ? el("span", { class: "pill lvl-critical" }, "Ouvert à tous") : null);
  }));
  const side = el("section", { class: "section topo-side" },
    el("div", { class: "section-head" }, el("div", {}, el("h2", {}, "Chemins vers le Tier 0"), el("p", {}, "Les plus courts ; cliquez pour les surligner"))),
    g.paths.length ? pathList : el("p", { class: "muted section-body" }, "Aucun chemin d'un compte non administrateur vers le Tier 0."),
    g.truncated ? el("p", { class: "note small section-body" }, "Graphe limité aux 400 objets les plus proches du Tier 0.") : null);

  // --- disposition en colonnes : distance au Tier 0 (0 à droite) ; comptes isolés à gauche
  const COLW = 230, ROWH = 38, PAD = 60;
  let layout = new Map(), viewBox = null, highlighted = null;
  function visible() {
    const keepNodes = new Set(g.nodes.filter((n) => !topoState.onlyPaths || n.distance !== null).map((n) => n.id));
    const es = g.edges.filter((e) => topoState.families.has(e.family) && keepNodes.has(e.source) && keepNodes.has(e.target));
    return { nodes: g.nodes.filter((n) => keepNodes.has(n.id)), edges: es };
  }
  function computeLayout(nodes) {
    const maxD = Math.max(0, ...nodes.map((n) => n.distance ?? 0));
    const cols = new Map();
    for (const n of nodes) {
      const col = n.distance === null ? maxD + 1 : n.distance;
      if (!cols.has(col)) cols.set(col, []);
      cols.get(col).push(n);
    }
    const order = { domain: 0, object: 1, group: 2, user: 3, computer: 4 };
    layout = new Map();
    let height = 0;
    for (const [col, list] of cols) {
      list.sort((a, b) => (b.low_priv - a.low_priv) || (order[a.type] - order[b.type]) || a.label.localeCompare(b.label));
      list.forEach((n, i) => layout.set(n.id, { x: PAD + (maxD + 1 - col) * COLW, y: PAD + i * ROWH }));
      height = Math.max(height, PAD * 2 + list.length * ROWH);
    }
    return { width: PAD * 2 + (maxD + 2) * COLW, height, maxD, hasIsolated: cols.has(maxD + 1) };
  }
  function shape(n) {
    const cls = ["node", `t-${n.type}`, n.tier0 || n.privileged ? "tier0" : "", n.exposed ? "exposed" : "", n.low_priv ? "lowpriv" : "",
      n.flags.some((f) => ["spn", "asrep", "unconstrained", "sid_history"].includes(f)) ? "risky" : "", n.flags.includes("disabled") ? "disabled" : ""].join(" ");
    const p = layout.get(n.id);
    const glyph = n.type === "group" ? svg("rect", { x: -11, y: -11, width: 22, height: 22, rx: 5 })
      : n.type === "computer" ? svg("rect", { x: -12, y: -8, width: 24, height: 16, rx: 2 })
        : n.type === "domain" || n.type === "object" ? svg("path", { d: "M0,-13 L13,0 L0,13 L-13,0 Z" }) : svg("circle", { r: 11 });
    const letter = { user: "U", group: "G", computer: "C", domain: "D", object: "O" }[n.type];
    const g1 = svg("g", { class: cls, transform: `translate(${p.x},${p.y})`, tabindex: "0", "data-id": n.id },
      glyph, svg("text", { class: "glyph", "text-anchor": "middle", y: 4 }, letter),
      svg("text", { class: "label", x: 18, y: 4 }, n.label.length > 26 ? `${n.label.slice(0, 25)}…` : n.label),
      n.flags.filter((f) => TOPO_FLAGS[f] && !["dc", "disabled"].includes(f)).length ? svg("circle", { class: "flag-dot", cx: 9, cy: -9, r: 4 }) : null);
    g1.addEventListener("mouseenter", () => { if (!highlighted) hover(n.id); });
    g1.addEventListener("mouseleave", () => { if (!highlighted) hover(null); });
    g1.addEventListener("click", (e) => { e.stopPropagation(); openNode(n); });
    g1.addEventListener("keydown", (e) => { if (e.key === "Enter") openNode(n); });
    return g1;
  }
  function edgePath(e) {
    const a = layout.get(e.source), b = layout.get(e.target);
    const x1 = a.x + 14, x2 = b.x - 16;
    const mx = (x1 + x2) / 2;
    const same = Math.abs(a.x - b.x) < 1;
    const d = same ? `M${a.x},${a.y + 12} C${a.x + 70},${a.y + 12} ${b.x + 70},${b.y - 12} ${b.x},${b.y - 12}` : `M${x1},${a.y} C${mx},${a.y} ${mx},${b.y} ${x2},${b.y}`;
    const p = svg("path", { class: `edge fam-${e.family}${e.to_tier0 ? " main" : ""}`, d, "marker-end": `url(#arrow-${e.family})`, "data-s": e.source, "data-t": e.target });
    p.append(svg("title", {}, `${byId.get(e.source)?.label} — ${g.edge_labels[e.kind] || e.kind} → ${byId.get(e.target)?.label}`));
    return p;
  }
  function draw() {
    const { nodes, edges } = visible();
    const dims = computeLayout(nodes);
    const defs = svg("defs", {}, Object.keys(TOPO_FAMILIES).map((f) => svg("marker", { id: `arrow-${f}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 9, markerHeight: 9, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" },
      svg("path", { class: `arrowhead fam-${f}`, d: "M0,0 L10,5 L0,10 z" }))));
    const headers = svg("g", { class: "col-heads" }, Array.from({ length: dims.maxD + 2 }, (_, i) => {
      const col = dims.maxD + 1 - i;
      if (col === dims.maxD + 1 && !dims.hasIsolated) return null;
      const label = col === 0 ? "Tier 0" : col === dims.maxD + 1 ? "Comptes à risque (sans chemin)" : `À ${col} étape${col > 1 ? "s" : ""} du Tier 0`;
      return svg("text", { x: PAD + i * COLW - 12, y: 24 }, label);
    }));
    svgEl.replaceChildren(defs, headers, svg("g", { class: "edges" }, edges.map(edgePath)), svg("g", { class: "nodes" }, nodes.map(shape)));
    viewBox = { x: 0, y: 0, w: dims.width, h: Math.max(dims.height, 420) };
    applyView();
    highlighted = null;
  }
  function applyView() { svgEl.setAttribute("viewBox", `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`); }
  function hover(id) {
    svgEl.classList.toggle("dimmed", !!id);
    svgEl.querySelectorAll(".on").forEach((x) => x.classList.remove("on"));
    if (!id) return;
    svgEl.querySelector(`.node[data-id="${CSS.escape(id)}"]`)?.classList.add("on");
    svgEl.querySelectorAll(".edge").forEach((p) => {
      if (p.dataset.s === id || p.dataset.t === id) {
        p.classList.add("on");
        svgEl.querySelector(`.node[data-id="${CSS.escape(p.dataset.s === id ? p.dataset.t : p.dataset.s)}"]`)?.classList.add("on");
      }
    });
  }
  function highlightPath(p) {
    pathList.querySelectorAll("li").forEach((li, i) => li.classList.toggle("active", g.paths[i] === p));
    highlighted = p;
    svgEl.classList.add("dimmed");
    svgEl.querySelectorAll(".on").forEach((x) => x.classList.remove("on"));
    p.nodes.forEach((id, i) => {
      svgEl.querySelector(`.node[data-id="${CSS.escape(id)}"]`)?.classList.add("on");
      if (i) svgEl.querySelector(`.edge[data-s="${CSS.escape(p.nodes[i - 1])}"][data-t="${CSS.escape(id)}"]`)?.classList.add("on");
    });
    const pts = p.nodes.map((id) => layout.get(id)).filter(Boolean);
    if (pts.length) {
      const xs = pts.map((q) => q.x), ys = pts.map((q) => q.y);
      const w = Math.max(...xs) - Math.min(...xs) + 400, h = Math.max(...ys) - Math.min(...ys) + 200;
      viewBox = { x: Math.min(...xs) - 150, y: Math.min(...ys) - 100, w: Math.max(w, 600), h: Math.max(h, 320) };
      applyView();
    }
  }
  function focusNode(id) {
    const p = layout.get(id);
    if (!p) return;
    viewBox = { x: p.x - 400, y: p.y - 220, w: 900, h: 480 };
    applyView();
    highlighted = null;
    hover(id);
  }
  function openNode(n) {
    const out = g.edges.filter((e) => e.source === n.id), inc = g.edges.filter((e) => e.target === n.id);
    const chain = [];
    let cur = n.id;
    for (let guard = 0; guard < 20; guard++) {
      const e = g.edges.find((x) => x.source === cur && x.to_tier0);
      if (!e) break;
      chain.push(e);
      cur = e.target;
    }
    const related = (scan.findings || []).filter((f) => f.affected.some((a) => a.toLowerCase() === n.label.toLowerCase() || a.toLowerCase().startsWith(`${n.label.toLowerCase()} `)));
    const rel = (list, dir) => el("ul", { class: "plain small" }, list.slice(0, 40).map((e) => {
      const other = byId.get(dir === "out" ? e.target : e.source);
      return el("li", {}, el("span", { class: `step-kind fam-${e.family}` }, g.edge_labels[e.kind] || e.kind), " ",
        el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); focusNode(other.id); openNode(other); } }, other?.label || "?"));
    }));
    openPanel(`${TOPO_TYPES[n.type]}${n.tier0 || n.privileged ? " · Tier 0" : ""}`, n.label, el("div", {},
      el("div", { class: "kv" },
        n.tier0 || n.privileged ? el("span", { class: "pill lvl-critical" }, "Tier 0") : n.exposed ? el("span", { class: "pill lvl-high" }, `À ${n.distance} étape${n.distance > 1 ? "s" : ""} du Tier 0`) : el("span", { class: "pill lvl-low" }, "Pas de chemin vers le Tier 0"),
        n.low_priv ? el("span", { class: "pill lvl-critical" }, "Inclut tous les utilisateurs") : null,
        n.members !== undefined ? el("span", {}, `${n.members} membre(s) direct(s)`) : null),
      n.flags.filter((f) => TOPO_FLAGS[f]).length ? [el("h3", {}, "Points d'attention"), el("ul", { class: "plain" }, n.flags.filter((f) => TOPO_FLAGS[f]).map((f) => el("li", {}, el("strong", {}, TOPO_FLAGS[f][0]), " : ", TOPO_FLAGS[f][1])))] : null,
      chain.length ? [el("h3", {}, "Chemin le plus court vers le Tier 0"), el("ol", { class: "plain small chain" }, chain.map((e) => el("li", {}, byId.get(e.source)?.label, " — ", el("span", { class: `step-kind fam-${e.family}` }, g.edge_labels[e.kind] || e.kind), " → ", el("strong", {}, byId.get(e.target)?.label))))] : null,
      out.length ? [el("h3", {}, `Peut agir sur (${out.length})`), rel(out, "out")] : null,
      inc.length ? [el("h3", {}, `Contrôlé par (${inc.length})`), rel(inc, "in")] : null,
      related.length ? [el("h3", {}, "Constats concernant cet objet"), el("ul", { class: "plain" }, related.map((f) => el("li", {}, sev(f.severity), " ", el("a", { href: "#", onclick: (ev) => { ev.preventDefault(); openFinding(f); } }, f.title))))] : null));
  }
  // zoom et déplacement
  svgEl.addEventListener("wheel", (e) => {
    e.preventDefault();
    const r = svgEl.getBoundingClientRect();
    const k = e.deltaY > 0 ? 1.15 : 1 / 1.15;
    const mx = viewBox.x + ((e.clientX - r.left) / r.width) * viewBox.w, my = viewBox.y + ((e.clientY - r.top) / r.height) * viewBox.h;
    viewBox = { x: mx - (mx - viewBox.x) * k, y: my - (my - viewBox.y) * k, w: viewBox.w * k, h: viewBox.h * k };
    applyView();
  }, { passive: false });
  let drag = null;
  svgEl.addEventListener("pointerdown", (e) => { if (e.target.closest(".node")) return; drag = { x: e.clientX, y: e.clientY, vb: { ...viewBox } }; svgEl.setPointerCapture(e.pointerId); });
  svgEl.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const r = svgEl.getBoundingClientRect();
    viewBox = { ...drag.vb, x: drag.vb.x - ((e.clientX - drag.x) / r.width) * drag.vb.w, y: drag.vb.y - ((e.clientY - drag.y) / r.height) * drag.vb.h };
    applyView();
  });
  svgEl.addEventListener("pointerup", () => { drag = null; });
  svgEl.addEventListener("click", (e) => {
    if (e.target.closest(".node")) return;
    highlighted = null; hover(null);
    pathList.querySelectorAll("li.active").forEach((li) => li.classList.remove("active"));
  });
  resetBtn.addEventListener("click", draw);
  draw();
  return [band, el("div", { class: "topo-layout" }, el("section", { class: "section topo-main" }, toolbar, wrap), side)];
}

// --- approbations ------------------------------------------------------------------
function trustReach(tm, from) {
  // Accès possibles en partant de comptes compromis dans « from » (approximation, vue du domaine audité)
  const reach = new Map([[from, { hops: 0, via: null, elevated: false }]]);
  const queue = [from];
  while (queue.length) {
    const cur = queue.shift();
    for (const t of tm.trusts) {
      for (const a of t.access) {
        if (a.from !== cur || reach.has(a.to)) continue;
        const prev = reach.get(cur);
        if (prev.hops > 0 && prev.via && prev.via.transitive === false) continue; // pas de rebond après une approbation non transitive
        reach.set(a.to, { hops: prev.hops + 1, via: t, from: cur, elevated: prev.elevated || t.sid_filtering === false });
        queue.push(a.to);
      }
    }
  }
  return reach;
}
function trustView(tm) {
  if (!tm.domains.length) return el("section", { class: "section" }, emptyState("Aucune donnée d'approbation", "Le domaine audité n'a pas pu être identifié."));
  const W = 820, boxW = 190, boxH = 46;
  const forests = tm.forests;
  const pos = new Map();
  const groups = [];
  const current = forests.find((f) => f.domains.includes(tm.current));
  const others = forests.filter((f) => f !== current);
  // forêt du domaine audité à gauche, les autres en colonne à droite
  const placeForest = (f, x, y) => {
    const doms = [...f.domains].sort((a, b) => (b === tm.current) - (a === tm.current) || (b === f.name) - (a === f.name) || a.localeCompare(b));
    const h = 54 + doms.length * (boxH + 18);
    groups.push({ f, x, y, w: boxW + 56, h });
    doms.forEach((d, i) => pos.set(d, { x: x + 40, y: y + 40 + i * (boxH + 18) }));
    return h;
  };
  placeForest(current, 30, 40);
  let y = 40;
  for (const f of others) y += placeForest(f, W - boxW - 86, y) + 24;
  const H = Math.max(y, ...groups.map((g) => g.y + g.h)) + 40;
  const reach = topoState.simFrom ? trustReach(tm, topoState.simFrom) : null;
  const svgEl = svg("svg", { class: "trust-svg", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Carte des approbations" },
    svg("defs", {}, ["none", "low", "medium", "high"].map((s) => svg("marker", { id: `tarrow-${s}`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 12, markerHeight: 12, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" },
      svg("path", { class: `tarrow sev-${s}`, d: "M0,0 L10,5 L0,10 z" })))));
  for (const g1 of groups) {
    svgEl.append(svg("g", { class: `forest${g1.f.name ? "" : " unknown"}` },
      svg("rect", { x: g1.x, y: g1.y, width: g1.w, height: g1.h, rx: 14 }),
      svg("text", { x: g1.x + 14, y: g1.y + 24 }, g1.f.name ? `Forêt ${g1.f.name}` : "Forêt non déterminée")));
  }
  tm.trusts.forEach((t, i) => {
    const a = pos.get(t.source), b = pos.get(t.target);
    if (!a || !b) return;
    const sevKey = t.severity || "none";
    const inSim = reach && t.access.some((x) => reach.has(x.from) && reach.get(x.to)?.via === t);
    const ax = a.x + boxW, ay = a.y + boxH / 2, bx = b.x, by = b.y + boxH / 2;
    const internal = t.kind === "within_forest";
    const d = internal ? `M${a.x},${a.y + boxH / 2} C${a.x - 34},${a.y + boxH / 2} ${b.x - 34},${b.y + boxH / 2} ${b.x},${b.y + boxH / 2}`
      : `M${ax},${ay} C${(ax + bx) / 2},${ay} ${(ax + bx) / 2},${by} ${bx},${by}`;
    // flèches dans le sens de l'accès (le domaine approuvé accède au domaine qui approuve)
    const toTarget = t.access.some((x) => x.to === t.target), toSource = t.access.some((x) => x.to === t.source);
    const line = svg("path", { class: `trust-line sev-${sevKey}${internal ? " internal" : ""}${t.transitive === false ? " nontransitive" : ""}${reach ? (inSim ? " sim-on" : " sim-off") : ""}`, d,
      "marker-end": toTarget ? `url(#tarrow-${sevKey})` : null, "marker-start": toSource ? `url(#tarrow-${sevKey})` : null, tabindex: "0" });
    line.append(svg("title", {}, `${t.kind_label} — ${t.direction}`));
    line.addEventListener("click", () => openTrust(t));
    line.addEventListener("keydown", (e) => { if (e.key === "Enter") openTrust(t); });
    svgEl.append(line);
    if (!internal) {
      const lx = (ax + bx) / 2, ly = (ay + by) / 2 - 8;
      svgEl.append(svg("text", { class: `trust-label sev-${sevKey}`, x: lx, y: ly, "text-anchor": "middle" }, t.kind_label.split(" (")[0] + (t.risks.length ? ` · ${t.risks.length} risque${t.risks.length > 1 ? "s" : ""}` : "")));
    }
  });
  for (const [name, p] of pos) {
    const r = reach?.get(name);
    const g1 = svg("g", { class: `dom${name === tm.current ? " current" : ""}${reach ? (r ? (r.hops === 0 ? " sim-origin" : r.elevated ? " sim-elevated" : " sim-reached") : " sim-off") : ""}`, transform: `translate(${p.x},${p.y})`, tabindex: "0" },
      svg("rect", { width: boxW, height: boxH, rx: 8 }),
      svg("text", { x: 14, y: 20, class: "dom-name" }, name.length > 26 ? `${name.slice(0, 25)}…` : name),
      svg("text", { x: 14, y: 36, class: "dom-sub" }, name === tm.current ? "Domaine audité" : r && r.hops > 0 ? (r.elevated ? "Atteint, élévation possible" : `Atteint en ${r.hops} étape${r.hops > 1 ? "s" : ""}`) : ""));
    g1.addEventListener("click", () => { topoState.simFrom = name; softRender(); });
    svgEl.append(g1);
  }

  // Simulation
  const sel = el("select", { "aria-label": "Domaine compromis" }, el("option", { value: "" }, "— choisir un domaine —"), tm.domains.map((d) => el("option", { value: d.name, selected: topoState.simFrom === d.name }, d.name)));
  sel.addEventListener("change", () => { topoState.simFrom = sel.value; softRender(); });
  let simText = el("p", { class: "muted" }, "Choisissez un domaine (ou cliquez dessus) pour voir jusqu'où un attaquant qui y contrôle un compte pourrait s'authentifier via les approbations.");
  if (reach) {
    const hops = [...reach.entries()].filter(([, r]) => r.hops > 0).sort((a, b) => a[1].hops - b[1].hops);
    simText = hops.length ? el("ol", { class: "plain sim-steps" }, hops.map(([d, r]) => el("li", {},
      el("strong", {}, d), ` : accessible depuis ${r.from} (${r.via.kind_label.toLowerCase()}${r.via.transitive === false ? ", non transitive" : r.via.transitive ? ", transitive" : ""}).`,
      r.via.sid_filtering === false ? el("div", { class: "note small" }, `Filtrage SID désactivé : un administrateur de ${r.from} pourrait obtenir les droits d'un administrateur de ${d} (historique SID).`) : null,
      r.via.risks.filter((x) => x.label !== "Filtrage SID désactivé").map((x) => el("div", { class: "small muted" }, `Risque : ${x.label}`)))))
      : el("p", {}, `Aucune approbation ne permet aux comptes de ${topoState.simFrom} d'accéder à un autre domaine connu.`);
  }
  const sim = section("Simuler une compromission", "Quels domaines un compte compromis peut-il atteindre ?",
    el("div", { class: "section-body" }, el("div", { class: "inline-fields" }, sel, topoState.simFrom ? el("button", { class: "btn btn-link", onclick: () => { topoState.simFrom = ""; softRender(); } }, "Effacer") : null),
      simText,
      el("p", { class: "muted small" }, "Approximation à partir des approbations vues depuis le domaine audité : les relations entre domaines tiers ne sont pas connues. L'accès ne donne pas de droits par lui-même ; il ouvre l'authentification, et les droits accordés aux comptes étrangers font le reste.")));

  const rows = tm.trusts.map((t) => el("tr", { class: "clickable", tabindex: "0", onclick: () => openTrust(t), onkeydown: (e) => { if (e.key === "Enter") openTrust(t); } },
    el("td", {}, el("strong", {}, t.target)), el("td", {}, t.kind_label),
    el("td", {}, { outbound: "Sortante", inbound: "Entrante", bidirectional: "Bidirectionnelle" }[t.direction] || t.direction),
    el("td", { class: "hide-sm" }, t.transitive === null ? "—" : t.transitive ? "Oui" : "Non"),
    el("td", {}, t.risks.length ? t.risks.map((r) => el("div", {}, sev(r.severity), " ", r.label)) : el("span", { class: "status status-succeeded" }, "Aucun"))));
  return [
    el("div", { class: "topo-layout" },
      el("section", { class: "section topo-main" }, el("div", { class: "trust-legend small" },
        el("span", {}, el("i", { class: "tl sev-high" }), "Risque élevé"), el("span", {}, el("i", { class: "tl sev-medium" }), "Risque moyen"),
        el("span", {}, el("i", { class: "tl sev-none" }), "Sans risque relevé"), el("span", {}, el("i", { class: "tl dashed" }), "Non transitive"),
        el("span", { class: "muted" }, "Flèche = sens de l'accès (le domaine approuvé accède au domaine qui l'approuve)")), el("div", { class: "trust-canvas" }, svgEl)),
      sim),
    section("Approbations du domaine " + tm.current, plural(tm.trusts.length, "approbation", "approbations"), el("div", { class: "table-wrap" }, el("table", { class: "data" },
      el("thead", {}, el("tr", {}, el("th", {}, "Domaine"), el("th", {}, "Type"), el("th", {}, "Sens"), el("th", { class: "hide-sm" }, "Transitive"), el("th", {}, "Risques"))),
      el("tbody", {}, rows)))),
  ];
}
function openTrust(t) {
  const dir = { outbound: `${t.source} approuve ${t.target} : les comptes de ${t.target} peuvent s'authentifier auprès des ressources de ${t.source}.`,
    inbound: `${t.target} approuve ${t.source} : les comptes de ${t.source} peuvent s'authentifier auprès des ressources de ${t.target}.`,
    bidirectional: `Approbation dans les deux sens : les comptes de chaque domaine peuvent s'authentifier auprès de l'autre.` }[t.direction] || "";
  const fixes = { "Filtrage SID désactivé": "Réactiver le filtrage SID (quarantaine) sur l'approbation, après avoir vérifié qu'aucune migration en cours ne repose sur l'historique SID.",
    "Délégation de TGT autorisée": "Désactiver la délégation de TGT à travers l'approbation (attribut de l'approbation), sauf besoin documenté.",
    "Chiffrement RC4 uniquement": "Activer AES sur l'approbation (types de chiffrement pris en charge) des deux côtés.",
    "Domaine NT4 (protocole obsolète)": "Retirer l'approbation vers le domaine NT4 ou migrer ce domaine.",
    "Secret d'approbation non renouvelé depuis plus de 45 jours": "Vérifier la réplication et le renouvellement automatique du secret (tous les 30 jours normalement)." };
  openPanel(t.kind_label, `${t.source} ↔ ${t.target}`, el("div", {},
    el("p", {}, dir),
    el("div", { class: "kv" }, el("span", {}, `Transitive : ${t.transitive === null ? "non collecté" : t.transitive ? "oui" : "non"}`),
      t.sid_filtering !== null ? el("span", {}, `Filtrage SID : ${t.sid_filtering ? "actif" : "désactivé"}`) : el("span", {}, "Filtrage SID : sans objet (intra-forêt)")),
    t.kind === "within_forest" ? el("p", { class: "note small" }, "Au sein d'une forêt, la frontière de sécurité est la forêt, pas le domaine : un administrateur d'un domaine enfant peut prendre le contrôle de toute la forêt.") : null,
    t.risks.length ? [el("h3", {}, "Risques et corrections"), el("ul", { class: "plain" }, t.risks.map((r) => el("li", {}, sev(r.severity), " ", el("strong", {}, r.label), el("div", { class: "small muted" }, fixes[r.label] || ""))))]
      : el("p", {}, "Aucun risque relevé sur cette approbation.")));
}

// ---------------------------------------------------------------------------- vue : IA locale (admin)
const DOC_TEMPLATE = `# Titre du document

## Contexte
Décrivez ici, avec vos propres mots, une règle ou une procédure interne
(ex. modèle d'administration Tier 0, procédure de rotation des mots de passe, contacts).

## Procédure
1. Première étape
2. Deuxième étape
`;
function readyBadge(ok, yes = "Prêt", no = "Absent") {
  return el("span", { class: `status status-${ok ? "succeeded" : "failed"}` }, ok ? yes : no);
}
function aiJobBox(kind) {
  const j = jobsState.list.find((x) => x.kind === kind && x.active);
  if (!j) return null;
  return el("div", { class: "job-live" },
    el("div", { class: "job-live-head" }, el("strong", {}, `${KIND[kind]} — ${STATUS[j.status]}`), el("span", {}, `${j.progress} %`)),
    progressBar(j), el("p", { class: "muted small" }, j.step));
}
async function viewAi() {
  const st = await api("/ai/status");
  if (!jobsState.worker) await pollJobs();
  const s = st.settings;
  const idx = st.index;

  // État
  const statusRow = (label, value, hint) => el("div", { class: "ai-status-item" }, el("span", { class: "k" }, label), value, hint ? el("span", { class: "muted small" }, hint) : null);
  const status = el("section", { class: "section" }, el("div", { class: "ai-status" },
    statusRow("Serveur Ollama", readyBadge(st.reachable, `Connecté (v${st.version})`, "Injoignable"), st.reachable ? st.ollama_url : st.error),
    statusRow("Modèle de base", readyBadge(st.base_ready), s.base_model),
    statusRow("Modèle analyste", readyBadge(st.analyst_ready), s.analyst_model),
    statusRow("Embeddings", readyBadge(st.embed_ready), s.embed_model),
    statusRow("Base de connaissances", idx.built ? readyBadge(!idx.stale, "Indexée", "À réindexer") : readyBadge(false, "", "Non indexée"),
      idx.built ? `${idx.chunks} extraits · ${fmtDateTime(idx.built_at)}` : `${st.knowledge.length} document(s)`)));

  // Installation
  const busyAi = (k) => jobsState.list.some((j) => j.kind === k && j.active);
  const setupBtn = el("button", { class: "btn btn-primary", disabled: !st.reachable || busyAi("ai_setup") }, st.analyst_ready ? "Réinstaller / mettre à jour" : "Installer le modèle");
  setupBtn.addEventListener("click", () => busy(setupBtn, "Envoi…", async () => {
    try { await api("/ai/setup", { method: "POST" }); toast("Installation lancée"); await pollJobs(); softRender(); } catch (e) { toast(e.message); }
  }));
  const lastSetup = st.last_jobs.ai_setup;
  const setup = section("1. Installer le modèle", "Téléchargement par Ollama, puis création du modèle analyste avec les consignes ADSentry",
    el("div", { class: "section-body" },
      !st.reachable ? el("div", { class: "banner" }, el("strong", {}, "Ollama ne répond pas. "),
        "Sur l'appliance, vérifiez le conteneur « ollama » ; sur un serveur Linux : curl -fsSL https://ollama.com/install.sh | sh, puis relancez la console.") : null,
      el("p", {}, `Télécharge ${s.base_model} (environ 3 Go) et ${s.embed_model}, puis crée ${s.analyst_model}. Compter 5 à 20 minutes selon la connexion. Le modèle tourne ensuite en local, sur CPU : aucune donnée ne sort.`),
      el("div", { id: "ai-live-setup" }, aiJobBox("ai_setup")),
      lastSetup && !lastSetup.active ? el("p", { class: "small" }, "Dernière installation : ", statusBadge(lastSetup.status), " ", fmtDateTime(lastSetup.finished_at),
        lastSetup.error ? el("span", { class: "note small" }, ` ${lastSetup.error}`) : null) : null,
      el("div", { class: "actions" }, setupBtn)));

  // Réglages
  const base = input({ value: s.base_model }), analyst = input({ value: s.analyst_model }), embed = input({ value: s.embed_model });
  const rag = check("Utiliser la base de connaissances dans les synthèses", s.use_rag, "Les extraits pertinents sont ajoutés au contexte du modèle");
  const snippets = el("input", { type: "number", min: 0, max: 20, value: s.rag_snippets });
  const err = formError();
  const save = el("button", { class: "btn btn-secondary", type: "submit" }, "Enregistrer les réglages");
  const settingsForm = el("form", { class: "form" },
    el("div", { class: "grid-fields" }, field("Modèle de base (Ollama)", base, "Ex. qwen3.5:4b (CPU), qwen3.5:9b (plus de RAM)"),
      field("Nom du modèle analyste", analyst), field("Modèle d'embeddings", embed), field("Extraits maximum par synthèse", snippets)),
    rag.node, err, el("div", { class: "actions" }, save));
  settingsForm.addEventListener("submit", (e) => {
    e.preventDefault();
    busy(save, "Enregistrement…", async () => {
      try {
        const body = { base_model: base.value.trim(), analyst_model: analyst.value.trim(), embed_model: embed.value.trim(), use_rag: rag.box.checked, rag_snippets: +snippets.value || 0 };
        await api("/ai/settings", { method: "PUT", body: JSON.stringify(body) });
        toast(body.base_model !== s.base_model ? "Réglages enregistrés : relancez l'installation pour le nouveau modèle" : "Réglages enregistrés");
        softRender();
      } catch (e2) { showError(err, e2.message); }
    });
  });

  // Base de connaissances
  const indexBtn = el("button", { class: "btn btn-primary", disabled: !st.embed_ready || busyAi("ai_index") }, "Réindexer");
  indexBtn.addEventListener("click", () => busy(indexBtn, "Envoi…", async () => {
    try { await api("/ai/index", { method: "POST" }); await pollJobs(); softRender(); } catch (e) { toast(e.message); }
  }));
  const docs = st.knowledge.length ? el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Document"), el("th", { class: "num" }, "Sections"), el("th", { class: "hide-sm" }, "Modifié le"), el("th", {}, ""))),
    el("tbody", {}, st.knowledge.map((d) => el("tr", {},
      el("td", {}, el("strong", {}, d.name)), el("td", { class: "num" }, d.sections), el("td", { class: "hide-sm" }, fmtDateTime(d.updated_at)),
      el("td", { class: "num" }, el("button", { class: "btn btn-link", onclick: () => openDoc(d.name) }, "Modifier"),
        el("button", { class: "btn btn-link danger", onclick: async () => {
          if (!confirm(`Supprimer « ${d.name} » ?`)) return;
          try { await api(`/ai/knowledge/${d.name}`, { method: "DELETE" }); toast("Document supprimé ; pensez à réindexer"); softRender(); } catch (e) { toast(e.message); }
        } }, "Supprimer"))))))) : el("p", { class: "muted section-body" }, "Aucun document : le catalogue des règles est tout de même indexé.");
  const knowledge = el("section", { class: "section" },
    el("div", { class: "section-head" }, el("div", {}, el("h2", {}, "2. Base de connaissances"),
      el("p", {}, "Vos procédures et politiques internes, consultées par l'analyste. Rédigez avec vos propres mots, sans aucun secret.")),
    el("div", { class: "actions" }, el("button", { class: "btn btn-secondary", onclick: () => openDoc(null) }, "Nouveau document"), indexBtn)),
    el("div", { id: "ai-live-index", class: "section-body" }, aiJobBox("ai_index"),
      idx.built && idx.stale ? el("p", { class: "note small" }, "Des documents ont changé depuis la dernière indexation : cliquez sur « Réindexer ».") : null),
    docs);

  // Tester l'analyste
  const q = el("textarea", { rows: 3, placeholder: "Ex. Quel est le risque d'un compte de service avec SPN membre de Domain Admins, et comment le corriger ?" });
  const answer = el("div", { class: "ai-answer", hidden: true });
  const askBtn = el("button", { class: "btn btn-primary", disabled: !st.analyst_ready }, "Poser la question");
  askBtn.addEventListener("click", () => busy(askBtn, "Réflexion… (jusqu'à 1 à 2 minutes sur CPU)", async () => {
    answer.hidden = false;
    answer.replaceChildren(el("p", { class: "muted" }, "Le modèle local rédige sa réponse…"));
    try {
      const r = await api("/ai/ask", { method: "POST", body: JSON.stringify({ question: q.value }) });
      answer.replaceChildren(el("div", { class: "ai-text" }, r.answer),
        el("p", { class: "muted small" }, `Modèle ${r.model} · ${plural(r.context.length, "extrait", "extraits")} de la base de connaissances utilisé(s)`));
    } catch (e) { answer.replaceChildren(el("p", { class: "note" }, e.message)); }
  }));
  const ask = section("3. Tester l'analyste", "Question libre ; ne remplace pas la synthèse d'un scan, fondée sur les seuls constats",
    el("div", { class: "section-body" }, field("Question", q), el("div", { class: "actions" }, askBtn), answer));

  // Fine-tuning
  const n = el("select", { "aria-label": "Nombre d'exemples" }, [500, 1500, 3000].map((v) => el("option", { value: v, selected: v === 1500 }, `${v} exemples`)));
  const dl = el("a", { class: "btn btn-secondary", href: "/api/ai/dataset?n=1500", download: "" }, "Télécharger le jeu d'entraînement");
  n.addEventListener("change", () => { dl.href = `/api/ai/dataset?n=${n.value}`; });
  const finetune = section("4. Spécialiser le modèle (optionnel)", "Fine-tuning sur un GPU gratuit, uniquement si les synthèses restent insuffisantes",
    el("div", { class: "section-body prose" },
      el("ol", {},
        el("li", {}, "Téléchargez le jeu d'entraînement : exemples ", el("strong", {}, "100 % synthétiques"), " générés à partir du catalogue, sans aucune donnée de votre annuaire. ", el("span", { class: "inline-fields" }, n, dl)),
        el("li", {}, "Dans Google Colab (GPU T4), exécutez ai/finetune/train_unsloth_colab.py du dépôt avec ce fichier."),
        el("li", {}, "Copiez le fichier .gguf obtenu sur le serveur, à côté de ai/Modelfile, remplacez la ligne FROM par ce fichier, puis : ollama create ", s.analyst_model, " -f ai/Modelfile.")),
      el("p", { class: "muted small" }, "N'envoyez jamais un rapport réel vers un service en ligne : seules les données synthétiques ou de laboratoire peuvent servir à l'entraînement.")));

  // Mises à jour en direct sans effacer les saisies
  state.liveUpdate = () => {
    const a = $("ai-live-setup"), b = $("ai-live-index");
    if (a) a.replaceChildren(...[aiJobBox("ai_setup")].filter(Boolean));
    if (b) b.replaceChildren(...[aiJobBox("ai_index")].filter(Boolean));
    const ended = jobsState.list.find((j) => ["ai_setup", "ai_index"].includes(j.kind) && !j.active && jobsState.seenActive?.has(j.id));
    jobsState.seenActive = new Set(jobsState.list.filter((j) => j.active).map((j) => j.id));
    if (ended) softRender();
  };
  return [workerBanner(),
    el("p", { class: "muted intro" }, "L'analyste rédige les synthèses à partir des seuls constats du moteur de règles ; il n'invente ni constat ni score. Tout s'exécute sur l'appliance."),
    status, setup, el("div", { class: "grid-2" }, knowledge, section("Réglages", null, el("div", { class: "section-body" }, settingsForm))), ask, finetune];
}
async function openDoc(name) {
  const err = formError();
  const fname = input({ value: name || "", disabled: !!name, placeholder: "tier0.md", maxlength: 64 });
  const content = el("textarea", { rows: 22, class: "mono", spellcheck: "true" });
  content.value = name ? (await api(`/ai/knowledge/${name}`)).content : DOC_TEMPLATE;
  const save = el("button", { class: "btn btn-primary", type: "submit" }, "Enregistrer");
  const form = el("form", { class: "form" },
    field("Nom du fichier", fname, "Minuscules, chiffres, - et _, extension .md"),
    field("Contenu (Markdown)", content, "Découpé par sections « ## Titre ». Pas de mot de passe ni de clé : ce texte est fourni au modèle."),
    err, el("div", { class: "actions" }, save));
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    let n = fname.value.trim().toLowerCase();
    if (n && !n.endsWith(".md")) n += ".md";
    busy(save, "Enregistrement…", async () => {
      try {
        await api(`/ai/knowledge/${encodeURIComponent(n)}`, { method: "PUT", body: JSON.stringify({ content: content.value }) });
        closeDrawer();
        toast("Document enregistré ; cliquez sur « Réindexer » pour qu'il soit pris en compte");
        softRender();
      } catch (e2) { showError(err, e2.message); }
    });
  });
  openPanel("Base de connaissances", name || "Nouveau document", form);
}

// ---------------------------------------------------------------------------- routeur
const RENDER = { dashboard: viewDashboard, maturity: viewMaturity, compare: viewCompare, overview: viewOverview,
  findings: viewFindings, pki: viewPki, entra: viewEntra, mitre: viewMitre, report: viewReport, scans: viewScans, rules: viewRules,
  targets: viewTargets, jobs: viewJobs, users: viewUsers, audit: viewAudit, help: viewHelp, ai: viewAi, topology: viewTopology };

function currentView() {
  const path = (location.hash.slice(2) || "dashboard").split("?")[0];
  return RENDER[path] && (!VIEWS[path].admin || state.user?.role === "admin") ? path : "dashboard";
}
let rendering = false;
let routeSeq = 0; // seule la navigation la plus récente peut afficher son contenu
async function softRender() {
  // Réaffiche la vue courante sans la remettre en haut de page (mises à jour en direct)
  if (rendering || !state.user || $("drawer").classList.contains("open")) return;
  rendering = true;
  const seq = routeSeq, view = currentView();
  try {
    const [, query] = (location.hash.slice(2) || "").split("?");
    const content = await RENDER[view](new URLSearchParams(query || ""));
    if (seq !== routeSeq || view !== currentView()) return; // l'utilisateur a changé de page entre-temps
    $("view").replaceChildren(...[content].flat().filter(Boolean));
  } catch { /* la prochaine actualisation réessaiera */ } finally { rendering = false; }
}

async function route() {
  if (!state.user) return;
  const seq = ++routeSeq;
  const [, query] = (location.hash.slice(2) || "dashboard").split("?");
  const name = currentView();
  const meta = VIEWS[name];
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
  $("page-title").textContent = meta.title;
  document.title = `${meta.title} – ADSentry`;
  $("domain-field").hidden = meta.group !== "pilotage";
  $("scan-field").hidden = meta.group !== "scan";
  closeSidebar();
  closeDrawer();
  tip.hide();
  const view = $("view");
  view.replaceChildren(el("p", { class: "muted" }, "Chargement…"));
  try {
    const content = await RENDER[name](new URLSearchParams(query || ""));
    if (seq !== routeSeq) return; // navigation plus récente en cours
    view.replaceChildren(...[content].flat().filter(Boolean));
  } catch (e) {
    if (seq !== routeSeq) return;
    view.replaceChildren(el("section", { class: "section" }, emptyState("Impossible d'afficher cette page", e.message)));
  }
  view.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function openSidebar() { $("sidebar").classList.add("open"); $("scrim").classList.add("show"); }
function closeSidebar() { $("sidebar").classList.remove("open"); $("scrim").classList.remove("show"); }

$("menu-btn").addEventListener("click", openSidebar);
$("scrim").addEventListener("click", closeSidebar);
$("drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); closeSidebar(); } });
$("scan-select").addEventListener("change", async (e) => { await loadScan(e.target.value); route(); });
$("domain-select").addEventListener("change", (e) => { state.domain = e.target.value; route(); });
$("logout-btn").addEventListener("click", logout);
$("password-btn").addEventListener("click", openPasswordForm);
$("upload").addEventListener("change", async (e) => {
  const form = new FormData();
  form.append("snapshot", e.target.files[0]);
  try {
    const r = await api("/scans", { method: "POST", body: form });
    await refreshScans(r.id);
    toast("Snapshot importé et analysé");
    location.hash = "#/overview";
    route();
  } catch (err) { toast(`Import refusé : ${err.message}`); }
  e.target.value = "";
});
window.addEventListener("hashchange", route);

(async () => {
  try {
    const st = await api("/auth/status");
    state.minPassword = st.min_password;
    if (st.setup_required) showAuth("setup", st);
    else if (!st.user) showAuth("login", st);
    else await startApp(st.user);
  } catch (e) {
    $("auth").replaceChildren(el("div", { class: "auth-card" }, emptyState("API injoignable", e.message)));
    document.body.classList.add("signed-out");
  }
})();
