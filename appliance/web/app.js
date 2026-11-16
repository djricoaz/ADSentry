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
  scans: { title: "Historique des scans", group: "ref" },
  rules: { title: "Catalogue de règles", group: "ref" },
  targets: { title: "Cibles d'audit", group: "admin", admin: true },
  jobs: { title: "Tâches", group: "admin", admin: true },
  users: { title: "Comptes et rôles", group: "admin", admin: true },
  audit: { title: "Journal d'audit", group: "admin", admin: true },
};

const state = { scans: [], scanId: null, scan: null, domain: null, rules: null, mitre: null, filters: {}, user: null, minPassword: 12 };
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
  step = false, height = 220, fmt = (v) => v, compact = false } = {}) {
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
  const hit = svg("rect", { class: "hit", x: m.l, y: 0, width: iw, height: H });
  hit.addEventListener("mousemove", (evt) => {
    const box = root.getBoundingClientRect();
    const px = ((evt.clientX - box.left) / box.width) * W;
    const i = Math.max(0, Math.min(points.length - 1, Math.round(((px - m.l) / iw) * (points.length - 1))));
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
async function viewDashboard() {
  if (!state.domain) return noScan();
  const d = await api(`/dashboard?domain=${encodeURIComponent(state.domain)}`);
  const k = d.kpis;
  const tl = d.timeline;
  const kpi = (label, value, unit, delta) => el("div", {}, el("div", { class: "k" }, label),
    el("div", { class: "v" }, value ?? "—", unit && value !== null && value !== undefined ? el("small", {}, unit) : null), delta);
  const band = el("section", { class: "section" }, el("div", { class: "kpis" },
    kpi("Score de risque", k.global_score, "/100", deltaEl(k.global_score_delta)),
    kpi("Maturité", `${k.maturity}`, `/5 ${k.maturity_label}`, deltaEl(k.maturity_delta, { lowerIsBetter: false, suffix: "niveau" })),
    kpi("Constats critiques", k.critical, null, deltaEl(k.critical_delta)),
    kpi("Constats ouverts", k.open, null, el("span", { class: "delta" }, `${k.resolved_total} corrigés depuis le premier scan`)),
    kpi("Taux de correction", k.remediation_rate, " %", el("span", { class: "delta" }, `sur ${plural(k.scans, "scan", "scans")}`)),
    kpi("Délai moyen de correction", k.mttr_days, " j", el("span", { class: "delta" },
      k.oldest_critical_days !== null ? `Critique le plus ancien ouvert : ${k.oldest_critical_days} j` : "Aucun critique ouvert"))));

  const scoreChart = lineChart(tl.map((t) => ({ x: t.collected_at, y: t.global_score,
    rows: [["Score", `${t.global_score}/100`], ["Maturité", `${t.maturity} ${t.maturity_label}`], ["Constats", t.findings]] })),
  { fmt: (v) => `${v}` });
  const multiples = el("div", { class: "multiples" }, Object.keys(CATS).map((c) => {
    const pts = tl.map((t) => ({ x: t.collected_at, y: t.scores[c] ?? 0, rows: [[CATS[c], `${t.scores[c] ?? 0}/100`]] }));
    const last = pts.at(-1)?.y ?? 0, prev = pts.at(-2)?.y;
    return el("div", {}, el("div", { class: "head" }, el("strong", {}, CATS[c]), el("span", {}, `${last}/100`)),
      deltaEl(prev === undefined ? null : last - prev),
      lineChart(pts, { compact: true, height: 70 }));
  }));
  const open = d.lifecycle.filter((x) => !x.resolved_at).slice(0, 10);
  const oldest = el("div", { class: "table-wrap" }, el("table", { class: "data" },
    el("thead", {}, el("tr", {}, el("th", {}, "Sévérité"), el("th", {}, "Constat"), el("th", { class: "num" }, "Ouvert depuis"))),
    el("tbody", {}, open.map((x) => el("tr", {}, el("td", {}, sev(x.severity)),
      el("td", {}, el("span", { class: "rule-id" }, x.rule_id), el("br"), x.title),
      el("td", { class: "num" }, `${x.age_days} j`))))));
  const changes = el("ul", { class: "events" }, d.events.slice(0, 6).map((e) => el("li", {},
    el("span", { class: "when" }, fmtDate(e.date)), el("span", { class: "rail" }, el("i")),
    el("div", { class: "what" }, el("strong", {}, e.first ? "Premier scan de référence" : `${e.resolved} corrigé(s), ${e.new} nouveau(x)`),
      el("p", {}, `Score ${e.global_score}/100, maturité ${e.maturity} ${MATURITY[e.maturity]}`)))));

  return [
    band,
    el("div", { class: "grid-2" },
      section("Score de risque global", "0 = aucun risque détecté, 100 = risque maximal", el("div", { class: "section-body" }, scoreChart)),
      section("Constats ouverts par sévérité", null, el("div", { class: "section-body" }, stackedBars(tl)))),
    el("div", { style: "height:1.25rem" }),
    section("Score par domaine d'analyse", `${tl.length} scans du ${fmtDate(tl[0]?.collected_at)} au ${fmtDate(tl.at(-1)?.collected_at)}`, multiples),
    el("div", { class: "grid-2" },
      section("Constats ouverts les plus anciens", "Triés par sévérité puis ancienneté", oldest),
      section("Derniers changements", null, changes, el("div", { class: "section-body" },
        el("a", { href: "#/compare" }, "Comparer deux rapports")))),
  ];
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
  const render = () => {
    state.filters = { q: search.value, category: cat.value, severity: sv.value };
    const q = search.value.toLowerCase();
    const list = s.findings.filter((x) => (!cat.value || x.category === cat.value) && (!sv.value || x.severity === sv.value))
      .filter((x) => !q || `${x.rule_id} ${x.title} ${x.affected.join(" ")} ${x.mitre.map((m) => m.technique).join(" ")}`.toLowerCase().includes(q))
      .sort(bySeverity);
    count.textContent = plural(list.length, "constat", "constats");
    holder.replaceChildren(list.length ? findingsTable(list) : el("div", { class: "empty" }, el("p", {}, "Aucun constat ne correspond à ces filtres.")));
  };
  search.addEventListener("input", render);
  cat.addEventListener("change", render);
  sv.addEventListener("change", render);
  render();
  return el("section", { class: "section" }, el("div", { class: "toolbar" }, search, cat, sv, count), holder);
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
const KIND = { scan: "Scan", test: "Test de connexion", ai: "Synthèse IA" };
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
  if (["targets", "jobs"].includes(view) || (view === "report" && active.some((j) => j.kind === "ai"))) softRender();
  if (finishedScan && ["dashboard", "scans", "overview"].includes(view)) softRender();
  jobsState.timer = setTimeout(pollJobs, active.length || ["targets", "jobs"].includes(view) ? 2500 : 15000);
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
      field("Compte d'audit", user, "Utilisateur standard, sans privilège"), field("Mot de passe", pwd)),
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
  snapshot_imported: "Snapshot importé", scan_deleted: "Rapport supprimé",
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
}
async function logout() {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* déjà déconnecté */ }
  state.scans = []; state.scan = null; state.scanId = null;
  jobsState.known.clear();
  closeDrawer();
  $("drawer-body").replaceChildren();
  $("view").replaceChildren();
  showAuth("login");
}

// ---------------------------------------------------------------------------- routeur
const RENDER = { dashboard: viewDashboard, maturity: viewMaturity, compare: viewCompare, overview: viewOverview,
  findings: viewFindings, pki: viewPki, entra: viewEntra, mitre: viewMitre, report: viewReport, scans: viewScans, rules: viewRules,
  targets: viewTargets, jobs: viewJobs, users: viewUsers, audit: viewAudit };

function currentView() {
  const path = (location.hash.slice(2) || "dashboard").split("?")[0];
  return RENDER[path] && (!VIEWS[path].admin || state.user?.role === "admin") ? path : "dashboard";
}
let rendering = false;
async function softRender() {
  // Réaffiche la vue courante sans la remettre en haut de page (mises à jour en direct)
  if (rendering || !state.user || $("drawer").classList.contains("open")) return;
  rendering = true;
  try {
    const [, query] = (location.hash.slice(2) || "").split("?");
    const content = await RENDER[currentView()](new URLSearchParams(query || ""));
    $("view").replaceChildren(...[content].flat().filter(Boolean));
  } catch { /* la prochaine actualisation réessaiera */ } finally { rendering = false; }
}

async function route() {
  if (!state.user) return;
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
    view.replaceChildren(...[content].flat().filter(Boolean));
  } catch (e) {
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
