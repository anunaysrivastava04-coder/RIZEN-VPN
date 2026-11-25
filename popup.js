import { COUNTRIES, validateProxy, dohProbe } from "./lib.js";

const DNS = [
  { id: "cloudflare", name: "Cloudflare", note: "Fast and private", url: "https://cloudflare-dns.com/dns-query" },
  { id: "google", name: "Google", note: "Reliable worldwide", url: "https://dns.google/dns-query" },
  { id: "quad9", name: "Quad9", note: "Blocks malicious sites", url: "https://dns.quad9.net/dns-query" },
  { id: "adguard", name: "AdGuard", note: "Blocks ads and trackers", url: "https://dns.adguard-dns.com/dns-query" }
];
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
let prefs = { cc: "IN", tcp: false, play: false, dns: "cloudflare", scheme: "http", consent: undefined };
let state = { status: "off" };
let tabUrl = "";
let timer;

const nameOf = (cc) => (COUNTRIES.find((c) => c[0] === cc) || [cc, cc || "unknown"])[1];
const send = (m) => chrome.runtime.sendMessage(m);
const savePrefs = () => chrome.storage.local.set({ prefs });

/* tabs */
$$("#tabs button").forEach((b, i) => b.addEventListener("click", () => {
  $$("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
  $$(".panel").forEach((p) => p.classList.toggle("on", p.id === "tab-" + b.dataset.tab));
  $(".ink").style.transform = `translateX(${i * 100}%)`;
  $("#countryMenu").classList.remove("open");
}));

/* consent */
const showConsent = () => { $("#consent").hidden = prefs.consent !== undefined; };
$("#cYes").onclick = () => { prefs.consent = true; savePrefs(); $("#consentToggle").checked = true; showConsent(); };
$("#cNo").onclick = () => { prefs.consent = false; savePrefs(); $("#consentToggle").checked = false; showConsent(); };
$("#consentToggle").onchange = (e) => { prefs.consent = e.target.checked; savePrefs(); if (!prefs.consent && state.status !== "off" && !state.manual) send({ type: "disconnect" }); };

/* country picker */
function drawCountries(q = "") {
  const list = $("#countryList");
  list.replaceChildren();
  COUNTRIES.filter((c) => c[1].toLowerCase().includes(q.toLowerCase())).forEach(([cc, name]) => {
    const d = el("div", "opt" + (cc === prefs.cc ? " sel" : ""));
    d.append(el("b", "code", cc), el("span", "", name));
    d.onclick = () => {
      prefs.cc = cc; savePrefs(); paintCountry();
      $("#countryMenu").classList.remove("open");
      if (state.status === "on" || state.status === "connecting") connect();
    };
    list.appendChild(d);
  });
}
const paintCountry = () => { $("#curCode").textContent = prefs.cc; $("#curName").textContent = nameOf(prefs.cc); };
$("#countryBtn").onclick = () => {
  const m = $("#countryMenu");
  m.classList.toggle("open");
  if (m.classList.contains("open")) { $("#search").value = ""; drawCountries(); $("#search").focus(); }
};
$("#search").oninput = (e) => drawCountries(e.target.value);

/* VPN */
function connect() { send({ type: "connect", cc: prefs.cc, tcp: prefs.tcp, playOnly: prefs.play }); }
$("#power").onclick = () => {
  if (state.status === "on" || state.status === "connecting") send({ type: "disconnect" });
  else if (prefs.consent !== true) { prefs.consent === undefined ? showConsent() : (prefs.consent = undefined, showConsent()); }
  else connect();
};
$("#unblock").onclick = () => send({ type: "disconnect" });
["tcp", "play"].forEach((k) => $("#" + k).addEventListener("change", (e) => {
  prefs[k] = e.target.checked; savePrefs();
  if (state.status === "on" && !state.manual) connect();
}));

const fmt = (s) => [s / 3600, (s / 60) % 60, s % 60].map((n) => String(Math.floor(n)).padStart(2, "0")).join(":");
function render() {
  const s = state;
  const cls = { on: "on", connecting: "busy", error: "err", off: "off" }[s.status] || "off";
  $("#pill").className = "pill " + cls;
  $("#power").className = "sun " + cls;
  $("#pill span").textContent = s.blocked ? "Blocked" : { on: "Protected", connecting: "Connecting", error: "Problem", off: "Off" }[s.status] || "Off";
  const hl = $("#headline"), sub = $("#sub");
  if (s.status === "on") {
    hl.textContent = s.manual ? "Using your proxy" : s.mismatch ? "Connected (exit: " + nameOf(s.exitCc) + ")" : "Connected to " + nameOf(s.cc);
    sub.textContent = s.mismatch ? "No free " + nameOf(s.cc) + " server passed the checks. Tap the sun twice to retry." : `Verified ${String(s.scheme).toUpperCase()} server${s.playOnly ? " · Play only" : ""}`;
  } else if (s.status === "connecting") {
    hl.textContent = "Checking servers";
    sub.textContent = s.total ? `Testing… ${s.attempt} of ${s.total}` : "Looking up free servers";
  } else if (s.status === "error") {
    hl.textContent = s.blocked ? "Internet blocked" : "Could not connect"; sub.textContent = s.msg || "Try again.";
  } else { hl.textContent = "Not protected"; sub.textContent = "Pick a country and tap the sun."; }
  $("#stIp").textContent = s.status === "on" ? s.ip : "—";
  $("#stMs").textContent = s.status === "on" ? s.ms + " ms" : "—";
  $("#unblock").hidden = !s.blocked;
  $("#httpWarn").hidden = !(s.status === "on" && tabUrl.startsWith("http://"));
  clearInterval(timer);
  const tick = () => { $("#stTime").textContent = s.status === "on" ? fmt((Date.now() - s.since) / 1000) : "00:00:00"; };
  tick(); if (s.status === "on") timer = setInterval(tick, 1000);
  if (s.manual && s.status === "error") { $("#pMsg").textContent = s.msg; $("#pMsg").className = "note bad"; }
  $("#pGo").textContent = s.status === "on" && s.manual ? "Disconnect proxy" : "Connect proxy";
}

/* manual proxy */
$$("#scheme button").forEach((b) => b.onclick = () => {
  $$("#scheme button").forEach((x) => x.classList.toggle("on", x === b));
  prefs.scheme = b.dataset.v; savePrefs();
});
$("#pGo").onclick = () => {
  if (state.status === "on" && state.manual) return send({ type: "disconnect" });
  const msg = $("#pMsg");
  try {
    const p = validateProxy({ scheme: prefs.scheme, host: $("#pHost").value, port: $("#pPort").value }, { allowPrivate: true, allowDomain: true });
    msg.textContent = ""; msg.className = "note";
    send({ type: "manual", scheme: p.scheme, host: p.host, port: p.port, playOnly: prefs.play });
  } catch (e) { msg.textContent = e.message; msg.className = "note bad"; }
};

/* DNS */
function drawDns() {
  const box = $("#dnsList"); box.replaceChildren();
  DNS.forEach((d) => {
    const row = el("div", "dns" + (d.id === prefs.dns ? " sel" : ""));
    const info = el("div"); info.append(el("b", "", d.name), el("small", "", d.note));
    const ms = el("em"); ms.id = "ms-" + d.id;
    row.append(info, ms);
    row.onclick = () => { prefs.dns = d.id; savePrefs(); drawDns(); };
    box.appendChild(row);
  });
}
$("#dnsBench").onclick = async () => {
  const m = $("#dnsMsg"); m.className = "note"; m.textContent = "Testing…";
  const res = await Promise.all(DNS.map(async (d) => [d, await dohProbe(d.url)]));
  res.forEach(([d, ms]) => { $("#ms-" + d.id).textContent = ms ? ms + " ms" : "failed"; });
  const best = res.filter((r) => r[1]).sort((a, b) => a[1] - b[1])[0];
  m.className = "note good";
  m.textContent = best ? `Fastest right now: ${best[0].name}` : "No provider answered. Check your connection.";
};
$("#dnsApply").onclick = async () => {
  const d = DNS.find((x) => x.id === prefs.dns);
  try { await navigator.clipboard.writeText(d.url); } catch (e) {}
  chrome.tabs.create({ url: "chrome://settings/security" });
  $("#dnsMsg").className = "note good";
  $("#dnsMsg").textContent = "Copied. In Chrome settings, turn on Secure DNS, choose Custom, and paste.";
};

/* leak test */
$("#testGo").onclick = async () => {
  const box = $("#results"), btn = $("#testGo");
  btn.disabled = true; btn.textContent = "Testing…"; box.replaceChildren();
  const r = await send({ type: "leaktest" }).catch(() => null);
  (r && r.results ? r.results : [{ label: "Test", status: "fail", detail: "The test could not run." }]).forEach((x) => {
    const row = el("div", "res " + x.status);
    const text = el("div"); text.append(el("b", "", x.label), el("small", "", x.detail));
    row.append(el("i", "", x.status === "pass" ? "✓" : x.status === "warn" ? "!" : "✕"), text);
    box.appendChild(row);
  });
  btn.disabled = false; btn.textContent = "Run leak test again";
};

/* boot */
(async () => {
  const st = await chrome.storage.local.get(["prefs", "state"]);
  prefs = { ...prefs, ...(st.prefs || {}) };
  state = st.state || state;
  try { const [t] = await chrome.tabs.query({ active: true, currentWindow: true }); tabUrl = (t && t.url) || ""; } catch (e) {}
  paintCountry(); drawDns();
  $("#tcp").checked = !!prefs.tcp; $("#play").checked = !!prefs.play; $("#consentToggle").checked = prefs.consent === true;
  $$("#scheme button").forEach((x) => x.classList.toggle("on", x.dataset.v === prefs.scheme));
  showConsent(); render();
})();
chrome.storage.onChanged.addListener((ch) => { if (ch.state) { state = ch.state.newValue || { status: "off" }; render(); } });
document.addEventListener("click", (e) => { if (!e.target.closest(".picker")) $("#countryMenu").classList.remove("open"); });
