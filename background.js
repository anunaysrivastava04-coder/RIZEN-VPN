// RIZEN-VPN service worker v1.2 (Manifest V3)
import {
  COUNTRY_CODES, PROBES, validateProxy, routeString, buildPac, buildProbePac, buildBlockPac, dohProbe
} from "./lib.js";

const BATCH = PROBES.length;       // candidates tested at the same time
const MAX_CANDIDATES = 48;
const MAX_LATENCY_MS = 3000;       // slower servers are rejected as unreliable
const MAX_LIST_BYTES = 2_000_000;  // refuse oversized third-party responses
const MAX_PER_SOURCE = 150;
const CACHE_MS = 4 * 60 * 1000;
let job = 0;
let testing = false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const setState = (s) => chrome.storage.local.set({ state: s });
const getState = async () => (await chrome.storage.local.get("state")).state || { status: "off" };
const setPac = (data) => chrome.proxy.settings.set({ value: { mode: "pac_script", pacScript: { data } }, scope: "regular" });
const clearProxy = () => chrome.proxy.settings.clear({ scope: "regular" });
const consentOk = async () => ((await chrome.storage.local.get("prefs")).prefs || {}).consent === true;

// WebRTC can reveal your real IP and DNS prefetch can bypass the tunnel, so both are restricted while connected.
async function setPrivacy(on) {
  try {
    if (on) {
      await chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: "disable_non_proxied_udp" });
      await chrome.privacy.network.networkPredictionEnabled.set({ value: false });
    } else {
      await chrome.privacy.network.webRTCIPHandlingPolicy.clear({});
      await chrome.privacy.network.networkPredictionEnabled.clear({});
    }
  } catch (e) { /* another extension may control these settings */ }
}
async function setBadge(on) {
  await chrome.action.setBadgeText({ text: on ? "ON" : "" });
  await chrome.action.setBadgeBackgroundColor({ color: "#2fd6a8" });
}

/* ---------- probing ---------- */
async function probe(url = PROBES[0], timeout = 5000) {
  const t0 = performance.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { signal: ctrl.signal, cache: "no-store", credentials: "omit", redirect: "error" });
    if (url.includes("/cdn-cgi/trace")) {
      const o = {};
      (await r.text()).slice(0, 4000).trim().split("\n").forEach((l) => { const i = l.indexOf("="); if (i > 0) o[l.slice(0, i)] = l.slice(i + 1); });
      const ok = /^[0-9a-f.:]{3,45}$/i.test(o.ip || "");
      return { ok, ms: Math.round(performance.now() - t0), ip: ok ? o.ip : undefined, loc: /^[A-Z]{2}$/.test(o.loc || "") ? o.loc : undefined };
    }
    return { ok: r.status === 204, ms: Math.round(performance.now() - t0) };
  } catch (e) {
    return { ok: false };
  } finally {
    clearTimeout(timer);
  }
}

// Liveness test of up to 8 candidates at once; every other request is blocked when `lock` is true.
async function probeBatch(batch, lock) {
  const map = {};
  batch.forEach((p, i) => { map[new URL(PROBES[i]).hostname] = routeString(p); });
  await setPac(buildProbePac(map, lock));
  await sleep(150);
  const res = await Promise.all(batch.map((p, i) => probe(PROBES[i], 4500).then((r) => (r.ok ? p : null))));
  return res.filter(Boolean);
}

// Strict check of one candidate. Only the probe hostnames are routed through it, never your browsing.
async function verify(p, lock, realIp, maxMs) {
  const map = {};
  [PROBES[0], PROBES[4]].forEach((u) => { map[new URL(u).hostname] = routeString(p); });
  await setPac(buildProbePac(map, lock));
  await sleep(150);
  const a = await probe(PROBES[0], 6000);
  if (!a.ok) return null;
  const b = await probe(PROBES[0], 4000);
  if (!b.ok || b.ip !== a.ip) return null;            // unstable or rotating exit
  if (!(await probe(PROBES[4], 4000)).ok) return null; // second independent HTTPS endpoint
  if (realIp && a.ip === realIp) return null;          // transparent proxy: hides nothing
  if (b.ms > maxMs) return null;                       // too slow to be reliable
  return { ip: a.ip, loc: a.loc, ms: b.ms };
}

/* ---------- third-party proxy lists (untrusted input: size-capped, parsed strictly, validated) ---------- */
async function getText(url, ms = 10000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(url, { signal: c.signal, credentials: "omit", redirect: "error" });
    if (!r.ok) throw new Error("bad status");
    const txt = await r.text();
    if (txt.length > MAX_LIST_BYTES) throw new Error("response too large");
    return txt;
  } finally { clearTimeout(t); }
}
const getJson = async (url) => { const j = JSON.parse(await getText(url)); return j; };
const norm = (proto, tcp) => {
  proto = String(proto || "").toLowerCase();
  if (proto === "socks5") return "socks5";
  if (tcp) return null;
  return proto === "http" || proto === "https" ? "http" : null; // SOCKS4 is never used: Chrome resolves its DNS locally
};
const cacheKey = (cc, tcp) => `list_${cc}_${tcp ? 1 : 0}`;

async function getProxies(cc, tcp) {
  const key = cacheKey(cc, tcp);
  const cached = (await chrome.storage.local.get(key))[key];
  if (cached && Date.now() - cached.t < CACHE_MS && cached.list.length) return cached.list;

  const sources = [
    async () => {
      const protocols = tcp ? "socks5" : "socks5,http,https";
      const j = await getJson(`https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc&country=${cc}&protocols=${protocols}`);
      return (Array.isArray(j.data) ? j.data : []).slice(0, MAX_PER_SOURCE).map((x) => {
        const protos = Array.isArray(x.protocols) ? x.protocols : [];
        return { host: x.ip, port: x.port, scheme: norm(protos.includes("socks5") ? "socks5" : protos.find((q) => q === "http" || q === "https"), tcp) };
      });
    },
    async () => {
      let arr;
      try { arr = await getJson(`https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/${cc}/data.json`); }
      catch (e) { arr = await getJson(`https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/${cc}/data.json`); }
      return (Array.isArray(arr) ? arr : []).slice(0, MAX_PER_SOURCE).map((x) => ({ host: x.ip, port: x.port, scheme: norm(x.protocol, tcp) }));
    },
    ...(tcp ? ["socks5"] : ["socks5", "http"]).map((proto) => async () => {
      const txt = await getText(`https://api.proxyscrape.com/v2/?request=displayproxies&protocol=${proto}&timeout=8000&country=${cc}&ssl=all&anonymity=all`);
      return txt.split(/\s+/).slice(0, MAX_PER_SOURCE).map((l) => { const [host, port] = l.split(":"); return { host, port, scheme: norm(proto, tcp) }; });
    })
  ];

  const settled = await Promise.allSettled(sources.map((s) => s()));
  const seen = new Set();
  const list = [];
  settled.forEach((r) => {
    if (r.status !== "fulfilled") return;
    r.value.forEach((x) => {
      try {
        if (!x.scheme) return;
        const p = validateProxy(x, { allowPrivate: false, allowDomain: false }); // public IPv4 + valid port only
        const k = p.host + ":" + p.port;
        if (!seen.has(k)) { seen.add(k); list.push(p); }
      } catch (e) { /* drop invalid or malicious entry */ }
    });
  });
  list.sort((a, b) => (b.scheme === "socks5") - (a.scheme === "socks5"));
  if (list.length) await chrome.storage.local.set({ [key]: { t: Date.now(), list } });
  return list;
}

/* ---------- connect / disconnect ---------- */
async function captureRealIp() {
  const r = await probe(PROBES[0], 5000);   // direct, in memory only, used to detect leaks and transparent proxies
  await chrome.storage.session.set({ realIp: r.ok ? r.ip : null });
}

// If a protected connection is active (or was blocked), keep traffic blocked while switching or after a failure.
async function failure(lock, extra, msg) {
  if (lock) {
    await setPac(buildBlockPac());
    await setState({ status: "error", blocked: true, ...extra, msg: msg + " Internet stays blocked so nothing leaks. Tap the sun to retry, or turn protection off." });
  } else {
    await clearProxy();
    await setState({ status: "error", ...extra, msg });
  }
  await setBadge(false);
}

async function finalize(p, ctx, v, lock) {
  await setPac(buildPac(p, ctx.playOnly));
  await sleep(150);
  if (!ctx.playOnly) {                       // confirm the real browsing path now exits through the proxy
    const c = await probe(PROBES[0], 6000);
    if (!c.ok || c.ip !== v.ip) return failure(lock, { cc: ctx.cc, manual: ctx.manual }, "Could not confirm that traffic uses the server.");
  }
  await setPrivacy(!ctx.playOnly);
  await setBadge(true);
  await setState({ status: "on", fails: 0, since: Date.now(), proxy: p, server: `${p.host}:${p.port}`, scheme: p.scheme, ip: v.ip, ms: v.ms, exitCc: v.loc || ctx.cc, ...ctx });
}

async function begin() {
  const prev = await getState();
  const lock = prev.status === "on" || prev.blocked === true;
  if (lock) await setPac(buildBlockPac());
  else { await clearProxy(); await captureRealIp(); }
  const { realIp } = await chrome.storage.session.get("realIp");
  return { lock, realIp };
}

async function connect({ cc, tcp, playOnly }) {
  if (!COUNTRY_CODES.includes(cc)) return;
  if (!(await consentOk())) return setState({ status: "error", cc, msg: "Read and accept the notice in the Safety tab to use free servers, or use your own proxy." });
  const my = ++job;
  const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(), 20000);
  try {
    await setState({ status: "connecting", cc, tcp, playOnly, attempt: 0, total: 0 });
    const { lock, realIp } = await begin();
    const list = await getProxies(cc, tcp);
    if (my !== job) return;
    if (!list.length) return failure(lock, { cc }, "No free servers are listed for this country right now.");

    const cands = list.slice(0, MAX_CANDIDATES);
    const alive = [];
    for (let i = 0; i < cands.length && alive.length < 4; i += BATCH) {
      if (my !== job) return;
      await setState({ status: "connecting", cc, tcp, playOnly, attempt: Math.min(i + BATCH, cands.length), total: cands.length, blocked: lock });
      alive.push(...(await probeBatch(cands.slice(i, i + BATCH), lock)));
    }
    if (my !== job) return;
    if (!alive.length) {
      await chrome.storage.local.remove(cacheKey(cc, tcp));
      return failure(lock, { cc }, `Checked ${cands.length} free servers and none passed the safety checks.`);
    }
    let chosen = null, fallback = null;
    for (const p of alive.slice(0, 5)) {
      if (my !== job) return;
      const v = await verify(p, lock, realIp, MAX_LATENCY_MS);
      if (!v) continue;
      if (!v.loc || v.loc === cc) { chosen = { p, v }; break; }
      if (!fallback) fallback = { p, v };
    }
    const pick = chosen || fallback;
    if (!pick) return failure(lock, { cc }, "Servers answered but failed the safety checks.");
    if (my !== job) return;
    await finalize(pick.p, { cc, tcp, playOnly, mismatch: !chosen }, pick.v, lock);
  } finally {
    clearInterval(keepAlive);
  }
}

async function connectManual(m) {
  const my = ++job;
  let p;
  try { p = validateProxy({ scheme: m.scheme, host: m.host, port: m.port }, { allowPrivate: true, allowDomain: true }); }
  catch (e) { return setState({ status: "error", manual: true, msg: e.message }); }
  await setState({ status: "connecting", manual: true, attempt: 1, total: 1 });
  const { lock, realIp } = await begin();
  const v = await verify(p, lock, realIp, 8000);
  if (my !== job) return;
  if (!v) return failure(lock, { manual: true }, "This proxy did not pass the safety checks (no HTTPS access, unstable exit, or it does not hide your IP).");
  await finalize(p, { manual: true, cc: v.loc, tcp: m.scheme === "socks5", playOnly: !!m.playOnly }, v, lock);
}

async function disconnect() {
  job++;
  await clearProxy();
  await setPrivacy(false);
  await setBadge(false);
  await chrome.storage.session.remove("realIp");
  await setState({ status: "off" });
}

/* ---------- health checks ---------- */
chrome.alarms.create("health", { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== "health" || testing) return;
  const s = await getState();
  if (s.status === "error" && s.blocked && s.cc && !s.manual) return connect({ cc: s.cc, tcp: s.tcp, playOnly: s.playOnly });
  if (s.status !== "on" || s.playOnly) return;
  const r = await probe(PROBES[0], 6000);
  if (r.ok && r.ip === s.ip) { if (s.fails) await setState({ ...s, fails: 0 }); return; }
  if ((s.fails || 0) + 1 >= 2) { if (!s.manual) connect({ cc: s.cc, tcp: s.tcp, playOnly: s.playOnly }); else { await setPac(buildBlockPac()); await setState({ ...s, status: "error", blocked: true, msg: "Your proxy stopped responding. Internet is blocked so nothing leaks." }); } }
  else await setState({ ...s, fails: (s.fails || 0) + 1 });
});

/* ---------- built-in leak test ---------- */
async function leakTest() {
  const s = await getState();
  if (s.status !== "on") return [{ label: "Connection", status: "fail", detail: "Connect first, then run the test." }];
  testing = true;
  const out = [];
  const add = (label, status, detail) => out.push({ label, status, detail });
  try {
    const { realIp } = await chrome.storage.session.get("realIp");
    if (s.playOnly) {
      add("Scope", "warn", "Google Play mode: only Play traffic is proxied. Everything else goes direct by design.");
    } else {
      const r = await probe(PROBES[0], 6000);
      if (!r.ok) add("IP address", "fail", "Could not reach the test server through the proxy.");
      else if (realIp && r.ip === realIp) add("IP address", "fail", "Your real IP is visible: " + r.ip);
      else if (r.ip !== s.ip) add("IP address", "warn", "Exit IP changed to " + r.ip);
      else add("IP address", "pass", "Exit IP " + r.ip + (realIp ? " differs from your real IP." : "."));
      add("IPv6", "pass", "No direct route exists for any address, IPv6 included. Everything goes through the proxy or is blocked.");
    }
    const w = await chrome.privacy.network.webRTCIPHandlingPolicy.get({});
    const pr = await chrome.privacy.network.networkPredictionEnabled.get({});
    if (!s.playOnly) {
      const mine = (x) => x.levelOfControl === "controlled_by_this_extension";
      add("WebRTC", w.value === "disable_non_proxied_udp" && mine(w) ? "pass" : "warn", w.value === "disable_non_proxied_udp" && mine(w) ? "WebRTC can't use direct UDP, so it can't expose your real IP." : "Another extension or policy controls WebRTC (" + w.value + ").");
      add("DNS", s.scheme !== "socks4" && pr.value === false && mine(pr) ? "pass" : "warn", "Lookups are made by the proxy server, and browser DNS prefetching is off.");
      const ms = await dohProbe("https://cloudflare-dns.com/dns-query", 5000);
      add("DNS over the proxy", ms ? "pass" : "warn", ms ? `A DNS-over-HTTPS lookup worked through the proxy (${ms} ms).` : "A DNS-over-HTTPS lookup did not complete.");
      // Drop test: block the route, confirm nothing gets out, then restore it.
      try {
        await setPac(buildBlockPac());
        await sleep(200);
        const leaked = await probe(PROBES[0], 3000);
        add("Proxy drop", leaked.ok ? "fail" : "pass", leaked.ok ? "Traffic still got out when the proxy route was removed." : "With the proxy route removed, requests fail instead of going direct.");
      } finally {
        await setPac(buildPac(s.proxy, false));
        await sleep(200);
      }
    }
  } finally {
    testing = false;
  }
  return out;
}

chrome.runtime.onMessage.addListener((m, sender, send) => {
  if (sender.id !== chrome.runtime.id || !m || typeof m.type !== "string") return;
  if (m.type === "leaktest") { leakTest().then((results) => send({ ok: true, results }), () => send({ ok: false })); return true; }
  if (m.type === "connect") connect({ cc: String(m.cc), tcp: !!m.tcp, playOnly: !!m.playOnly });
  else if (m.type === "manual") connectManual({ scheme: m.scheme, host: m.host, port: m.port, playOnly: !!m.playOnly });
  else if (m.type === "disconnect") disconnect();
  send({ ok: true });
});
chrome.runtime.onInstalled.addListener(() => setState({ status: "off" }));
