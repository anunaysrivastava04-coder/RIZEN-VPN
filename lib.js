// Shared, dependency-free helpers (used by the service worker, the popup and the tests).

export const COUNTRIES = [
  ["IN","India"],["AU","Australia"],["BR","Brazil"],["CA","Canada"],["CN","China"],["EG","Egypt"],
  ["FR","France"],["DE","Germany"],["ID","Indonesia"],["IT","Italy"],["JP","Japan"],["KE","Kenya"],
  ["MX","Mexico"],["NG","Nigeria"],["NO","Norway"],["SA","Saudi Arabia"],["ZA","South Africa"],
  ["KR","South Korea"],["ES","Spain"],["GB","United Kingdom"]
];
export const COUNTRY_CODES = COUNTRIES.map((c) => c[0]);

export const SCHEMES = ["http", "https-tls", "socks5"]; // SOCKS4 removed: Chrome resolves DNS locally for it (DNS leak)
export const PLAY_HOSTS = [
  "play.google.com", "play.googleapis.com", "android.clients.google.com",
  "play-lh.googleusercontent.com", "googleusercontent.com", "gvt1.com", "gvt2.com",
  "ggpht.com", "accounts.google.com", "gstatic.com"
];
// Probe hostnames. Each one can be routed to a different proxy so several proxies are tested at once.
export const PROBES = [
  "https://www.cloudflare.com/cdn-cgi/trace",
  "https://one.one.one.one/cdn-cgi/trace",
  "https://1.1.1.1/cdn-cgi/trace",
  "https://1.0.0.1/cdn-cgi/trace",
  "https://www.gstatic.com/generate_204",
  "https://connectivitycheck.gstatic.com/generate_204",
  "https://clients3.google.com/generate_204",
  "https://www.google.com/generate_204"
];
// The only hosts reachable directly while the connection is locked down.
export const SOURCE_HOSTS = ["proxylist.geonode.com", "cdn.jsdelivr.net", "raw.githubusercontent.com", "api.proxyscrape.com"];
export const BLACKHOLE = "PROXY 127.0.0.1:9"; // nothing listens on the discard port, so requests fail

/* ---------- strict validation ---------- */
export function isValidPort(p) {
  const s = String(p).trim();
  return /^\d{1,5}$/.test(s) && +s >= 1 && +s <= 65535;
}
export function isIPv4(h) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(h));
  return !!m && m.slice(1).every((o) => +o <= 255 && (o === "0" || !o.startsWith("0")));
}
export function isPublicIPv4(h) {
  if (!isIPv4(h)) return false;
  const [a, b] = h.split(".").map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0)) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return true;
}
export function isValidDomain(h) {
  h = String(h);
  if (h.length > 253) return false;
  const labels = h.split(".");
  return labels.length >= 2 &&
    labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(l)) &&
    /^[a-z]{2,63}$/i.test(labels[labels.length - 1]);
}
// Returns a clean {scheme, host, port} or throws an Error with a user-readable message.
export function validateProxy(p, { allowPrivate = false, allowDomain = false } = {}) {
  const scheme = String(p && p.scheme);
  if (!SCHEMES.includes(scheme)) throw new Error("Choose HTTP, HTTPS or SOCKS5.");
  const host = String((p && p.host) ?? "").trim().toLowerCase();
  if (isIPv4(host)) {
    if (!allowPrivate && !isPublicIPv4(host)) throw new Error("Private or reserved addresses are not allowed.");
  } else if (!(allowDomain && isValidDomain(host))) {
    throw new Error(allowDomain ? "Enter an IPv4 address or a domain name, without http:// or a path." : "Invalid server address.");
  }
  if (!isValidPort(p.port)) throw new Error("Port must be a number from 1 to 65535.");
  return { scheme, host, port: Number(p.port) };
}

/* ---------- PAC generation: every value is JSON-encoded, never concatenated as code ---------- */
export function routeString(p) {
  const v = validateProxy(p, { allowPrivate: true, allowDomain: true });
  const hp = `${v.host}:${v.port}`;
  return v.scheme === "socks5" ? `SOCKS5 ${hp}` : v.scheme === "https-tls" ? `HTTPS ${hp}` : `PROXY ${hp}`;
}

// IPv6 literals contain no dots, so they must be handled before isPlainHostName() or they would bypass the proxy.
const LOCAL_CHECK = `if (host.indexOf(":") !== -1) {
    if (/^\\[?(::1\\]?$|fe80:|f[cd][0-9a-f]{2}:)/i.test(host)) return "DIRECT";
  } else {
    if (isPlainHostName(host) || host === "localhost") return "DIRECT";
    if (/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host) && (isInNet(host,"10.0.0.0","255.0.0.0") || isInNet(host,"172.16.0.0","255.240.0.0") ||
        isInNet(host,"192.168.0.0","255.255.0.0") || isInNet(host,"127.0.0.0","255.0.0.0"))) return "DIRECT";
  }`;

// Full mode has no DIRECT fallback: if the proxy fails, the request fails (fail-closed).
export function buildPac(p, playOnly = false) {
  return `function FindProxyForURL(url, host) {
  var R = ${JSON.stringify(routeString(p))};
  var P = ${JSON.stringify(PLAY_HOSTS)};
  ${LOCAL_CHECK}
  ${playOnly ? "" : "return R;"}
  for (var i = 0; i < P.length; i++) {
    if (host === P[i] || (host.length > P[i].length && host.substr(host.length - P[i].length - 1) === "." + P[i])) return R;
  }
  return "DIRECT";
}`;
}

// Used while testing candidates: only probe hostnames reach the candidate. When locked, everything else is blocked.
export function buildProbePac(map, lock) {
  const m = {};
  Object.keys(map).forEach((h) => { m[h] = map[h]; });
  return `function FindProxyForURL(url, host) {
  var M = ${JSON.stringify(m)};
  var A = ${JSON.stringify(SOURCE_HOSTS)};
  if (Object.prototype.hasOwnProperty.call(M, host)) return M[host];
  ${lock
    ? `for (var i = 0; i < A.length; i++) { if (host === A[i]) return "DIRECT"; }
  return ${JSON.stringify(BLACKHOLE)};`
    : `return "DIRECT";`}
}`;
}
export const buildBlockPac = () => buildProbePac({}, true);

/* ---------- DNS-over-HTTPS probe (wire format, works with every provider) ---------- */
export function dnsQueryB64(name) {
  const parts = name.split(".").flatMap((l) => [l.length, ...[...l].map((c) => c.charCodeAt(0))]);
  const bytes = new Uint8Array([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...parts, 0, 0, 1, 0, 1]);
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export async function dohProbe(url, timeout = 4000) {
  const t = performance.now(), c = new AbortController(), to = setTimeout(() => c.abort(), timeout);
  try {
    const r = await fetch(`${url}?dns=${dnsQueryB64("example.com")}`, { headers: { accept: "application/dns-message" }, signal: c.signal, cache: "no-store", credentials: "omit" });
    if (!r.ok) return null;
    const b = new Uint8Array(await r.arrayBuffer());
    if (b.length < 12 || (b[3] & 15) !== 0) return null;
    return Math.round(performance.now() - t);
  } catch (e) { return null; } finally { clearTimeout(to); }
}
