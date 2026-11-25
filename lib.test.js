import assert from "node:assert/strict";
import vm from "node:vm";
import { isIPv4, isPublicIPv4, isValidDomain, isValidPort, validateProxy, buildPac, buildProbePac, buildBlockPac, BLACKHOLE } from "../lib.js";

let n = 0; const t = (name, fn) => { fn(); n++; console.log("ok -", name); };
const ip2n = (s) => s.split(".").reduce((a, o) => (a << 8) + +o, 0) >>> 0;
function pac(src) {
  const ctx = {
    isPlainHostName: (h) => !h.includes("."),
    isInNet: (h, net, mask) => (ip2n(h) & ip2n(mask)) === (ip2n(net) & ip2n(mask)),
    dnsDomainIs: () => false
  };
  vm.createContext(ctx); vm.runInContext(src, ctx);
  return (host) => ctx.FindProxyForURL(`https://${host}/`, host);
}

t("ports", () => {
  ["1", "80", "65535"].forEach((p) => assert.ok(isValidPort(p)));
  ["0", "65536", "-1", "80a", "", "8 0", "1e3", "0x50"].forEach((p) => assert.ok(!isValidPort(p), p));
});
t("ipv4 / public ranges", () => {
  assert.ok(isIPv4("8.8.8.8")); assert.ok(!isIPv4("08.8.8.8")); assert.ok(!isIPv4("256.1.1.1")); assert.ok(!isIPv4("1.2.3"));
  ["10.0.0.1", "127.0.0.1", "192.168.1.5", "172.20.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "224.0.0.1"].forEach((h) => assert.ok(!isPublicIPv4(h), h));
  assert.ok(isPublicIPv4("8.8.8.8")); assert.ok(isPublicIPv4("172.32.0.1"));
});
t("domains", () => {
  ["proxy.example.com", "a-b.example.org"].forEach((d) => assert.ok(isValidDomain(d), d));
  ["localhost", "-a.com", "a..com", "exa mple.com", "http://x.com", "x.com/path", 'x.com"; return "DIRECT"; //', "x.c0m1", "a".repeat(64) + ".com"].forEach((d) => assert.ok(!isValidDomain(d), d));
});
t("manual proxy validation", () => {
  assert.deepEqual(validateProxy({ scheme: "socks5", host: "Proxy.Example.com", port: "1080" }, { allowDomain: true }), { scheme: "socks5", host: "proxy.example.com", port: 1080 });
  assert.throws(() => validateProxy({ scheme: "ftp", host: "1.2.3.4", port: 80 }));
  assert.throws(() => validateProxy({ scheme: "socks4", host: "1.2.3.4", port: 80 }));
  assert.throws(() => validateProxy({ scheme: "http", host: "10.0.0.1", port: 80 }));            // list entries must be public
  assert.doesNotThrow(() => validateProxy({ scheme: "socks5", host: "127.0.0.1", port: 9050 }, { allowPrivate: true })); // own Tor/local proxy
  assert.throws(() => validateProxy({ scheme: "http", host: "x.com", port: 80 }));               // domains only when allowed
});
t("PAC injection is impossible", () => {
  const evil = ['1.2.3.4"; return "DIRECT"; //', "1.2.3.4\nreturn 'DIRECT'", "evil.com\"+(function(){})()+\"", "1.2.3.4:80/;alert(1)", "a b"];
  evil.forEach((h) => assert.throws(() => buildPac({ scheme: "http", host: h, port: 80 }), undefined, h));
  assert.throws(() => buildPac({ scheme: "http", host: "1.2.3.4", port: '80"; return "DIRECT"; //' }));
});
t("full mode is fail-closed (no DIRECT for public hosts, IPv4/IPv6/domains)", () => {
  const f = pac(buildPac({ scheme: "socks5", host: "8.8.4.4", port: 1080 }));
  ["example.com", "93.184.216.34", "2606:4700:4700::1111", "play.google.com", "sub.deep.site.org"].forEach((h) => assert.equal(f(h), "SOCKS5 8.8.4.4:1080", h));
  ["localhost", "intranet", "192.168.0.10", "10.1.2.3", "127.0.0.1", "::1", "fe80::1", "fd12:3456::1"].forEach((h) => assert.equal(f(h), "DIRECT", h));
  assert.ok(!buildPac({ scheme: "http", host: "8.8.4.4", port: 80 }).includes('"DIRECT";\n  return'));
});
t("IPv6 literals never bypass the proxy in full mode; stay direct in Play-only split mode", () => {
  const full = pac(buildPac({ scheme: "http", host: "8.8.4.4", port: 80 }));
  ["2001:db8::1", "[2606:4700:4700::1111]"].forEach((h) => assert.equal(full(h), "PROXY 8.8.4.4:80", h));
  const play = pac(buildPac({ scheme: "http", host: "8.8.4.4", port: 80 }, true));
  assert.equal(play("2001:db8::1"), "DIRECT");
});
t("Play-only mode proxies only Play hosts", () => {
  const f = pac(buildPac({ scheme: "http", host: "8.8.4.4", port: 3128 }, true));
  ["play.google.com", "a.play.google.com", "play.googleapis.com", "accounts.google.com", "lh3.googleusercontent.com", "x.gstatic.com"].forEach((h) => assert.equal(f(h), "PROXY 8.8.4.4:3128", h));
  ["example.com", "notplay.google.com.evil.com", "evilgstatic.com", "google.com"].forEach((h) => assert.equal(f(h), "DIRECT", h));
});
t("probe PAC: candidate only sees probe hosts; locked mode blocks everything else", () => {
  const map = { "www.cloudflare.com": "PROXY 8.8.4.4:80" };
  const open = pac(buildProbePac(map, false)), locked = pac(buildProbePac(map, true));
  assert.equal(open("www.cloudflare.com"), "PROXY 8.8.4.4:80"); assert.equal(open("example.com"), "DIRECT");
  assert.equal(locked("www.cloudflare.com"), "PROXY 8.8.4.4:80");
  assert.equal(locked("example.com"), BLACKHOLE); assert.equal(locked("proxylist.geonode.com"), "DIRECT");
});
t("block PAC lets nothing out except list sources", () => {
  const f = pac(buildBlockPac());
  ["example.com", "1.1.1.1", "2606:4700:4700::1111", "play.google.com"].forEach((h) => assert.equal(f(h), BLACKHOLE, h));
  assert.equal(f("api.proxyscrape.com"), "DIRECT");
});
console.log(`\n${n} test groups passed`);
