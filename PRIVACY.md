# RIZEN-VPN privacy and security notice

**What this is:** a browser extension that routes Chrome traffic through a proxy. It is not a device-wide VPN and it does not encrypt traffic itself.

**Free public servers are untrusted.** Their operators can see which sites you connect to and read or alter anything sent over plain HTTP. HTTPS content stays encrypted end to end. Do not log in to banking, email or other sensitive accounts through them. For anything sensitive use your own server or a paid provider in the Proxy tab.

## Network requests the extension makes
| Purpose | Destination | Goes through proxy? |
|---|---|---|
| Fetch free server lists | proxylist.geonode.com, cdn.jsdelivr.net / raw.githubusercontent.com (Proxifly), api.proxyscrape.com | No (they see your real IP) |
| Learn your real IP once, to detect leaks | www.cloudflare.com | No, only when connecting from "off" |
| Test and verify servers, health check every minute | Cloudflare, Google (gstatic / google.com) test pages | Yes, via the server being tested |
| DNS speed test (only when you press it) | cloudflare-dns.com, dns.google, dns.quad9.net, dns.adguard-dns.com | Yes, if connected |

No analytics, accounts, ads or telemetry. Nothing is sent to the extension's author.

## Data stored on your device
Settings, connection state (server address, exit IP, time), and a server list cached for 4 minutes. Your real IP is kept in session memory only and is deleted when you disconnect or close the browser. No passwords or credentials are stored or handled.

## Protections
Strict host/port validation, no user input inserted into PAC code, no SOCKS4 (DNS leak), only public IPv4 servers from lists, no direct fallback while connected, traffic blocked while switching servers or after a failure, WebRTC restricted to proxied paths, DNS prefetch off, servers rejected if unstable, slow, non-HTTPS-capable or if they don't hide your IP.

## Limits
A browser extension cannot protect other apps, cannot control the operating system's IPv6 or DNS, and cannot make an untrusted server safe. Google Play mode sends only Play traffic through the proxy; all other traffic is direct by design.
