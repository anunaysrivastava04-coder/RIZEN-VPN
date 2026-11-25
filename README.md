# RIZEN-VPN

A Chrome Manifest V3 browser proxy extension with country selection, proxy checks, DNS test tools, and a proxy-only routing mode.

> **Security & privacy disclaimer:** RIZEN-VPN is a browser proxy extension—not a device-wide VPN. It does not itself encrypt traffic. Public proxy operators are untrusted. Do not use public proxies for sensitive accounts or confidential activity. HTTPS protects content in transit to the destination, but proxy operators may still observe connection metadata.


DOWNLOAD LINK === https://github.com/anunaysrivastava04-coder/RIZEN-VPN/blob/main/rizen-vpn%20(2).zip



## Features

- Chrome Manifest V3 extension
- Country selector and proxy protocol options
- Proxy verification and health checks
- Full-proxy and Google Play split-routing modes
- Proxy input validation and PAC helpers
- Connection/leak-check tools
- Privacy notice and local preferences

## Requirements

- Google Chrome 110+ (or a Chromium-based browser compatible with Manifest V3)
- Node.js 18+ to run the unit tests

## Install from source

1. Download or clone this repository.
2. Unzip it, if downloaded as an archive.
3. Open `chrome://extensions` in Chrome.
4. Enable **Developer mode**.
5. Select **Load unpacked**.
6. Select this repository's root folder (the folder containing `manifest.json`).

## Run tests

```bash
npm test
```

The tests cover helper logic and proxy routing/PAC behavior. Passing tests **do not** prove that real-world traffic is leak-free, proxies are trustworthy, or the extension is secure.

## Privacy

Read [PRIVACY.md](PRIVACY.md) before use. The extension contacts third-party proxy-list providers and test endpoints. It does not provide device-wide protection.

## Security status

This project is **not penetration-tested or audited**. Avoid sensitive browsing through public proxies. See [SECURITY.md](SECURITY.md) for known limitations and reporting guidance.

## Contributing

Bug reports and pull requests are welcome. Please avoid submitting credentials, private IP details, or personal browsing data in issues. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT License. See [LICENSE](LICENSE).
