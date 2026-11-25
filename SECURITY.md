# Security policy

## Scope and limitations

RIZEN-VPN is a Chrome browser proxy extension, not a device-wide VPN. It does not provide its own encryption, and it cannot guarantee protection from IP, DNS, WebRTC, IPv6, or proxy failures across all browser configurations.

The current source fetches public proxy lists. Those proxy operators are untrusted and may log traffic metadata or modify unencrypted HTTP traffic. Proxy validation is not a trust or safety guarantee.

The current code has not undergone a professional security audit or penetration test. Unit tests validate helper logic only.

## Reporting a vulnerability

Please do not disclose vulnerabilities in public issues with exploit details or private user data. Until a private security contact is configured, use GitHub's private vulnerability reporting feature (if enabled for this repository) or contact the repository owner through their GitHub profile.

Please include:
- affected commit/version
- reproducible steps
- impact and relevant logs (scrub IPs, tokens, personal data)

## Safe use

Do not rely on this extension for sensitive browsing or as a replacement for a reputable, audited, device-wide VPN.
