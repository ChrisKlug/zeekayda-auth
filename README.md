# ZeeKayDa.Auth

> A modular, spec-compliant OpenID Connect identity provider framework for .NET

<!-- Badges — update once CI and NuGet publishing are wired up -->
![Build](https://img.shields.io/github/actions/workflow/status/ChrisKlug/zeekayda-auth/ci.yml?branch=main&label=build)
![NuGet](https://img.shields.io/nuget/v/ZeeKayDa.Auth?label=nuget)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

---

## What is ZeeKayDa.Auth?

ZeeKayDa.Auth is an open-source framework for building OpenID Connect identity providers on top of ASP.NET Core. It targets developers who need full control over their authentication infrastructure without adopting a large, opinionated platform. The library is designed to be composable: you can adopt only the pieces you need and replace or extend everything else.

The project follows the relevant IETF and OpenID Foundation specifications closely, treating spec compliance as a first-class concern throughout design and implementation.

---

## Planned Features

- **Authorization Code Flow** with PKCE enforcement (RFC 7636)
- **OpenID Connect Core 1.0** — ID token issuance, UserInfo endpoint
- **Token endpoint** — access token and refresh token issuance
- **Discovery document** (`/.well-known/openid-configuration`, RFC 8414)
- **JWKS endpoint** (`/.well-known/jwks.json`)
- **Client credentials flow** (RFC 6749 §4.4)
- **Token introspection** (RFC 7662) and **revocation** (RFC 7009)
- **Dynamic client registration** (RFC 7591)
- **ASP.NET Core middleware** integration with a clean, minimal-API-friendly builder API
- **Extensibility hooks** for custom token generation, claims transformation, and storage

---

## Getting Started

> ⚠️ **The library is in early development and is not yet published to NuGet.** The Getting Started guide will be added when the first alpha package is available.

Watch this space — or check the [roadmap](https://github.com/ChrisKlug/zeekayda-auth/projects) for progress.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Security

If you discover a security vulnerability, **please do not open a public issue**. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## License

ZeeKayDa.Auth is licensed under the [Apache License 2.0](LICENSE).

Copyright © 2025–2026 ZeeKayDa
