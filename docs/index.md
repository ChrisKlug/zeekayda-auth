---
title: Home
layout: home
nav_order: 1
description: "ZeeKayDa.Auth — an open-source OpenID Connect identity provider framework for .NET"
permalink: /
---

# ZeeKayDa.Auth

ZeeKayDa.Auth is an open-source **OpenID Connect identity provider framework for .NET**. It gives
you the building blocks to run a spec-compliant, production-grade authorization server inside any
ASP.NET Core application — without tying you to a particular storage engine, UI, or hosting model.

> **Pre-alpha:** the current implementation exposes discovery/configuration building blocks only.
> Advertised authorization, token, and JWKS endpoints return `501 Not Implemented` until those
> protocol surfaces are implemented.

The name comes from the phonetic spelling of *ZKDA* — Zero Knowledge Driven Auth.

---

## Get started

New here? Read the [Tutorials](tutorials/) for hand-held walk-throughs, or jump straight to
[How-to Guides](how-to/) if you already know what you want to do.

---

## Documentation sections

| Section | What you will find |
|---|---|
| [Tutorials](tutorials/) | Step-by-step guides designed for newcomers — start here if you have never used ZeeKayDa.Auth before |
| [How-to Guides](how-to/) | Task-focused recipes for common configuration and integration scenarios |
| [Reference](reference/) | Precise descriptions of every endpoint, configuration option, and public API surface |
| [Explanation](explanation/) | Concepts, design decisions, and the *why* behind how the library works |

---

## Governing specifications

ZeeKayDa.Auth is built to conform to the following standards:

- [OAuth 2.0 — RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [PKCE — RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 Authorization Server Metadata — RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)
- [OAuth 2.0 Security Best Current Practice — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)

When library behaviour and convenience diverge, the spec wins.

---

## Contributing and support

- **Source:** [github.com/ChrisKlug/zeekayda-auth](https://github.com/ChrisKlug/zeekayda-auth)
- **Issues:** [GitHub Issues](https://github.com/ChrisKlug/zeekayda-auth/issues)
- **Security:** see [SECURITY.md](https://github.com/ChrisKlug/zeekayda-auth/blob/main/SECURITY.md)
- **Contributing:** see [CONTRIBUTING.md](https://github.com/ChrisKlug/zeekayda-auth/blob/main/CONTRIBUTING.md)
