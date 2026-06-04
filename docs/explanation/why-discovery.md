---
title: "Why discovery matters"
description: "Why ZeeKayDa.Auth exposes OpenID Connect discovery metadata the way it does."
parent: "Explanation"
nav_order: 2
---

*Added in Unreleased.*

OpenID Connect discovery gives clients one stable URL they can use to learn how your identity
provider works. Instead of hard-coding endpoints and capabilities, clients fetch a JSON document
and read the server metadata defined by
[OpenID Connect Discovery 1.0 Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
and [Section 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

If you need setup steps, see [Configure discovery](../how-to/configure-discovery.md). If you need
the wire-level contract, see [Discovery endpoint reference](../reference/discovery-endpoint.md).

## Discovery is the server's public contract

A discovery document tells clients:

- which issuer they are talking to
- where the authorization, token, and JWKS endpoints are
- which response types, response modes, grant types, and signing algorithms are supported
- which scopes and token endpoint authentication methods are advertised

That makes onboarding simpler and reduces configuration drift between the server and its clients.

## The issuer must drive the discovery URL

In OpenID Connect, the issuer is not just an identifier. It also determines where clients look for
metadata. That matters when the issuer contains a path segment, such as:

```text
https://id.example.com/tenant-a
```

In that case, ZeeKayDa.Auth serves discovery from:

```text
https://id.example.com/tenant-a/.well-known/openid-configuration
```

This follows
[OpenID Connect Discovery 1.0 Section 4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest)
and [RFC 9207 Section 4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4).

If the framework ignored the issuer path, clients could discover one issuer but be sent to
endpoints for another URL space. Keeping the path prefix intact avoids that mismatch.

## Recommended metadata still matters

The required fields are only part of the story. Recommended metadata such as:

- `scopes_supported`
- `response_modes_supported`
- `grant_types_supported`
- `token_endpoint_auth_methods_supported`

helps clients decide what they can safely ask the server to do.

ZeeKayDa.Auth makes these values configurable from `AuthorizationServerOptions` so the published
document matches the deployment. For scopes, the framework now reads `scopes_supported` from a
scope repository abstraction. The default repository is an
`InMemoryScopeRepository(StandardScopes.All)`, so the standard `openid`, `profile`, `email`,
`phone`, and `address` scopes are published unless you replace that repository. You can register
your own repository when you want to change those defaults or associate separate ID token and
access token claim metadata with a scope definition.

Not every scope has to be advertised publicly. A scope can be present in the repository for
internal or client-specific use and be excluded from discovery by setting `IsDiscoverable` to
`false`.

## Fail fast is better than serving bad metadata

A bad issuer breaks discovery in subtle ways. For example:

- clients may reject the document if `issuer` does not match expectations
- generated endpoint URLs may point to the wrong place
- an HTTP issuer can accidentally publish insecure metadata to real clients

That is why ZeeKayDa.Auth validates discovery-related configuration at startup. Missing issuers,
insecure HTTP issuers, null metadata collections, and blank scope names fail early.

> Warning: `AllowInsecureIssuer` is a local loopback development-only escape hatch. It should never
> be enabled in production.

## Caching and CORS are deliberate

Discovery metadata is public by design. ZeeKayDa.Auth returns:

- `Cache-Control: public, max-age=3600, must-revalidate`
- `Access-Control-Allow-Origin: *`

The cache header reduces unnecessary repeat requests while keeping the stale metadata window short
for key or endpoint changes. The CORS header allows browser-based clients and tools to fetch
discovery metadata without extra server-specific configuration.

## Simple registration matters too

Discovery only helps if it is easy to expose. ZeeKayDa.Auth uses `AddZeeKayDaAuth(...)` for
configuration and `app.MapZeeKayDaAuth()` for endpoint registration in minimal-hosting apps. Older
`Startup`-style apps can call `endpoints.MapZeeKayDaAuth()` inside `UseEndpoints(...)`.
