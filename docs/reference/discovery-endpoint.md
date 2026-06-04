---
title: "Discovery endpoint"
description: "Reference for the OpenID Connect discovery endpoint exposed by ZeeKayDa.Auth."
parent: "Reference"
nav_order: 2
---

*Added in Unreleased.*

ZeeKayDa.Auth exposes an OpenID Connect discovery document as defined by
[OpenID Connect Discovery 1.0 Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
and
[Section 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).

For setup steps, see [Configure discovery](../how-to/configure-discovery.md). For design
rationale, see [Why discovery matters](../explanation/why-discovery.md).

## Endpoint URL

**Method:** `GET`

**Route:**

- Root issuer: `/.well-known/openid-configuration`
- Path-bearing issuer: `{issuer-path}/.well-known/openid-configuration`

The route is constrained to the configured issuer host. A request for the same path on a different
host is not handled by ZeeKayDa.Auth. Requests over HTTP are rejected for non-loopback hosts.

Examples:

- Issuer: `https://id.example.com`  
  Discovery URL: `https://id.example.com/.well-known/openid-configuration`
- Issuer: `https://id.example.com/tenant-a`  
  Discovery URL: `https://id.example.com/tenant-a/.well-known/openid-configuration`

This path behavior follows
[OpenID Connect Discovery 1.0 Section 4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest)
and [RFC 9207 Section 4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4).

## Registration

Register services with `AddZeeKayDaAuth(...)`, then map endpoints with `app.MapZeeKayDaAuth()`.

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

## Response

### Status code

- `200 OK` when discovery is configured correctly
- `421 Misdirected Request` when the request is HTTP on a non-loopback host

### Response headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Cache-Control` | `public, max-age=3600, must-revalidate` by default; `no-store` when `DiscoveryDocument.CacheMaxAgeSeconds` is `0` |
| `Access-Control-Allow-Origin` | `*` when `DiscoveryDocument.CorsOrigins` is empty; the matched allowlist entry when non-empty |
| `Vary` | `Origin` (only when `DiscoveryDocument.CorsOrigins` is non-empty), appended to any existing `Vary` value |
| `X-Content-Type-Options` | `nosniff` (default; disable with `SecurityHeaders.ContentTypeOptionsNoSniff = false`) |
| `Referrer-Policy` | `no-referrer` (default; configurable via `SecurityHeaders.ReferrerPolicy`) |
| `Cross-Origin-Resource-Policy` | `cross-origin` (default; configurable via `SecurityHeaders.CrossOriginResourcePolicy`) |
| `X-ZeeKayDa-Insecure-Issuer` | `true` (only when `AllowInsecureIssuer = true`) |

## CORS configuration

By default ZeeKayDa.Auth returns `Access-Control-Allow-Origin: *`, which allows any browser-based
client to fetch the discovery document. This is intentional: the discovery document is public
information with no credentials and no user-specific data.

To restrict CORS to a known set of origins, populate `DiscoveryDocument.CorsOrigins`:

```csharp
options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");
options.DiscoveryDocument.CorsOrigins.Add("https://admin.example.com");
```

When the list is non-empty:

- `Access-Control-Allow-Origin` is set to the matching allowlist entry (lowercased, authority-only
  canonical form).
- `Vary: Origin` is appended additively so that shared caches never serve the wrong
  `Access-Control-Allow-Origin` to a different origin.
- Requests with an absent or non-matching `Origin` header receive no `Access-Control-Allow-Origin`
  header.

Allowlist entries are validated at startup. Each entry must be an absolute origin
(`scheme://host[:port]`) with no path, query, fragment, user information, wildcards, or the
literal string `null`. Entries are canonicalized, deduplicated, and frozen into an immutable
startup snapshot used by endpoint lookups. Invalid entries cause the host to fail fast at startup.

`https://` origins are accepted by default. `http://` origins are rejected unless
`AllowInsecureIssuer = true`; when enabled, HTTP origins must still use loopback hosts.

> Note: ZeeKayDa.Auth does not register an HTTP `OPTIONS` route. The discovery endpoint is
> a [simple CORS request](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)
> (`GET` with no custom request headers), so browsers do not send a preflight `OPTIONS` request
> before fetching the discovery document.

## Metadata fields

All of the fields below are published in the discovery document. Some are fixed values, and others
come from `AuthorizationServerOptions`.

| JSON field | Source | Default / notes |
|---|---|---|
| `issuer` | `Issuer` | Published verbatim as configured. |
| `authorization_endpoint` | `AuthorizationEndpoint.Uri` or derived from `Issuer` | Default is `{issuer}/connect/authorize`. |
| `token_endpoint` | `TokenEndpoint.Uri` or derived from `Issuer` | Default is `{issuer}/connect/token`. |
| `jwks_uri` | `JwksEndpoint.Uri` or derived from `Issuer` | Default is `{issuer}/connect/jwks`. |
| `response_types_supported` | `Response.TypesSupported` | Defaults to `["code"]`. Required by OIDC Discovery 1.0 Section 3. |
| `scopes_supported` | `IScopeRepository` | By default, published from the built-in `InMemoryScopeRepository` seeded with `StandardScopes.All` (`openid`, `profile`, `email`, `phone`, `address`). |
| `response_modes_supported` | `Response.ModesSupported` | Defaults to `["query"]`. |
| `grant_types_supported` | `GrantTypesSupported` | Defaults to `["authorization_code"]`. |
| `token_endpoint_auth_methods_supported` | `TokenEndpoint.AuthMethodsSupported` | Defaults to `["client_secret_basic"]`. |
| `subject_types_supported` | Fixed value | Always `["public"]`. Pairwise subject identifiers are not currently supported. |
| `id_token_signing_alg_values_supported` | `IdToken.SigningAlgValuesSupported` | Defaults to `["RS256"]`. Required by OIDC Discovery 1.0 Section 3. |
| `code_challenge_methods_supported` | `AuthorizationEndpoint.CodeChallengeMethodsSupported` | Omitted when `null` (the default). Set to `[CodeChallengeMethod.S256]` to advertise PKCE support once token-endpoint enforcement is in place. |

The recommended metadata fields are described by
[OpenID Connect Discovery 1.0 Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
and [RFC 8414 Section 2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).

To replace the default scope source, register a custom scope repository. For example:

```csharp
using ZeeKayDa.Auth.Scopes;

var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

auth.AddInMemoryScopes(
[
    new ScopeDefinition
    {
        Name = StandardScopes.OpenId.Name,
        IdTokenClaims = ["sub"],
        AccessTokenClaims = ["scope"],
    },
    new ScopeDefinition
    {
        Name = StandardScopes.Profile.Name,
        IdTokenClaims = ["name", "family_name"],
        AccessTokenClaims = ["name"],
    },
    new ScopeDefinition
    {
        Name = "internal.admin",
        IsDiscoverable = false,
        AccessTokenClaims = ["scope"],
    },
]);
```

Only scopes with `IsDiscoverable = true` are included in `scopes_supported`.

## Pre-alpha advertised endpoints

ZeeKayDa.Auth is pre-alpha. Discovery currently publishes default `authorization_endpoint`,
`token_endpoint`, and `jwks_uri` values so clients can observe the intended metadata shape, but the
protocol implementations are not complete yet.

Until those surfaces are implemented:

| Endpoint | Methods | Status |
|---|---|---|
| `{issuer}/connect/authorize` | `GET`, `POST` | `501 Not Implemented` |
| `{issuer}/connect/token` | `POST` | `501 Not Implemented` |
| `{issuer}/connect/jwks` | `GET` | `501 Not Implemented` |

## Endpoint URI derivation

When endpoint overrides are not set, ZeeKayDa.Auth derives published endpoint URLs from the
configured issuer using URI combination rules.

For example, with this issuer:

```text
https://id.example.com/tenant-a
```

the default published endpoints are:

- `https://id.example.com/tenant-a/connect/authorize`
- `https://id.example.com/tenant-a/connect/token`
- `https://id.example.com/tenant-a/connect/jwks`

This matters for issuers with path segments.

## Example document

```json
{
  "issuer": "https://id.example.com/tenant-a",
  "authorization_endpoint": "https://id.example.com/tenant-a/connect/authorize",
  "token_endpoint": "https://id.example.com/tenant-a/connect/token",
  "jwks_uri": "https://id.example.com/tenant-a/connect/jwks",
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "api.read"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

## Startup validation

Discovery configuration is validated at startup.

Startup fails when:

- `Issuer` is missing or empty
- `Issuer` is not an absolute URI
- `Issuer` uses HTTP and `AllowInsecureIssuer` is not enabled
- `Issuer` uses HTTP with a non-loopback host
- `Issuer` is non-canonical (uppercase scheme/host or explicit default port)
- `Issuer` contains a query string or fragment
- `Issuer` contains user information
- an endpoint override authority differs from `Issuer`
- `Response.TypesSupported` or `IdToken.SigningAlgValuesSupported` is null or empty
- any supported metadata collection is null
- a custom scope repository is configured with blank or duplicate scope names
- `AuthorizationEndpoint.CodeChallengeMethodsSupported` is set to a non-null empty collection

> Warning: `AllowInsecureIssuer = true` is for local loopback development and testing only. It does
> not permit HTTP issuers on non-loopback hosts.
