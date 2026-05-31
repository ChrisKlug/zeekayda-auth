---
title: "Discovery endpoint"
description: "Reference for the OpenID Connect discovery endpoint exposed by ZeeKayDa.Auth."
parent: "Reference"
nav_order: 1
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

### Response headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `Cache-Control` | `public, max-age=86400` |
| `Access-Control-Allow-Origin` | `*` |

## Metadata fields

All of the fields below are published in the discovery document. Some are fixed values, and others
come from `AuthorizationServerOptions`.

| JSON field | Source | Default / notes |
|---|---|---|
| `issuer` | `Issuer` | Published verbatim as configured. |
| `authorization_endpoint` | `AuthorizationEndpoint` or derived from `Issuer` | Default is `{issuer}/connect/authorize`. |
| `token_endpoint` | `TokenEndpoint` or derived from `Issuer` | Default is `{issuer}/connect/token`. |
| `jwks_uri` | `JwksUri` or derived from `Issuer` | Default is `{issuer}/connect/jwks`. |
| `response_types_supported` | `ResponseTypesSupported` | Defaults to `["code"]`. Required by OIDC Discovery 1.0 Section 3. |
| `scopes_supported` | `IScopeRepository` | By default, published from the built-in repository containing `openid` and `profile`. |
| `response_modes_supported` | `ResponseModesSupported` | Defaults to `["query"]`. |
| `grant_types_supported` | `GrantTypesSupported` | Defaults to `["authorization_code"]`. |
| `token_endpoint_auth_methods_supported` | `TokenEndpointAuthMethodsSupported` | Defaults to `["client_secret_basic"]`. |
| `subject_types_supported` | Fixed value | Always `["public"]`. Pairwise subject identifiers are not currently supported. |
| `id_token_signing_alg_values_supported` | `IdTokenSigningAlgValuesSupported` | Defaults to `["RS256"]`. Required by OIDC Discovery 1.0 Section 3. |

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
        Name = ScopeNames.OpenId,
        IdTokenClaims = ["sub"],
        AccessTokenClaims = ["scope"],
    },
    new ScopeDefinition
    {
        Name = ScopeNames.Profile,
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
- `Issuer` contains a query string or fragment
- `ResponseTypesSupported` or `IdTokenSigningAlgValuesSupported` is null or empty
- any supported metadata collection is null
- a custom scope repository is configured with blank or duplicate scope names

> Warning: `AllowInsecureIssuer = true` is for local development and testing only. Do not use an
> HTTP issuer in production.
