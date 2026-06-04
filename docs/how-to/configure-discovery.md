---
title: "Configure discovery"
description: "How to configure the OpenID Connect discovery document in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 2
---

*Added in Unreleased.*

This guide shows how to publish a correct OpenID Connect discovery document with ZeeKayDa.Auth.

For the full endpoint contract, see [Discovery endpoint reference](../reference/discovery-endpoint.md).
For the reasoning behind these rules, see [Why discovery matters](../explanation/why-discovery.md).

## 1. Register ZeeKayDa.Auth and set the issuer

Configure `AuthorizationServerOptions` with `AddZeeKayDaAuth(...)`, then map the endpoints with
`app.MapZeeKayDaAuth()`.

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    options.Response.TypesSupported = [ResponseType.Code];
    options.Response.ModesSupported = [ResponseMode.Query];
    options.GrantTypesSupported = [GrantType.AuthorizationCode];
    options.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
    options.IdToken.SigningAlgValuesSupported = [SigningAlgorithm.RS256];
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

The discovery document will be available at:

```text
https://id.example.com/.well-known/openid-configuration
```

## 2. Use a path-bearing issuer when you need tenant or product prefixes

If your issuer includes a path segment, ZeeKayDa.Auth publishes discovery under that same path
prefix.

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com/tenant-a";
    options.Response.TypesSupported = [ResponseType.Code];
    options.IdToken.SigningAlgValuesSupported = [SigningAlgorithm.RS256];
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

The discovery document will be available at:

```text
https://id.example.com/tenant-a/.well-known/openid-configuration
```

This matches
[OpenID Connect Discovery 1.0 Section 4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest)
and [RFC 9207 Section 4](https://www.rfc-editor.org/rfc/rfc9207.html#section-4).

## 3. Advertise the metadata your clients need

ZeeKayDa.Auth always publishes the required core fields. You can also configure the recommended
metadata fields from `AuthorizationServerOptions`.

| Option | Published field | Default |
|---|---|---|
| built-in scope repository | `scopes_supported` | `["openid", "profile"]` |
| `Response.ModesSupported` | `response_modes_supported` | `["query"]` |
| `GrantTypesSupported` | `grant_types_supported` | `["authorization_code"]` |
| `TokenEndpoint.AuthMethodsSupported` | `token_endpoint_auth_methods_supported` | `["client_secret_basic"]` |

`scopes_supported` is described by
[OIDC Discovery 1.0 Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
and [RFC 8414 Section 2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).
`grant_types_supported` and `token_endpoint_auth_methods_supported` are authorization server
metadata fields from [RFC 8414 Section 2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).

By default, `scopes_supported` is sourced from the built-in scope repository, which publishes
`openid` and `profile`. If you want to publish the full standard OIDC scope set or attach
token-claim metadata to scopes, register the in-memory scope repository and start with
`StandardScopes`:

```csharp
using ZeeKayDa.Auth.Scopes;

var builder = WebApplication.CreateBuilder(args);

var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

auth.AddInMemoryScopes(
[
    .. StandardScopes.All,
    new ScopeDefinition
    {
        Name = "api.read",
        AccessTokenClaims = ["scope"],
    },
    new ScopeDefinition
    {
        Name = "internal.admin",
        IsDiscoverable = false,
        AccessTokenClaims = ["scope"],
    },
]);

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();
```

If you register a custom `IScopeRepository`, include `openid` in the configured scopes so startup
validation succeeds.

Discovery still publishes only the scope names, and only for scopes where `IsDiscoverable` is
`true`. `IdTokenClaims` and `AccessTokenClaims` are repository metadata for future authorization
server behavior and are not emitted as custom discovery fields.

## 4. Override published endpoint URLs when needed

By default, ZeeKayDa.Auth derives these values from `Issuer`:

- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`

Override them if your externally visible URLs differ from the issuer-derived defaults on the same
authority.

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com/tenant-a";
    options.AuthorizationEndpoint.Uri = "https://id.example.com/tenant-a/custom/authorize";
    options.TokenEndpoint.Uri = "https://id.example.com/tenant-a/custom/token";
    options.JwksEndpoint.Uri = "https://id.example.com/tenant-a/custom/jwks";
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

## 5. Verify the discovery document

Fetch the document after startup.

Root issuer:

```bash
curl https://id.example.com/.well-known/openid-configuration
```

Path-bearing issuer:

```bash
curl https://id.example.com/tenant-a/.well-known/openid-configuration
```

Check for these basics:

- `issuer` matches your configured issuer exactly
- endpoint URLs point to the public URLs clients should use
- response types and signing algorithms reflect your server
- the recommended metadata values match the capabilities you intend to advertise

The response is returned as JSON with:

- `Content-Type: application/json`
- `Cache-Control: public, max-age=3600, must-revalidate` by default
- `Access-Control-Allow-Origin: *`

## 6. Fix startup failures early

ZeeKayDa.Auth validates discovery-related options at startup. Common failures include:

- missing `Issuer`
- non-absolute issuer values
- HTTP issuers without `AllowInsecureIssuer = true`
- HTTP issuers on non-loopback hosts
- non-canonical issuers (uppercase scheme/host or explicit default port)
- issuer values with a query string or fragment
- issuer values with user information
- endpoint overrides with a different authority than `Issuer`
- null metadata collections
- empty required metadata collections
- scope repositories that do not include `openid`
- blank scope names

> Warning: Only enable `AllowInsecureIssuer` for local loopback development or tests. Production
> issuers should always use HTTPS.
