---
title: "Configure ZeeKayDa.Auth"
description: "How to register and configure ZeeKayDa.Auth in an ASP.NET Core application."
parent: "How-to Guides"
nav_order: 1
---

*Added in Unreleased.*

This guide shows how to register ZeeKayDa.Auth in an ASP.NET Core application and configure the
minimum required options to get a running authorization server.

For the full list of available options and their validation rules, see
[AuthorizationServerOptions reference](../reference/configuration.md). For next steps after basic
setup, see [Configure discovery](configure-discovery.md).

## Before you start

- Target framework: .NET 10 or later
- NuGet packages: `ZeeKayDa.Auth` and `ZeeKayDa.Auth.AspNetCore`

## 1. Add the minimum viable configuration

Call `AddZeeKayDaAuth(...)` on `IServiceCollection` with at least `Issuer` set, then call
`app.MapZeeKayDaAuth()` to register the endpoints.

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

`Issuer` is the only property you must set. All other properties have defaults that are valid for a
standard authorization code flow server.

> Note: `Issuer` must be an absolute HTTPS URI with no query string and no fragment. These
> requirements come from
> [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2) and
> [OpenID Connect Discovery 1.0 §1.2](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

## 2. Understand what the defaults give you

With only `Issuer` configured, ZeeKayDa.Auth registers the following defaults:

| Option | Default value |
|---|---|
| `Response.TypesSupported` | `["code"]` |
| `Response.ModesSupported` | `["query"]` |
| `GrantTypesSupported` | `["authorization_code"]` |
| `TokenEndpoint.AuthMethodsSupported` | `["client_secret_basic"]` |
| `IdToken.AdvertisedSigningAlgorithms` | `null` — every algorithm in the configured signing keys is advertised |

These defaults are a safe starting point for a standard authorization code flow with a
confidential client.

## 3. Understand startup validation

`AddZeeKayDaAuth` validates its options, and those of every signing source and hasher you add, when
`MapZeeKayDaAuth()` runs and again when the host starts, so any misconfiguration stops the host
before it accepts requests. You will
see one `ZeeKayDaConfigurationException` in the startup output, listing every failure with a stable
code you can alert on.

Common startup failures and their causes:

| Code | Cause |
|---|---|
| `configuration.issuer.*` | `Issuer` is not set, not an absolute URI, is not canonical (uppercase scheme/host or explicit default port), uses HTTP without `AllowInsecureIssuer`, uses HTTP on a non-loopback host, ends with `/`, or contains query, fragment, or user information |
| `configuration.response.types_supported.null` / `.empty` | The collection was set to `null` or emptied |
| `configuration.id_token.advertised_signing_algorithms.empty` | The filter was set to a non-null empty collection |
| `signing.key_ring.missing` | No signing key source was registered — the discovery document has no key set to derive `id_token_signing_alg_values_supported` from |
| `signing.advertised_algorithms.excludes_signing_key` | `IdToken.AdvertisedSigningAlgorithms` excludes the algorithm of the key that signs |
| `configuration.grant_types_supported.null`, `configuration.response.modes_supported.null` | `GrantTypesSupported` or `Response.ModesSupported` was set to `null` |

The full validation rule set is in the
[AuthorizationServerOptions reference](../reference/configuration.md#startup-validation).

## 4. Use an HTTP issuer for local development

If you are developing locally without TLS, enable `AllowInsecureIssuer` to allow an HTTP loopback issuer.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "http://localhost:5000";
    options.AllowInsecureIssuer = true;
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

When `AllowInsecureIssuer = true`, ZeeKayDa.Auth emits a warning via `ILogger` on every startup as
a reminder that this setting is active.

> Warning: Never set `AllowInsecureIssuer = true` in a production environment. It only permits HTTP
> loopback issuers for local development and tests. HTTP issuers allow token responses to be
> intercepted and identity documents to be forged. ZeeKayDa.Auth also rejects non-HTTPS
> non-loopback protocol requests with `421 Misdirected Request`.

## 5. Use the builder for optional features

`AddZeeKayDaAuth` returns a `ZeeKayDaAuthBuilder`. Use it to register optional features such as
custom scope repositories.

```csharp
var builder = WebApplication.CreateBuilder(args);

var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

// Register optional features on the builder:
// auth.AddInMemoryScopes([...]);

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

> 💡 **Development opt-out for exception message sanitization:** Set
> `AuthorizationServerOptions.Logging.DisableExceptionSanitizing` to `true` in
> `appsettings.Development.json` to turn off the unconditional exception message redaction
> performed by `SecretSanitizingLogger`. This is a development-only setting — never enable it
> in production. See [Configure host-level log hygiene](configure-host-log-hygiene.md)
> for full guidance.

## 6. Register client secret hashers

Client secrets are hashed before storage using a pluggable `IClientSecretHasher`.
`AddZeeKayDaAuth` always registers the built-in PBKDF2-HMAC-SHA256 hasher; there is nothing to add.

### Configure the iteration count

Override the default iteration count of 600,000 on the builder, or bind
`Pbkdf2ClientSecretHasherOptions` from configuration:

```csharp
auth.ConfigurePbkdf2ClientSecretHasher(options => options.Iterations = 1_200_000);
```

A value below 600,000 or above 2,000,000 fails startup.

### Multiple hashers (credential rotation)

The composite verifier dispatches each stored credential to the hasher that handles it. The built-in PBKDF2 hasher is always registered and, unless you mark another hasher as the
default, creates every new secret. To keep verifying secrets hashed with another algorithm,
register that hasher alongside it; to make your own hasher create new secrets, mark it
`isDefault: true` — PBKDF2 stays registered, so existing PBKDF2 secrets keep verifying:

```csharp
auth.AddClientSecretHasher<BcryptClientSecretHasher>();                  // verifies old bcrypt secrets
auth.AddClientSecretHasher<Argon2ClientSecretHasher>(isDefault: true);   // creates new secrets
```

Startup validation fails if more than one registered hasher has `isDefault: true`, or if the
PBKDF2 iteration count is below 600,000 or above 2,000,000.

For the full `Pbkdf2ClientSecretHasherOptions` property reference, see
[Client secrets reference](../reference/client-secrets.md). To implement a custom hasher, see
[Implement a custom extension point](implement-custom-extension-points.md).

## 7. Enable extended error codes per client (`EnableZkdErrorCodes`)

`EnableZkdErrorCodes` is a per-client flag, set in the client's `AddConfidential` callback (or on
an `IClientRegistration` you build yourself). When `true`, the server may include a `zkd_error`
field in token endpoint error responses for that client, surfacing machine-readable diagnostic
codes beyond what RFC 6749 defines.

```csharp
builder.AddInMemoryClients(clients =>
    clients.AddConfidential(/* ... */, options => options.EnableZkdErrorCodes = true));
```

### Operator guidance

Extended error codes improve diagnostics for legitimate callers, but they give an attacker more
signal in aggregate — every additional code is a distinguisher. Follow these guidelines:

- Enable `EnableZkdErrorCodes` only for **confidential clients** with a demonstrated diagnostic
  need, such as a trusted first-party backend that requires machine-readable error routing.
- Do **not** enable it for public clients (single-page applications, native apps) or for clients
  operated by third parties you do not fully trust.
- If you operate a multi-tenant deployment, treat the flag as **trusted-tenant-only** by default.

### Rate limiting is load-bearing for public-client identification

> ⚠️ **Rate limiting is load-bearing for public-client identification.** When `IsPublic == true`,
> the framework intentionally accepts a response-timing distinguishability between public and
> confidential clients. An observer can infer client type from timing differences. Rate limiting
> on the token endpoint is not optional — it is the primary mitigation for this accepted
> distinguishability.
>
> This residual is accepted deliberately. Regardless of `EnableZkdErrorCodes`, operators
> must apply rate limiting to the token endpoint. Timing uniformity alone is not sufficient to
> defeat a sustained enumeration attempt.

### `zkd_error` non-disclosure constraint

Even with `EnableZkdErrorCodes = true`, the `zkd_error` value for `invalid_client` **must not**
distinguish "unknown `client_id`" from "wrong credential". The framework enforces this constraint
internally; no configuration is required.

## Next steps

- [Configure discovery](configure-discovery.md) — customise the OpenID Connect discovery document,
  override endpoint URLs, and manage published scopes
- [AuthorizationServerOptions reference](../reference/configuration.md) — complete property
  reference with types, defaults, and validation rules
- [Client secrets reference](../reference/client-secrets.md) — `Pbkdf2ClientSecretHasherOptions`
  property reference
