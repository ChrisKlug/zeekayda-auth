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
| `IdToken.SigningAlgValuesSupported` | `["RS256"]` |

These defaults are a safe starting point for a standard authorization code flow with a
confidential client.

## 3. Understand startup validation

`AddZeeKayDaAuth` wires `ValidateOnStart()` so that any misconfiguration causes the host to fail
immediately at startup, before it starts accepting requests. You will see an
`OptionsValidationException` in the startup output.

Common startup failures and their causes:

| Failure | Cause |
|---|---|
| `Issuer` validation error | `Issuer` is not set, not an absolute URI, is not canonical (uppercase scheme/host or explicit default port), uses HTTP without `AllowInsecureIssuer`, uses HTTP on a non-loopback host, or contains query, fragment, or user information |
| `Response.TypesSupported` validation error | The collection was set to `null` or emptied |
| `IdToken.SigningAlgValuesSupported` validation error | The collection was set to `null` or emptied |
| Other collection validation errors | Any of the remaining `ICollection` properties was set to `null` |

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

Client secrets are hashed before storage using a pluggable `IClientSecretHasher`. Use
`AddPbkdf2SecretsHasher()` to register the built-in PBKDF2-HMAC-SHA256 hasher in one call:

```csharp
using ZeeKayDa.Auth.AspNetCore.Extensions;

var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

auth.AddPbkdf2SecretsHasher();
```

### Configure the iteration count

Pass an optional configure delegate to override the default iteration count of 600,000:

```csharp
auth.AddPbkdf2SecretsHasher(options => options.Iterations = 1_200_000);
```

### Multiple hashers (credential rotation)

When migrating from one algorithm to another, register both hashers and mark the new one as
default. The composite verifier dispatches each credential to the correct hasher; `isDefault: true`
controls which hasher creates new secrets:

```csharp
auth.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);   // creates new secrets
auth.AddSecretsHasher<BcryptClientSecretHasher>(isDefault: false);   // verifies old secrets
```

Startup validation fails at host startup if:

- No hashers are registered
- Multiple hashers are registered but zero or more than one has `isDefault: true`

For the full `Pbkdf2ClientSecretHasherOptions` property reference, see
[Client secrets reference](../reference/client-secrets.md). To implement a custom hasher, see
[Implement a custom extension point](implement-custom-extension-points.md).

## 7. Enable extended error codes per client (`EnableZkdErrorCodes`)

`EnableZkdErrorCodes` is a per-client flag on `ClientRegistration` (and `IClientRegistration`).
When `true`, the server may include a `zkd_error` field in token endpoint error responses for that
client, surfacing machine-readable diagnostic codes beyond what RFC 6749 defines.

```csharp
var customClient = ClientRegistration.CreateConfidential(/* ... */)
    with { EnableZkdErrorCodes = true };
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
> This residual is documented in ADR 0007 §3.4. Regardless of `EnableZkdErrorCodes`, operators
> must apply rate limiting to the token endpoint. Timing uniformity alone is not sufficient to
> defeat a sustained enumeration attempt.

### `zkd_error` non-disclosure constraint

Even with `EnableZkdErrorCodes = true`, the `zkd_error` value for `invalid_client` **must not**
distinguish "unknown `client_id`" from "wrong credential". The framework enforces this constraint
internally; no configuration is required. See ADR 0007 §7 for the binding constraint details.

## Next steps

- [Configure discovery](configure-discovery.md) — customise the OpenID Connect discovery document,
  override endpoint URLs, and manage published scopes
- [AuthorizationServerOptions reference](../reference/configuration.md) — complete property
  reference with types, defaults, and validation rules
- [Client secrets reference](../reference/client-secrets.md) — `Pbkdf2ClientSecretHasherOptions`
  property reference
