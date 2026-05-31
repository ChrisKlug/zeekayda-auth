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
| `ResponseTypesSupported` | `["code"]` |
| `ResponseModesSupported` | `["query"]` |
| `GrantTypesSupported` | `["authorization_code"]` |
| `TokenEndpointAuthMethodsSupported` | `["client_secret_basic"]` |
| `IdTokenSigningAlgValuesSupported` | `["RS256"]` |

These defaults are a safe starting point for a standard authorization code flow with a
confidential client.

## 3. Understand startup validation

`AddZeeKayDaAuth` wires `ValidateOnStart()` so that any misconfiguration causes the host to fail
immediately at startup, before it starts accepting requests. You will see an
`OptionsValidationException` in the startup output.

Common startup failures and their causes:

| Failure | Cause |
|---|---|
| `Issuer` validation error | `Issuer` is not set, not an absolute URI, uses HTTP without `AllowInsecureIssuer`, or contains a query string or fragment |
| `ResponseTypesSupported` validation error | The collection was set to `null` or emptied |
| `IdTokenSigningAlgValuesSupported` validation error | The collection was set to `null` or emptied |
| Other collection validation errors | Any of the remaining `ICollection` properties was set to `null` |

The full validation rule set is in the
[AuthorizationServerOptions reference](../reference/configuration.md#startup-validation).

## 4. Use an HTTP issuer for local development

If you are developing locally without TLS, enable `AllowInsecureIssuer` to allow an HTTP issuer.

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

> Warning: Never set `AllowInsecureIssuer = true` in a production environment. HTTP issuers allow
> token responses to be intercepted and identity documents to be forged. This flag exists solely
> for local development and automated test environments.

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

## Next steps

- [Configure discovery](configure-discovery.md) — customise the OpenID Connect discovery document,
  override endpoint URLs, and manage published scopes
- [AuthorizationServerOptions reference](../reference/configuration.md) — complete property
  reference with types, defaults, and validation rules
