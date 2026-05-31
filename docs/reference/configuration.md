---
title: "AuthorizationServerOptions"
description: "Complete reference for AuthorizationServerOptions, the central configuration type for ZeeKayDa.Auth."
parent: "Reference"
nav_order: 1
---

*Added in Unreleased.*

`AuthorizationServerOptions` is the central configuration type for ZeeKayDa.Auth. It controls the
issuer identity, published endpoint URLs, and the capability sets advertised in the OpenID Connect
discovery document.

Pass an `Action<AuthorizationServerOptions>` delegate to `AddZeeKayDaAuth(...)` at service
registration time. For step-by-step setup instructions, see
[Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md). For the discovery document that
these options feed, see [Discovery endpoint](discovery-endpoint.md).

## Registration

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});
```

`AddZeeKayDaAuth` registers all ZeeKayDa.Auth services and wires `ValidateOnStart()` so that
misconfigured options cause the host to fail fast on startup rather than at request time. It returns
a `ZeeKayDaAuthBuilder` for registering optional features.

## Properties

### `Issuer`

| Attribute | Value |
|---|---|
| Type | `string?` |
| Default | `null` |
| Required | Yes |

The issuer identifier for this authorization server. Published verbatim as the `issuer` field in
the OpenID Connect discovery document.

The value must be an absolute HTTPS URI with no query string and no fragment. The
`/.well-known/openid-configuration` discovery endpoint is derived from this value.

```csharp
options.Issuer = "https://id.example.com";
// or, for a path-bearing issuer:
options.Issuer = "https://id.example.com/tenant-a";
```

Issuer syntax requirements are defined by
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2) and
[OpenID Connect Discovery 1.0 §1.2](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

---

### `AllowInsecureIssuer`

| Attribute | Value |
|---|---|
| Type | `bool` |
| Default | `false` |
| Required | No |

When `true`, relaxes the HTTPS requirement on `Issuer` to allow HTTP. Intended for local
development and automated testing only.

> Warning: Never set `AllowInsecureIssuer = true` in production. An HTTP issuer allows token
> responses to be intercepted and identity documents to be forged. When this flag is enabled,
> `InsecureIssuerWarningService` emits a warning via `ILogger` at every startup.

```csharp
// Local development only
options.Issuer = "http://localhost:5000";
options.AllowInsecureIssuer = true;
```

---

### `AuthorizationEndpoint`

| Attribute | Value |
|---|---|
| Type | `string?` |
| Default | `null` (derived from `Issuer`) |
| Required | No |

Override for the `authorization_endpoint` value published in the discovery document. When `null`,
ZeeKayDa.Auth derives the URL from `Issuer` as `{issuer}/connect/authorize`.

Set this when the URL your clients should use differs from the issuer-derived default — for example,
when a reverse proxy rewrites paths.

```csharp
options.AuthorizationEndpoint = "https://login.example.com/tenant-a/connect/authorize";
```

---

### `TokenEndpoint`

| Attribute | Value |
|---|---|
| Type | `string?` |
| Default | `null` (derived from `Issuer`) |
| Required | No |

Override for the `token_endpoint` value published in the discovery document. When `null`,
ZeeKayDa.Auth derives the URL from `Issuer` as `{issuer}/connect/token`.

```csharp
options.TokenEndpoint = "https://login.example.com/tenant-a/connect/token";
```

---

### `JwksUri`

| Attribute | Value |
|---|---|
| Type | `string?` |
| Default | `null` (derived from `Issuer`) |
| Required | No |

Override for the `jwks_uri` value published in the discovery document. When `null`, ZeeKayDa.Auth
derives the URL from `Issuer` as `{issuer}/connect/jwks`.

```csharp
options.JwksUri = "https://login.example.com/tenant-a/connect/jwks";
```

---

### `ResponseTypesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<ResponseType>` |
| Default | `[ResponseType.Code]` |
| Required | Yes (must not be null or empty) |

The response types this server supports. Published as `response_types_supported` in the discovery
document.

| Enum value | JSON serialization |
|---|---|
| `ResponseType.Code` | `"code"` |

`response_types_supported` is a required field in the discovery document per
[OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

---

### `ResponseModesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<ResponseMode>` |
| Default | `[ResponseMode.Query]` |
| Required | Yes (must not be null) |

The response modes this server supports. Published as `response_modes_supported` in the discovery
document.

| Enum value | JSON serialization |
|---|---|
| `ResponseMode.Query` | `"query"` |

---

### `GrantTypesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<GrantType>` |
| Default | `[GrantType.AuthorizationCode]` |
| Required | Yes (must not be null) |

The grant types this server supports. Published as `grant_types_supported` in the discovery
document.

| Enum value | JSON serialization |
|---|---|
| `GrantType.AuthorizationCode` | `"authorization_code"` |

`grant_types_supported` is an authorization server metadata field defined by
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).

---

### `TokenEndpointAuthMethodsSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<TokenEndpointAuthMethod>` |
| Default | `[TokenEndpointAuthMethod.ClientSecretBasic]` |
| Required | Yes (must not be null) |

The client authentication methods supported at the token endpoint. Published as
`token_endpoint_auth_methods_supported` in the discovery document.

| Enum value | JSON serialization |
|---|---|
| `TokenEndpointAuthMethod.ClientSecretBasic` | `"client_secret_basic"` |

`token_endpoint_auth_methods_supported` is defined by
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).

---

### `IdTokenSigningAlgValuesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<SigningAlgorithm>` |
| Default | `[SigningAlgorithm.RS256]` |
| Required | Yes (must not be null or empty) |

The signing algorithms supported for ID tokens. Published as
`id_token_signing_alg_values_supported` in the discovery document.

| Enum value | JSON serialization |
|---|---|
| `SigningAlgorithm.RS256` | `"RS256"` |
| `SigningAlgorithm.RS384` | `"RS384"` |
| `SigningAlgorithm.RS512` | `"RS512"` |
| `SigningAlgorithm.ES256` | `"ES256"` |
| `SigningAlgorithm.ES384` | `"ES384"` |
| `SigningAlgorithm.ES512` | `"ES512"` |
| `SigningAlgorithm.PS256` | `"PS256"` |
| `SigningAlgorithm.PS384` | `"PS384"` |
| `SigningAlgorithm.PS512` | `"PS512"` |

`id_token_signing_alg_values_supported` is a required field in the discovery document per
[OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

## Startup validation

`AuthorizationServerOptionsValidator` validates `AuthorizationServerOptions` at host startup via
`ValidateOnStart()`. The host will not start if any rule below is violated.

| Rule | Condition that causes failure |
|---|---|
| `Issuer` is required | `Issuer` is `null`, empty, or whitespace |
| `Issuer` must be absolute | `Issuer` is not an absolute URI |
| `Issuer` must not have a query string | `Issuer` contains a `?` component |
| `Issuer` must not have a fragment | `Issuer` contains a `#` component |
| `Issuer` must use HTTPS | `Issuer` uses HTTP and `AllowInsecureIssuer` is `false` |
| `ResponseTypesSupported` is required | `ResponseTypesSupported` is `null` or empty |
| `ResponseModesSupported` is required | `ResponseModesSupported` is `null` |
| `GrantTypesSupported` is required | `GrantTypesSupported` is `null` |
| `TokenEndpointAuthMethodsSupported` is required | `TokenEndpointAuthMethodsSupported` is `null` |
| `IdTokenSigningAlgValuesSupported` is required | `IdTokenSigningAlgValuesSupported` is `null` or empty |

Validation errors are reported as `OptionsValidationException` and prevent the host from starting.
They are visible in the startup output and host logs.

> Note: Startup validation only checks `AuthorizationServerOptions`. Other configuration objects
> (for example, scope registrations) have their own validation rules.

## Related pages

- [Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md) — step-by-step setup guide
- [Configure discovery](../how-to/configure-discovery.md) — how to tune the discovery document
- [Discovery endpoint](discovery-endpoint.md) — full contract for the discovery endpoint
