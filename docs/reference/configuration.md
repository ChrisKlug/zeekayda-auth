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

The value must be an absolute HTTPS URI with no query string, fragment, or user information. The
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

When `true`, relaxes the HTTPS requirement on `Issuer` to allow HTTP loopback issuers only.
Intended for local development and automated testing only.

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
| Type | `AuthorizationEndpointOptions` |
| Default | `new AuthorizationEndpointOptions()` |
| Required | No |

Group for authorization endpoint settings.

`AuthorizationEndpoint.Uri` overrides the `authorization_endpoint` value published in the discovery
document. When `null`, ZeeKayDa.Auth derives the URL from `Issuer` as
`{issuer}/connect/authorize`.

Set this when the URL your clients should use differs from the issuer-derived default — for example,
when a reverse proxy rewrites paths. The value must be an absolute HTTPS URI without user
information or fragment. Query strings are permitted by RFC 6749 Section 3.1.

```csharp
options.AuthorizationEndpoint.Uri = "https://login.example.com/tenant-a/connect/authorize";
```

---

### `AuthorizationEndpoint.CodeChallengeMethodsSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<CodeChallengeMethod>?` |
| Default | `null` |
| Required | No |

The PKCE code challenge methods advertised in the discovery document. When `null` (the default),
the `code_challenge_methods_supported` field is omitted entirely from the discovery document.

> ⚠️ **Do not set this property until PKCE challenge verification is enforced at the token
> endpoint.** Advertising methods the server cannot verify gives clients a false assurance —
> a PKCE-aware client will include a `code_verifier` at the token endpoint, and if the server
> silently ignores it, an authorization-code interception attack can succeed undetected.

Once PKCE enforcement is implemented, set this property to advertise `S256` support:

```csharp
options.AuthorizationEndpoint.CodeChallengeMethodsSupported = [CodeChallengeMethod.S256];
```

| Enum value | JSON serialization |
|---|---|
| `CodeChallengeMethod.S256` | `"S256"` |

The `plain` challenge method is intentionally absent from `CodeChallengeMethod`. RFC 9700 §2.1.1
explicitly prohibits its use: advertising `plain` would negate PKCE's security benefit because the
challenge is identical to the verifier and provides no protection against interception.

Startup validation rejects a non-null empty collection (e.g. `= []`), which would publish
`"code_challenge_methods_supported": []` — advertising PKCE support with no usable method.

Maps to `code_challenge_methods_supported` as defined in
[RFC 7636 §4.3](https://www.rfc-editor.org/rfc/rfc7636#section-4.3) and
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).

---

### `TokenEndpoint`

| Attribute | Value |
|---|---|
| Type | `TokenEndpointOptions` |
| Default | `new TokenEndpointOptions()` |
| Required | No |

Group for token endpoint settings.

`TokenEndpoint.Uri` overrides the `token_endpoint` value published in the discovery document. When
`null`, ZeeKayDa.Auth derives the URL from `Issuer` as `{issuer}/connect/token`.

The value must be an absolute HTTPS URI without user information or fragment.

```csharp
options.TokenEndpoint.Uri = "https://login.example.com/tenant-a/connect/token";
```

---

### `JwksEndpoint`

| Attribute | Value |
|---|---|
| Type | `JwksEndpointOptions` |
| Default | `new JwksEndpointOptions()` |
| Required | No |

Group for JSON Web Key Set endpoint settings.

`JwksEndpoint.Uri` overrides the `jwks_uri` value published in the discovery document. When `null`,
ZeeKayDa.Auth derives the URL from `Issuer` as `{issuer}/connect/jwks`.

The value must be an absolute HTTPS URI without user information, query, or fragment.

```csharp
options.JwksEndpoint.Uri = "https://login.example.com/tenant-a/connect/jwks";
```

---

### `Response.TypesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<ResponseType>` |
| Default | `[ResponseType.Code]` |
| Required | Yes (must not be null or empty) |

The response types this server supports. Published as `response_types_supported` in the discovery
document. This value lives in the `Response` options group.

| Enum value | JSON serialization |
|---|---|
| `ResponseType.Code` | `"code"` |

Hybrid and implicit response types are not supported by ZeeKayDa.Auth. The library intentionally
publishes code flow only, aligned with OAuth 2.1 §3.3 and RFC 9700 §2.1.2.

`response_types_supported` is a required field in the discovery document per
[OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).

---

### `Response.ModesSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<ResponseMode>` |
| Default | `[ResponseMode.Query]` |
| Required | Yes (must not be null) |

The response modes this server supports. Published as `response_modes_supported` in the discovery
document. This value lives in the `Response` options group.

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

### `TokenEndpoint.AuthMethodsSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<TokenEndpointAuthMethod>` |
| Default | `[TokenEndpointAuthMethod.ClientSecretBasic]` |
| Required | Yes (must not be null) |

The client authentication methods supported at the token endpoint. Published as
`token_endpoint_auth_methods_supported` in the discovery document.

This value must not be null or empty. If `GrantTypesSupported` includes
`GrantType.ClientCredentials`, it must contain at least one method other than
`TokenEndpointAuthMethod.None`.

This cross-group validator rule is defined in
[ADR 0002 §4 Rule 2](../decisions/0002-options-shape-grouped-nested.md#required-validator-rules-for-tokenendpointauthmethodssupported)
and is grounded in [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) and
[RFC 9700 §2.6](https://www.rfc-editor.org/rfc/rfc9700#section-2.6). If violated, startup validation
emits:

```text
GrantTypesSupported includes 'client_credentials', which requires confidential clients. TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).
```

| Enum value | JSON serialization |
|---|---|
| `TokenEndpointAuthMethod.ClientSecretBasic` | `"client_secret_basic"` |
| `TokenEndpointAuthMethod.ClientSecretPost` | `"client_secret_post"` |
| `TokenEndpointAuthMethod.ClientSecretJwt` | `"client_secret_jwt"` |
| `TokenEndpointAuthMethod.PrivateKeyJwt` | `"private_key_jwt"` |
| `TokenEndpointAuthMethod.None` | `"none"` |

`token_endpoint_auth_methods_supported` is defined by
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).

#### `TokenEndpointAuthMethod.None` and PKCE

`TokenEndpointAuthMethod.None` represents **public clients** — clients with no client secret. Public clients cannot securely transmit credentials at the token endpoint.

> ⚠️ **Warning:** Public clients MUST use PKCE (Proof Key for Public OAuth 2.0 Clients) as the sole protection mechanism for the authorization code. This is mandated by [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) (OAuth 2.0 Security Best Current Practice).

**PKCE is defined for the authorization code grant** per [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636). Therefore:

- Public clients using the authorization code flow with `TokenEndpointAuthMethod.None` **must** use PKCE and present a valid `code_verifier` at the token endpoint.
- `TokenEndpointAuthMethod.None` may be advertised alongside confidential-client methods such as `ClientSecretBasic`; this supports deployments that serve both public clients and confidential clients.
- Startup validation does **not** reject `None` just because `GrantTypesSupported` omits `GrantType.AuthorizationCode`. ADR 0002 rejects only the `client_credentials` + `none`-only combination above.
- When the token endpoint is implemented, it must enforce each registered client's `token_endpoint_auth_method` at request time (tracked by issue #64). Without per-client enforcement, a confidential client could downgrade to public-client behavior by omitting credentials.

Attempting to support `ClientCredentials` with only public-client authentication will fail at host startup with the ADR 0002 error message shown above.

```csharp
// ✓ Valid: public clients with authorization code grant + PKCE
options.TokenEndpoint.AuthMethodsSupported = new[] { TokenEndpointAuthMethod.None };
options.GrantTypesSupported = new[] { GrantType.AuthorizationCode };

// ✗ Invalid: client_credentials with only public-client authentication
// This will fail startup validation
options.TokenEndpoint.AuthMethodsSupported = new[] { TokenEndpointAuthMethod.None };
options.GrantTypesSupported = new[] { GrantType.ClientCredentials };
```

Authorization-code clients that use `TokenEndpointAuthMethod.None` must perform the token exchange with a PKCE challenge and verifier. Consult your OAuth client library's documentation for PKCE implementation details.

---

### `IdToken.SigningAlgValuesSupported`

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

---

### `DiscoveryDocument.CacheMaxAgeSeconds`

| Attribute | Value |
|---|---|
| Type | `int` |
| Default | `3600` |
| Required | No |

The `max-age` value, in seconds, for the discovery endpoint's `Cache-Control` header. The default
response is:

```text
Cache-Control: public, max-age=3600, must-revalidate
```

Set the value to `0` to disable public caching:

```text
Cache-Control: no-store
```

Negative values fail startup validation.

---

### `DiscoveryDocument.CorsOrigins`

| Attribute | Value |
|---|---|
| Type | `IList<string>` |
| Default | `[]` (empty) |
| Required | No |

The list of origins permitted to fetch the discovery document from a browser via CORS. When empty
(the default), the endpoint returns `Access-Control-Allow-Origin: *`. When non-empty, only requests
whose `Origin` header matches an allowlist entry receive an `Access-Control-Allow-Origin` response
header.

Each entry must be an absolute origin in the form `scheme://host[:port]` with no path, query,
fragment, user information, wildcards, or the literal string `null`. Entries are canonicalized
(lowercased) and deduplicated at startup. Invalid entries cause the host to fail fast.

```csharp
options.DiscoveryDocument.CorsOrigins.Add("https://app.example.com");
options.DiscoveryDocument.CorsOrigins.Add("https://admin.example.com");
```

See [Discovery endpoint — CORS configuration](discovery-endpoint.md#cors-configuration) for the
full CORS behaviour and an OPTIONS preflight note.

---

### `SecurityHeaders.ContentTypeOptionsNoSniff`

| Attribute | Value |
|---|---|
| Type | `bool` |
| Default | `true` |
| Required | No |

When `true` (the default), every ZeeKayDa.Auth protocol endpoint response includes
`X-Content-Type-Options: nosniff`. Set to `false` to suppress this header if your application
already sets it globally via a security-headers middleware.

---

### `SecurityHeaders.ReferrerPolicy`

| Attribute | Value |
|---|---|
| Type | `ReferrerPolicy` |
| Default | `ReferrerPolicy.NoReferrer` |
| Required | No |

Controls the `Referrer-Policy` response header emitted by all ZeeKayDa.Auth protocol endpoints.
The default `no-referrer` suppresses the `Referer` request header entirely, which is appropriate
for OAuth/OIDC endpoints that should not leak token URLs to third-party origins.

| Enum value | Header value |
|---|---|
| `ReferrerPolicy.NoReferrer` | `no-referrer` |
| `ReferrerPolicy.NoReferrerWhenDowngrade` | `no-referrer-when-downgrade` |
| `ReferrerPolicy.Origin` | `origin` |
| `ReferrerPolicy.OriginWhenCrossOrigin` | `origin-when-cross-origin` |
| `ReferrerPolicy.SameOrigin` | `same-origin` |
| `ReferrerPolicy.StrictOrigin` | `strict-origin` |
| `ReferrerPolicy.StrictOriginWhenCrossOrigin` | `strict-origin-when-cross-origin` |
| `ReferrerPolicy.UnsafeUrl` | `unsafe-url` |

---

### `SecurityHeaders.CrossOriginResourcePolicy`

| Attribute | Value |
|---|---|
| Type | `CrossOriginResourcePolicy` |
| Default | `CrossOriginResourcePolicy.CrossOrigin` |
| Required | No |

Controls the `Cross-Origin-Resource-Policy` response header emitted by all ZeeKayDa.Auth protocol
endpoints. The default `cross-origin` permits cross-origin subresource fetches (required for
browser-based relying parties reading the discovery document). Set to `same-origin` or `same-site`
only when all relying parties are co-hosted on the same origin or site as the authorization server.

> Note: If your application already applies a security-headers middleware that sets
> `Cross-Origin-Resource-Policy`, the header will be duplicated in ZeeKayDa.Auth responses.
> Since `CrossOriginResourcePolicy` is an enum (not a boolean), there is no way to suppress the
> header entirely. To avoid duplication, configure only one side: either exclude ZeeKayDa.Auth
> routes from your middleware's header policy, or rely solely on ZeeKayDa.Auth's built-in header.
> For example, with ASP.NET Core's `UseSecurityHeaders()` (NWebSec or similar), scope the
> middleware to non-ZeeKayDa routes only.

| Enum value | Header value |
|---|---|
| `CrossOriginResourcePolicy.SameSite` | `same-site` |
| `CrossOriginResourcePolicy.SameOrigin` | `same-origin` |
| `CrossOriginResourcePolicy.CrossOrigin` | `cross-origin` |

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
| HTTP issuer must be loopback | `Issuer` uses HTTP with a non-loopback host |
| `Issuer` must not have user information | `Issuer` contains `user:password@host` userinfo |
| Endpoint overrides must be absolute HTTPS URIs | an override is relative, uses an unsupported scheme, or uses HTTP without `AllowInsecureIssuer` |
| HTTP endpoint overrides must be loopback | an override uses HTTP with a non-loopback host |
| Endpoint overrides must not have user information | an override contains `user:password@host` userinfo |
| Endpoint fragments are rejected | `AuthorizationEndpoint.Uri`, `TokenEndpoint.Uri`, or `JwksEndpoint.Uri` contains `#` |
| `JwksEndpoint.Uri` must not have a query string | `JwksEndpoint.Uri` contains `?` |
| `Response.TypesSupported` is required | `Response.TypesSupported` is `null` or empty |
| `Response.ModesSupported` is required | `Response.ModesSupported` is `null` |
| `GrantTypesSupported` is required | `GrantTypesSupported` is `null` |
| `TokenEndpoint.AuthMethodsSupported` is required | `TokenEndpoint.AuthMethodsSupported` is `null` or empty |
| `client_credentials` requires non-`none` token auth method | `GrantTypesSupported` includes `ClientCredentials` and every `TokenEndpoint.AuthMethodsSupported` value is `None` |
| `IdToken.SigningAlgValuesSupported` is required | `IdToken.SigningAlgValuesSupported` is `null` or empty |
| `IScopeRepository` must include `openid` | the configured scope repository does not include a scope named `openid` |
| Cache max-age must not be negative | `DiscoveryDocument.CacheMaxAgeSeconds` is less than `0` |
| `AuthorizationEndpoint.CodeChallengeMethodsSupported` must not be empty | `AuthorizationEndpoint.CodeChallengeMethodsSupported` is a non-null empty collection |

For the exact failure text of the `client_credentials` + `none`-only token auth combination, see
[`TokenEndpoint.AuthMethodsSupported`](#tokenendpointauthmethodssupported) above.

Validation errors are reported as `OptionsValidationException` and prevent the host from starting.
They are visible in the startup output and host logs.

> Note: Startup validation checks `AuthorizationServerOptions` and verifies that
> `IScopeRepository` includes `openid`. Scope repositories still enforce their own validation rules
> (for example, blank or duplicate scope names).

## Related pages

- [Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md) — step-by-step setup guide
- [Configure discovery](../how-to/configure-discovery.md) — how to tune the discovery document
- [Discovery endpoint](discovery-endpoint.md) — full contract for the discovery endpoint
