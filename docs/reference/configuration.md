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
> the `InsecureIssuer` startup verifier emits a warning at every startup.
>
> Request-time enforcement also applies: ZeeKayDa.Auth protocol endpoints reject non-HTTPS
> non-loopback requests with `421 Misdirected Request`. Loopback is determined from the TCP-level
> `HttpContext.Connection.RemoteIpAddress`, not from the `Host` header.
>
> **Reverse-proxy caution:** If the application runs behind a reverse proxy with
> `UseForwardedHeaders()` configured to trust an unbounded set of proxies, `RemoteIpAddress` can
> be overwritten from a client-controlled `X-Forwarded-For` value. An attacker could then forge
> `X-Forwarded-For: 127.0.0.1` to appear loopback. Always scope `KnownProxies` or `KnownNetworks`
> to the actual proxy addresses and ensure `UseForwardedHeaders()` runs before
> `app.UseEndpoints()`; never combine `AllowInsecureIssuer = true` with a wildcard trusted-proxy
> configuration.

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
when a reverse proxy rewrites paths under the same authority. The value must be an absolute HTTPS
URI without user information or fragment. Query strings are permitted by RFC 6749 Section 3.1. The
override must use the same authority as `Issuer`.

```csharp
options.AuthorizationEndpoint.Uri = "https://id.example.com/tenant-a/custom/authorize";
```

---

### `AuthorizationEndpoint.MaxRequestContextBytes`

| Attribute | Value |
|---|---|
| Type | `int` |
| Default | `16384` (16 KB) |
| Required | No |

The most an authorization request may occupy in the interaction store, in bytes of encoded request
context, before it is refused. An authorization request needs no authentication, and every valid one
is stored for the interaction's lifetime, so this bounds what one request can make the store hold. A
typical request encodes to a few hundred bytes; `state` and `nonce` are the only unbounded fields, so
the default is far above what any real client sends. A request over the cap is answered locally with
`invalid_request` — never redirected, since echoing an oversized `state` builds a `Location` the
client's server may not accept.

Raise it only for clients that legitimately send larger `state` values:

```csharp
options.AuthorizationEndpoint.MaxRequestContextBytes = 64 * 1024;
```

Must be greater than zero; rejected at startup otherwise.

---

### `AuthorizationEndpoint.CodeChallengeMethodsSupported`

| Attribute | Value |
|---|---|
| Type | `ICollection<CodeChallengeMethod>?` |
| Default | `[CodeChallengeMethod.S256]` |
| Required | When `GrantTypesSupported` contains `AuthorizationCode` |

The PKCE code challenge methods advertised in the discovery document, and the one method the token
endpoint verifies every `code_verifier` with. PKCE is enforced for the authorization code grant
(OAuth 2.1 §4.1.1, RFC 9700 §2.1.1) for every client except a confidential one whose registration
sets `AllowNonceInsteadOfPkce`, so a host that serves the grant must keep `S256` in this collection:
startup fails otherwise. When `null`, the
`code_challenge_methods_supported` field is omitted from the discovery document, which is only
valid on a host whose `GrantTypesSupported` does not contain the code grant.

| Enum value | JSON serialization |
|---|---|
| `CodeChallengeMethod.S256` | `"S256"` |

The `plain` challenge method is intentionally absent from `CodeChallengeMethod`. RFC 9700 §2.1.1
explicitly prohibits its use: advertising `plain` would negate PKCE's security benefit because the
challenge is identical to the verifier and provides no protection against interception.

Startup validation rejects a non-null empty collection (e.g. `= []`), which would publish
`"code_challenge_methods_supported": []` — advertising PKCE support with no usable method — and
rejects `null` or a collection without `S256` on a host that serves the authorization code grant.

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
The override must use the same authority as `Issuer`.

```csharp
options.TokenEndpoint.Uri = "https://id.example.com/tenant-a/custom/token";
```

`TokenEndpoint.AccessTokenLifetime` (default ten minutes) and `TokenEndpoint.IdTokenLifetime`
(default five minutes) are the server-wide lifetimes of the tokens the endpoint issues. Both must be
greater than zero; there is no upper bound, but a value longer than
`TokenEndpoint.AbsoluteFamilyLifetime` logs a startup warning. A client registration may override
either through its own `AccessTokenLifetime` and `IdTokenLifetime`, where `null` (the default) means
the server value.

```csharp
options.TokenEndpoint.AccessTokenLifetime = TimeSpan.FromMinutes(30);
options.TokenEndpoint.IdTokenLifetime = TimeSpan.FromMinutes(2);
```

The access-token default is short because the token is a self-contained JWT: nothing checks it
against a store, so a resource server keeps accepting it until it expires however the grant behind
it ended — revoked, signed out, or deleted. `AccessTokenLifetime` is that window, and every minute
added to it is a minute added to the window. Budget for a little more than the value you set: a
resource server applies its own clock-skew tolerance to `exp`, five minutes being a common default,
and that tolerance is added to this lifetime. [RFC 7009
§3](https://www.rfc-editor.org/rfc/rfc7009#section-3) sanctions that trade for self-contained
tokens: keep them short and renew them.

Renewal today is a fresh authorization request the client starts itself, by redirecting through the
authorization endpoint roughly every ten minutes instead of every hour. That is the path [RFC 9700
§4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2) describes for a server that issues
no refresh token: the client obtains a new access token through another grant, and the server uses
the sign-in session to keep that cheap. A browser that still holds
its sign-in session is not asked to sign in again, but it **is** asked for consent again: consent is
not remembered between requests, so a client left at the default `RequireConsent = true` prompts the
user on every renewal, and a renewal sent with `prompt=none` is answered `consent_required`. Only a
client registered with `RequireConsent = false` renews without the user seeing anything. Turn
consent off for that reason alone only for your own first-party applications — it is the control
that lets a user notice an authorization request they never started. The refresh-token grant is not
served yet, so putting `GrantType.RefreshToken` in `GrantTypesSupported` advertises it in discovery
without making it work.

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
The override must use the same authority as `Issuer`.

```csharp
options.JwksEndpoint.Uri = "https://id.example.com/tenant-a/custom/jwks";
```

`JwksEndpoint.CacheMaxAge` (`TimeSpan`, default one hour) sets the `max-age` duration for the JWKS
response's `Cache-Control` header, emitted in whole seconds exactly like
[`DiscoveryDocument.CacheMaxAge`](#discoverydocumentcachemaxage): `public, max-age=3600,
must-revalidate` by default, `no-store` below one second, and negative values fail startup
validation. This value governs how long a relying party may keep trusting a cached key set —
including a key that has since been removed from configuration — so a shorter TTL shortens that
revocation window at the cost of more JWKS traffic.

See the [JWKS endpoint reference](jwks-endpoint.md) for the response format.

---

### `UserInfoEndpoint`

| Attribute | Value |
|---|---|
| Type | `UserInfoEndpointOptions` |
| Default | `new UserInfoEndpointOptions()` |
| Required | No |

Group for UserInfo endpoint settings.

`UserInfoEndpoint.Uri` overrides the `userinfo_endpoint` value published in the discovery document.
When `null`, ZeeKayDa.Auth derives the URL from `Issuer` as `{issuer}/connect/userinfo`.

The value must be an absolute HTTPS URI without user information, query, or fragment, and must use
the same authority as `Issuer`.

```csharp
options.UserInfoEndpoint.Uri = "https://id.example.com/tenant-a/custom/userinfo";
```

The endpoint is served, and its URL published, only when `GrantTypesSupported` includes
`AuthorizationCode`. The browser origins allowed to read its responses are [`CorsOrigins`](#corsorigins).

See the [UserInfo endpoint reference](userinfo-endpoint.md) for the token, response and error
contract.

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
| Type | `ICollection<string>` |
| Default | `["client_secret_basic"]` (see `TokenEndpointAuthMethods.ClientSecretBasic`) |
| Required | Yes (must not be null or empty) |

The client authentication methods supported at the token endpoint. Published as
`token_endpoint_auth_methods_supported` in the discovery document.

Well-known method string constants are available on `TokenEndpointAuthMethods`. Custom authentication
methods (e.g. `"tls_client_auth"` from RFC 8705) may also be included as plain strings alongside
those constants.

> ⚠️ **Note:** Every method listed in `AuthMethodsSupported` (except `"none"`) must be present in
> exactly one registered `IClientAuthenticator`'s `AuthenticationMethods`. Advertising a method with
> no covering authenticator — or with more than one — will be caught by startup validation.

Each entry must be a non-empty, non-whitespace string with no leading or trailing whitespace and no
control characters. If `GrantTypesSupported` includes `GrantType.ClientCredentials`, the collection
must contain at least one method other than `TokenEndpointAuthMethods.None` (`"none"`).

This cross-group validator rule is grounded in [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) and
[RFC 9700 §2.6](https://www.rfc-editor.org/rfc/rfc9700#section-2.6). If violated, startup validation
emits:

```text
GrantTypesSupported includes 'client_credentials', which requires confidential clients. TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'. See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).
```

| `TokenEndpointAuthMethods` constant | String value |
|---|---|
| `ClientSecretBasic` | `"client_secret_basic"` |
| `ClientSecretPost` | `"client_secret_post"` |
| `None` | `"none"` |

Custom methods not listed above (e.g. `"tls_client_auth"`, `"private_key_jwt"`) are expressed as
plain strings alongside these constants.

`token_endpoint_auth_methods_supported` is defined by
[RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414#section-2).

#### `"none"` and PKCE

`TokenEndpointAuthMethods.None` (`"none"`) represents **public clients** — clients with no client
secret. Public clients cannot securely transmit credentials at the token endpoint.

> ⚠️ **Warning:** Public clients MUST use PKCE (Proof Key for Public OAuth 2.0 Clients) as the sole protection mechanism for the authorization code. This is mandated by [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) (OAuth 2.0 Security Best Current Practice).

**PKCE is defined for the authorization code grant** per [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636). Therefore:

- Public clients using the authorization code flow with `"none"` **must** use PKCE and present a valid `code_verifier` at the token endpoint.
- `"none"` may be advertised alongside confidential-client methods such as `"client_secret_basic"`; this supports deployments that serve both public clients and confidential clients.
- Startup validation does **not** reject `"none"` just because `GrantTypesSupported` omits `GrantType.AuthorizationCode`. Only the `client_credentials` + `none`-only combination above is rejected.
- When the token endpoint is implemented, it must enforce each registered client's `token_endpoint_auth_method` at request time (tracked by issue #64). Without per-client enforcement, a confidential client could downgrade to public-client behavior by omitting credentials.

Attempting to support `ClientCredentials` with only public-client authentication will fail at host startup with the error message shown above.

```csharp
// ✓ Valid: public clients with authorization code grant + PKCE
options.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
options.GrantTypesSupported = [GrantType.AuthorizationCode];

// ✗ Invalid: client_credentials with only public-client authentication
// This will fail startup validation
options.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethods.None];
options.GrantTypesSupported = [GrantType.ClientCredentials];
```

Authorization-code clients that use `"none"` must perform the token exchange with a PKCE challenge
and verifier. Consult your OAuth client library's documentation for PKCE implementation details.

---

### `IdToken.AdvertisedSigningAlgorithms`

| Attribute | Value |
|---|---|
| Type | `ICollection<SigningAlgorithm>?` |
| Default | `null` |
| Required | No (when set, must not be empty) |

An optional **narrowing filter** on what `id_token_signing_alg_values_supported` publishes. The
advertised set is derived from the configured signing keys — the distinct algorithms of every
published key (`Previous`, `Current`, and `Next`), ascending by `SigningAlgorithm` value — so the
server can never advertise an algorithm it holds no key for.

Leave this `null` (the default) to advertise that whole set. Set it to withhold an algorithm the
server could otherwise advertise; it can never add one. A filter that excludes the signing key's own
algorithm fails startup with `signing.advertised_algorithms.excludes_signing_key`.

Three startup warnings cover the rest:

| Code | Meaning |
|---|---|
| `signing.advertised_algorithms.withholds_published_algorithm` | The filter withholds an algorithm a published key still uses. Those keys stay in the JWKS and tokens they signed remain verifiable, but a relying party that pins acceptance to `id_token_signing_alg_values_supported` will reject them until they expire. Logged at `Information`, not `Warning`: every filter that narrows anything withholds a published algorithm, so this fires on correct use of the feature too. |
| `signing.advertised_algorithms.absent_from_key_set` | The filter names an algorithm no configured key uses. The entry has no effect. |
| `signing.advertised_algorithms.rs256_absent` | The advertised set omits `RS256`, which [OpenID Connect Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) requires. The framework warns rather than injecting it — advertising an algorithm with no key behind it is the failure this derivation exists to prevent. |

```csharp
// Two keys are configured, RS256 and ES256, but only RS256 is advertised.
options.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];
```

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

### `DiscoveryDocument.CacheMaxAge`

| Attribute | Value |
|---|---|
| Type | `TimeSpan` |
| Default | `TimeSpan.FromHours(1)` |
| Required | No |

The `max-age` duration for the discovery endpoint's `Cache-Control` header, emitted in whole
seconds. The default response is:

```text
Cache-Control: public, max-age=3600, must-revalidate
```

Any value below one second — `TimeSpan.Zero` being the idiomatic choice — disables public caching:

```text
Cache-Control: no-store
```

Negative values fail startup validation.

The JWKS endpoint has its own, independently configured equivalent:
[`JwksEndpoint.CacheMaxAge`](#jwksendpoint).

---

### `CorsOrigins`

| Attribute | Value |
|---|---|
| Type | `IList<string>` |
| Default | `[]` (empty) |
| Required | No |

The list of browser origins permitted to read the responses of the endpoints a script may call:
the discovery document, the JWKS and userinfo. When empty (the default), each returns
`Access-Control-Allow-Origin: *`. When non-empty, only requests whose `Origin` header matches an
allowlist entry receive an `Access-Control-Allow-Origin` response header.

One list covers every one of those endpoints. None of them authenticates with a cookie, so the
allowlist decides which origins may read a public document or a response the caller already holds
the access token for, and that answer does not vary by endpoint.

Each entry must be an absolute origin in the form `scheme://host[:port]` with no path, query,
fragment, user information, wildcards, or the literal string `null`. Entries are canonicalized
(lowercased), deduplicated, and frozen into an immutable startup snapshot. Invalid entries cause
the host to fail fast.

`https://` origins are always accepted. `http://` origins are rejected unless
`AllowInsecureIssuer = true`; when enabled, HTTP origins must still target loopback hosts only.

```csharp
options.CorsOrigins.Add("https://app.example.com");
options.CorsOrigins.Add("https://admin.example.com");
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
| `Issuer` must be canonical | `Issuer` uses uppercase scheme or host, or explicitly specifies a default port (`:443` for HTTPS, `:80` for HTTP loopback) |
| Endpoint overrides must be absolute HTTPS URIs | an override is relative, uses an unsupported scheme, or uses HTTP without `AllowInsecureIssuer` |
| HTTP endpoint overrides must be loopback | an override uses HTTP with a non-loopback host |
| Endpoint overrides must share issuer authority | an override host/port differs from `Issuer` |
| Endpoint overrides must not have user information | an override contains `user:password@host` userinfo |
| Endpoint fragments are rejected | `AuthorizationEndpoint.Uri`, `TokenEndpoint.Uri`, `JwksEndpoint.Uri`, `EndSessionEndpoint.Uri`, or `UserInfoEndpoint.Uri` contains `#` |
| Some endpoint overrides must not have a query string | `JwksEndpoint.Uri`, `EndSessionEndpoint.Uri`, or `UserInfoEndpoint.Uri` contains `?` |
| `Response.TypesSupported` is required | `Response.TypesSupported` is `null` or empty |
| `Response.ModesSupported` is required | `Response.ModesSupported` is `null` |
| `GrantTypesSupported` is required | `GrantTypesSupported` is `null` |
| `TokenEndpoint.AuthMethodsSupported` is required | `TokenEndpoint.AuthMethodsSupported` is `null` or empty |
| `client_credentials` requires non-`none` token auth method | `GrantTypesSupported` includes `ClientCredentials` and every `TokenEndpoint.AuthMethodsSupported` value is `None` |
| `IdToken.AdvertisedSigningAlgorithms` must not be empty | `IdToken.AdvertisedSigningAlgorithms` is a non-null empty collection |
| `IScopeRepository` must include `openid` | the configured scope repository does not include a scope named `openid` |
| Cache max-age must not be negative | `DiscoveryDocument.CacheMaxAge` or `JwksEndpoint.CacheMaxAge` is negative |
| `AuthorizationEndpoint.CodeChallengeMethodsSupported` must not be empty | `AuthorizationEndpoint.CodeChallengeMethodsSupported` is a non-null empty collection |
| The code grant requires `S256` | `GrantTypesSupported` contains `AuthorizationCode` and `AuthorizationEndpoint.CodeChallengeMethodsSupported` is `null` or lacks `CodeChallengeMethod.S256` |
| Token lifetimes must be positive | `TokenEndpoint.AccessTokenLifetime` or `TokenEndpoint.IdTokenLifetime` is zero or negative |
| `AuthorizationEndpoint.MaxRequestContextBytes` must be greater than zero | `AuthorizationEndpoint.MaxRequestContextBytes` is zero or negative |
| CORS origins must use HTTPS by default | a `CorsOrigins` entry uses HTTP while `AllowInsecureIssuer` is `false` |
| HTTP CORS origins must be loopback when allowed | a `CorsOrigins` entry uses HTTP with a non-loopback host |
| `SecurityHeaders.ReferrerPolicy` must be a defined enum value | `SecurityHeaders.ReferrerPolicy` is set via an out-of-range cast |
| `SecurityHeaders.CrossOriginResourcePolicy` must be a defined enum value | `SecurityHeaders.CrossOriginResourcePolicy` is set via an out-of-range cast |

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
- [Configure token stores](../how-to/configure-token-stores.md) — step-by-step token store setup
- [Token stores](token-stores.md) — reference for `IAuthorizationCodeStore`, `IRefreshTokenStore`, lifetime options, and `ZeeKayDaStoreException`
- [Discovery endpoint](discovery-endpoint.md) — full contract for the discovery endpoint
- [UserInfo endpoint](userinfo-endpoint.md) — full contract for the userinfo endpoint
