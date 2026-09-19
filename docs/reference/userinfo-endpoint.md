---
title: "UserInfo endpoint"
description: "Reference for the OpenID Connect UserInfo endpoint exposed by ZeeKayDa.Auth."
parent: "Reference"
nav_order: 9
---

*Added in Unreleased.*

The UserInfo endpoint returns claims about the signed-in user to a client holding an access token
for them, as defined by
[OpenID Connect Core 1.0 Section 5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
Its URL is published as `userinfo_endpoint` in the [discovery document](discovery-endpoint.md).

The endpoint is a protected resource, not a protocol endpoint the client authenticates to. It
validates the presented access token exactly as
[RFC 9068 Section 4](https://www.rfc-editor.org/rfc/rfc9068#section-4) obliges any resource server
to validate a JWT access token, rather than trusting a token merely because it can verify the
signature.

## Endpoint URL

**Methods:** `GET`, `POST`, `OPTIONS`

**Route:**

- Default: `{issuer}/connect/userinfo`
- Override: the exact URI configured in `UserInfoEndpoint.Uri`

The route is constrained to the configured issuer host, and the path must match exactly. Requests
over HTTP are rejected with `421 Misdirected Request`; loopback HTTP is permitted only when
`AllowInsecureIssuer` is enabled.

The endpoint is served, and `userinfo_endpoint` is published, only when `GrantTypesSupported`
includes `AuthorizationCode`. No other grant issues an access token for an end user, so a host
without it has nothing to answer here — and the metadata and the route never disagree.

## Presenting the access token

| How | Where |
|---|---|
| `Authorization: Bearer {token}` | Any request (RFC 6750 §2.1) |
| `access_token={token}` form field | A `POST` with `Content-Type: application/x-www-form-urlencoded` (RFC 6750 §2.2) |

The URI query parameter of RFC 6750 §2.3 is **not** read. It is deprecated there, and it puts a
live credential into server logs, browser history, and `Referer` headers.

Presenting the token both ways in one request is `invalid_request`, and so is presenting it
malformed: a repeated `access_token` field, more than one `Authorization` header whatever scheme
they name, or a `Bearer` header with nothing after the scheme.

## Response

`200 OK`, `Content-Type: application/json`, `Cache-Control: no-store`. The body is a JSON object
carrying `sub` plus every claim the token's granted scopes and the client's
`AdditionalUserInfoClaims` unlock at userinfo:

```json
{
  "sub": "248289761001",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "email_verified": true
}
```

Claim values are written as the JSON types the host's `IClaimsProvider` built them as — a boolean
stays a boolean, an address stays an object. A claim the provider does not return is omitted
entirely, never written as `null` or an empty string (OpenID Connect Core §5.3.2).

Which claims each scope unlocks here is `ScopeDefinition.UserInfoClaims`; see
[Configuration](configuration.md) for the scope and client registration options.

## Errors

Errors are reported in the `WWW-Authenticate` header with no response body, as RFC 6750 §3
requires of a protected resource.

| Status | `error` | When |
|---|---|---|
| `401` | *(none)* | No access token was presented at all |
| `401` | `invalid_token` | The token is malformed, unsigned by this server, expired, not yet valid, addressed to another audience, or its client registration or subject is no longer served |
| `403` | `insufficient_scope` | The token is valid but was not granted the `openid` scope |
| `400` | `invalid_request` | The token was presented in more than one place |
| `500` | *(none)* | The host's `IClaimsProvider` failed |

One description covers every `invalid_token` cause. A caller that could tell them apart could probe
which keys, audiences, clients and subjects the server accepts.

## Validation performed

Every one of these must hold before any claim is resolved:

| Check | Source |
|---|---|
| Signature verifies against a key still published in the JWKS, under that key's own algorithm | RFC 9068 §4 |
| `typ` header is `at+jwt` or `application/at+jwt` | RFC 9068 §2.1, §4 |
| `iss` equals the configured issuer | RFC 9068 §4 |
| `aud` contains the issuer, as a string or an array entry | RFC 9068 §4, RFC 7519 §4.1.3 |
| `exp` is present and has not passed, allowing `ClockSkewTolerance` | RFC 9068 §2.2 |
| `nbf`, when present, has passed, allowing `ClockSkewTolerance` | RFC 7519 §4.1.5 |
| `sub` and `client_id` are present | RFC 9068 §2.2 |
| `scope` contains `openid` | OpenID Connect Core §5.3.1 |

The issuer is always an audience of an access token issued with `openid`, which is what lets
userinfo validate one as an ordinary resource server. See
[Token contents](../decisions/token-contents.md) for why.

Claims are then resolved **fresh** from the host's `IClaimsProvider` on every call — nothing is
read from a store or a cache. An access token is self-contained and keeps working until it expires
however the grant behind it ended, so asking the provider again is what bounds staleness: a subject
it no longer serves is refused here at the next call.

## CORS

The endpoint honours the server-wide `CorsOrigins` allowlist, shared with the discovery and JWKS
endpoints. Empty (the default) emits `Access-Control-Allow-Origin: *`; a non-empty list emits
`Vary: Origin` and echoes the matching allowlist entry.

Because a browser sending `Authorization: Bearer` triggers a CORS preflight, the endpoint answers
`OPTIONS` with `204 No Content` and:

| Header | Value |
|---|---|
| `Access-Control-Allow-Methods` | `GET, POST, OPTIONS` |
| `Access-Control-Allow-Headers` | `Authorization, Content-Type` |
| `Access-Control-Max-Age` | `3600` |

`Access-Control-Allow-Credentials` is never emitted. No endpoint here authenticates with a cookie,
and withholding it is what keeps the default wildcard origin safe.

## Related pages

- [Discovery endpoint](discovery-endpoint.md) — where `userinfo_endpoint` is published
- [Configuration](configuration.md) — `UserInfoEndpoint.Uri` and `CorsOrigins`
