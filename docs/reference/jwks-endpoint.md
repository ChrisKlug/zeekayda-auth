---
title: "JWKS endpoint"
description: "Reference for the JSON Web Key Set endpoint exposed by ZeeKayDa.Auth."
parent: "Reference"
nav_order: 8
---

*Added in Unreleased.*

ZeeKayDa.Auth publishes the signing keys relying parties need to validate token signatures as a
JSON Web Key Set, as defined by
[RFC 7517 Section 5](https://www.rfc-editor.org/rfc/rfc7517#section-5). The endpoint's URL is
published as `jwks_uri` in the [discovery document](discovery-endpoint.md).

## Endpoint URL

**Method:** `GET`

**Route:**

- Default: `{issuer}/connect/jwks`
- Override: the exact URI configured in `JwksEndpoint.Uri`

The route is constrained to the configured issuer host. A request for the same path on a different
host is not handled by ZeeKayDa.Auth. Requests over HTTP are rejected at request time with
`421 Misdirected Request`; loopback HTTP is permitted only when `AllowInsecureIssuer` is enabled.
The endpoint requires no authentication — the key set is public by design and contains only public
key material — and it opts out of any host-wide authorization fallback policy so it stays readable
in hardened hosts.

Examples:

- Issuer: `https://id.example.com`  
  JWKS URL: `https://id.example.com/connect/jwks`
- Issuer: `https://id.example.com/tenant-a`  
  JWKS URL: `https://id.example.com/tenant-a/connect/jwks`

## Response

The response is the signing key ring's published key set — every configured slot
(`Previous`/`Current`/`Next`), in that order. Only the `Current` slot's key ever signs; `Previous`
and `Next` appear so relying parties can validate tokens signed before a rotation and pre-fetch the
key that signs after the next one.

Each JWK carries exactly these members:

| Member | Value |
|---|---|
| `kid` | The [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) SHA-256 thumbprint of the key's public material — the same `kid` issued tokens carry in their JOSE header |
| `kty` | `RSA` or `EC` |
| `use` | `sig` |
| `alg` | The key's [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) algorithm identifier (`RS256`, `ES256`, …) |
| `n`, `e` | RSA keys: modulus and exponent, minimally encoded per RFC 7518 §6.3.1.1 |
| `crv`, `x`, `y` | EC keys: curve name and point coordinates per RFC 7518 §6.2.1 |

No private key component is ever present, and the response is byte-identical across requests for
as long as the configured key set is unchanged.

Example:

```json
{
  "keys": [
    {
      "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nnd...",
      "e": "AQAB"
    }
  ]
}
```

## Response headers

| Header | Value |
|---|---|
| `Content-Type` | `application/jwk-set+json` |
| `Cache-Control` | `public, max-age=3600, must-revalidate` by default; `no-store` when `JwksEndpoint.CacheMaxAge` is below one second |
| `Access-Control-Allow-Origin` | `*` when `JwksEndpoint.CorsOrigins` is empty; the matching allowlist entry (plus `Vary: Origin`) otherwise |

`JwksEndpoint.CacheMaxAge` governs how long a relying party may keep trusting a cached key set —
including a key that has since been removed from configuration. See
[`JwksEndpoint`](configuration.md#jwksendpoint) for the configuration details.
