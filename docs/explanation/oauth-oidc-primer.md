---
title: "OAuth 2.0 & OpenID Connect Primer"
description: "Why OAuth 2.0 and OpenID Connect exist, the problems they solve, and how they relate to each other"
parent: Explanation
nav_order: 1
---

# OAuth 2.0 & OpenID Connect Primer

*This page covers conceptual background. For setup steps, see [Configure discovery](../how-to/configure-discovery.md).
For precise endpoint details, see the [Reference](../reference/).*

---

## The problem: credentials are the wrong tool for delegation

Before OAuth, delegating access to a third party typically meant sharing a username and password.
A user who wanted a calendar app to read their email had to hand over their email credentials
entirely. That created serious problems:

- the third-party app gained *more* access than the user intended
- the user could not revoke access to the app without changing their password
- the service holding the data had no way to tell which requests came from the real user and which
  came from the app

OAuth 2.0 was designed to solve exactly this. It separates **authentication** (proving who you are)
from **authorisation** (granting access to resources), and introduces a third party — the
*authorisation server* — to issue scoped, revocable access tokens on behalf of the user.

---

## OAuth 2.0: authorisation, not authentication

[RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) defines OAuth 2.0 as an *authorisation
framework*. Its core job is to let a *resource owner* (typically a user) grant a *client*
application limited access to a *resource server* — without sharing credentials.

The four roles defined by RFC 6749:

| Role | Responsibility |
|---|---|
| **Resource owner** | The entity granting access (usually the end-user) |
| **Client** | The application requesting access on behalf of the resource owner |
| **Resource server** | The API or service holding the protected resources |
| **Authorisation server** | Issues access tokens after authenticating the resource owner and obtaining authorisation |

ZeeKayDa.Auth implements the **authorisation server** role.

### The authorisation code flow

The most important OAuth 2.0 grant is the *authorisation code* flow
([RFC 6749 Section 4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)). In brief:

1. The client redirects the user's browser to the authorisation endpoint.
2. The user authenticates and grants (or denies) the request.
3. The authorisation server redirects back to the client with a short-lived *authorisation code*.
4. The client exchanges the code at the token endpoint for an *access token* (and optionally a
   *refresh token*).
5. The client uses the access token to call the resource server.

The authorisation code is single-use and short-lived. Access tokens are separate from credentials
and carry only the scope the user consented to.

> 💡 **Tip:** Modern deployments always combine the authorisation code flow with PKCE
> ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) to protect against authorisation code
> interception, even for confidential clients.
> [RFC 9700 Section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) recommends PKCE
> for all clients.

---

## The gap OAuth 2.0 leaves: who is the user?

OAuth 2.0 access tokens tell a resource server *what* the client is allowed to do. They do not
reliably tell the client *who* the user is.

Different authorisation servers used different conventions for returning user identity, which made
interoperability impossible. An application built against one server could not be ported to another
without custom integration work.

OpenID Connect fills that gap.

---

## OpenID Connect: authentication built on top of OAuth 2.0

[OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) is an identity
layer built directly on top of OAuth 2.0. It adds a standard way for the authorisation server to
return a verified identity assertion — the *ID token* — alongside or instead of an access token.

The key addition is the **ID token**: a [JSON Web Token (RFC 7519)](https://www.rfc-editor.org/rfc/rfc7519)
that the authorisation server signs and the client can verify. It contains *claims* — assertions
about the authenticated user — such as:

| Claim | Meaning |
|---|---|
| `sub` | Subject identifier — a stable, unique identifier for the user at this issuer |
| `iss` | Issuer — the URL of the authorisation server that issued the token |
| `aud` | Audience — the client(s) the token is intended for |
| `exp` | Expiry time |
| `iat` | Issued-at time |

With these, a client can verify that the token came from the expected server, was issued for this
specific client, has not expired, and identifies a particular user.

### OIDC and OAuth 2.0 are not separate things

A common misconception is that OIDC and OAuth 2.0 are alternatives. They are not.
OpenID Connect *extends* the OAuth 2.0 authorisation code flow:

- OIDC uses the same authorisation endpoint and token endpoint
- OIDC adds the `openid` scope to signal that identity information is requested
- The token endpoint response carries an additional `id_token` field
- OIDC defines the [UserInfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
  for fetching additional claims

ZeeKayDa.Auth implements an OIDC-compliant authorisation server. When a client requests the
`openid` scope, the token response includes a signed ID token.

---

## Discovery: making authorisation servers self-describing

Hard-coding endpoint URLs — authorisation endpoint, token endpoint, JWKS endpoint — creates
fragile integrations. If any URL changes, every client must be updated.

[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) solves
this by defining a standard metadata document — the *discovery document* — that clients can fetch
from a well-known URL:

```text
{issuer}/.well-known/openid-configuration
```

The document tells clients everything they need: where endpoints are, which grant types and signing
algorithms the server supports, and which scopes are available. This is the contract that
ZeeKayDa.Auth publishes.

For more detail on how ZeeKayDa.Auth implements discovery, read
[Why discovery matters](why-discovery.md).

---

## Further reading

| Resource | Description |
|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) | OAuth 2.0 — the authorisation framework |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) | OIDC — identity on top of OAuth 2.0 |
| [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Server metadata and discovery |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | PKCE — protecting the authorisation code flow |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | OAuth 2.0 Security Best Current Practice |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | OAuth 2.0 Authorization Server Metadata |
