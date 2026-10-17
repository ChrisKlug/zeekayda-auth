# Logout, discovery and JWKS, explained

Explains the end-session half of `interaction-and-session.md`, the discovery half of
`configuration-and-discovery.md`, and the JWKS endpoint from `endpoints.md`. Key rotation behind
JWKS is in `signing-keys.md`; principles that apply beyond this part are in `principles.md`.

## Logout

**`/connect/endsession`** (OIDC RP-Initiated Logout 1.0) takes the request by GET or POST:

- `id_token_hint` proves which client and user are asking. It must be an ID token this server
  signed; expiry is not checked, since a client sends the one it got at sign-in. If `client_id` is
  sent too, they must agree.
- `post_logout_redirect_uri` is used only if it is registered for that client, exact match, or the
  endpoint would be an open redirect, and never after a hint that failed: §4 forbids redirecting
  after an error in the request. `state` is echoed, up to 2048 characters.
- With no session, the user is signed out at once. Otherwise the user is **asked**, because any page
  can trigger a logout with a link, unless the hint is valid, the client set
  `SkipLogoutConfirmation`, and the hint names the user who is signed in.
- A request that cannot be stored to ask about does not sign anyone out: fail closed.

**Confirming** (`LogoutInteraction`) follows the sign-in pages' pattern: the request is stored and
reached through `zkd_i` plus a binding cookie, read for rendering, and completed by a POST-only
terminal call. The host's `LogoutPath` page is used, or a minimal built-in one. The confirmation is
bound to the session it asked about, so a user who signed in again since cannot be signed out by
it, nor shown the old subject. The client and redirect are checked again at confirm time.

**Signing out** deletes the session cookie only when the request carries it; the cookie is
`SameSite=Lax`, so a cross-site POST cannot end a session. It also deletes every interaction
binding in the browser, tombstones included, so no half-finished sign-in in another tab survives. The
browser goes to the registered redirect with `state`, or `SignedOutPath`, or a built-in page.

## Discovery

The same document is served at the OIDC path (`{issuer}/.well-known/openid-configuration`), the
RFC 8414 path, and the RFC 8414 name appended to the issuer for proxies that forward only the
issuer's path. It is built from live configuration on every request: scopes and their claims from
the scope catalogue (hidden scopes left out), auth methods from the registered authenticators, the
signing algorithm from the key ring. Without the code grant, everything describing the
authorization endpoint is omitted. `authorization_response_iss_parameter_supported` is published,
since RFC 9207 reads an omitted value as false and a client might skip the `iss` check.

Clients cache it for `CacheMaxAge`; a failed build is a 500 without a cache header, so an error is
never cached. The provider is internal, so the document cannot be replaced with one advertising what
the server does not do.

## JWKS

`/connect/jwks` publishes the ring's published keys, public halves only. The body is built once per
key-set snapshot and reused until the ring refreshes. An empty set is served `no-store`, so no
relying party caches "no keys" past the moment signing resumes. The ring's lead time is never
shorter than `CacheMaxAge` plus its refresh interval, so a new key reaches every cache before it
signs.

## What it costs

- Logout tells no other client: no front- or back-channel logout, and no server-side session to
  drive it (#103, #955).
- A sign-out kills every in-flight sign-in in that browser, and the other tab lands on the error page.
- Discovery reads the whole scope catalogue on every request (#956).

## What the walkthrough changed

The maintainer walked this part at code level. On the branch: discovery advertises
`authorization_response_iss_parameter_supported`. Kept as is: sign-out deleting every interaction
binding, judged too rare a case to soften. Recorded on #956: discovery is another caller of the
scope repository a cache would cover.

## What was rejected

- **A "discoverable only" scope query.** The other callers need the whole catalogue, catalogues are
  small, and the cost is the round trip, which a cache addresses.
