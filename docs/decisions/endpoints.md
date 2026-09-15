# Endpoints

How protocol endpoints are hosted, and the issuer/URI hygiene every one of them inherits. Options
shape and the discovery document's contents are `configuration-and-discovery.md`; the authorization
endpoint's interaction flow is `authorization-and-interaction.md` and `interaction-and-session.md`.

## Decisions in force

**`MapZeeKayDaAuth()`, never `UseZeeKayDaAuth()`.** These are routed endpoints, not middleware.
`Use*` is ASP.NET Core's convention for the pipeline and would mislead a host about ordering and
short-circuit semantics. Routing also keeps authorization policies, rate limiting, OpenAPI metadata
and endpoint diagnostics available, which a catch-all middleware dispatching on `Request.Path`
would forfeit.

**The endpoint set is closed.** `IZeeKayDaEndpoint` is `internal` to `ZeeKayDa.Auth.AspNetCore`,
each implementation is `internal sealed`, and `MapZeeKayDaAuth()` maps whatever DI enumeration
returns. A public version would let a host inject arbitrary routes into the protocol surface,
bypassing framework invariants, and would freeze a low-level shape into the SemVer contract.
Customisation is options plus the named service seams in `extension-surface.md`. Registration is
`TryAddEnumerable`, so a repeated `AddZeeKayDaAuth()` cannot double-map a route. The cost is that
the set is only discoverable by finding implementations rather than reading one call site —
acceptable while it is internal, finite and auditable.

**Core has zero ASP.NET Core knowledge, and the dependency never reverses.** `ZeeKayDa.Auth`
takes all of `Microsoft.Extensions.*` (host-agnostic, no transitive web stack) and exactly one
`Microsoft.AspNetCore.*` package: `Microsoft.AspNetCore.DataProtection.Abstractions`, which is
host-agnostic despite its name. Any further `Microsoft.AspNetCore.*` reference in core needs its
own justification. This is a review rule, not a build rule — nothing in CI enforces it.

**Every ZeeKayDa route is mapped into one group carrying two filters.** The first rejects any
request that is not HTTPS with `421 Misdirected Request`; the only exemption is a loopback remote
address *and* `AllowInsecureIssuer`, so plain HTTP on loopback is still refused by default. The
second writes the configured security headers, and advertises `X-ZeeKayDa-Insecure-Issuer: true`
whenever the insecure-issuer escape hatch is on. Grouping is what keeps both off the host's own
routes. `AllowInsecureIssuer` is a loopback development hatch, never an assertion that the
deployment is safe.

**Endpoint URIs must share the issuer's authority, and the issuer must be canonical.** Startup
rejects a cross-authority `AuthorizationEndpoint.Uri`, `TokenEndpoint.Uri`, `JwksEndpoint.Uri` or
`EndSessionEndpoint.Uri` outright rather than gating it behind an opt-in — metadata integrity is the whole point of the
issuer, and no deployment has yet needed the hole. It also rejects a non-canonical issuer
(uppercase scheme or host, an explicit default port) and names the canonical replacement in the
error, and it rejects any trailing slash, the root's included: the document publishes the issuer
verbatim, while RFC 8414 §3.1 strips the slash to build the metadata URL, so a client configured
without it would reject the document (§3.3). A query component is permitted on the authorization endpoint URI, because RFC 6749 §3.1
allows one there; it is rejected on the token, JWKS and end-session URIs, and a fragment is rejected everywhere.

**Endpoint URIs are derived from the issuer by `Uri` combination, never string concatenation**, and
each can be overridden individually. Every mapped route additionally constrains the request host to
the issuer's, so a route reachable on a second binding cannot answer as this issuer. The path must
match exactly too: routing matches literals case-insensitively and tolerates a trailing `/`, but a
URL path is case-sensitive (RFC 3986 §6.2.2.1), so `/TENANT1/connect/token` and
`/tenant1/connect/token/` are 404. A matcher policy decides it during route selection, ahead of the
HTTP-method policy, for every route on the framework's group: a wrong path is no route at all, never
a 405 or a 421. An endpoint filter was tried first and rejected — it runs after selection, so routing
answered 405 for an unmapped method and the HTTPS filter answered 421 before it could run.

**The discovery routes are derived from the issuer's path component, not hardcoded.** A path-based
issuer publishes at `/tenant1/.well-known/openid-configuration` (OIDC Discovery 1.0 §4.1, appended)
and at `/.well-known/oauth-authorization-server/tenant1` (RFC 8414 §3.1, inserted). The OAuth document
is also served at the appended `/tenant1/.well-known/oauth-authorization-server`, so a proxy forwarding
only the issuer's path prefix reaches both documents alike. Rejecting
path-based issuers would have been simpler but silently breaks a spec-permitted multi-tenant
pattern, and path-based issuers are what RFC 9207 mix-up resistance relies on in those deployments.

**Map-time and startup-time issuer errors are the same error.** `MapZeeKayDaAuth()` eagerly reads
`IOptions<AuthorizationServerOptions>.Value`, so a bad issuer surfaces the validator's
`OptionsValidationException` at map time exactly as `ValidateOnStart()` surfaces it.

**The issuer is immutable after startup.** Endpoints resolve `IOptions<T>`, never
`IOptionsSnapshot`/`IOptionsMonitor`. Changing an issuer at runtime invalidates every outstanding
token and relying-party registration — that is standing up a new server, not reconfiguring one.

**Every endpoint's `Cache-Control` is written in the handler, not by middleware or an
output-caching policy.** A policy would make the header depend on the host having registered output
caching and subject it to the host's global caching rules, and it would stop being unit-testable in
isolation. Token responses, success and error alike, carry `no-store` and `Pragma: no-cache` — RFC
6749 §5.1 asks for both, OAuth 2.1 keeps the first, and writing both satisfies either reading.

**The token endpoint is POST-only, mapped unconditionally, and refuses before it reads.** Discovery
publishes `token_endpoint` unconditionally because RFC 8414 §2 requires it, so the route is mapped
on the same condition — none — and metadata and route never disagree the way authorize's once did.
The form is parsed and every shape rule checked, then the server's own grant list consulted, then
the client authenticated, then its grant allowlist read, before any store is touched: a malformed
or unauthenticated request costs no I/O and consumes nothing, and a host that stopped serving the
code grant redeems no code that outlived the change. Only `application/x-www-form-urlencoded` is
read, and a body the form reader refuses is `invalid_request`, never the host's 500.
`invalid_client` is `401` with a `WWW-Authenticate` naming the scheme the client used when it sent
one `Authorization` header (§5.2 MUST) and `400` otherwise; the description never says whether the
client was unknown or the credential wrong. A server fault is `500` with `server_error`, and a
`GET` is `405`, not a protocol error. The route allows anonymous access, as the discovery, JWKS,
resume and provider-callback routes do, so a host's fallback authorization policy cannot pre-empt
client authentication.

**The end-session endpoint refuses nothing and asks by default.** GET and form POST alike; a
parameter that fails to validate is ignored, as RP-Initiated Logout §4 requires of an
`id_token_hint`, so a bad request lands the user on a confirmation or signed-out page, never an
error. The user is asked unless there is no session to end, or a valid hint names the signed-in
user and its client set `SkipLogoutConfirmation` (§2: asking is a SHOULD with a hint, a MUST
without). `post_logout_redirect_uri` is honoured only on an exact match against the registration of
the client the request resolves to — the hint's, else `client_id`'s — with `state` echoed, capped
at 2048 characters. A pending confirmation is an interaction like any other, `zkd_i` plus a binding
cookie, which is its CSRF protection. There is no cancel call: a sign-out has no error response.

**Every protocol endpoint is implemented; nothing answers `501` any more.** Routes were
mapped and shaped before their implementations landed so discovery stayed stable; the last stub,
the token route, is gone.

**The JWKS response is derived lazily from the ring's current key set, keyed by reference
equality — not maintained by an observer.** Under the read-once ring the body is fixed for the
process lifetime anyway, and lazy derivation stays correct if a future ring swaps its set at
runtime, with no observer wiring to keep in sync. The body is served as
`application/jwk-set+json`, the RFC 7517 §8.5.1 registered media type.

## Tried, didn't work

Nothing reversed here yet.
