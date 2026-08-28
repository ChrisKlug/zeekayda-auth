# Endpoints

How protocol endpoints are hosted, and the issuer/URI hygiene every one of them inherits. Options
shape and the discovery document's contents are `configuration-and-discovery.md`; the authorization
endpoint's interaction flow is `authorization-and-interaction.md`.

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
rejects a cross-authority `AuthorizationEndpoint.Uri`, `TokenEndpoint.Uri` or `JwksEndpoint.Uri`
outright rather than gating it behind an opt-in — metadata integrity is the whole point of the
issuer, and no deployment has yet needed the hole. It also rejects a non-canonical issuer
(uppercase scheme or host, an explicit default port) and names the canonical replacement in the
error. A query component is permitted on the authorization endpoint URI, because RFC 6749 §3.1
allows one there; it is rejected on the token and JWKS URIs, and a fragment is rejected everywhere.

**Endpoint URIs are derived from the issuer by `Uri` combination, never string concatenation**, and
each can be overridden individually. Every mapped route additionally constrains the request host to
the issuer's, so a route reachable on a second binding cannot answer as this issuer.

**The discovery route is derived from the issuer's path component, not hardcoded.** A path-based
issuer publishes at `/tenant1/.well-known/openid-configuration` (OIDC Discovery 1.0 §4.1). Rejecting
path-based issuers would have been simpler but silently breaks a spec-permitted multi-tenant
pattern, and path-based issuers are what RFC 9207 mix-up resistance relies on in those deployments.

**Map-time and startup-time issuer errors are the same error.** `MapZeeKayDaAuth()` eagerly reads
`IOptions<AuthorizationServerOptions>.Value`, so a bad issuer surfaces the validator's
`OptionsValidationException` at map time exactly as `ValidateOnStart()` surfaces it.

**The issuer is immutable after startup.** Endpoints resolve `IOptions<T>`, never
`IOptionsSnapshot`/`IOptionsMonitor`. Changing an issuer at runtime invalidates every outstanding
token and relying-party registration — that is standing up a new server, not reconfiguring one.

**Discovery's and JWKS's `Cache-Control` is written in the handler, not by middleware or an
output-caching policy.** A policy would make the header depend on the host having registered output
caching and subject it to the host's global caching rules, and it would stop being unit-testable in
isolation.

**An advertised-but-unbuilt endpoint answers `501`, not `404`.** Routes are mapped and shaped
before their implementations land so discovery is stable and the route surface does not shift.
The token route answers `501` today. The authorization endpoint validates requests (#83) and
answers `501` only once validation has passed, until interaction and code issuance land. The JWKS
endpoint is implemented.

**The JWKS response is derived lazily from the ring's current key set, keyed by reference
equality — not maintained by an observer.** Under the read-once ring the body is fixed for the
process lifetime anyway, and lazy derivation stays correct if a future ring swaps its set at
runtime, with no observer wiring to keep in sync. The body is served as
`application/jwk-set+json`, the RFC 7517 §8.5.1 registered media type.

## Tried, didn't work

Nothing reversed here yet.
