# ADR 0001 — Endpoint Architecture Pattern

Status: Accepted   ·   Date: 2026-05-31   ·   Issue: #106, #156

## Decision

Protocol endpoints (discovery, JWKS, token, authorization, …) are each an `internal sealed`
class implementing a package-internal `IZeeKayDaEndpoint` (`ZeeKayDa.Auth.AspNetCore`), registered
in DI via `TryAddEnumerable`, and mapped by the public `MapZeeKayDaAuth()` extension, which
resolves and calls every registered `IZeeKayDaEndpoint`. Registration is `AddZeeKayDaAuth()` +
`MapZeeKayDaAuth()` — not `UseZeeKayDaAuth`, since these are routed endpoints, not middleware.

`ZeeKayDa.Auth` (core) has zero ASP.NET Core knowledge; `ZeeKayDa.Auth.AspNetCore` depends on
it, never the reverse. Dependencies are governed by a namespace allowlist: all of
`Microsoft.Extensions.*` is permitted (host-agnostic, no transitive ASP.NET Core dependency);
`Microsoft.AspNetCore.*` is prohibited except an explicit, individually-justified whitelist
(currently `Microsoft.AspNetCore.DataProtection.Abstractions`, which is host-agnostic despite its
name). Any addition to the whitelist requires its own ADR justification.

`AuthorizationServerOptions` (configuration) is never serialized directly. `IDiscoveryDocumentProvider`
maps it to `OpenIdConfigurationDocument` (the OIDC Discovery 1.0 wire model), keeping the two free
to evolve independently. Endpoint URIs (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, …)
default to values derived from `AuthorizationServerOptions.Issuer` via `Uri` combination (never
string concatenation), and can be overridden individually. The discovery endpoint's own
registration path is likewise derived from the issuer's path component (not hardcoded to
`/.well-known/openid-configuration`), per [OIDC Discovery 1.0 §4.1](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest) —
required for RFC 9207 mix-up-attack resistance in multi-tenant (path-based issuer) deployments.

An `IValidateOptions<AuthorizationServerOptions>` (in `ZeeKayDa.Auth`, `ValidateOnStart()`-triggered
from `AddZeeKayDaAuth()`) fails fast at startup if `Issuer` is missing, not an absolute URI, carries
a query/fragment, or is non-HTTPS (unless `AllowInsecureIssuer = true`, intended only for loopback
dev/test). `MapZeeKayDaAuth()` also eagerly reads `IOptions<AuthorizationServerOptions>.Value` so
an invalid issuer fails the same way at map time as at startup. The discovery endpoint resolves
`IOptions<T>` (singleton, not snapshot/monitor) at response time, since the issuer is treated as
immutable after startup — changing it at runtime invalidates every outstanding token and RP
registration, effectively standing up a new server. Its `Cache-Control` header is set directly in
the endpoint handler, not via middleware or an output-caching policy.

## Why

- `IZeeKayDaEndpoint` is `internal`, not public: a public interface would let consumers inject
  arbitrary routes into the protocol surface, bypassing framework invariants, and lock a
  low-level shape into the public contract. Customisation is via options and dedicated service
  interfaces instead.
- `MapZeeKayDaAuth`, not `UseZeeKayDaAuth`: `Use*` is ASP.NET Core's convention for middleware;
  these are endpoint routes, and naming them `Use*` would mislead consumers about ordering and
  pipeline semantics.
- A catch-all middleware dispatching on `HttpContext.Request.Path` was rejected: it forfeits
  endpoint-routing features (authorization policies, rate limiting, OpenAPI metadata, endpoint
  diagnostics) for no benefit.
- Serializing `AuthorizationServerOptions` directly was rejected: it would couple an internal,
  freely-refactorable configuration class to a spec-mandated wire contract.
- Rejecting path-based issuers outright (instead of deriving the discovery path dynamically) was
  simpler but would silently break a legitimate multi-tenant deployment pattern for no technical
  reason — the spec permits it, so the framework supports it correctly instead.
- Output-caching middleware for the discovery `Cache-Control` header was rejected: it makes the
  header depend on the consumer having registered output caching, and is subject to the
  consumer's global caching policy rather than being unit-testable in isolation.

## Consequences

The endpoint set is only discoverable by searching for `IZeeKayDaEndpoint` implementations, not
from one call site — acceptable because the set is `internal`, finite, and auditable.
`AllowInsecureIssuer` is a documented development-only escape hatch, not a guarantee the hosting
environment is safe. Runtime issuer reconfiguration is unsupported by design; revisiting that
requires a new ADR.
