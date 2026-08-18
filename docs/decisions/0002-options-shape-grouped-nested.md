# ADR 0002 — Options Shape: Grouped Nested Per-Endpoint Options

Status: Accepted   ·   Date: 2026-06-07   ·   Issue: #51, #337

## Decision

`AuthorizationServerOptions` is a **grouped nested** model: server-wide settings (`Issuer`,
`AllowInsecureIssuer`, `GrantTypesSupported`, …) stay on the root; per-endpoint settings move onto
strongly-typed, `sealed`, get-only nested option groups (`TokenEndpoint`, `AuthorizationEndpoint`,
`JwksEndpoint`, `IdToken`, `Response`, …), each default-initialised so it can never be nulled out.

```csharp
// Before: flat
public class AuthorizationServerOptions
{
    public Uri? Issuer { get; set; }
    public Uri? TokenEndpointUri { get; set; }
    public ICollection<TokenEndpointAuthMethod>? TokenEndpointAuthMethodsSupported { get; set; }
}

// After: grouped nested
public class AuthorizationServerOptions
{
    public Uri? Issuer { get; set; }
    public TokenEndpointOptions TokenEndpoint { get; } = new(); // get-only: can't be nulled out
}

public sealed class TokenEndpointOptions
{
    public Uri? Uri { get; set; }
    public ICollection<TokenEndpointAuthMethod>? AuthMethodsSupported { get; set; }
}
```

A settable group (`{ get; set; }`) would let a consumer assign `null` and drop the framework's
defaults for that whole endpoint; `{ get; }` with eager initialisation makes that state
unrepresentable.

**Grouping rule (mechanical, spec-driven):** a property groups with any other property whose
discovery-document key shares a spec-defined prefix — an endpoint name (`token_endpoint_*`), an
artifact name (`id_token_*`), or a response-shape name (`response_*`). Groups named after an HTTP
endpoint carry an `Endpoint` suffix (`TokenEndpoint`); groups that don't (`IdToken`, `Response`)
don't. A property with no shared prefix stays on the root. Endpoint-affinity is a permitted
secondary criterion: a property may join an endpoint's group when the *spec text itself* names it
as a modifier of that endpoint (e.g. RFC 7636's `code_challenge_*` parameters live in
`AuthorizationEndpoint`, not on the root, even though no other `code_challenge_*` field exists to
form a group with) — this must be spec-mandated, never a judgement call. `JwksEndpoint` exists as
a group (holding just `Uri` today) purely for forward compatibility, since the JWKS endpoint will
plausibly grow policy fields (e.g. cache `max-age`) with no discovery-key analogue.

A second, explicitly recognised category — **framework-behavior groups** (e.g. `SecurityHeaders`)
— covers settings with no discovery-document counterpart at all, governing the framework's own
runtime behaviour. These are permitted outside the spec-prefix rule provided the name is plain
descriptive English and never carries an `Endpoint` suffix.

**Scope limit:** this grouping rule places *discovery-shaped configuration* only. A
feature-registration escape hatch or safety gate that is inert unless some other opt-in feature
was also registered (a signing-key provider, an in-memory store, etc.) is not a discovery-metadata
property, and this rule does not license hoisting it onto the shared root by default — it
co-locates with the feature that introduces it (see ADR 0011).

The `AuthorizationServerOptionsValidator` (`ZeeKayDa.Auth/Configuration/`) stays a single,
root-rooted `IValidateOptions<AuthorizationServerOptions>` — not one validator per group — because
many real rules are cross-group (e.g. `client_credentials` in `GrantTypesSupported` requires
`TokenEndpoint.AuthMethodsSupported` to contain at least one non-`none` method). It is a pure
read-only check: CORS-origin canonicalization runs earlier, in an
`IPostConfigureOptions<AuthorizationServerOptions>`; the async `IScopeRepository` presence check
runs in a separate `IHostedService`, since blocking on async I/O inside `Validate` risks deadlocks.

`TokenEndpoint.AuthMethodsSupported` was originally a `TokenEndpointAuthMethod` enum; ADR 0007
changed it to `ICollection<string>` (an open, ordinal vocabulary validated as authenticator
coverage rather than a closed advertised set) — ADR 0007 is authoritative for that shape.

`ZeeKayDaAuthBuilder` (from `AddZeeKayDaAuth`) remains the *service-registration* surface (stores,
signing keys, DI-shaped extension points); options *data* never moves onto it. Per-endpoint
*behaviour* customisation (as opposed to configuration) still goes through narrow, DI-resolved,
single-purpose interfaces, not through a public `IZeeKayDaEndpoint` — see ADR 0001.

> ⚠️ **Warning:** `none` may legitimately appear in `TokenEndpoint.AuthMethodsSupported` alongside
> other methods, to support public clients. This is safe only if the token endpoint enforces
> `token_endpoint_auth_method` **per registered client** at request time — without that, a
> confidential client could authenticate as a public client by omitting credentials (an auth
> method downgrade). Per-client enforcement is a hard prerequisite for the token endpoint, not an
> optional hardening step; no opt-in flag substitutes for it.

## Why

- A flat options class does not scale to the ~70 metadata fields the full OIDC + RFC 8414 +
  extension surface eventually defines; IntelliSense collapses and cross-endpoint invariants have
  no home. Reshaping now, pre-1.0, is a small breaking change; reshaping later would not be.
- **Builder extensions per endpoint** (`.WithTokenEndpointConfiguration(...)`) were rejected: they
  split configuration across two surfaces, don't bind from `IConfiguration`, break
  `IOptionsSnapshot`/`IPostConfigureOptions` composition, and are invisible to a single validator.
- **A generic third-party endpoint bag** (`options.Endpoints["foo"]`) was rejected: every endpoint
  ZeeKayDa.Auth hosts is already named by a spec, so there is no need to support arbitrary
  unnamed endpoints; a string/type-keyed bag is also untyped, defeating the whole point of the
  grouped shape, and is really a *behaviour*-extension point in disguise — which reopens ADR
  0001's closed question about public endpoint injection.
- **An ASP.NET-`Events`-style callback surface** was considered and deferred, not adopted: an
  identity provider's extension points are replaceable services (issuers, validators, claim
  transformers), not client-side lifecycle notifications; observability needs are served by
  `ILogger`/`ActivitySource`/`Meter` instead.

## Consequences

Every consumer updates property paths (`options.TokenEndpoint` → `options.TokenEndpoint.Uri`,
etc.) — a one-time, pre-1.0 breaking change. `IConfiguration` key paths change accordingly
(`ZeeKayDaAuth:TokenEndpoint:*`); an operator who sets only one entry of a collection key loses the
rest of the defaults, since binding replaces rather than merges collections — the validator's
empty-collection checks catch the resulting gap. The root validator carries all cross-group rules,
so it grows over time but stays the single place to read and audit.
