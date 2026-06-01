# ADR 0002 — Options Shape: Grouped Nested Per-Endpoint Options on `AuthorizationServerOptions`

**Status:** Proposed  
**Date:** 2026-06-07

---

## Context

`AuthorizationServerOptions` (in `ZeeKayDa.Auth`) is the single configuration class consumers
populate via `AddZeeKayDaAuth(options => { … })`. Today it is a **flat** class: issuer settings,
endpoint URI overrides, supported-values collections, and per-endpoint policy knobs all sit at the
same level. With only the discovery surface implemented, the class is already approaching twenty
properties (see `src/ZeeKayDa.Auth/AuthorizationServerOptions.cs`). The remaining endpoints —
authorization, token, userinfo, introspection, revocation, registration, end-session, device
authorization — each contribute their own family of metadata fields per
[OIDC Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
and [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414#section-2). A flat class will not
scale: discoverability collapses, IntelliSense becomes unusable, and grouping invariants (e.g.
"the token endpoint's supported client auth methods and its supported signing algorithms must be
consistent") have no natural home.

Crucially, the discovery specs **already group their fields by endpoint**: every metadata key whose
name begins with an endpoint prefix (`token_endpoint_*`, `userinfo_*`, `revocation_endpoint_*`, …)
describes that endpoint. The wire format does not nest — it remains a flat JSON object — but the
spec's *naming convention* is itself the grouping rule.

ADR 0001 already established the separation between the configuration model
(`AuthorizationServerOptions`) and the wire model (`OpenIdConfigurationDocument`). The wire model
is a stable, spec-mandated contract and is unaffected by this ADR: only the shape of the internal
configuration class changes. `IDiscoveryDocumentProvider` continues to be the single mapping seam
between the two.

ADR 0001 also closed the question of whether `IZeeKayDaEndpoint` should be public (it is
`internal`, intentionally, to prevent consumers from injecting arbitrary routes into the protocol
surface — see #43). This ADR does not reopen that question. Customisation remains expressed through
options and dedicated, typed service abstractions, never through endpoint replacement.

The framework is pre-1.0; reshaping the options class now is a small, contained breaking change.
After 1.0 it would not be.

---

## Decision

`AuthorizationServerOptions` is reshaped into a **grouped nested** model: server-wide settings stay
on the root class; per-endpoint settings move onto strongly-typed nested option groups exposed as
get-only properties on the root.

### 1. Grouping rule (spec-driven, not opinion-driven)

A property belongs in a group **if and only if** its corresponding discovery metadata key shares a
spec-defined name prefix with one or more other properties. The prefix may be an **endpoint name**
(`token_endpoint_*`, `userinfo_*`), an **artifact name** (`id_token_*`), or a **response-shape
name** (`response_*`). Whatever the spec calls the prefix, that becomes the group name; everything
else stays on the root.

| Discovery key prefix | Group |
|---|---|
| `authorization_endpoint`, `request_parameter_supported`, `request_uri_parameter_supported`, `require_request_uri_registration`, `request_object_signing_alg_values_supported`, … | `Authorization` |
| `token_endpoint`, `token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported`, … | `Token` |
| `jwks_uri` (plus future JWKS-endpoint policy such as response cache-control) | `Jwks` |
| `userinfo_endpoint`, `userinfo_signing_alg_values_supported`, `userinfo_encryption_alg_values_supported`, … | `UserInfo` |
| `revocation_endpoint`, `revocation_endpoint_auth_methods_supported`, … | `Revocation` |
| `introspection_endpoint`, `introspection_endpoint_auth_methods_supported`, … | `Introspection` |
| `registration_endpoint` | `Registration` |
| `end_session_endpoint` (OIDC Session Management / RP-Initiated Logout) | `EndSession` |
| `device_authorization_endpoint` (RFC 8628) | `DeviceAuthorization` |
| `id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`, `id_token_encryption_enc_values_supported` | `IdToken` |
| `response_types_supported`, `response_modes_supported` | `Response` |
| `issuer`, `scopes_supported`, `grant_types_supported`, `subject_types_supported`, `claims_supported`, … (no shared spec prefix) | root |

The rule is mechanical: pick any property, look at its discovery key, find the prefix, that's the
group. If no other current or near-future spec field shares the prefix, the property lives on the
root.

**Why the rule extends beyond endpoint prefixes.** Restricting grouping to endpoint names was the
strictest possible reading of the spec; extending it to any shared spec prefix is the *consistent*
reading. The DX wins are real (`options.IdToken.SigningAlgValuesSupported`,
`options.Response.TypesSupported`) and the rule remains mechanical — there is no judgement call
about whether two properties are "conceptually related," only whether the spec prefixes them with
the same word. Cosmetic groupings invented without a spec prefix (e.g. lumping unrelated
server-wide flags into a "General" bag) are still prohibited.

`jwks_uri` is grouped under `Jwks` even though the spec defines no other `jwks_*_supported`
metadata fields today. The reason is forward-looking: the JWKS endpoint will almost certainly grow
endpoint-policy configuration that has no discovery analogue — most obviously a response
`Cache-Control` `max-age` value (as `Discovery` already has). Placing `Uri` on the root and then
moving it into a `Jwks` group later would be a second breaking change for no benefit. The same
forward-looking argument does not apply to keeping any other URI on the root, because every other
endpoint already has spec-defined per-endpoint metadata.

### 2. Per-endpoint properties migration table (initial cut)

Concrete moves required by this ADR for the surface that exists today:

| Today (flat) | After (grouped) |
|---|---|
| `Issuer` | `Issuer` (unchanged) |
| `AllowInsecureIssuer` | `AllowInsecureIssuer` (unchanged — server-wide; gates all endpoint URI schemes) |
| `JwksUri` | `Jwks.Uri` |
| `ResponseTypesSupported` | `Response.TypesSupported` |
| `ResponseModesSupported` | `Response.ModesSupported` |
| `GrantTypesSupported` | `GrantTypesSupported` (unchanged — no shared spec prefix) |
| `IdTokenSigningAlgValuesSupported` | `IdToken.SigningAlgValuesSupported` |
| `DiscoveryDocumentCacheMaxAgeSeconds` | `Discovery.CacheMaxAgeSeconds` (per-endpoint policy) |
| `AuthorizationEndpoint` | `Authorization.Uri` |
| `TokenEndpoint` | `Token.Uri` |
| `TokenEndpointAuthMethodsSupported` | `Token.AuthMethodsSupported` |

Future endpoints, artifacts, or response-shape fields add their own groups under the same rule.

### 3. Group classes: `sealed`, get-only, default-initialised

Each group is a `sealed` class. It is exposed on `AuthorizationServerOptions` as a **get-only**
property initialised to a default instance:

```csharp
public sealed class AuthorizationServerOptions
{
    public string? Issuer { get; set; }
    public bool AllowInsecureIssuer { get; set; }

    public ICollection<GrantType> GrantTypesSupported { get; set; } = [GrantType.AuthorizationCode];
    // … other root-level collections that have no shared spec prefix …

    public DiscoveryOptions     Discovery     { get; } = new();
    public AuthorizationOptions Authorization { get; } = new();
    public TokenOptions         Token         { get; } = new();
    public JwksOptions          Jwks          { get; } = new();
    public IdTokenOptions       IdToken       { get; } = new();
    public ResponseOptions      Response      { get; } = new();
}

public sealed class TokenOptions
{
    public string? Uri { get; set; }
    public ICollection<TokenEndpointAuthMethod> AuthMethodsSupported { get; set; } =
        [TokenEndpointAuthMethod.ClientSecretBasic];
}

public sealed class JwksOptions
{
    public string? Uri { get; set; }
}

public sealed class IdTokenOptions
{
    public ICollection<SigningAlgorithm> SigningAlgValuesSupported { get; set; } =
        [SigningAlgorithm.RS256];
}

public sealed class ResponseOptions
{
    public ICollection<ResponseType> TypesSupported { get; set; } = [ResponseType.Code];
    public ICollection<ResponseMode> ModesSupported { get; set; } = [ResponseMode.Query];
}
```

The groups are **never** `{ get; set; }`. A settable group property would let a consumer write
`options.Token = new()` and silently null-out every default the framework relies on, including any
defaults a future security-sensitive field acquires. Get-only with a default instance means
consumers may mutate members of a group, but the group itself — and the framework's invariants on
it — cannot be replaced or nulled.

Groups are `sealed` for the same reason `AuthorizationServerOptions` is sealed: inheritance is not
an extension model the framework supports, and sealing keeps the binary shape predictable for
future serialisation/`IConfiguration` binding.

### 4. Validator stays single-rooted

The validator remains a single `IValidateOptions<AuthorizationServerOptions>` (today:
`AuthorizationServerOptionsValidator` in `ZeeKayDa.Auth/Configuration/`) that reaches into the
groups:

```csharp
if (options.Token.AuthMethodsSupported is null) …
if (options.Authorization.Uri is { } ae && /* … */) …
```

We deliberately do **not** introduce per-group `IValidateOptions<TokenOptions>` etc. The reasons:

- Many real validation rules are **cross-group** (e.g. "if `client_credentials` is in
  `GrantTypesSupported`, then `Token.AuthMethodsSupported` must contain at least one non-`none`
  method"). Cross-group rules have no natural home in a per-group validator and would force
  duplication or arbitrary placement.
- A single root validator gives one fail-fast surface — one place to read, one place to extend, one
  place the security agent can audit.
- Group validation can still be factored internally into private helper methods per group for
  readability; that is an implementation detail, not part of the contract.

### 5. `ZeeKayDaAuthBuilder` role unchanged

`ZeeKayDaAuthBuilder` (returned by `AddZeeKayDaAuth`) continues to be the **service-registration**
surface — stores, signing keys, and other DI-shaped extension points. Options *data* does not move
onto the builder. This preserves the clean separation:

- **What the server is configured with** → `AuthorizationServerOptions` (data, bindable from
  `IConfiguration`, validatable, snapshotable).
- **What the server is composed of** → `ZeeKayDaAuthBuilder` (DI registrations, replaceable
  services).

Mixing the two would mean some settings could be bound from `appsettings.json` and others could
not, with no principled rule for which goes where.

### 6. Endpoint surface remains internal (cross-ref ADR 0001 / #43)

This ADR explicitly does **not** open `IZeeKayDaEndpoint` or introduce any new public extension
interface for endpoint behaviour. Per-endpoint *configuration* is now strongly grouped; per-endpoint
*behaviour* customisation, when needed, will be added through narrow, typed, DI-resolved
single-purpose interfaces in subsequent ADRs as use-cases arise. The endpoint surface itself
remains closed.

---

## Rejected Alternatives

### Builder extensions per endpoint (`.WithTokenEndpointConfiguration(...)`)

**Rejected.** A fluent shape such as
`builder.WithTokenEndpointConfiguration(t => { t.AuthMethodsSupported = …; })` was considered. It
was rejected because:

- It splits configuration across two surfaces (`options =>` lambdas and builder calls), making it
  unclear where any given setting lives without IntelliSense exploration.
- It does not bind from `IConfiguration`, breaks `IOptionsSnapshot<T>`/`IPostConfigureOptions<T>`
  composition, and is invisible to a single-rooted validator.
- It conflates *data configuration* with *service composition* — exactly the separation §5 above
  preserves.
- It encourages a "one fluent method per setting" sprawl that scales worse than nested options, not
  better.

### Status quo — keep `AuthorizationServerOptions` flat

**Rejected.** A flat shape is fine for the eight properties that exist today; it is untenable for
the ~70 metadata fields the OIDC + RFC 8414 surface defines once authorization, token, userinfo,
introspection, revocation, registration, end-session, and device endpoints are implemented.
IntelliSense at the root would be useless, cross-endpoint invariants would be undiscoverable in
code, and naming collisions would force ever-longer property names (`TokenEndpointAuthMethodsSupported`,
`IntrospectionEndpointAuthMethodsSupported`, `RevocationEndpointAuthMethodsSupported`, …). Keeping
flat now and reshaping later — post-1.0 — would be a far larger breaking change for every consumer
than reshaping once, now, while there are none.

### Generic third-party endpoint bag (`options.Endpoints["foo"]` / `options.GetEndpointOptions<T>()`)

**Rejected.** A pattern where consumers register arbitrary `TOptions` keyed by string or type was
considered as a forward-compatibility hedge for spec-extension endpoints. It was rejected because:

- It is fundamentally a *behaviour* extension point in disguise — a string-keyed bag of options is
  only useful if there is also a way to register the *endpoint* that consumes it. That re-opens
  ADR 0001's closed question about public `IZeeKayDaEndpoint`.
- It is untyped at the binding boundary, defeating IntelliSense and `IConfiguration` binding —
  the two largest benefits of the grouped-nested shape.
- Every endpoint that ZeeKayDa.Auth implements is already named by a spec (OIDC, RFC 8414, RFC
  8628, RFC 7662, RFC 7009, RFC 7591, …). There is no "third-party endpoint" that the framework
  needs to host without a corresponding spec.
- If a future spec adds an endpoint, the cost of adding one more strongly-typed group is trivial;
  the cost of supporting an arbitrary bag in perpetuity is not.

### `WithEvents`-style ASP.NET-authentication-events surface

Briefly considered (raised during design discussion) and **deferred**, not adopted. The
`AuthenticationOptions.Events` pattern from `Microsoft.AspNetCore.Authentication.*` exists for
client-side handlers that need to customise specific lifecycle moments of an outbound auth flow. An
identity provider sits on the other side of the wire: its behaviour extension points are
fundamentally *replaceable services* (issuers, validators, claim transformers), not
*notification callbacks*. Observability concerns — what an `Events`-style API is most commonly
abused for — are properly served by `ILogger`, `ActivitySource`, and `Meter`, not by a parallel
callback surface. When behaviour extension is needed it will be exposed as typed, DI-resolved,
single-purpose interfaces. The full rationale belongs in a future events/extensibility ADR; it is
recorded here only so the option is not silently relitigated.

---

## Consequences

### Positive

- **Spec-aligned.** The grouping rule is mechanical and falls directly out of OIDC Discovery 1.0
  §3 and RFC 8414 §2 naming conventions. Future contributors have no judgement call to make about
  where a new property lives.
- **Scales.** The model accommodates the full OIDC + RFC family without the root class exceeding
  a screenful.
- **IntelliSense becomes useful again.** `options.Token.` narrows the surface; `options.` shows
  only server-wide settings and a short list of groups.
- **Discovery emission becomes near-mechanical.** `IDiscoveryDocumentProvider` can map group by
  group, with the spec's prefix convention as the lookup table. Adding a new endpoint becomes:
  add a group class, add a mapping block, add validator rules.
- **Plays correctly with `Microsoft.Extensions.Options`.** Nested classes bind from
  `IConfiguration` (`appsettings.json` → `ZeeKayDaAuth:Token:AuthMethodsSupported`),
  compose under `IOptionsSnapshot<T>` / `IOptionsMonitor<T>`, and remain a single
  `IValidateOptions<AuthorizationServerOptions>` target. Named options keep working unchanged
  (a future multi-tenant scenario can use named `AuthorizationServerOptions` instances).
- **Get-only group properties cannot be nulled.** Defaults and the validator's reachable surface
  are preserved no matter what the consumer's options lambda does.

### Negative / Trade-offs

- **Pre-1.0 breaking change.** Every consumer (today: samples and tests inside this repo only)
  updates property paths: `options.TokenEndpoint` → `options.Token.Uri`,
  `options.TokenEndpointAuthMethodsSupported` → `options.Token.AuthMethodsSupported`, etc. The
  migration table in §2 is the canonical reference. Doing this now is cheap; doing it after 1.0
  would be a major-version break.
- **Slight cognitive cost: "which group does this live on?"** A consumer who knows OIDC will
  guess correctly every time, because the grouping rule *is* the spec's naming rule. A consumer
  who does not will lean on IntelliSense — which now narrows usefully — and on documentation.
  The cost is real but small, and is the price of the discoverability gains above.
- **Single root validator does more work.** Cross-group rules belong somewhere, and they belong
  here. The class grows; it stays auditable because it stays the *only* validator.
- **No per-group `IOptions<TokenOptions>` injection.** A consumer service cannot ask DI for
  `IOptions<TokenOptions>` directly; it asks for `IOptions<AuthorizationServerOptions>` and reads
  `.Token`. This is intentional — `TokenOptions` has no standalone meaning outside its parent —
  but it is a minor ergonomic asymmetry worth noting.

---

## Security Note

The current validator enforces that `TokenEndpointAuthMethodsSupported` is not null but **does
permit it to be empty**. An empty supported-methods set, or a set whose only entry is `none`,
allows unauthenticated token-endpoint calls and is the kind of insecure-default footgun this
framework exists to prevent
([OAuth 2.0 Security BCP §2.6](https://www.rfc-editor.org/rfc/rfc9700#section-2.6)).

After this ADR's reshape, the analogous field is `options.Token.AuthMethodsSupported`. The
**rule** we want is: empty (or `none`-only) must require explicit, named opt-in — never the
default. The **exact wording** of the opt-in (flag name, placement: `TokenOptions` vs root vs
`AllowInsecure*` family, validator message, whether it is one flag or two) is deliberately left
to the security agent's review of this ADR. This ADR records the constraint and flags it for
attention; it does not pre-empt the recommendation.

---

## References

- [OpenID Connect Discovery 1.0 §3 — Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
- [RFC 8414 §2 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
- [OAuth 2.0 Security Best Current Practice §2.6 — Client Authentication](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [ADR 0001 — Endpoint Architecture Pattern](./0001-endpoint-architecture-pattern.md)
- Issue [#51](https://github.com/ChrisKlug/zeekayda-auth/issues/51) — the originating design discussion
- Issue [#43](https://github.com/ChrisKlug/zeekayda-auth/issues/43) — closed: `IZeeKayDaEndpoint` remains internal
- Prior art:
  [Duende IdentityServer's `IdentityServerOptions`](https://docs.duendesoftware.com/identityserver/v7/reference/options/)
  groups settings by concern (`Endpoints`, `Discovery`, `Authentication`, …), which is the
  closest precedent to the shape adopted here. Contrast with
  [OpenIddict](https://documentation.openiddict.com/configuration/)'s pure-fluent builder model
  and [Microsoft.Identity.Web](https://learn.microsoft.com/en-us/entra/msal/dotnet/microsoft-identity-web/)'s
  flat `MicrosoftIdentityOptions` — both were considered as reference points; neither was adopted
  wholesale, for the reasons in *Rejected Alternatives* above.
