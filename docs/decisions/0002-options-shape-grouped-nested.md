# ADR 0002 — Options Shape: Grouped Nested Per-Endpoint Options on `AuthorizationServerOptions`

**Status:** Accepted
**Date:** 2026-06-07 (original) · rewritten 2026-07-11 (issue #337)

> **Format note.** This ADR was migrated to the three-part format defined in
> [`docs/decisions/README.md`](./README.md) (current state · considered and rejected
> alternatives · changelog appendix) as part of issue #337. Its earlier top "Decision" section and
> its dated amendment log (the inline §4 validator amendment, the `SecurityHeaders`
> framework-behavior-group amendment, and the grouping-rule scope clarification) have been folded
> into the current-state description below and reduced to pointer entries in the changelog
> appendix. Nothing substantive was dropped in the migration.

> **Amended by ADR 0007 §1a (2026-06-08):** `TokenEndpoint.AuthMethodsSupported` is changed from `ICollection<TokenEndpointAuthMethod>` (enum) to `ICollection<string>` (ordinal), and the `TokenEndpointAuthMethod` enum is removed. The discovery document advertises this configured server allowlist exactly; registered `IClientAuthenticator` methods are validated as capability coverage, not automatically advertised. The validator rules below remain in spirit (non-empty, at least one non-`"none"` method, coverage by an authenticator, etc.) but their type-system expression changes. The discussion below is preserved as historical record; ADR 0007 is the authority for the current `string`-based shape.

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

## Current State

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
| `authorization_endpoint`, `request_parameter_supported`, `request_uri_parameter_supported`, `require_request_uri_registration`, `request_object_signing_alg_values_supported`, … | `AuthorizationEndpoint` |
| `token_endpoint`, `token_endpoint_auth_methods_supported`, `token_endpoint_auth_signing_alg_values_supported`, … | `TokenEndpoint` |
| `jwks_uri` (plus future JWKS-endpoint policy such as response cache-control) | `JwksEndpoint` |
| `userinfo_endpoint`, `userinfo_signing_alg_values_supported`, `userinfo_encryption_alg_values_supported`, … | `UserInfoEndpoint` |
| `revocation_endpoint`, `revocation_endpoint_auth_methods_supported`, … | `RevocationEndpoint` |
| `introspection_endpoint`, `introspection_endpoint_auth_methods_supported`, … | `IntrospectionEndpoint` |
| `registration_endpoint` | `RegistrationEndpoint` |
| `end_session_endpoint` (OIDC Session Management / RP-Initiated Logout) | `EndSessionEndpoint` |
| `device_authorization_endpoint` (RFC 8628) | `DeviceAuthorizationEndpoint` |
| `id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`, `id_token_encryption_enc_values_supported` | `IdToken` |
| `response_types_supported`, `response_modes_supported` | `Response` |
| `issuer`, `scopes_supported`, `grant_types_supported`, `subject_types_supported`, `claims_supported`, … (no shared spec prefix) | root |

The rule is mechanical: pick any property, look at its discovery key, find the prefix, that's the
group. If no other current or near-future spec field shares the prefix, the property lives on the
root.

**Scope of the "no shared prefix → root" fallback (clarified 2026-07-11, issue #337).** This
fallback governs **OIDC discovery-document / RFC 8414 metadata configuration** — properties that
have a discovery-document counterpart (or a spec-defined endpoint-modifier relationship, §"Endpoint-affinity"
below). It is *not* a general licence to hoist arbitrary settings onto the shared
`AuthorizationServerOptions` root merely because they lack a discovery prefix. In particular, a
**feature-registration escape hatch or safety gate** — a flag or list that is inert unless a
specific opt-in feature (a signing-key provider, an in-memory store, etc.) was also registered — is
**not** a discovery-metadata property at all, so this rule says nothing about where it belongs.
Such a gate co-locates with the feature that introduces it (on that feature's provider-specific
options type, or as a parameter on its registration method), **not** on the root by default,
unless there is a genuine *cross-feature* reason to share it. Placing a feature-scoped gate on the
shared root creates a setting that silently does nothing unless an unrelated extension method was
called — the discoverability trap ADR 0008 names in the auto-registration context. This
clarification is recorded because PR #333 cited this ADR (alongside ADR 0008) as precedent for
hoisting `AllowedDevelopmentJwtSigningKeysEnvironments` onto `AuthorizationServerOptions`; that was
a misreading of this rule's scope, reversed by issue #337 (see ADR 0011 and ADR 0008). The
grouping rule places *discovery-shaped configuration*; it does not adjudicate the placement of
service-registration escape hatches.

**Why the rule extends beyond endpoint prefixes.** Restricting grouping to endpoint names was the
strictest possible reading of the spec; extending it to any shared spec prefix is the *consistent*
reading. The DX wins are real (`options.IdToken.SigningAlgValuesSupported`,
`options.Response.TypesSupported`) and the rule remains mechanical — there is no judgement call
about whether two properties are "conceptually related," only whether the spec prefixes them with
the same word. Cosmetic groupings invented without a spec prefix (e.g. lumping unrelated
server-wide flags into a "General" bag) are still prohibited.

`jwks_uri` is grouped under `JwksEndpoint` even though the spec defines no other `jwks_*_supported`
metadata fields today, and unlike other endpoint groups the spec prefix is `jwks_uri` rather than
`jwks_endpoint_*`. This is the one group whose `Endpoint` suffix is not directly derived from the
mechanical prefix rule; the justification is endpoint-affinity and forward-compatibility. The JWKS
endpoint will almost certainly grow endpoint-policy configuration that has no discovery analogue —
most obviously a response `Cache-Control` `max-age` value (as `DiscoveryDocument` already has via
`DiscoveryDocument.CacheMaxAgeSeconds`). Placing `Uri` on the root and then moving it into a
`JwksEndpoint` group later would be a second breaking change for no benefit. The same
forward-looking argument does not apply to keeping any other URI on the root, because every other
endpoint already has spec-defined per-endpoint metadata.

**Endpoint-affinity as a permitted secondary criterion.** The prefix rule is the *primary*
criterion. The `Authorization` row above also includes `require_request_uri_registration` and the
`request_*` family even though those keys do not share the literal `authorization_endpoint_*`
prefix. They are grouped under `Authorization` because the spec defines them as modifiers of the
authorization-endpoint behaviour. This is a permitted secondary criterion: a property may join a
group whose name is the endpoint it spec-modifies, even when the property's own discovery key does
not share that endpoint's prefix. The criterion is still mechanical (the spec text itself must
identify the property as an authorization/token/etc. endpoint modifier — not a judgement call by
the implementer), and a separate `Request` group would be silly. Cosmetic groupings invented
without either a spec prefix *or* a spec-defined endpoint-modifier relationship remain
prohibited.

**Naming rule for endpoint groups.** When the spec prefix identifies an HTTP endpoint, the C#
property name includes `Endpoint` as a suffix (e.g. `token_endpoint_*` → `TokenEndpoint`), even
though the class name already ends in `Options`. This preserves a clear semantic signal at the
call site: any property ending in `Endpoint` configures a network-accessible HTTP resource;
properties without the suffix (`IdToken`, `Response`, `DiscoveryDocument`) configure protocol
artifacts or cross-endpoint concepts.

**Framework-behavior groups: a second permitted category outside the spec-prefix rule.** Some
settings govern the framework's *own* runtime behaviour — HTTP security headers, caching policy,
logging policy — and have **no** OIDC Discovery 1.0 / RFC 8414 discovery-key counterpart at all.
`SecurityHeaders` on `AuthorizationServerOptions` is the motivating case: it controls the HTTP
security headers ZeeKayDa.Auth itself emits, not server-capability metadata advertised to clients,
so the spec-prefix rule does not reach it. This ADR formally recognises a second category —
**framework-behavior groups** — which collect settings that govern the framework's runtime
behaviour (headers, caching policy, logging policy, etc.) with no discovery-document analogue.
Framework-behavior groups are permitted outside the spec-prefix rule, subject to two constraints:
their names must be plain, descriptive English, and they MUST NOT carry an `Endpoint` suffix (they
are not HTTP endpoints). The `SecurityHeaders` name is correct for this category. A property that
*does* have a discovery-key counterpart belongs in its spec-prefix group and MUST NOT be placed in
a framework-behavior group. Any future framework-behavior group follows this precedent: descriptive
name, no `Endpoint` suffix, not subject to the spec-prefix rule.

### 2. Per-endpoint properties migration table (initial cut)

Concrete moves required by this ADR for the surface that exists today:

| Today (flat) | After (grouped) |
|---|---|
| `Issuer` | `Issuer` (unchanged) |
| `AllowInsecureIssuer` | `AllowInsecureIssuer` (unchanged — server-wide; gates all endpoint URI schemes) |
| `JwksUri` | `JwksEndpoint.Uri` |
| `ResponseTypesSupported` | `Response.TypesSupported` |
| `ResponseModesSupported` | `Response.ModesSupported` |
| `GrantTypesSupported` | `GrantTypesSupported` (unchanged — no shared spec prefix) |
| `IdTokenSigningAlgValuesSupported` | `IdToken.SigningAlgValuesSupported` |
| `DiscoveryDocumentCacheMaxAgeSeconds` | `DiscoveryDocument.CacheMaxAgeSeconds` (per-endpoint policy) |
| `AuthorizationEndpoint` | `AuthorizationEndpoint.Uri` |
| `TokenEndpoint` | `TokenEndpoint.Uri` |
| `TokenEndpointAuthMethodsSupported` | `TokenEndpoint.AuthMethodsSupported` |

Future endpoints, artifacts, or response-shape fields add their own groups under the same rule.

**Known future groups (recorded so they are not forgotten).** The §1 rule predicts a `Claims`
group the moment a second `claims_*` discovery field lands. `claims_supported` is on the root in
the table above because it is the only `claims_*` field exposed today, but the spec also defines
`claims_parameter_supported`, `claims_locales_supported`, and `claim_types_supported`. The first
PR that introduces any second `claims_*` field must form the `Claims` group at that point and
move `claims_supported` into it — the same forward-looking-but-not-pre-empted reasoning applied
to `JwksEndpoint` above. Recording this here so the implementer of that PR is not surprised.

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

    public DiscoveryOptions               DiscoveryDocument     { get; } = new();
    public AuthorizationEndpointOptions   AuthorizationEndpoint { get; } = new();
    public TokenEndpointOptions           TokenEndpoint         { get; } = new();
    public JwksEndpointOptions            JwksEndpoint          { get; } = new();
    public IdTokenOptions                 IdToken               { get; } = new();
    public ResponseOptions                Response              { get; } = new();
}

public sealed class TokenEndpointOptions
{
    public string? Uri { get; set; }
    public ICollection<TokenEndpointAuthMethod> AuthMethodsSupported { get; set; } =
        [TokenEndpointAuthMethod.ClientSecretBasic];
}

public sealed class JwksEndpointOptions
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
`AuthorizationServerOptionsValidator` in `ZeeKayDa.Auth/Configuration/`), and is a **pure read-only
check**, exactly as the `IValidateOptions<T>` contract requires. Two responsibilities a validator
must not carry are deliberately kept out of it:

- **CORS-origin canonicalization and deduplication** run in
  `AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>`,
  which executes *before* validation and freezes `DiscoveryOptions.CorsOrigins` into an immutable
  canonical snapshot. `IValidateOptions<T>.Validate` is a read-only contract; mutating options
  during validation is unexpected and can produce subtle ordering bugs.
- **The async `IScopeRepository` presence check** runs in `ScopePresenceStartupValidator :
  IHostedService`, whose `StartAsync` is awaitable. Blocking on async I/O inside the synchronous
  `Validate` method risks deadlocks in certain hosting configurations.

The validator reaches into the groups:

```csharp
if (options.TokenEndpoint.AuthMethodsSupported is null) …
if (options.AuthorizationEndpoint.Uri is { } ae && /* … */) …
```

We deliberately do **not** introduce per-group `IValidateOptions<TokenOptions>` etc. The reasons:

- Many real validation rules are **cross-group** (e.g. "if `client_credentials` is in
  `GrantTypesSupported`, then `TokenEndpoint.AuthMethodsSupported` must contain at least one non-`none`
  method"). Cross-group rules have no natural home in a per-group validator and would force
  duplication or arbitrary placement.
- A single root validator gives one fail-fast surface — one place to read, one place to extend, one
  place the security agent can audit.
- Group validation can still be factored internally into private helper methods per group for
  readability; that is an implementation detail, not part of the contract.

#### Required validator rules for `TokenEndpoint.AuthMethodsSupported`

Two hard errors must be enforced at startup:

**Rule 1 — Null or empty collection is always an error:**
```
TokenEndpoint.AuthMethodsSupported must not be null or empty. Specify at least one client authentication method
(e.g. TokenEndpointAuthMethod.ClientSecretBasic). See OAuth 2.0 Security BCP §2.6 (RFC 9700).
```

**Rule 2 — `client_credentials` grant requires at least one non-`none` method (cross-group):**
```
GrantTypesSupported includes 'client_credentials', which requires confidential clients.
TokenEndpoint.AuthMethodsSupported must contain at least one method other than 'none'.
See RFC 6749 §4.4 and OAuth 2.0 Security BCP §2.6 (RFC 9700).
```

Note: `none` may legitimately appear alongside other methods in `AuthMethodsSupported` to support
public clients (mobile apps, browser-based applications using PKCE). This is safe provided the
token endpoint enforces `token_endpoint_auth_method` **per client** at request time — see
§ Security Note below and issue #64.

When `RevocationEndpoint` and `IntrospectionEndpoint` options are introduced, the same two rules must be
applied to their `AuthMethodsSupported` collections.

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

## Considered and Rejected Alternatives

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
- **IntelliSense becomes useful again.** `options.TokenEndpoint.` narrows the surface; `options.` shows
  only server-wide settings and a short list of groups.
- **Discovery emission becomes near-mechanical.** `IDiscoveryDocumentProvider` can map group by
  group, with the spec's prefix convention as the lookup table. Adding a new endpoint becomes:
  add a group class, add a mapping block, add validator rules.
- **Plays correctly with `Microsoft.Extensions.Options`.** Nested classes bind from
  `IConfiguration` (`appsettings.json` → `ZeeKayDaAuth:Token:AuthMethodsSupported`),
  compose under `IOptionsSnapshot<T>` / `IOptionsMonitor<T>`, and remain a single
  `IValidateOptions<AuthorizationServerOptions>` target. Named options keep working unchanged
  (a future multi-tenant scenario can use named `AuthorizationServerOptions` instances).
  **Note:** Key paths reflect the current grouped names — e.g. `ZeeKayDaAuth:TokenEndpoint:AuthMethodsSupported`, not the pre-rename `ZeeKayDaAuth:Token:AuthMethodsSupported`.
- **Get-only group properties cannot be nulled.** Defaults and the validator's reachable surface
  are preserved no matter what the consumer's options lambda does.

### Negative / Trade-offs

- **Pre-1.0 breaking change.** Every consumer (today: samples and tests inside this repo only)
  updates property paths: `options.TokenEndpoint` → `options.TokenEndpoint.Uri`,
  `options.TokenEndpointAuthMethodsSupported` → `options.TokenEndpoint.AuthMethodsSupported`, etc. The
  migration table in §2 is the canonical reference. Doing this now is cheap; doing it after 1.0
  would be a major-version break.
- **Slight cognitive cost: "which group does this live on?"** A consumer who knows OIDC will
  guess correctly every time, because the grouping rule *is* the spec's naming rule. A consumer
  who does not will lean on IntelliSense — which now narrows usefully — and on documentation.
  The cost is real but small, and is the price of the discoverability gains above.
- **Single root validator does more work.** Cross-group rules belong somewhere, and they belong
  here. The class grows; it stays auditable because it stays the *only* validator.
- **`IConfiguration` collection binding replaces, does not merge.** When any entry for a
  collection (e.g. `ZeeKayDaAuth:TokenEndpoint:AuthMethodsSupported`) is present in `appsettings.json`,
  the `IConfiguration` binder replaces the entire default collection with the configured values.
  An operator who specifies only one method in config silently loses any other defaults. The
  fail-fast validator catches an empty result, but operators should be aware that collection
  settings must be specified in full. Documentation should call this out explicitly.
- **`IConfiguration` key paths change on upgrade.** Operators who previously configured
  `ZeeKayDaAuth:Token:*` or `ZeeKayDaAuth:Authorization:*` keys in `appsettings.json` must rename
  those keys to `ZeeKayDaAuth:TokenEndpoint:*` and `ZeeKayDaAuth:AuthorizationEndpoint:*`
  respectively. If they do not, the keys are silently ignored and the framework falls back to
  defaults — which may be less restrictive than what the operator intended. The migration guide
  and upgrade notes must call this out explicitly.
- **`none` in `AuthMethodsSupported` is safe only with per-client enforcement.** Advertising
  `none` alongside other methods does not itself create a downgrade path, but only because the
  token endpoint is required to enforce the `token_endpoint_auth_method` registered per client
  (see issue #64). If that per-client enforcement were absent, a confidential client could
  authenticate as a public client by simply omitting credentials. This dependency is a
  **hard prerequisite** for the token endpoint implementation — it is not optional.
- **Same pattern required for future `RevocationEndpoint` and `IntrospectionEndpoint` groups.** When
  those options are implemented, their `AuthMethodsSupported`
  collections carry the same risks and must apply the same validator rules (§4) and the same
  per-client enforcement requirement.

---

## Security Considerations

**`TokenEndpoint.AuthMethodsSupported` — validator rules and per-client enforcement dependency.**

The validator enforces two hard errors at startup (see §4 for exact messages):

1. **Empty collection** — unconditionally rejected. There is no valid deployment where zero
   authentication methods are supported.
2. **`client_credentials` grant + `none`-only methods** — rejected. The client credentials grant
   requires a confidential client; a server that advertises only `none` cannot securely support it.

`none` may appear alongside other methods to support public clients (mobile apps, browser-based
applications). This is a spec-blessed pattern ([RFC 6749 §2.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.1),
[OpenID Connect Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication))
and is **not** treated as an error on its own.

However, advertising `none` alongside confidential-client methods is only safe if the token
endpoint enforces the `token_endpoint_auth_method` **per registered client** at request time. A
server that only checks "is this method in `AuthMethodsSupported`?" would allow a confidential
client to authenticate as a public client by omitting its credentials — an auth method downgrade
attack. Per-client enforcement is therefore a **hard prerequisite** for the token endpoint
implementation and is tracked in issue [#64](https://github.com/ChrisKlug/zeekayda-auth/issues/64).

No opt-in flag is introduced for `none`. The correct mitigation is implementation correctness, not
a flag that papers over an absent control.

---

## Changelog

Pointer-only index (date · PR/issue · what changed). Full reasoning lives in the current-state and
alternatives sections above.

- **2026-06-07 — issue #51** — Initial ADR: `AuthorizationServerOptions` reshaped into grouped-nested per-endpoint options; spec-prefix grouping rule; `sealed`, get-only, default-initialised group classes; single-rooted validator; endpoint surface stays internal (ADR 0001 / #43).
- **2026-06-08 — ADR 0007 §1a** — `TokenEndpoint.AuthMethodsSupported` changed from the `TokenEndpointAuthMethod` enum to `ICollection<string>` (ordinal); enum removed. ADR 0007 is the authority; the enum-based validator discussion here is retained as historical record (see the note at the top of this ADR).
- **2026-06-13 — architecture review AA-M4 / AA-M5** — `AuthorizationServerOptionsValidator` made a pure read-only check: CORS-origin canonicalization moved to `AuthorizationServerOptionsPostConfigurer`; the async `IScopeRepository` presence check moved to `ScopePresenceStartupValidator : IHostedService`. Folded into §4.
- **2026-06-13 — architecture review AA-m13 (resolves #159 partial)** — `SecurityHeaders` recognised as a **framework-behavior group** outside the spec-prefix rule (descriptive name, no `Endpoint` suffix); name blessed, no rename. Folded into §1.
- **2026-07-11 — issue #337 (this PR)** — ADR migrated to the three-part format ([README](./README.md)). Grouping-rule scope clarified: the "no shared discovery-prefix → root" fallback governs discovery-document / RFC 8414 metadata configuration only and does **not** license hoisting a feature-registration escape hatch onto the shared root (PR #333 misread it as precedent for `AllowedDevelopmentJwtSigningKeysEnvironments`; reversed — see ADR 0011 and ADR 0008's equivalent `AllowInMemoryStoresOutsideDevelopment` reversal). Folded into §1.

---

## References

- [OpenID Connect Discovery 1.0 §3 — Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
- [RFC 8414 §2 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
- [OAuth 2.0 Security Best Current Practice (RFC 9700) §2.6 — Client Authentication](https://www.rfc-editor.org/rfc/rfc9700#section-2.6)
- [ADR 0001 — Endpoint Architecture Pattern](./0001-endpoint-architecture-pattern.md)
- Issue [#64](https://github.com/ChrisKlug/zeekayda-auth/issues/64) — per-client `token_endpoint_auth_method` enforcement (hard prerequisite for token endpoint)
- Issue [#51](https://github.com/ChrisKlug/zeekayda-auth/issues/51) — the originating design discussion
- Issue [#43](https://github.com/ChrisKlug/zeekayda-auth/issues/43) — closed: `IZeeKayDaEndpoint` remains internal
- Prior art:
  [Duende IdentityServer's `IdentityServerOptions`](https://docs.duendesoftware.com/identityserver/v7/reference/options/)
  groups settings by concern (`Endpoints`, `Discovery`, `Authentication`, …), which is the
  closest precedent to the shape adopted here. Contrast with
  [OpenIddict](https://documentation.openiddict.com/configuration/)'s pure-fluent builder model
  and [Microsoft.Identity.Web](https://learn.microsoft.com/en-us/entra/msal/dotnet/microsoft-identity-web/)'s
  flat `MicrosoftIdentityOptions` — both were considered as reference points; neither was adopted
  wholesale, for the reasons in *Considered and Rejected Alternatives* above.
