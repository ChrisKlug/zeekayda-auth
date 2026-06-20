# ADR 0010 — Claims Resolution Strategy for Token Issuance

**Status:** Accepted  
**Date:** 2026-06-20

---

## Context

ADR 0008 defined the store contracts for authorization codes and refresh tokens. Both entry
records (`AuthorizationCodeEntry` and `RefreshTokenEntry`) carry `Sub` plus grant metadata —
scope, expiry, client ID, SSO session ID — but neither carries user claims. The question of
where claims come from when an access token or ID token is minted was not addressed, leaving
the behaviour determined by implementation convention rather than an explicit decision.

The gap matters for three reasons:

1. **Breaking-change timing.** If claims belong on the entry records (the snapshot model),
   a `Claims` property must be added to both records before any implementing code merges.
   Adding it post-merge is a breaking change to a freshly-shipped public API. The store
   contract and token endpoint work cannot merge until this decision is settled.

2. **Session consistency.** The behaviour of "re-fetch on every issuance" versus "snapshot at
   grant time" has direct, user-visible consequences: one model means a role revocation is
   reflected in the very next access token; the other means it is not visible until
   re-authentication. Both are valid industry choices but they must be explicit.

3. **Security model.** Stale claims in a long-lived session — particularly stale authorization
   claims such as roles or group memberships — affect the blast radius of a compromised or
   mis-attributed account. The choice must be grounded in the relevant threat model
   (RFC 6819, RFC 9700).

### What the current codebase does (implicit)

Neither entry record has a `Claims` property. The token issuance pipeline — which does not exist
yet as implemented code — would implicitly need to load claims from somewhere at every access
token mint. No claims-loading seam exists; there is no defined extension point an operator can
implement or replace.

### Industry reference

Duende IdentityServer, Auth0, and Keycloak all re-fetch claims by default but expose a
transformation hook (IdentityServer's `IProfileService`, Auth0's Actions pipeline, Keycloak's
Protocol Mapper SPIs). The hook is the load-bearing component: it is what gives operators
control over which claims appear in tokens and where they come from. The default behaviour
(re-fetch) is relevant only to operators who do not configure the hook. ZeeKayDa.Auth follows
this pattern by making the hook (`IClaimsProvider`) mandatory rather than optional, which
removes any ambiguity about where claims originate.

---

## Decision

### 1. Strategy: re-fetch claims on every issuance via a mandatory `IClaimsProvider` abstraction

Claims are **not** stored on either entry record. `AuthorizationCodeEntry` and
`RefreshTokenEntry` remain claims-free, exactly as ADR 0008 defined them. No `Claims`
property is added to either record. This ADR therefore does **not** amend ADR 0008.

All issuance paths — authorization code exchange and every refresh token rotation — obtain
subject claims through a single mandatory interface, `IClaimsProvider`, defined in
`ZeeKayDa.Auth`. The framework MUST NOT read the identity store directly. The token endpoint
MUST call `IClaimsProvider` and MUST use the returned claim set for both the access token and
the ID token for that issuance. There is no fallback, no alternative path, and no way to
bypass `IClaimsProvider`.

The rationale follows from first principles:

**Claims must be live by default to avoid privilege escalation windows.** The snapshot model
defers privilege revocation until re-authentication. ADR 0008 defines `RefreshTokenEntry.ExpiresAt`
as `IssuedAt + RefreshTokenLifetime`, where `IssuedAt` is the timestamp of each individual
rotation — not the original grant time. The lifetime is sliding: every rotation resets the
clock, and ADR 0008 explicitly enforces no upper bound on `RefreshTokenLifetime` by design
(to support long-lived integrations). For an active client that rotates before the current
token expires, the staleness window is therefore indefinite — the grant never expires as long
as the client keeps rotating. Short access token lifetimes (15 minutes, per RFC 9700 §4.2.2)
bound the window per issued token, but continuous rotation allows the client to keep obtaining
fresh access tokens — each carrying the stale snapshot — with no expiry imposed by the
framework. The default single-token lifetime (14 days) only bounds an inactive client that
stops rotating; it does not bound an active one. Re-fetch ensures that any structural validity
check (is the subject still active?) runs on every issuance and cannot be bypassed by rotation.

**A mandatory seam makes all claims resolution observable and replaceable.** With no seam,
the framework would need to read the identity store directly, tightly coupling the token
endpoint to a specific store API. With `IClaimsProvider` as a mandatory interface, the host
application owns the claims resolution logic entirely. There is no hidden I/O path. The token
endpoint is testable by supplying a stub `IClaimsProvider` with no running identity store
required.

**`IClaimsProvider` composes cleanly with the subject-validity check.** Refresh token
rotation MUST re-confirm that the subject is still active: a disabled or deleted user MUST
NOT receive new tokens. This check is structural: if `IClaimsProvider` cannot resolve a
valid claim set for the subject, issuance MUST abort with `invalid_grant`. This is not an
additional check on top of claims resolution — it is the same call. An `IClaimsProvider`
implementation that validates subject existence as part of returning claims
(the natural implementation pattern) satisfies both requirements in a single round-trip.

**A caching decorator can restore snapshot-equivalent performance at the implementor's
discretion.** An `IClaimsProvider` that internally caches the resolved claim set by
`FamilyId` achieves the same performance profile as a stored snapshot — one identity store
read per grant, not per issuance — while still passing every resolution through the
framework's defined seam. Caching inside the provider is a legitimate availability
optimisation; it is not a change to the framework's security posture, because the provider
contract still runs on every issuance and the cache is managed entirely by the implementor.

### 2. `IClaimsProvider` interface

`IClaimsProvider` is defined in `ZeeKayDa.Auth`:

```csharp
namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Resolves the claims to include in tokens issued for a given subject and grant.
/// Called on every token issuance, including every refresh token rotation.
/// </summary>
/// <remarks>
/// <para>
/// Implementations MUST be registered in DI. ZeeKayDa.Auth does not provide a default
/// implementation — the framework cannot know how the host application stores or resolves
/// user claims. A missing registration surfaces as <see cref="ZeeKayDaConfigurationException"/>
/// at startup.
/// </para>
/// <para>
/// Implementations SHOULD validate that the subject is still active and return a
/// <see cref="ClaimsResolutionResult.SubjectInvalid"/> result if the subject has been
/// disabled, deleted, or otherwise deactivated. The token endpoint treats a
/// <see cref="ClaimsResolutionResult.SubjectInvalid"/> result as <c>error=invalid_grant</c>
/// and does not issue any token. This is the mechanism through which account deactivation
/// and SSO-session revocation compose with refresh token rotation (see issues #103 and #104).
/// </para>
/// <para>
/// Resolved claims MUST NOT appear in log entries, error responses, or exception messages.
/// See ADR 0009 for the logging hygiene requirements that apply across all issuance paths.
/// </para>
/// </remarks>
public interface IClaimsProvider
{
    /// <summary>
    /// Resolves the claims to be included in tokens for the given context.
    /// Called on every token issuance, including every refresh token rotation.
    /// </summary>
    /// <param name="context">
    /// Contextual information about the issuance. See <see cref="ClaimsProviderContext"/>
    /// for the fields provided.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="ClaimsResolutionResult"/> describing the outcome.
    /// </returns>
    Task<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context,
        CancellationToken cancellationToken);
}
```

### 3. `ClaimsProviderContext`

The context object passed to `IClaimsProvider.GetClaimsAsync` carries exactly three fields.
No additional fields will be added to this type without a new ADR, because every field adds
a framework dependency that implementors must understand.

```csharp
namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Contextual information provided to <see cref="IClaimsProvider"/> on every token issuance.
/// </summary>
/// <param name="Sub">
/// The subject identifier for whom tokens are being issued. Stable across all
/// rotations of the same grant.
/// </param>
/// <param name="Scopes">
/// The granted scopes for this issuance. Rotation MUST NOT widen scope
/// (RFC 6749 §6); the framework enforces this before calling the provider.
/// </param>
/// <param name="FamilyId">
/// The refresh token family identifier, stable across all rotations of the same
/// grant. Created once at authorization code exchange and carried forward on every
/// <see cref="ZeeKayDa.Auth.Stores.RefreshTokenEntry"/> in the chain.
/// </param>
/// <remarks>
/// <para>
/// <see cref="FamilyId"/> is the natural cache key for any <see cref="IClaimsProvider"/>
/// implementation that performs internal caching to reduce identity store load. A cache
/// miss on <see cref="FamilyId"/> is structurally equivalent to the "first issuance"
/// signal — no <c>IsRefreshRotation</c> flag or <c>GrantType</c> discriminator is
/// required or provided. See ADR 0010 §4 for the caching guidance.
/// </para>
/// <para>
/// Only the minimum information required to resolve claims is included. Additional
/// context (e.g. client ID, request metadata) is deliberately excluded to prevent
/// implementors from building claims logic that depends on client identity rather than
/// subject identity, which is the relevant boundary for claims resolution.
/// </para>
/// </remarks>
public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    string FamilyId);
```

**Why exactly these three fields and no others:**

- `Sub` is the only input that identifies the subject in the identity store. It is the
  primary key for any subject lookup.
- `Scopes` lets the implementor return scope-filtered claims — for example, only returning
  `email` and `profile` claims when the `openid` scope is present, or only returning
  `roles` claims when an `api` scope is present. Scope-filtered claims are the standard
  pattern in IdentityServer's `IProfileService` and Auth0's Actions pipeline.
- `FamilyId` is the stable per-grant identifier. It enables internal caching (see §4) and
  allows an implementor who deliberately snapshots claims on first issuance to look up
  the cached set on subsequent rotations — without any framework change. A cache miss on
  `FamilyId` is structurally "first issuance"; a cache hit is "rotation". No
  `IsRefreshRotation` flag is needed or provided, because the flag is redundant given
  `FamilyId` and adds an API surface that encodes an implementation assumption.

**What is deliberately excluded:**

- `ClientId` — claims resolution is a subject-level concern, not a client-level concern.
  Implementors who vary claims by client are coupling claims logic to client identity,
  which should be handled in a claim transformation pipeline (a separate, later ADR) rather
  than inside `IClaimsProvider`.
- `GrantType` — the provider does not need to know whether the issuance is from an
  authorization code exchange or a refresh rotation. The subject and scopes are sufficient
  context; the `FamilyId` cache-miss heuristic replaces any "first issuance" flag.
- Request-level metadata (IP address, user agent, etc.) — out of scope for claims
  resolution. Security-relevant request context belongs in audit logging, not in claims.

### 4. `ClaimsResolutionResult`

`GetClaimsAsync` returns `ClaimsResolutionResult`, a closed hierarchy using the same
private-constructor idiom as the store outcome types in ADR 0008:

```csharp
namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// Describes the outcome of a <see cref="IClaimsProvider.GetClaimsAsync"/> call.
/// </summary>
public abstract class ClaimsResolutionResult
{
    private ClaimsResolutionResult() { }

    /// <summary>
    /// Claims were successfully resolved. The token endpoint will use
    /// <see cref="Claims"/> to populate both the access token and the ID token
    /// for this issuance.
    /// </summary>
    public sealed class Resolved : ClaimsResolutionResult
    {
        /// <summary>
        /// The resolved claims. Must not be null; use an empty list for subjects
        /// with no claims applicable to the requested scopes.
        /// </summary>
        public required IReadOnlyList<ClaimRecord> Claims { get; init; }
    }

    /// <summary>
    /// The subject is no longer valid — disabled, deleted, or deactivated.
    /// The token endpoint will abort issuance and return <c>error=invalid_grant</c>.
    /// No token is issued. This outcome MUST be returned (rather than throwing) when
    /// the subject's non-existence or deactivation is a known, expected condition.
    /// </summary>
    public sealed class SubjectInvalid : ClaimsResolutionResult { }
}
```

The private constructor prevents consumers from adding subtypes. The token endpoint switches
exhaustively over the two known outcomes. Any exception thrown by `IClaimsProvider` (as
opposed to a typed `SubjectInvalid` return) is treated as an infrastructure failure and
surfaces as `error=server_error` — see §5.

**Why two outcomes and not one with a nullable list:**

A nullable `IReadOnlyList<ClaimRecord>?` return from `GetClaimsAsync` would conflate two
distinct situations: a subject who has no claims applicable to the requested scopes
(legitimate, return an empty list) and a subject who is invalid (should abort issuance).
Using `null` as a sentinel for "subject invalid" would require every implementor to know the
convention, and any implementor who mistakenly returns `null` from a "no claims found" path
would silently abort issuance. The typed `SubjectInvalid` case makes the contract explicit
and the error path auditable.

### 5. `ClaimRecord` type

`ClaimRecord` is a `readonly record struct` in `ZeeKayDa.Auth.Claims` (not in
`ZeeKayDa.Auth.Stores`, since this ADR does not add claims to the store entry records):

```csharp
namespace ZeeKayDa.Auth.Claims;

/// <summary>
/// A serialisable name/value pair representing a single claim returned by
/// <see cref="IClaimsProvider"/>.
/// </summary>
/// <remarks>
/// <see cref="System.Security.Claims.Claim"/> is intentionally not used here.
/// <c>Claim</c> is not serialisable without custom converters, carries a back-reference
/// to <c>ClaimsIdentity</c>, has mutable properties, and depends on
/// <c>System.Security.Claims</c> semantics (issuer, original issuer, value type) that
/// have no meaning in the claims resolution context. <c>ClaimRecord</c> is the
/// serialisation-stable, back-reference-free projection.
/// Store implementors or token pipeline components that need a <c>ClaimsPrincipal</c>
/// convert from <c>ClaimRecord</c> at the boundary; the provider itself never sees
/// <c>Claim</c>.
/// </remarks>
public readonly record struct ClaimRecord(string Type, string Value);
```

The same type rationale that the original ADR 0010 draft documented for rejecting
`System.Security.Claims.Claim`, `IReadOnlyDictionary<string, string>`, and value tuples
applies here unchanged and is not repeated. The namespace placement (`ZeeKayDa.Auth.Claims`
rather than `ZeeKayDa.Auth.Stores`) reflects that `ClaimRecord` is an output of the claims
resolution pipeline, not a storage type. If a future ADR introduces claim storage on entry
records, `ClaimRecord` would be reused from this namespace with no breaking change.

### 6. Mandatory registration and startup validation

`IClaimsProvider` has no default implementation. The framework cannot know how the host
application stores or resolves user claims; providing a default that reads from an imaginary
identity store would be misleading.

`AddZeeKayDaAuth()` MUST verify that `IClaimsProvider` is registered in the DI container
before the host starts. A missing registration MUST surface as
`ZeeKayDaConfigurationException` (per ADR 0006) at startup — not as a `NullReferenceException`
or `InvalidOperationException` at first token issuance. The startup check follows the same
options-validation pattern used for `IDistributedCache` in ADR 0008 §5.

### 7. Fail-closed resolution semantics (MUST-level requirements)

The following requirements are non-negotiable. They came from security review and may not
be relaxed by configuration, subclassing, or extension.

**Re-fetch is structural.** Claims MUST be resolved fresh on every issuance and every
rotation. Entry records (`AuthorizationCodeEntry`, `RefreshTokenEntry`) MUST NOT carry a
claims snapshot. There is no configuration flag that switches to a snapshot mode; any such
mode is explicitly opt-in for the implementor within their own `IClaimsProvider`, not a
framework mode (see §8).

**Single resolution seam.** All issuance paths MUST call `IClaimsProvider`. No path reads
the identity store directly. The access token and ID token for a given issuance MUST be
built from the same resolved claim set returned by the single `GetClaimsAsync` call for
that issuance.

**Resolution failure is fail-closed.** If `IClaimsProvider.GetClaimsAsync` throws or
returns an unusable result:

- A `SubjectInvalid` result MUST abort issuance with `error=invalid_grant`. This is the
  correct error code per RFC 6749 §5.2: the subject's grant is no longer valid.
- Any exception thrown MUST be treated as an infrastructure failure and MUST abort
  issuance with `error=server_error`. The exception MUST be wrapped and logged per
  ADR 0009 hygiene requirements (no claims in log output). There is NO fallback to a
  cached or previous claim set.

**Subject-still-valid check on refresh.** Refresh token rotation MUST re-confirm that
the subject is active. A disabled or deleted subject MUST result in `error=invalid_grant`.
This is not a separate check — it is the consequence of calling `IClaimsProvider` on every
rotation: an implementor that validates subject existence as part of resolving claims
satisfies this requirement naturally. This composes with SSO-session revocation (see issues
#103 and #104).

**No claims in logs or errors.** Resolved claims MUST NOT appear in log entries, error
responses, or exception messages. `SecretSanitizingLogger` (ADR 0009) provides the
logging-side guarantee; the token endpoint MUST NOT embed claim values in any
`ZeeKayDaException` message or error response property.

### 8. Caching inside `IClaimsProvider` — availability optimisation, not a posture change

An `IClaimsProvider` implementation that caches resolved claims by `FamilyId` (the natural
cache key, available in `ClaimsProviderContext`) reduces identity store load to one read per
grant — the same profile as the snapshot model in terms of I/O — while still passing every
issuance through the framework's defined seam.

This is a legitimate availability optimisation. It is distinct from the snapshot model in
one critical way: the framework contract still calls `GetClaimsAsync` on every issuance,
and the caching implementor is responsible for TTL management. Any caching implementor
MUST use a TTL well under the access token lifetime — never a grant-lifetime or
refresh-token-lifetime snapshot — so that a subject deactivation takes effect within the
TTL window, not at grant expiry. A TTL of zero (no caching) is the safe default.

A caching decorator (`CachingClaimsProvider` or similar) that wraps a live-reading inner
`IClaimsProvider` is explicitly deferred as a low-priority future feature. It is tracked
as a separate issue (to be created by the maintainer). `FamilyId` in
`ClaimsProviderContext` is already the natural cache key, so no future API change to
`IClaimsProvider` or `ClaimsProviderContext` is required to ship it.

Any snapshot/caching mode reachable without writing custom code (i.e. a framework-provided
mode) MUST be opt-in, MUST be documented as deferring privilege revocation, and MUST NOT be
the default or reachable by default configuration.

### 9. Claim transformation pipeline — deferred

A claim transformation pipeline (`IClaimsTransformer` or equivalent) that sits between the
resolved `IReadOnlyList<ClaimRecord>` and the final token payload is explicitly deferred,
pending the access token and ID token generation ADRs (issues #205 and #206). The shape of
a transformer is tightly coupled to how token claims are assembled (namespace mapping,
audience filtering, claim type URI normalisation), which must be designed first.

`ClaimRecord` is the transfer object that will cross the boundary between `IClaimsProvider`
and the (future) transformation pipeline. Its design is forward-compatible: no breaking
change to `IClaimsProvider` or `ClaimsProviderContext` is needed when the transformer is
added.

---

## Rejected Alternatives

### Option B — Snapshot claims at grant time; store them on the entry records

**Rejected.** Under the sliding refresh token lifetime defined by ADR 0008 — where
`RefreshTokenEntry.ExpiresAt` is `IssuedAt + RefreshTokenLifetime` and `IssuedAt` is the
timestamp of each individual rotation — a snapshot model means a role revocation, account
suspension, or group membership change is invisible to the token endpoint for an indefinite
period. Every rotation resets the clock, and ADR 0008 explicitly enforces no upper bound on
`RefreshTokenLifetime` by design (to support long-lived integrations). Continuous rotation
does not help: each rotation replays the same snapshot. The blast radius of a compromised
account or a mis-attributed role is therefore structurally unbounded for an active client,
not merely wide.

Short access token lifetimes (15 minutes per RFC 9700 §4.2.2) bound the window per issued
token, but continuous rotation allows an active client to keep refreshing — and receiving
stale-privileged access tokens — indefinitely, with no mechanism for the framework or the
operator to intervene without revoking the entire refresh token family. The 14-day default
single-token lifetime only caps the exposure of an inactive client that stops rotating; an
active client is not bounded by it.

The snapshot model also adds an implicit coupling between the authorization endpoint (which
collects claims) and the token endpoint (which replays them), with no defined seam through
which an operator can validate, transform, or replace the snapshot. The `IClaimsProvider`
seam does not exist in the snapshot model; claims transformation would require a separate,
additional hook with different lifecycle semantics.

Re-fetch via `IClaimsProvider` gives operators the re-validation hook for free as a
consequence of making every issuance call the provider. The snapshot model would require an
additional hook to achieve equivalent security coverage, with more surface area and more
complexity.

**Snapshotting with a bounded TTL can still be achieved.** Operators who prefer the
snapshot performance profile implement a caching `IClaimsProvider` with a TTL well under the
access token lifetime (see §8). This is the implementor's decision, not a framework mode. It
preserves the `IClaimsProvider` call on every issuance — meaning the framework's fail-closed
semantics and subject-validity check still apply — while reducing identity store round-trips
at the operator's discretion.

### No explicit seam — resolve claims by calling the identity store directly in the token endpoint

**Rejected.** A hardcoded identity store call in the token endpoint couples the framework to
a specific storage API. The framework's design principle — "framework, not black box" — rules
out hidden I/O dependencies in protocol endpoints. Any hardcoded store call is not replaceable
without forking the endpoint. The `IClaimsProvider` abstraction exists precisely to give the
host application control over this dependency without requiring a fork.

### Optional `IClaimsProvider` with a no-op default

**Rejected.** An optional provider with a no-op default that returns an empty claim set
would silently issue tokens with no subject claims for every deployment that does not
register a provider. A missing provider registration is a configuration error, not a valid
deployment state. Surfacing it at startup (as `ZeeKayDaConfigurationException`) rather than
at runtime (as empty tokens) gives the operator a clear signal and a clear fix. The
optional-with-default pattern is appropriate for optional capabilities; claims resolution is
not optional for a functioning identity provider.

### Separate interface for refresh rotation vs. first issuance

**Rejected.** A distinct `IRefreshClaimsProvider` for rotation calls (or an
`IsRefreshRotation` flag on the context) was considered to allow implementors to use
different resolution logic during rotation. The `FamilyId` field in `ClaimsProviderContext`
is a structurally-equivalent signal: a cache miss on `FamilyId` is the first issuance; a
cache hit is a rotation. Implementors who need different logic can branch on cache presence.
Exposing a separate interface or a discriminator flag encodes an implementation assumption
into the framework API, increases surface area, and would require explanation in every
doc and code review. The minimal context object with `FamilyId` achieves the same
capability without the added API surface.

---

## Consequences

### Positive

- **Privilege revocation is timely.** Disabling a subject or revoking a role takes effect
  at the next token issuance, bounded by the access token lifetime. There is no grant-lifetime
  staleness window. This is the strongest revocation guarantee achievable without token
  introspection.
- **Subject-validity check is structural.** Refresh token rotation cannot succeed for a
  disabled subject without the implementor explicitly returning `SubjectInvalid` from
  `IClaimsProvider`. The check is not a separate call; it is the natural consequence of
  requiring claims resolution on every issuance. This composes with session revocation
  (issues #103 and #104) without additional framework surface.
- **Single seam, no hidden I/O.** All claims resolution flows through `IClaimsProvider`.
  The token endpoint has no hidden identity store dependency. The full issuance pipeline is
  independently testable by supplying a stub `IClaimsProvider` with no running server required.
- **Access token and ID token are coherent.** Both tokens for a given issuance are built
  from the same claim set returned by a single `GetClaimsAsync` call. There is no state
  split where different tokens for the same issuance carry different claims.
- **No schema change to ADR 0008 entry records.** `AuthorizationCodeEntry` and
  `RefreshTokenEntry` remain exactly as ADR 0008 defined them. No `Claims` property, no
  serialisation change, no storage size increase.
- **Availability optimisation is available without API change.** A caching `IClaimsProvider`
  using `FamilyId` as a cache key achieves snapshot-equivalent performance. The API is already
  designed for this; no future change required.
- **Forward-compatible with claim transformation pipeline.** `ClaimRecord` and
  `IReadOnlyList<ClaimRecord>` are the transfer types. The transformer (issues #205, #206)
  sits downstream of `IClaimsProvider`; no breaking change to this ADR's API is needed when
  the transformer is added.

### Negative / Trade-offs

- **Every token issuance makes an identity store round-trip by default.** Implementors who
  do not cache will see one identity store call per token issuance, including every refresh
  rotation. For high-rotation workloads this may be a performance concern. The `FamilyId`
  caching pattern (§8) is the documented mitigation; operators are responsible for evaluating
  whether it is needed for their workload.
- **No framework-provided default implementation.** `IClaimsProvider` has no default. Every
  deployment must implement and register one. This is intentional (the framework cannot know
  where the host stores user data) but it means the "getting started" experience requires
  more initial code than a snapshot model, where a default could defer the claims question.
- **`ZeeKayDaConfigurationException` at startup for missing registration.** Operators who
  omit `IClaimsProvider` will see a startup failure, not a runtime failure. This is the
  correct behaviour (fail early, fail clearly) but it may surprise operators who use other
  frameworks with optional providers.
- **Implementors must handle the `SubjectInvalid` case.** An `IClaimsProvider` that always
  returns `Resolved` — perhaps because the implementor does not yet validate subject
  existence — will issue tokens for disabled subjects. The XML documentation on
  `IClaimsProvider` MUST clearly describe the `SubjectInvalid` contract and when it
  MUST be returned; this is an implementation burden that does not exist in the snapshot
  model.

---

## Security Considerations

### Re-fetch is the only way to make subject deactivation effective during token rotation

Under the snapshot model, a subject who is disabled or deleted between grant establishment
and the next rotation continues to receive new access tokens for the full refresh token
lifetime. `IClaimsProvider` closes this gap structurally: every rotation calls
`GetClaimsAsync`, and an implementor that validates subject existence as part of resolution
returns `SubjectInvalid` for a deactivated account. The framework treats `SubjectInvalid`
as `invalid_grant`, terminating the rotation and invalidating the refresh token. RFC 9700 §4.13
and the broader principle of RFC 6819 §4.4.2 support this: access grants must be revocable.

### Claims MUST NOT appear in logs, errors, or exceptions (ADR 0009 requirement)

Claims returned by `IClaimsProvider` may contain personal data (names, email addresses,
role identifiers). These values MUST NOT appear in log entries at any level, in OAuth 2.0
error responses (`error_description` etc.), or in exception messages that may propagate
through the logging pipeline. `SecretSanitizingLogger` (ADR 0009) provides structural
protection against claims appearing in structured log state if claim types are registered
as sensitive keys. The token endpoint MUST additionally ensure that `ClaimsResolutionResult`
values are not embedded in any exception message construction.

### Resolution failure must be fail-closed with no fallback

If `IClaimsProvider.GetClaimsAsync` throws, the token endpoint MUST NOT fall back to a
previous claim set, a cached claim set, or an empty claim set. Falling back would convert
an identity store outage into a pass for any token request during the outage window — an
attacker who can cause a controlled identity store failure gains free token issuance. The
only safe behaviour on an unexpected exception is to abort with `error=server_error`. The
operator's job is to ensure the identity store is available; the framework's job is to
fail closed when it is not.

### Caching inside `IClaimsProvider` MUST use a TTL well under the access token lifetime

An `IClaimsProvider` that caches by `FamilyId` with a grant-lifetime TTL is equivalent to
the snapshot model in terms of revocation latency: a disabled subject is not detected until
cache expiry. The security requirement is that any caching TTL must be well under the
access token lifetime — typically a fraction of it — so that a subject deactivation takes
effect within the TTL window. The framework cannot enforce this constraint on a custom
implementor, but the ADR and the `IClaimsProvider` XML documentation MUST state it clearly
as a security invariant.

A grant-lifetime or refresh-token-lifetime cache TTL defeats the entire purpose of
the re-fetch model and MUST NOT be used. It is equivalent to the snapshot model without
the clarity of an explicit API contract.

### `SubjectInvalid` is a security contract, not a convenience feature

The framework cannot mechanically enforce that `IClaimsProvider` returns `SubjectInvalid`
for a disabled or deleted subject — it can only define what happens when it does. An
implementation that always returns `Resolved` will issue tokens for deactivated accounts
without any compile-time error, startup failure, or runtime warning from the framework.
Combined with ADR 0008's sliding refresh token lifetime (no absolute upper bound), an
active client on such an implementation will refresh indefinitely and receive access tokens
carrying claims the subject no longer holds, with no mechanism for the operator to stop it
short of revoking the entire refresh token family out of band.

This is the residual risk the framework cannot eliminate structurally. It MUST be addressed
through documentation and sample code:

- The XML documentation on `IClaimsProvider` MUST make the `SubjectInvalid` contract
  impossible to miss — it is not optional subject-validation; it is how the operator's
  account-deactivation action takes effect in the token pipeline.
- Getting-started samples and documentation MUST demonstrate a `SubjectInvalid` return for
  a disabled/deleted subject, not just the `Resolved` happy path.
- The implementation PR that lands `IClaimsProvider` MUST include a test verifying that
  `SubjectInvalid` from the provider results in `invalid_grant` from the token endpoint.

### `FamilyId` logging hygiene

`FamilyId` appears in `ClaimsProviderContext` and may be passed to internal caches or
logged by implementors. It is not a bearer credential, but it is a correlator linking
every token in a chain. The logging guidance from ADR 0008 §"familyId logging hygiene"
applies here unchanged: if `FamilyId` must be logged, log `H(FamilyId)` truncated to
≥ 64 bits rather than the raw value.

### Single call per issuance — no split-brain claim sets

The requirement that access token and ID token for a single issuance are built from the
same `GetClaimsAsync` result eliminates the risk of split-brain: a scenario where the
access token contains a revoked role but the ID token does not (or vice versa) because
the identity store changed between two resolution calls. One call, one result, both tokens.
