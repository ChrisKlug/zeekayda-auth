# ADR 0008 — Authorization Code and Refresh Token Store

**Status:** Accepted (amended 2026-06-20)  
**Date:** 2026-06-07

**Amends ADR 0005 §6b** — extends the authorization-code bound-parameter list with
`AuthTime`, `Acr`, and `Amr`. See §2.

---

## Context

ADR 0005 established the authorization endpoint interaction orchestration and settled the
properties of the authorization code issued at the end of a successful interaction:

- Short-lived — ≤ 60 seconds (RFC 6749 §4.1.2, RFC 9700 §2.1.1)
- Generated from `RandomNumberGenerator` with ≥ 128 bits of entropy
- Bound to: `client_id`, validated `redirect_uri`, `code_challenge` + `code_challenge_method`,
  user `sub`, SSO session ID, interaction context ID
- Compared using `CryptographicOperations.FixedTimeEquals` at redemption time

ADR 0005 explicitly deferred the storage contract: *"The store that persists codes (and later
refresh tokens) is a separate concern. It must be shared across instances and durable enough to
enforce single-use across the brief window between issuance and redemption; see the
authorization-code/refresh-token store ADR."*

Two questions were left open by ADR 0005:

1. **Should the token store use `IDistributedCache` directly** (following the precedent of the
   interaction context store in §6b), or should it define purpose-specific interfaces?

2. **How should the store express the semantics required by the spec** — single-use enforcement
   (RFC 9700 §2.1.1) and refresh token family revocation (RFC 9700 §4.13) — which have no direct
   equivalent in the key-value abstraction?

A third concern, which does not arise for the interaction context, is the consequences of a
server restart. The interaction context is also short-lived and can be lost on restart without
user-visible harm; a refresh token is long-lived (hours to days) and losing it forces users to
re-authenticate. The two stores have fundamentally different durability requirements and must be
designed independently.

This ADR also closes several questions left implicit in earlier ADRs: where on
`AuthorizationServerOptions` lifetime knobs live (per the ADR 0002 grouping rule), what the
exception contract is for store implementations (per ADR 0006), and which deferred capabilities
(revocation endpoint, introspection endpoint, back-channel logout, telemetry) the store
interface is expected to grow into. The interface is shaped so those additions are purely
additive.

### Why this ADR is necessary now

The token endpoint cannot be implemented without a settled store contract. The store interface
determines:
- How single-use is enforced (and what happens when it is violated)
- How the token endpoint detects refresh token reuse and triggers family revocation
- Where the default implementation lives and what infrastructure it requires
- What documentation and guidance consumers need to deploy safely

These decisions affect the public API surface of both `ZeeKayDa.Auth` (the store interfaces and
data types) and `ZeeKayDa.Auth.AspNetCore` (the default implementations and DI registration).
Deferring them further would block the token endpoint entirely.

---

## Decision

### 1. Store interface design: purpose-specific interfaces backed by a default `IDistributedCache` implementation

Two dedicated interfaces are defined — `IAuthorizationCodeStore` and `IRefreshTokenStore` — in
`ZeeKayDa.Auth` (the core package, no ASP.NET Core knowledge). Default implementations of both
interfaces, backed by `IDistributedCache` and `IMemoryCache`, also live in `ZeeKayDa.Auth`
(see §5 for the package-placement rationale; the dependencies these defaults pull in are
covered by the namespace-level allowlist in [ADR 0001 §3](0001-endpoint-architecture-pattern.md#3-layering-strict-core--aspnetcore-boundary)).

**Why not `IDistributedCache` directly?**

ADR 0005 §6b chose `IDistributedCache` for the interaction context store and explicitly stated the
guiding principle: *"do not create a ZeeKayDa abstraction when a standard .NET abstraction already
exists for the same purpose."* That principle was correct for the interaction context, because the
interaction context lifecycle is write-once, read-once, delete — semantics that map cleanly onto
a key-value cache.

The token stores have richer semantics that do not map onto `IDistributedCache`:

- **Atomic single-use enforcement (RFC 9700 §2.1.1).** On second presentation of an
  authorization code, ZeeKayDa must detect the replay and revoke the associated refresh token
  family — not merely return a "not found" error. This requires distinguishing three states:
  *valid and unredeemed*, *already redeemed (tombstone)*, and *not found*. `IDistributedCache`
  has no native compare-and-swap or atomic test-and-delete. The tombstone state is not
  representable without leaking implementation detail into the token endpoint logic.

- **Refresh token family revocation (RFC 9700 §4.13).** When reuse is detected, every token
  sharing the same `familyId` must be revoked in a single operation. `IDistributedCache` has no
  set-query or multi-key operation. Encoding family revocation in `IDistributedCache` forces
  the caller to know the key-space convention — which is precisely the implementation detail
  that a store interface is meant to encapsulate.

Forcing these semantics into `IDistributedCache` would either (a) silently lose them — the
`IDistributedCache`-backed implementation would have a TOCTOU window that is not visible to
callers — or (b) leak implementation detail (key-space manipulation) into the token endpoint,
making it impossible to replace the default with a Redis/Lua or SQL-optimistic-concurrency
implementation without also changing the endpoint logic.

Purpose-specific interfaces express the required semantics as method contracts. The token
endpoint calls `TryRedeemAsync` and receives a typed outcome; it does not need to know how
the store detects replay. A consumer replacing the default implementation with a
Redis-Lua-backed store can do so without touching the token endpoint.

The interaction context comparison reinforces rather than contradicts this decision: the
interaction context genuinely needed only `IDistributedCache` semantics; the token stores
genuinely need more. Using the same abstraction for both would misrepresent one of them.

### 2. Authorization code store contract

`IAuthorizationCodeStore` is defined in `ZeeKayDa.Auth`:

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Stores and redeems short-lived authorization codes, enforcing single-use per
/// RFC 9700 §2.1.1 and atomic client-binding per RFC 6749 §4.1.3.
/// </summary>
/// <remarks>
/// Implementations must be able to distinguish four states for a given code handle:
/// (1) present, unredeemed, and bound to the presenting client;
/// (2) present but bound to a different client (ClientMismatch — must NOT be consumed);
/// (3) already redeemed (tombstone);
/// (4) never issued / expired beyond the tombstone retention window.
/// The distinction between (3) and (4) is load-bearing: a second presentation of a
/// redeemed code must trigger refresh token family revocation. The distinction between
/// (2) and (3)/(4) prevents a confused-deputy attack where an attacker who captured the
/// code can DoS the legitimate client by causing the code to be consumed under the wrong
/// client_id.
/// </remarks>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Persists a newly issued authorization code entry.
    /// Called by the authorization endpoint immediately after code generation.
    /// </summary>
    /// <remarks>
    /// Implementations MUST fail closed: any I/O failure MUST surface as a
    /// <see cref="ZeeKayDaStoreException"/> (see §"Failure modes and exception contract")
    /// and the authorization endpoint MUST abort the response — no code may be returned
    /// to the client until <see cref="StoreAsync"/> has completed successfully.
    /// </remarks>
    Task StoreAsync(AuthorizationCodeEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Redeems the authorization code identified by <paramref name="code"/> for the client
    /// identified by <paramref name="clientId"/>, binding the prospective refresh-token
    /// <paramref name="familyId"/> into the tombstone in the same step. The
    /// client-binding check and the consume step MUST be performed atomically by
    /// implementations targeting multi-instance production deployments.
    /// </summary>
    /// <remarks>
    /// The shipped <c>IDistributedCache</c>-backed default does NOT satisfy the atomicity
    /// requirement and is dev/test-only; see §4c. The shipped in-memory default is atomic
    /// via per-handle semaphores. Custom stores targeting multi-instance production MUST
    /// use backend-specific primitives (Redis+Lua, SQL with optimistic concurrency, etc.)
    /// to close the TOCTOU window — see §4c and §8.
    /// </remarks>
    /// <param name="familyId">
    /// A freshly-minted refresh-token family identifier (≥ 128 bits CSPRNG entropy) chosen
    /// by the token endpoint BEFORE this call. On a successful redemption, this identifier
    /// MUST be written into the tombstone in the same atomic step that marks the code as
    /// redeemed, so that a later replay producing <see cref="AuthorizationCodeRedemptionOutcome.AlreadyRedeemed"/>
    /// is guaranteed to carry the correct family identifier for revocation. The token
    /// endpoint then uses this same <paramref name="familyId"/> when constructing the
    /// new <see cref="RefreshTokenEntry"/>.
    /// </param>
    /// <returns>
    /// <see cref="AuthorizationCodeRedemptionOutcome"/> describing the outcome.
    /// </returns>
    ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
        string code,
        string clientId,
        string familyId,
        CancellationToken cancellationToken);
}
```

**`AuthorizationCodeEntry`** (a `sealed` record in `ZeeKayDa.Auth.Stores`) carries the
properties below. Properties marked **R** are declared `required` on the record (failure
to set them at construction is a compile-time error); all others are nullable or have
sensible defaults so the record remains additively-extensible without a binary break:

| Property | Req | Type | Notes |
|---|---|---|---|
| `ClientId` | **R** | `string` | Bound at issuance (RFC 6749 §4.1.2) |
| `RedirectUri` | **R** | `string` | Exact-match validated redirect URI (RFC 6749 §4.1.3) |
| `CodeChallenge` | **R** | `string` | PKCE challenge value (RFC 7636 §4.2; mandatory per OAuth 2.1 §4.1.1) |
| `CodeChallengeMethod` | **R** | `CodeChallengeMethod` | Always `S256` in the current implementation |
| `Sub` | **R** | `string` | Authenticated user subject identifier |
| `Scope` | **R** | `IReadOnlyList<string>` | Granted scope values |
| `Nonce` |  | `string?` | OIDC nonce — null for pure OAuth 2 flows |
| `AuthTime` | **R** | `DateTimeOffset` | Time of end-user authentication for this code (OIDC Core §2 `auth_time`). Bound at issuance because the SSO session value may have advanced by the time the code is exchanged; `max_age` enforcement and ID-token `auth_time` MUST reflect the authentication that produced *this* code. |
| `Acr` |  | `string?` | Authentication Context Class Reference at issuance (OIDC Core §2). Null when no ACR was satisfied. |
| `Amr` |  | `IReadOnlyList<string>?` | Authentication Methods References at issuance (OIDC Core §2). Null when not applicable. |
| `SsoSessionId` | **R** | `string` | Binds the code to the SSO session established during the interaction |
| `InteractionId` | **R** | `string` | The interaction context ID that produced this code |
| `IssuedAt` | **R** | `DateTimeOffset` | UTC timestamp of issuance |
| `ExpiresAt` | **R** | `DateTimeOffset` | UTC expiry — at most `IssuedAt + AuthorizationCodeLifetime` (default 60 s; see §"Options placement") |

The raw handle is **not** stored on the entry. Replay detection happens via the cache
key (`SHA-256(handle)` — §4a): a presented handle either hits its hashed-key entry or it
does not. SHA-256 over a ≥128-bit CSPRNG input is collision-resistant; a false-positive
key collision is not a realistic attack model. Removing the raw handle from the entry
value means a DP-unprotect compromise does not double-expose the bearer credential.
Custom stores that retain raw handles for their own reasons (e.g. legacy schema) MUST
compare them using `CryptographicOperations.FixedTimeEquals` — see §"Handle comparison".

Binding `AuthTime`/`Acr`/`Amr` onto the code is the same pattern ADR 0005 §6b applies to
`nonce`: parameters fixed at the moment of authentication are captured at the code, not
re-read from the SSO session at redemption. **This ADR amends ADR 0005 §6b's
bound-parameter list to include `AuthTime`, `Acr`, and `Amr`** (see the "Amends" header
at the top of this ADR); no follow-up ADR is required.

**`AuthorizationCodeRedemptionOutcome`** is a closed hierarchy using the nested-class +
private-constructor idiom (the C# convention for closed discriminated unions today; see
`dotnet/csharplang#113` for the language-level proposal that may replace it):

```csharp
namespace ZeeKayDa.Auth.Stores;

public abstract class AuthorizationCodeRedemptionOutcome
{
    private AuthorizationCodeRedemptionOutcome() { }

    /// <summary>
    /// The code was valid, bound to the presenting client, and has been marked as
    /// redeemed. The tombstone has been written carrying the <c>familyId</c> that the
    /// caller passed into <see cref="IAuthorizationCodeStore.TryRedeemAsync"/>; any
    /// subsequent replay will surface as <see cref="AlreadyRedeemed"/> with that
    /// familyId populated. The entry is returned for the token endpoint to complete
    /// the exchange.
    /// </summary>
    public sealed class Redeemed : AuthorizationCodeRedemptionOutcome
    {
        public required AuthorizationCodeEntry Entry { get; init; }
    }

    /// <summary>
    /// The code exists and is unredeemed but is bound to a different client. The store
    /// has NOT consumed the code. The caller MUST return <c>error=invalid_grant</c>
    /// and SHOULD emit a security-relevant log event (potential code-injection / DoS
    /// against the legitimate client).
    /// </summary>
    public sealed class ClientMismatch : AuthorizationCodeRedemptionOutcome { }

    /// <summary>
    /// The code has already been redeemed. Per RFC 9700 §2.1.1, the caller MUST
    /// revoke the refresh token family identified by <see cref="FamilyId"/> and
    /// return <c>error=invalid_grant</c> to the client.
    /// </summary>
    public sealed class AlreadyRedeemed : AuthorizationCodeRedemptionOutcome
    {
        /// <summary>
        /// The refresh token family ID that was committed into the tombstone during
        /// the original redemption. Always non-null: the family ID is written into the
        /// tombstone atomically with the redemption itself (single-phase commit), so
        /// every observed <see cref="AlreadyRedeemed"/> carries a usable target for
        /// <see cref="IRefreshTokenStore.RevokeFamilyAsync"/>.
        /// </summary>
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The code is not known to the store — never issued, the tombstone has been
    /// garbage-collected, or the code is syntactically invalid.
    /// The caller MUST return <c>error=invalid_grant</c>.
    /// </summary>
    public sealed class NotFound : AuthorizationCodeRedemptionOutcome { }
}
```

The sealed private constructor prevents consumers from adding subtypes. The token endpoint
switches exhaustively over the four known outcomes; an unknown subtype is structurally
impossible. Hot-path return types are `ValueTask<T>` because most cache lookups complete
synchronously after the first hit; the asymmetry with `Task` on the write path
(`StoreAsync`) is intentional — that path always performs I/O.

**Single-use semantics — record-of-redemption, not record-of-validity:**

On first redemption, the store marks the code as redeemed rather than deleting it.
Deletion would make a subsequent replay indistinguishable from a `NotFound` case,
preventing the family revocation required by RFC 9700 §2.1.1. The tombstone must remain
alive long enough that any token issued from this code is still revocable when the replay
is detected. The chosen tombstone retention is therefore **max refresh-token lifetime**
(not 60 s + small grace as a previous draft proposed); see §"Options placement".
Tombstones are tiny (a few hundred bytes) — retention cost is negligible. Capacity-plan
implications are covered in §8.

**Pre-commit `familyId` (single-phase redemption):**

The token endpoint:

1. Mints `familyId` (≥ 128 bits CSPRNG) up front, before any store call.
2. Calls `TryRedeemAsync(code, clientId, familyId, ct)`. On `Redeemed`, the tombstone
   has already been written with `FamilyId = familyId` in the same atomic step.
3. Issues access/ID/refresh tokens. Calls `IRefreshTokenStore.StoreAsync(...)` using the
   same `familyId` to construct the new `RefreshTokenEntry`.
4. Returns the token response to the client.

If step 3 throws, the endpoint MUST call `RevokeFamilyAsync(familyId)` before propagating
(see §7). On a non-`Redeemed` outcome (`AlreadyRedeemed`, `ClientMismatch`, `NotFound`),
the caller MUST discard its locally-minted `familyId` — it was never associated with any
stored entry and requires no cleanup. In particular, on `AlreadyRedeemed` the caller
MUST revoke the `FamilyId` returned in the outcome (the one that landed in the
tombstone), not the locally-minted one.

The previous draft used a two-phase
`TryRedeemAsync` → `CompleteRedemptionAsync` shape; that design opened a race window in
which `AlreadyRedeemed` could carry a null `FamilyId`, allowing an attacker to escape the
RFC 9700 §2.1.1 family-revocation mandate. Pre-committing the familyId closes the race
unconditionally — across every backend, atomic or non-atomic — at the cost of nothing
the endpoint did not need to compute anyway. See "Rejected alternatives" for the full
analysis.

### 3. Refresh token store contract

`IRefreshTokenStore` is defined in `ZeeKayDa.Auth`:

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Stores, rotates, and revokes refresh tokens, enforcing rotation and reuse detection per
/// RFC 9700 §4.13 and atomic client-binding per RFC 6749 §10.4.
/// </summary>
/// <remarks>
/// The interface is intentionally minimal in v1. It is expected to grow:
/// <list type="bullet">
///   <item><c>RevokeAsync(handle, ...)</c> for the RFC 7009 revocation endpoint
///         (see issue #105).</item>
///   <item><c>RevokeBySessionAsync(ssoSessionId, ...)</c> for back-channel logout
///         (see issue #103).</item>
/// </list>
/// Forward-compatibility strategy: post-1.0 additions ship as <c>default</c> interface
/// methods (DIMs), throwing <see cref="NotSupportedException"/> by default. Custom stores
/// compile against new versions without source changes; opting in is an override. This
/// preserves binary compatibility per the SemVer commitment in ADR 0001. See the
/// "Forward compatibility and SemVer" subsection below.
/// </remarks>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Persists a newly issued or rotated refresh token entry.
    /// Called by the token endpoint after every successful token issuance or refresh.
    /// </summary>
    /// <remarks>
    /// Implementations MUST fail closed — any I/O failure surfaces as
    /// <see cref="ZeeKayDaStoreException"/> and the token endpoint MUST abort the response.
    /// Rotation-specific mid-flight failure handling is specified in §7.
    /// </remarks>
    Task StoreAsync(RefreshTokenEntry entry, CancellationToken cancellationToken);

    /// <summary>
    /// Non-destructive lookup, used by the RFC 7662 introspection endpoint and by
    /// diagnostic tooling. MUST NOT consume, mark, or otherwise alter the entry.
    /// Returns <see langword="null"/> for tokens that have been consumed (rotated out),
    /// expired, never issued, or belong to a revoked family. Only the currently-active
    /// handle in a rotation chain is observable; this is the correct RFC 7662 §2.2
    /// behaviour — introspection on a rotated-out handle returns <c>active=false</c>.
    /// </summary>
    ValueTask<RefreshTokenEntry?> FindAsync(
        string tokenHandle,
        CancellationToken cancellationToken);

    /// <summary>
    /// Attempts to consume the refresh token identified by <paramref name="tokenHandle"/>
    /// for the client identified by <paramref name="clientId"/>. The client-binding check
    /// (RFC 6749 §10.4) MUST be performed atomically with consumption by implementations
    /// targeting multi-instance production deployments. A consumed token may not be used
    /// again; the caller must issue a new token (rotation) before returning the response.
    /// </summary>
    /// <remarks>
    /// The shipped <c>IDistributedCache</c>-backed default does NOT satisfy the atomicity
    /// requirement and is dev/test-only; see §4d. The shipped in-memory default is atomic
    /// via per-handle semaphores. Custom stores targeting multi-instance production MUST
    /// close the TOCTOU window with backend-specific primitives — see §4d and §8.
    /// </remarks>
    /// <returns>
    /// <see cref="RefreshTokenConsumptionOutcome"/> describing the outcome.
    /// </returns>
    ValueTask<RefreshTokenConsumptionOutcome> TryConsumeAsync(
        string tokenHandle,
        string clientId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Revokes all refresh tokens belonging to the family identified by
    /// <paramref name="familyId"/>. Must be idempotent — calling this method on an
    /// already-revoked family must not throw.
    /// </summary>
    /// <remarks>
    /// Called by the token endpoint whenever reuse is detected (RFC 9700 §4.13), whenever
    /// a rotation fails mid-flight (see §"Failure modes and exception contract"), or
    /// whenever the host application explicitly revokes a session. Transport failures
    /// MUST surface as <see cref="ZeeKayDaStoreException"/>; the caller decides whether
    /// to retry or propagate.
    /// </remarks>
    Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken);
}
```

**`RefreshTokenEntry`** (a `sealed` record in `ZeeKayDa.Auth.Stores`) carries the
properties below. Properties marked **R** are declared `required` on the record; all
others are nullable or have sensible defaults so the record remains
additively-extensible (e.g. for DPoP jkt / MTLS thumbprint in issue #100) without a
binary break.

| Property | Req | Type | Notes |
|---|---|---|---|
| `FamilyId` | **R** | `string` | Shared across all rotations of a token chain (opaque, generated once per code exchange) |
| `PreviousTokenHandleHash` |  | `string?` | `Base64Url(SHA-256(previousHandle))` — the hash of the handle this token was rotated *from*, or `null` for the original token in the family. Forensic forward-tracing only; never used for authorization decisions. Stored as a hash, not the raw handle, because retaining the raw previous handle would defeat the §4a protection (handle-hashing in cache keys) by reintroducing the live bearer credential into stored entry values. |
| `ClientId` | **R** | `string` | Bound at issuance |
| `Sub` | **R** | `string` | Authenticated user subject identifier |
| `Scope` | **R** | `IReadOnlyList<string>` | Granted scope values for this refresh token. Rotation MUST NOT widen scope; see RFC 6749 §6 — the token endpoint enforces this before calling `StoreAsync`. |
| `SsoSessionId` | **R** | `string` | The SSO session that produced this token; used by future session-linked revocation (see issue #104) |
| `IssuedAt` | **R** | `DateTimeOffset` | UTC timestamp |
| `ExpiresAt` | **R** | `DateTimeOffset` | UTC expiry — `IssuedAt + RefreshTokenLifetime` (see §"Options placement") |

The raw token handle is **not** stored on the entry. As with `AuthorizationCodeEntry`,
the cache key is `SHA-256(handle)` (§4a); lookup is the comparison.

**`RefreshTokenConsumptionOutcome`** follows the same closed-hierarchy idiom:

```csharp
namespace ZeeKayDa.Auth.Stores;

public abstract class RefreshTokenConsumptionOutcome
{
    private RefreshTokenConsumptionOutcome() { }

    /// <summary>
    /// The token was valid, bound to the presenting client, and has been marked as
    /// consumed. The caller MUST issue a rotated replacement before returning a response.
    /// </summary>
    public sealed class Consumed : RefreshTokenConsumptionOutcome
    {
        public required RefreshTokenEntry Entry { get; init; }
    }

    /// <summary>
    /// The token exists but is bound to a different client (RFC 6749 §10.4). The store
    /// has NOT consumed the token and has NOT triggered family revocation: doing so
    /// would create a DoS where an attacker who captured a refresh token could kill the
    /// legitimate session simply by presenting the token under their own client_id.
    /// The caller MUST return <c>error=invalid_grant</c> and SHOULD emit a
    /// security-relevant log event.
    /// </summary>
    public sealed class ClientMismatch : RefreshTokenConsumptionOutcome { }

    /// <summary>
    /// The token has already been consumed. Per RFC 9700 §4.13, the caller MUST
    /// revoke the entire family identified by <see cref="FamilyId"/> and return
    /// <c>error=invalid_grant</c>.
    /// </summary>
    public sealed class AlreadyConsumed : RefreshTokenConsumptionOutcome
    {
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The token belongs to a family that has already been revoked. Behaviour for the
    /// client is identical to <see cref="AlreadyConsumed"/> (<c>invalid_grant</c>), but
    /// surfacing it as a distinct case lets the token endpoint emit a different
    /// telemetry signal: a token-after-revocation event is a strong attack indicator
    /// (the family was revoked precisely because reuse was detected earlier), whereas
    /// <see cref="AlreadyConsumed"/> is the trigger event itself.
    /// </summary>
    public sealed class Revoked : RefreshTokenConsumptionOutcome
    {
        public required string FamilyId { get; init; }
    }

    /// <summary>
    /// The token is not known to the store — expired or never issued.
    /// The caller MUST return <c>error=invalid_grant</c>.
    /// </summary>
    public sealed class NotFound : RefreshTokenConsumptionOutcome { }
}
```

Outcomes are deliberately rich so an observability layer can meter the security-relevant
distinctions (`ClientMismatch`, `AlreadyConsumed`, `Revoked`) without a second round-trip
to the store — see "Forward references" below.

**Family tracking rules (RFC 9700 §4.13):**

- A new `familyId` is minted once — at authorization code exchange. Every refresh token issued
  in that chain (original plus all rotations) shares that `familyId`.
- `familyId` is an opaque handle generated from `RandomNumberGenerator` with ≥ 128 bits of
  entropy, identical to the code and token handle generation policy.
- On every successful refresh, the old token handle is consumed by replacing its
  `zkd:rt:{H(handle)}` entry with a consumed-token tombstone that records `familyId`.
  Deleting the old entry would turn replay into `NotFound` and lose the RFC 9700 §4.13
  family-revocation trigger. A new `RefreshTokenEntry` is stored under the cache key
  `zkd:rt:{H(newHandle)}` (per §4a), with the same `familyId` and
  `PreviousTokenHandleHash = Base64Url(SHA-256(consumedHandle))`. The fresh handle itself
  is **not** stored on the entry — the hashed cache key *is* the comparison (§4a).
- When `TryConsumeAsync` returns `AlreadyConsumed`, the token endpoint calls
  `RevokeFamilyAsync(familyId)` before returning `error=invalid_grant`. This is the mandatory
  response to a detected refresh token replay (RFC 9700 §4.13 — the AS "MUST revoke all tokens
  in the token family").
- `RevokeFamilyAsync` must be idempotent. A double-invocation (e.g., from a race between
  concurrent requests) must not throw. Calling `RevokeFamilyAsync` with a `familyId` that
  has no associated entries — e.g. a defensive call from a `catch` block, or the
  concurrent-redemption "orphan family" case described in §4c — is a successful
  idempotent operation: the marker is written, no entries are affected, and the call
  MUST NOT throw.

**Rotation is single-use and non-configurable.** Every successful refresh token exchange must
consume the presented handle and issue a new one; the new handle is what the client receives.
Presenting the same handle a second time — even before it expires — is treated as evidence of
token theft and triggers full family revocation.

RFC 9700 §4.14.2 requires authorization servers to use **one of** the following replay-detection
mechanisms for public clients: refresh token rotation **or** sender-constrained tokens (e.g.
DPoP per RFC 9449, mutual TLS per RFC 8705). ZeeKayDa.Auth does not implement sender-constrained
tokens in v1, so rotation is the only available mechanism and is therefore applied universally —
for public and confidential clients alike — without a configuration knob. Making rotation
configurable would create a path to disable the only replay-detection mechanism in the framework,
which is not an acceptable trade-off.

Sender-constrained refresh tokens are tracked as a future capability (see issue #100). When DPoP
support is added, a new ADR will determine whether rotation can be relaxed for clients that opt
in to proof-of-possession binding. The `IRefreshTokenStore` interface is deliberately minimal to
avoid closing off that extension path.

#### 3a. Forward compatibility and SemVer

`IRefreshTokenStore` is published in v1 with four methods (`StoreAsync`, `FindAsync`,
`TryConsumeAsync`, `RevokeFamilyAsync`). Three categories of addition are anticipated
(§12): `RevokeAsync`, `RevokeBySessionAsync`, and possibly DPoP/MTLS lookup variants.

Per ADR 0001's SemVer commitment, adding members to a public interface is a binary
breaking change unless those members ship as **`default` interface methods (DIMs)**. This
ADR adopts DIMs as the forward-evolution mechanism:

- Each post-1.0 addition declares a default body that throws
  `NotSupportedException` with a message naming the missing capability (e.g.
  *"This IRefreshTokenStore implementation does not support RevokeBySessionAsync; the
  back-channel logout endpoint requires an opt-in override."*).
- The endpoint that needs the capability is responsible for surfacing that as a
  configuration / capability error to the operator at startup where possible, or as a
  clean 5xx at request time otherwise.
- Custom stores that *want* the capability override the default; custom stores that
  *don't* recompile cleanly and remain functional for the surface they did implement.

**Rejected alternatives:**

- *Separate interfaces (`IRevocableRefreshTokenStore`, `ISessionRevocableRefreshTokenStore`)
  per capability.* Splits the public surface — most stores would end up implementing all
  of them, defeating the discoverability benefit. Capability detection at runtime via
  `is` checks is more error-prone than a uniform interface with overridable defaults.
- *Treat the additions as pre-1.0 churn.* The project's SemVer discipline prohibits
  unannounced breakage, and 1.0 is the relevant horizon for store implementers building
  against the public abstractions today.

DIMs were introduced in C# 8 / .NET Core 3.0 and are fully supported on .NET 10 (the
project floor — ADR 0001). No platform constraint blocks this strategy.

### 4. Default implementations

Two defaults ship out of the box:

| Default | Backed by | Suitable for |
|---|---|---|
| `InMemoryAuthorizationCodeStore` / `InMemoryRefreshTokenStore` | `IMemoryCache` + per-handle `SemaphoreSlim` | Development and testing only. Provides true atomicity for single-use and rotation within the process. **Single-instance is a deployment invariant, not a recommendation** — see §9 and the XML doc on each in-memory store. Refresh tokens are lost on restart. |
| `DistributedCacheAuthorizationCodeStore` / `DistributedCacheRefreshTokenStore` | `IDistributedCache` | Dev/test against `AddDistributedMemoryCache`, and as a starting point for custom multi-instance implementations. **Not production-grade for multi-instance hosts** — the non-atomic check-then-set permits a measurable revocation-bypass window (§4d, §"Security Considerations"). Multi-instance production deployments MUST replace this with an atomic implementation; see §8. |

Neither default is auto-registered. `AddZeeKayDaAuth` leaves both `IAuthorizationCodeStore`
and `IRefreshTokenStore` unregistered. Consumers must choose explicitly (see §5). Multi-instance
production deployments MUST replace these defaults with a custom store backed by an atomic
backend (Redis+Lua, SQL with optimistic concurrency, or equivalent) — see §8.

#### 4a. Key derivation: cache keys MUST be `SHA-256(handle)`, never the raw handle

The raw token handle is a bearer credential with ≥ 128 bits of entropy. Using it as a cache
key exposes that credential to anyone with cache read access: Redis ops, backups, log
sidecars, SIEM pipelines that ingest cache traffic. RFC 6819 §5.1.4.1.3 and RFC 9700 §4.14.2
require the token *value* to be protected; encrypting the entry value while leaving the
key plaintext does not satisfy this. Both OpenIddict and Duende IdentityServer hash handles
before using them as storage keys for the same reason.

All cache keys in the default implementations are therefore derived as:

```
key (handle-keyed shape) = "zkd:" + <segment> + ":" + Base64Url(SHA256(handle))
```

The formula above describes the *handle-keyed* entries and tombstones. The
`<segment>` is `code` for authorization-code entries and `rt` for refresh-token entries.
The family-revocation marker uses an extended shape (`zkd:rt:family:{H(familyId)}:revoked`)
because the marker is keyed by `familyId`, not by a handle, and is distinguished by a
trailing `:revoked` suffix so it cannot collide with a handle-keyed entry. The full
key-space layout is:

| Entry type | Cache key |
|---|---|
| Authorization code entry (unredeemed) | `zkd:code:{H(handle)}` |
| Authorization code tombstone (redeemed) | `zkd:code:{H(handle)}:redeemed` |
| Refresh token entry | `zkd:rt:{H(handle)}` |
| Refresh token tombstone (consumed) | `zkd:rt:{H(handle)}` (same key, value replaced with consumed marker carrying `familyId`) |
| Family revocation marker | `zkd:rt:family:{H(familyId)}:revoked` |

Plain SHA-256 (no HKDF, no per-tenant salt) is sufficient: with ≥ 128 bits of input entropy
the preimage is computationally infeasible to recover from the hash, and the security goal
here is preventing credential exposure from the key, not preventing offline brute force of a
low-entropy secret.

The `zkd:` namespace prefix prevents collision when the host shares a cache. **The key-space
layout is implementation detail of the default stores, not part of the interface contract.**
A custom `IDistributedCache`-based store is free to use a different layout; downstream code
MUST NOT depend on these key shapes.

#### 4b. Encryption at rest

Stored entry *values* carry sensitive personal data (`sub`, `scope`, session IDs). The
default implementations serialise each entry to JSON and encrypt the serialised bytes using
`IDataProtectionProvider` before writing to the cache. Data Protection purpose strings:

- `ZeeKayDa.Auth:AuthorizationCodeStore`
- `ZeeKayDa.Auth:RefreshTokenStore`

Family-revocation markers carry no secret material (just the marker existence) and are
written plaintext. This is deliberate: a DP unprotect failure on a marker would otherwise
fail-closed into "not revoked", which is the wrong direction. Markers as plaintext fail-safe
toward "still revoked" if reading succeeds at all.

**DP unprotect failure on an entry value MUST be treated as `NotFound`** — never as
"successful read of empty entry". Operators MUST configure Data Protection key retention
to at least the maximum refresh-token lifetime; shorter retention causes silent fail-closed
behaviour where users are logged out after key rotation (see §"Failure modes and exception
contract" and §7).

#### 4c. Atomicity: in-memory default is atomic; distributed default is not

The in-memory default holds a `ConcurrentDictionary<string, SemaphoreSlim>` keyed by the
hashed handle. `TryRedeemAsync` / `TryConsumeAsync` acquire the per-handle semaphore around
the read-mark-write sequence, producing genuine atomicity within the process. Semaphores
are removed lazily when the underlying entry expires.

The `IDistributedCache` default cannot do this. `IDistributedCache` exposes no
compare-and-swap, no Lua, and no multi-key transaction. Its single-use enforcement is a
non-atomic check-then-set:

1. Read the tombstone key. If present → `AlreadyRedeemed` / `AlreadyConsumed`.
2. Otherwise read the entry, verify client binding, write the tombstone, return `Redeemed` /
   `Consumed`.

A TOCTOU window exists between steps 1 and 2. **This window is exploitable on any deployment
— including single-instance.** ASP.NET Core / Kestrel serves concurrent requests across the
thread pool; a single process handles many token requests in parallel. A previous draft of
this ADR claimed single-instance was safe because requests are sequential. That claim was
wrong and has been removed. The distributed default is suitable for dev/test (where the race
is harmless) and as a starting point for custom implementations that close the race with
backend-specific primitives. It is **not** the recommended production default.

Single-instance production should use a persistent store (or `.AddDistributedCacheTokenStores()`
against a durable backend) rather than the in-memory default — the in-memory stores are
development and testing only (see §5). Multi-instance production should use a Redis+Lua or
SQL-with-optimistic-concurrency implementation; the framework documents the pattern but does not
ship a Redis dependency (see §8).

**Redemption race in the distributed default — unrecoverable familyId.** The pre-commit
`familyId` design (§2) ensures every *individual* `AlreadyRedeemed` outcome carries a
usable target for family revocation. In the non-atomic distributed default, however, a
true concurrent double-`Redeemed` produces a worse outcome that the per-outcome guarantee
cannot fix. Consider:

1. Endpoint instance A mints `familyId_A`, calls `TryRedeemAsync(code, c, familyId_A)`.
   Reads tombstone → absent. Reads entry → present, client matches.
2. Endpoint instance B mints `familyId_B`, calls `TryRedeemAsync(code, c, familyId_B)`.
   Reads tombstone → still absent (A hasn't written yet). Reads entry → present, client
   matches.
3. A writes the tombstone `{familyId: familyId_A}`, returns `Redeemed`. The token
   endpoint issues a refresh token in family A (`StoreAsync(RefreshTokenEntry { FamilyId = familyId_A })`).
4. B writes the tombstone `{familyId: familyId_B}` (overwriting A's), returns
   `Redeemed`. The token endpoint issues a refresh token in family B.
5. An attacker (or the legitimate client retrying) presents the code a third time and
   gets `AlreadyRedeemed(FamilyId = familyId_B)`. The endpoint calls
   `RevokeFamilyAsync(familyId_B)`. **Family A is never revoked through the normal
   replay-detection path** — its tokens persist until natural expiry.

The net effect is that a concurrent double-redemption produces one revocable family and
one orphan family. Which of the two surviving requests was the attacker's vs the
legitimate client's is 50/50 by timing — the orphan family may be either. The in-memory
default closes this via the per-handle semaphore; atomic backends (Redis+Lua, SQL with
single transaction) close it natively. The distributed default documents but does not
fix it. This is the same risk class as §4d's family-revocation marker race, and the
remediation is identical: **multi-instance production MUST replace the distributed
default with an atomic backend; see §8.**

#### 4d. Family revocation in the distributed default

`RevokeFamilyAsync` writes a revocation marker (`zkd:rt:family:{H(familyId)}:revoked`)
rather than enumerating individual token entries — `IDistributedCache` cannot enumerate.
`TryConsumeAsync` and `FindAsync` check the marker; if present, they return `Revoked` /
`null` respectively.

**Marker TTL = `RefreshTokenLifetime` + small grace.** Once every token plausibly issued
into the family has expired, the marker is a no-op and can be evicted. A previous draft
called the marker "pinned" — that wording has been dropped; an unbounded marker would grow
unboundedly. The grace covers clock skew between the issuer and the cache backend.

**Family revocation marker race (distributed default — not benign):** The marker-check
and consume steps in `TryConsumeAsync` are not atomic with `RevokeFamilyAsync`. Consider
the staggered rotation scenario:

1. Legitimate client rotates `RT_n` → `RT_{n+1}` successfully (entry written, no marker).
2. Attacker (with a copy of `RT_n`) presents it. `TryConsumeAsync` sees the tombstone for
   `RT_n` and returns `AlreadyConsumed(FamilyId)`. The token endpoint calls
   `RevokeFamilyAsync(FamilyId)` — the marker write is in flight.
3. Before the marker is observable, the legitimate client presents `RT_{n+1}`.
   `TryConsumeAsync` does not see the marker, consumes `RT_{n+1}`, and the endpoint
   issues `RT_{n+2}` into a family that the previous step has just revoked.
4. The client's NEXT rotation (`RT_{n+2}` → `RT_{n+3}`) hits `Revoked` and the family is
   correctly closed.

The net effect: an attacker who races correctly against a freshly-rotating legitimate
session can extend the revocation window by exactly one rotation cycle (≈ one cache RTT)
before reuse detection kicks in. Their fresh `RT_{n+2}` is usable until the next legitimate
rotation, then dies. This is a measurable bypass, not a benign timing curiosity.

The in-memory default closes the race via the per-handle semaphore. Atomic backends
(Redis+Lua, SQL with single transaction) close it natively. **The distributed default
documents but does not fix the race — fixing it requires primitives `IDistributedCache`
does not offer.** This is why multi-instance production MUST replace the distributed
default; see §8.

### 5. Package placement and DI registration

| Type | Package |
|---|---|
| `IAuthorizationCodeStore` / `IRefreshTokenStore` | `ZeeKayDa.Auth` |
| `AuthorizationCodeEntry` / `RefreshTokenEntry` | `ZeeKayDa.Auth` |
| `AuthorizationCodeRedemptionOutcome` (and nested cases) | `ZeeKayDa.Auth` |
| `RefreshTokenConsumptionOutcome` (and nested cases) | `ZeeKayDa.Auth` |
| `InMemoryAuthorizationCodeStore` / `InMemoryRefreshTokenStore` (default) | `ZeeKayDa.Auth` |
| `DistributedCacheAuthorizationCodeStore` / `DistributedCacheRefreshTokenStore` | `ZeeKayDa.Auth` |
| `DistributedCacheTokenStoreOptions` | `ZeeKayDa.Auth` |
| `AddZeeKayDaAuth` DI integration | `ZeeKayDa.Auth.AspNetCore` |

**Defaults live in `ZeeKayDa.Auth` (core), not in `ZeeKayDa.Auth.AspNetCore`.** The previous
draft placed them in AspNetCore on the rationale that AspNetCore already references the
required packages. That is convenience, not principle, and it contradicts the
[ADR 0001 §3](0001-endpoint-architecture-pattern.md#3-layering-strict-core--aspnetcore-boundary)
allowlist, which permits core to depend on `Microsoft.Extensions.*` and the individually
whitelisted `Microsoft.AspNetCore.DataProtection.Abstractions`. None of the default store
code touches `HttpContext` or `IEndpointRouteBuilder`. Keeping defaults in core means:

- Non-ASP.NET hosts (a future worker-service ID-server, integration tests, custom transports)
  can use the defaults without a synthetic dependency on `Microsoft.AspNetCore.App`.
- The "secure by default" path doesn't require crossing a package boundary.

A separate `ZeeKayDa.Auth.DistributedCache` package was considered (architect's option b)
and rejected: it splits the secure-by-default surface across two NuGet packages for marginal
benefit, increases versioning surface, and the abstractions are genuinely host-agnostic.

**Registration.** `AddZeeKayDaAuth` does **not** register either store. Both
`IAuthorizationCodeStore` and `IRefreshTokenStore` are left unregistered after the call.
Consumers must explicitly opt in to one of the provided implementations, or register a custom
one directly on `IServiceCollection`. At startup, an `IHostedService` presence validator
(following the `ScopePresenceStartupValidator` precedent already in the codebase) checks that
both interfaces are registered. If either is missing it throws `ZeeKayDaConfigurationException`
(per ADR 0006), naming the missing interface and pointing to this ADR for the registration
options. The presence validator runs before the in-memory warning emitter (see below), so a
half-registered configuration fails fast rather than emitting a misleading warning.

Consumers opt in to the in-memory defaults via `.AddInMemoryStores()` on the
`ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth`:

```csharp
services.AddZeeKayDaAuth(...)
        .AddInMemoryStores();   // development and testing only — emits a startup warning
```

`.AddInMemoryStores()` registers both stores using `TryAddSingleton`. A registration
already present in the container wins; the in-memory default is skipped silently.
**To replace one or both stores while still using `.AddInMemoryStores()` for the other,
register the custom implementation *before* calling `AddZeeKayDaAuth`:**

```csharp
// Register the custom store first — .AddInMemoryStores()'s TryAdd is then a no-op for it.
services.AddSingleton<IRefreshTokenStore, MyPersistentRefreshTokenStore>();

services.AddZeeKayDaAuth(...)
        .AddInMemoryStores();   // registers IAuthorizationCodeStore in-memory;
                                // IRefreshTokenStore is already present — TryAdd skips it.
```

Registering a custom implementation *after* `.AddInMemoryStores()` is a no-op: the
`TryAddSingleton` inside the helper has already locked in the in-memory default and
subsequent registrations of the same interface are silently ignored by the DI container.
The ordering requirement is intentional — it mirrors the convention used by ASP.NET Core's
`TryAdd`-based registration helpers and is documented in the XML doc on `AddInMemoryStores`.

Consumers opt in to the distributed defaults via `.AddDistributedCacheTokenStores()`:

```csharp
services.AddZeeKayDaAuth(...)
        .AddDistributedCacheTokenStores();
```

Consumers may also register custom implementations directly, without using either builder
helper:

```csharp
services.AddSingleton<IAuthorizationCodeStore, MyAuthorizationCodeStore>();
services.AddSingleton<IRefreshTokenStore, MyRefreshTokenStore>();

services.AddZeeKayDaAuth(...);
```

**The two stores are independently replaceable.** A consumer may register a custom
`IRefreshTokenStore` (e.g. SQL-backed) before `AddZeeKayDaAuth` and then call
`.AddInMemoryStores()`: because `.AddInMemoryStores()` uses `TryAdd`, the custom
`IRefreshTokenStore` already in the container is preserved.

**Mixing builder helpers.** `.AddInMemoryStores()` and `.AddDistributedCacheTokenStores()`
are convenience wrappers that register both stores at once. Mixing them — for example,
using the distributed-cache store for authorization codes and the in-memory store for
refresh tokens — requires direct `IServiceCollection` registration using `TryAdd` semantics
*before* the `AddZeeKayDaAuth` call, following the same override ordering rule above:

```csharp
// Example: distributed-cache authorization codes, custom persistent refresh tokens.
services.TryAddSingleton<IAuthorizationCodeStore, DistributedCacheAuthorizationCodeStore>();
services.AddSingleton<IRefreshTokenStore, MyPersistentRefreshTokenStore>();

services.AddZeeKayDaAuth(...);   // no builder helper called; both stores already registered.
```

There is no builder API for mixed-store configurations; callers who need them work
directly against `IServiceCollection`.

**Mandatory startup warning when `.AddInMemoryStores()` is used.** Because the in-memory
stores lose all tokens on process restart and disable single-use enforcement and reuse
detection across multiple instances, the framework emits a warning before the first request
is served via a registered `IHostedService`. The warning MUST be at `LogLevel.Warning` and
MUST include the following text verbatim:

> "ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on
> process restart, and single-use enforcement and reuse detection are disabled across
> multiple instances. This configuration is intended for development and testing only and
> must not be used in production."

This warning fires unconditionally whenever `.AddInMemoryStores()` is used — there is no
suppression mechanism. In-memory stores are development and testing only, regardless of
instance count.

The XML doc on `AddInMemoryStores` MUST lead with this limitation, first sentence:

> Registers in-memory token stores for development and testing only. All tokens are lost on
> process restart, and single-use enforcement and reuse detection are disabled across multiple
> instances. A startup warning is emitted before the first request. Do not use in production.

**`AddDistributedCacheTokenStores()` behaves as before.** It performs an
`IDistributedCache`-registration check at startup and **fails fast with
`ZeeKayDaConfigurationException`** (per ADR 0006) if `IDistributedCache` is not registered.
The framework does **not** silently call `AddDistributedMemoryCache` — that would mask
configuration mistakes and produce an in-memory-in-production surprise. The XML doc on
`AddDistributedCacheTokenStores` MUST lead with the limitation verbatim, first sentence:

> Registers a non-atomic `IDistributedCache`-backed default suitable for dev/test only.
> Multi-instance production deployments MUST replace these stores with an atomic
> implementation; see ADR 0008 §8.

**Startup warning when a real distributed backend is detected.** On registration the
helper resolves the `IDistributedCache` implementation type. If it is anything other than
`MemoryDistributedCache` (i.e. the operator has wired up Redis, SQL Server, etc.) the
framework logs a warning via `ILogger<...>` stating that the non-atomic default is now
running against a real distributed backend — which is precisely the configuration the
default is unsuitable for — and pointing to §8 for the production migration path.
This is documentation, not a startup failure: rejecting the configuration would block
the legitimate "I'm replacing this with my own store on the next line" case.

### 6. Options placement

Per ADR 0002, options live on the endpoint group whose behaviour they describe; cross-cutting
implementation knobs live on a dedicated options type, not on `AuthorizationServerOptions`.
Each value introduced by this ADR is placed accordingly:

| Value | Location | Default | Justification |
|---|---|---|---|
| Authorization code lifetime | `AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime` | `60 s` | RFC 9700 §2.1.1 mandates "short-lived"; 60 s is the figure ADR 0005 already cited. Behavioural property of the authorization endpoint. |
| Refresh token lifetime | `AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime` | `14 days` | Behavioural property of the token endpoint. 14 days is a common industry default (Auth0, Okta, Duende) — long enough to avoid daily re-auth on inactive clients, short enough that an undetected family revocation gap is bounded. Operators with stricter policies dial it down; ones running long-lived integrations dial it up. **No upper bound is enforced by the framework by design**, to support long-lived integration scenarios where the operator accepts the security trade-off of wider token validity windows. Operators are responsible for choosing a value appropriate to their threat model. |
| Family revocation marker TTL | `DistributedCacheTokenStoreOptions.FamilyRevocationMarkerTtl` | `RefreshTokenLifetime + 5 min grace` | Implementation detail of the default store. |
| Clock skew tolerance | `AuthorizationServerOptions.ClockSkewTolerance` | `5 s` | Deployment property, not a store implementation detail. Applied as a grace window on `ExpiresAt` liveness checks in any store implementation that operates across multiple nodes (`entry.ExpiresAt + ClockSkewTolerance > now`). Does not affect the in-memory store (single-instance deployment invariant — one process, one clock, no inter-node skew possible) or tombstone TTL (dominated by `RefreshTokenLifetime`). Default is intentionally small; see §"Security Considerations — Clock skew tolerance". |
| Per-handle semaphore eviction window (in-memory store) | `InMemoryTokenStoreOptions.SemaphoreEvictionWindow` | `5 min` after entry expiry | Implementation detail; non-security. |

`DistributedCacheTokenStoreOptions` and `InMemoryTokenStoreOptions` are bound by their
respective registration helpers (`AddDistributedCacheTokenStores(Action<...>)` on `ZeeKayDaAuthBuilder` /
`AddZeeKayDaAuth(...)` accepting an optional configurator). They are NOT properties on
`AuthorizationServerOptions` — placing them there would force every consumer (including those
who swap in a custom store) to look at irrelevant knobs, violating the ADR 0002 grouping rule.

The tombstone TTL is fixed at `RefreshTokenLifetime` and is not operator-configurable.
The only safe direction to adjust it would be upward (longer retention), but exposing
a configurable option invites operators to set it downward, silently defeating the
RFC 9700 §2.1.1 replay-detection guarantee. Setting tombstone TTL below
`AuthorizationCodeLifetime` would cause a delayed replay to return `NotFound` instead
of `AlreadyRedeemed`, bypassing family revocation with no startup error to signal the
misconfiguration. The option can be introduced in a future release if a genuine use case
emerges; removing it now keeps the surface minimal and the security invariant
unconditional. See amendment 2026-06-20 in §"Amendments" below.

The tombstone retention defaults to `RefreshTokenLifetime` rather than the previous draft's
60 s + 60 s grace. A 120 s window means an attacker who delays code replay beyond two minutes
escapes family revocation entirely (the tombstone is gone, the code looks `NotFound`). Setting
retention to the refresh-token lifetime ensures any code replay that *could* still produce a
useful refresh token is detectable as `AlreadyRedeemed`. Tombstones are a few hundred bytes;
the storage cost is negligible compared with the entries they record.

### 7. Failure modes and exception contract

Per ADR 0006, store transport failures are surfaced through a dedicated exception type
deriving from `ZeeKayDaException` (the abstract base introduced in ADR 0006, which
exposes both a `(string message)` and a `(string message, Exception innerException)`
constructor):

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Thrown by <see cref="IAuthorizationCodeStore"/> and <see cref="IRefreshTokenStore"/>
/// implementations when an underlying transport (cache, database, network) fails. Distinct
/// from semantic outcomes such as <c>NotFound</c> or <c>AlreadyConsumed</c>, which are
/// returned, not thrown.
/// </summary>
public class ZeeKayDaStoreException : ZeeKayDaException
{
    public ZeeKayDaStoreException(string message)
        : base(message) { }

    public ZeeKayDaStoreException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

`ZeeKayDaStoreException` is **not** sealed, consistent with ADR 0006 §7. Custom store
implementors may subclass it to carry backend-specific diagnostic context (e.g. a
`RedisStoreException` with connection info or retry count) while still satisfying the
store contract — callers catching `ZeeKayDaStoreException` will catch subclasses
transparently. ADR 0006's base ctor signatures are preserved unchanged — the two ctors
above chain cleanly without passing `null` to a non-nullable parameter.

**Default implementations** wrap `IDistributedCache` / `IMemoryCache` / DP failures in
`ZeeKayDaStoreException` with the original exception preserved as `InnerException`.

**Custom implementations** SHOULD do the same. The XML doc on each store interface method
states this expectation; we do not (and cannot) enforce it through the type system.

**Configuration faults at startup** surface as `ZeeKayDaConfigurationException` (per ADR
0006), not as `InvalidOperationException`. Two categories exist: (1) a missing store
registration — detected by the `IHostedService` presence validator described in §5, which
follows the `ScopePresenceStartupValidator` precedent already in the codebase; (2) a
missing infrastructure dependency (e.g. `AddDistributedCacheTokenStores` called without
`IDistributedCache` registered) — detected at startup by the options-validation path
established in ADR 0001 §6.

**Fail-closed semantics — all paths:**

- Any I/O failure during *issuance* (`StoreAsync` on either store) MUST abort the response.
  No code or token is returned to the client. The endpoint returns `error=server_error`
  (or the appropriate transport-level error). Returning a code/token whose persistence
  failed would create a credential the framework cannot validate or revoke.
- DP unprotect failure on a stored entry MUST be treated as `NotFound`. Operators MUST
  configure Data Protection key retention to at least `RefreshTokenLifetime`; shorter
  retention manifests as silent user logout after key rotation.
- Cache backend unreachable on `TryRedeemAsync` / `TryConsumeAsync` MUST throw
  `ZeeKayDaStoreException`; the token endpoint returns `error=server_error`. It MUST NOT
  fall back to "treat as NotFound" — that would convert a transport failure into a free
  pass for an attacker presenting an expired-or-unknown token, by removing the
  family-revocation signal that `AlreadyConsumed` would have produced.

**Rotation ordering and mid-flight failure:**

The token endpoint, on a refresh exchange, MUST:

1. `TryConsumeAsync(oldHandle, clientId)`.
2. On `Consumed`, issue the new token material.
3. `StoreAsync(newEntry)` — store-before-respond.
4. Return the response.

If step 3 throws, the old token is already consumed and the new token cannot be persisted.
The endpoint MUST call `RevokeFamilyAsync(familyEntry.FamilyId)` before propagating the
error. This converts a partially-applied rotation into a fully-revoked family — the user is
forced to re-authenticate, but no token is left in an indeterminate state.

If `RevokeFamilyAsync` *itself* throws on this failure path, the endpoint propagates the
original `ZeeKayDaStoreException` (chained with the revocation failure as data). The
family is then naturally revoked by the consume that already happened in step 1: the old
handle is tombstoned, no new handle was issued, so an attacker presenting the old handle
will see `AlreadyConsumed` and trigger family revocation via the normal RFC 9700 §4.13
path on next contact. The only residual exposure is the absence of the marker for any
*other* extant tokens in the family — a non-issue for the first rotation but a
documentation point for stores where the family already contains multiple live entries.

**Authorization code redemption ordering:**

`TryRedeemAsync` is single-phase — the tombstone (including `familyId`) is written
atomically with the redemption. If `IRefreshTokenStore.StoreAsync` for the new refresh
token throws after a successful `TryRedeemAsync`, the endpoint MUST call
`RevokeFamilyAsync(familyId)` before propagating the error. Even if the
`RevokeFamilyAsync` call fails, the code's tombstone already carries the `familyId`, so
any later replay correctly surfaces `AlreadyRedeemed(familyId)` and the family is revoked
on that path. The previous draft's `CompleteRedemptionAsync` second-phase has been
deleted; see "Rejected alternatives".

### 8. Multi-instance and custom-store guidance

The defaults shipped in this ADR cover **dev/test only**. Both the in-memory pair (via
`.AddInMemoryStores()`) and the distributed pair (via `.AddDistributedCacheTokenStores()`
against `MemoryDistributedCache`) are unsuitable for production without understanding their
constraints:

- The in-memory pair loses all tokens on restart and silently disables single-use
  enforcement and reuse detection in multi-instance deployments. It is only suitable for
  development and testing.
- The distributed pair is **not production-grade for any deployment shape** — single or
  multi-instance — because the non-atomic check-then-set permits a measurable
  revocation-bypass window (§4c, §4d). Its only supported uses are dev/test and as a
  starting point for a custom atomic implementation.

Both single-instance and multi-instance production deployments require a persistent or
atomic store. Single-instance production where session continuity across restarts is
required must use a custom persistent `IRefreshTokenStore` (in-memory
`IAuthorizationCodeStore` remains acceptable — see §9 and §11). Multi-instance production
MUST use a custom atomic store for both interfaces. Multi-instance production is **out of
scope for the shipped defaults** and requires a custom store. This section consolidates the
guidance previously scattered across §4, §5, §7, and §11.

**Why no shipped multi-instance default?**

The two implementations that would work — Redis with Lua scripting, and a SQL backend
with optimistic concurrency — each pull in a non-trivial transitive dependency
(`StackExchange.Redis`, an EF Core provider, or a raw ADO.NET driver). Making either of
those mandatory for every `ZeeKayDa.Auth` consumer violates ADR 0001 §3's minimal-graph
principle. Making them optional via additional NuGet packages
(`ZeeKayDa.Auth.Redis`, `ZeeKayDa.Auth.Sql`) is plausible but premature — until the
interfaces have shipped and real consumers have built against them, the right factoring
of those packages is unknown.

**Recommended patterns for custom implementations:**

*Redis + Lua.* The atomic operations needed by both stores map to single Lua scripts:

- `TryRedeemAsync` (authorization code): one `EVAL` that (a) reads the entry by hashed
  key, (b) checks for an existing tombstone, (c) checks `client_id` against the entry,
  (d) writes the tombstone with the passed-in `familyId`, all in one round trip.
- `TryConsumeAsync` (refresh token): equivalent script with marker check first.
- `RevokeFamilyAsync`: simple `SET` of the marker key with `NX` semantics for
  idempotence and a TTL of `RefreshTokenLifetime + grace`.

*SQL with optimistic concurrency.* A single `UPDATE ... WHERE redeemed_at IS NULL`
returning the affected row achieves the same atomicity. Row-versioning columns or
transactional isolation level `SERIALIZABLE` both work; the choice depends on the
backend's contention behaviour.

In both cases the `familyId` parameter on `TryRedeemAsync` is critical: it MUST be
written into the tombstone in the same atomic step as the redemption mark, so that any
later replay surfaces `AlreadyRedeemed` with a non-null `FamilyId` for revocation.

**Capacity planning.**

Tombstone storage cost is `O(authorization-code-issuance-rate × RefreshTokenLifetime)`.
For a 14-day refresh-token lifetime at 10 codes/second sustained, the tombstone working
set is ≈ 12 million entries × a few hundred bytes ≈ 5 GB. This is well within typical
Redis or SQL deployments but worth budgeting explicitly: a shorter
`RefreshTokenLifetime` shrinks the working set proportionally, and shorter is also
better for revocation latency. Refresh-token entry storage scales with active sessions,
which for most deployments is much smaller than the tombstone set.

Family-revocation markers add `O(revocation-events × RefreshTokenLifetime)` entries —
negligible in normal operation, but a thundering-herd revocation (e.g. a mass logout
event) is bounded by `RefreshTokenLifetime + grace`.

**Configuration faults are `ZeeKayDaConfigurationException`.** Custom stores SHOULD use
the same exception type at startup-validation time for symmetry with the shipped
defaults; per ADR 0006 this is the typed channel for configuration errors.

### 9. Restart and durability semantics

**Authorization codes (≤ 60 seconds):**

Losing in-flight authorization codes on a server restart is acceptable from a user-experience
perspective. The code lifetime is short enough that no legitimate user would be mid-flow for
longer than a minute, and a restart within a 60-second window is operationally unusual. The
user experience of an occasional `invalid_grant` during a restart is equivalent to a session
timeout. However, the in-memory authorization code store is still development and testing only
(see §5); its dev/test classification is driven by the requirement to emit the startup warning
consistently whenever `.AddInMemoryStores()` is used, not by durability risk on the code store
specifically.

**Refresh tokens (hours to days):**

Losing refresh tokens on a restart forces every active user to re-authenticate. For a
framework issuing tokens with a 14-day default lifetime, the in-memory default is
**unsuitable for any production deployment**. This is not a defect to be fixed by the
framework — it is an inherent property of any in-process store, and it is why the in-memory
stores require an explicit `.AddInMemoryStores()` opt-in and emit a mandatory startup warning.

The framework must document this clearly:

> The `InMemoryRefreshTokenStore` is in-process. It loses all refresh tokens on restart.
> It is intended for development and testing only. For production, replace
> `IRefreshTokenStore` with an implementation backed by a persistent store. The shipped
> `.AddDistributedCacheTokenStores()` opt-in is suitable for dev/test
> against `AddDistributedMemoryCache`; for multi-instance production see §8.

This guidance must appear in the XML documentation on `IRefreshTokenStore`, in the package
README, and in the framework's deployment documentation. It must not be relegated to a
footnote.

**Single-instance is a deployment invariant of the in-memory default.** The XML doc on
both `InMemoryAuthorizationCodeStore` and `InMemoryRefreshTokenStore` MUST state, in the
type-level remarks:

> **Single-instance is a deployment invariant, not a recommendation.** Running multiple
> instances of this host with the in-memory default silently disables single-use
> enforcement (RFC 9700 §2.1.1) and refresh token reuse detection (RFC 9700 §4.14.2):
> codes and refresh tokens issued by instance A are invisible to instance B. Multi-instance
> deployments MUST replace this store with one backed by a shared, atomic backend (see
> ADR 0008 §8).

Runtime detection of multi-instance deployment was considered (e.g. inspecting
`IServer.Features`, `WEBSITE_INSTANCE_ID`, or sibling-process heuristics) and rejected:
those signals are weak (false positives for ephemeral scale-out events, false negatives
for non-Azure multi-instance hosts) and a runtime block based on them would erode trust.
Documentation is the correct enforcement mechanism here.

**In-flight code during session revocation (known gap).** If a user-initiated logout (or
back-channel logout) revokes the SSO session while an authorization code is in flight
between authorization-endpoint issuance and token-endpoint redemption, the code remains
redeemable until either (a) it expires naturally, or (b) it is redeemed and the resulting
refresh token's family is revoked by the session-bound revocation path. The window is
bounded by `AuthorizationCodeLifetime` (60 s default). This is an accepted gap in v1; a
follow-up may add session-id checking at redemption (see issue #104).

### 10. Data Protection key sharing implications

Authorization codes and refresh tokens are stored server-side as opaque handles. The
handles are not self-contained (not JWTs) and carry no embedded data; their integrity is
provided entirely by the store lookup. Data Protection is therefore not needed for handle
integrity.

The stored entry *values* contain sensitive personal data (`sub`, `scope`, session
identifiers). The default implementations encrypt these values using
`IDataProtectionProvider` (see §4b). This imposes the same key-sharing requirement that
ADR 0005 documented for the interaction context and session cookies:

> In multi-instance deployments, Data Protection keys must be shared across all instances.
> This is standard ASP.NET Core infrastructure (Azure Blob Storage + Azure Key Vault,
> shared file path, SQL Server key ring, etc.). ZeeKayDa does not solve distributed key
> management; it uses the host application's configured key ring.
>
> Key retention MUST be ≥ `RefreshTokenLifetime`. Shorter retention causes silent
> fail-closed user logouts after key rotation (the entry exists, but DP cannot unprotect
> it; per §7 this surfaces as `NotFound`).

Family-revocation markers are stored plaintext (§4b) — a DP failure on a marker would
otherwise fail-open into "not revoked".

Consumers who implement either store directly against a purpose-built backend (SQL with
column-level encryption, Redis with server-side encryption at rest) do not need to involve
`IDataProtectionProvider` at all — the store interface has no opinion on how values are
protected at rest.

### 11. Upgrade paths

The framework supports a progressive upgrade model. Consumers start with `.AddInMemoryStores()`
during development and replace individual stores as deployment requirements evolve. Note that
"multi-instance" on the in-memory default is **not** an upgrade decision — it is a correctness
violation (§9); the table below reflects that.

| Deployment scenario | `IAuthorizationCodeStore` | `IRefreshTokenStore` |
|---|---|---|
| Development / integration tests | `.AddInMemoryStores()` (emits startup warning) | `.AddInMemoryStores()` (emits startup warning) |
| Single-instance production | Custom persistent store, or `.AddDistributedCacheTokenStores()` against a persistent backend | Custom persistent store |
| Multi-instance production | **MUST** use a custom atomic store (Redis+Lua, SQL with optimistic concurrency) — see §8 | **MUST** use a custom atomic store (same backends) |

In-memory stores are development and testing only, regardless of instance count. The previous
"single-instance production (re-auth on deploy acceptable)" row has been removed — that framing
was based on the premise that the in-memory store was an acceptable silent default. With explicit
opt-in and a mandatory startup warning, there is no supported path where in-memory is an
appropriate production choice.

For multi-instance deployments, the recommended starting point for both stores is a
Redis-backed implementation using a Lua script for the atomic consume-or-tombstone
operation. A reference implementation is provided in the framework documentation
(see §8), **not** in the package itself — adding `StackExchange.Redis` as a direct
dependency of any ZeeKayDa package would make it mandatory for all consumers.

**Multi-tenancy.** Multi-tenant key-space isolation is the **responsibility of the custom
store implementation**. A naive multi-tenant store that does not namespace its cache
key-space (or include a tenant identifier in entries that is checked at consume time)
creates a confused-deputy risk: a token minted for tenant A could be presented and
accepted at tenant B's token endpoint. The framework deliberately does **not** carry a
`TenantId` on entries today because the framework is not tenant-aware; when
ZeeKayDa.Auth itself becomes tenant-aware (a future ADR), this entry will be revisited.
Today, the only workable isolation path is a **custom store** that namespaces cache keys
by tenant id and validates the tenant binding on every consume. A keyed `IDistributedCache`
registration per tenant is not viable with the shipped defaults: the default store
implementations resolve a plain (unkeyed) `IDistributedCache` from DI and have no
mechanism to select a tenant-specific instance at request time.

### 12. Out of scope — deferred to follow-up ADRs

The following capabilities depend on this store contract but are not designed here. The
`IRefreshTokenStore` interface is expected to grow additively to support them; that
evolution is explicit in the XML doc.

| Capability | Follow-up | Required interface additions |
|---|---|---|
| RFC 7009 revocation endpoint | issue #105 | `RevokeAsync(handle, clientId)` on `IRefreshTokenStore` |
| RFC 7662 introspection endpoint | issue #101 | None new — uses `FindAsync` added in this ADR |
| Back-channel logout (OIDC Front-Channel/Back-Channel Logout) | issue #103 | `RevokeBySessionAsync(ssoSessionId)` on `IRefreshTokenStore`; may also fire revocation events |
| Session-bound revocation (logout invalidates issued tokens) | issue #104 | As above; may also gate `TryConsumeAsync` on session validity |
| Telemetry / observability seam | issues #96 and #102 | None new — the rich outcome types are deliberately designed so a metering decorator can observe `ClientMismatch` / `AlreadyConsumed` / `Revoked` events without a second round-trip |

The introspection endpoint is the only one whose required interface addition (`FindAsync`)
is included in this ADR, because it is purely additive and avoids forcing a breaking
change in the very next release. The others are deferred so that the breaking-change
discussion happens in the ADR that motivates the change, not here.

**On `FindAsync`'s nullable return.** `FindAsync` returns `RefreshTokenEntry?` —
collapsing "consumed", "expired", "revoked", and "not found" into a single null result.
An outcome-typed variant (`Found` / `Revoked(familyId)` / `Expired` / `NotFound`)
analogous to `TryConsumeAsync` was considered. For introspection (RFC 7662 §2.2) the
client-observable answer is always `active=false` for any non-`Found` case, so the
distinctions add no protocol value at this layer; they would only feed telemetry. This
ADR therefore ships the nullable shape; if introspection telemetry needs the
distinctions, the introspection ADR (#101) will introduce an outcome-typed
`FindAsync` variant as a DIM addition (§3a) rather than a breaking change.

Whether `RevokeFamilyAsync` should fire events for back-channel logout fan-out is out of
scope and will be decided in the back-channel logout ADR.

---

## Rejected Alternatives

### Two-phase commit (`TryRedeemAsync` returning `CommitToken` → separate `CompleteRedemptionAsync`)

**Rejected.** A previous revision of this ADR shaped the code-redemption interface as a
two-step protocol: `TryRedeemAsync` would write the tombstone without a `familyId` and
return an opaque `CommitToken`; the token endpoint would then mint the `familyId`, persist
the refresh token, and finally call `CompleteRedemptionAsync(commitToken, familyId)` to
back-fill the `familyId` onto the tombstone. That shape was argued for on the grounds that
"atomic backends make `CompleteRedemptionAsync` a no-op" — and so it appeared to be the
right shape for the distributed default while being free for atomic stores.

It is the wrong shape. The race window between the two phases is not benign:

1. Endpoint calls `TryRedeemAsync` → tombstone written, `familyId = null`.
2. Endpoint crashes / cache loses connectivity / process is killed *before*
   `CompleteRedemptionAsync` runs.
3. Attacker (with a copy of the code) presents it. `TryRedeemAsync` returns
   `AlreadyRedeemed(FamilyId: null)`.
4. There is no `familyId` to pass to `RevokeFamilyAsync`. The attacker has escaped the
   RFC 9700 §2.1.1 mandate that the AS MUST revoke "any tokens issued based on it" —
   any token issued in step 1 is still live, and there is no entry-point for revoking it
   short of operator intervention.

This failure mode existed *every* time a crash interleaved between the two phases — on
*any* backend, not just the distributed default — because the durability concern was baked
into the interface itself. It also forced the `AlreadyRedeemed.FamilyId` property to be
nullable, which propagated the unhandled-revocation case into every consumer of the
outcome type.

The pre-commit shape adopted in this revision (§2) eliminates the race by inverting the
ordering: the token endpoint mints the `familyId` BEFORE calling `TryRedeemAsync`, passes
it as a parameter, and the store writes the tombstone with the `familyId` atomically.
There is no second phase, no `CommitToken`, no nullable `FamilyId`. Atomic backends gain
nothing they did not already have; non-atomic backends gain the only thing that matters —
the guarantee that every `AlreadyRedeemed` outcome carries a usable revocation target.

The cost is that the token endpoint is responsible for choosing the `familyId` up front,
which is a trivially-correct one-liner against `RandomNumberGenerator`. The benefit is
the elimination of an entire category of revocation-escape bug.

### Using `IDistributedCache` directly (no purpose-specific interface)

**Rejected.** Following the interaction context precedent (ADR 0005 §6b) and using
`IDistributedCache` directly for both stores was considered as the default path. The guiding
principle cited in ADR 0005 — "do not create a ZeeKayDa abstraction when a standard .NET
abstraction already exists" — does not apply here, because `IDistributedCache` cannot express
the semantics that the spec requires.

Single-use detection requires distinguishing `AlreadyRedeemed` from `NotFound`. Family
revocation requires an operation that acts on a set of entries identified by a shared
attribute, not by individual keys. Neither semantic is available in the `IDistributedCache`
interface. Encoding them directly in the token endpoint would embed cache key-space
conventions into protocol logic, preventing replacement with a purpose-built store without
modifying the endpoint.

The interaction context genuinely needed only write-once / read-once / expire semantics;
the token stores do not. The two cases are not analogous, and treating them identically
would silently degrade the security properties of the token stores.

### Storing authorization codes as encrypted JWTs (self-contained, no server-side store)

**Rejected.** A self-contained authorization code — an encrypted JWT containing all bound
parameters — would eliminate the need for server-side storage entirely. The token endpoint
would decrypt the code, verify the bound parameters, and issue tokens without any store
lookup.

This approach is fundamentally incompatible with RFC 9700 §2.1.1, which requires single-use
enforcement. A self-contained code has no server-side existence that can be marked as
redeemed. A stolen code could be presented an arbitrary number of times within its lifetime.
The framework cannot implement this approach and comply with the spec simultaneously.

The only self-contained approach that could satisfy single-use would be to additionally
maintain a "seen codes" set on the server — which reintroduces a server-side store, with no
benefit over storing the code entry directly and additional complexity around expiry and the
JWT/store split.

### Single combined `ITokenStore` interface

**Rejected.** Merging authorization codes and refresh tokens into a single `ITokenStore`
interface was considered to reduce the number of types a consumer must understand and
implement when replacing the default.

The lifecycles and revocation semantics of the two token types are different enough that a
single interface would be a leaky abstraction:

- Authorization codes have a fixed maximum lifetime of 60 seconds; refresh tokens live for
  hours to days.
- Authorization codes are stored once and redeemed once; refresh tokens are stored, consumed,
  and rotated repeatedly throughout their lifetime.
- Authorization code single-use enforcement is about detecting a replay within a narrow window;
  refresh token reuse detection is an ongoing security control throughout the token's lifetime.
- Family revocation is a refresh-token concept; authorization codes have no equivalent.
- Durability requirements differ: code loss on restart is acceptable; refresh token loss is
  not.

A single interface would force any custom implementation to address all of these concerns
simultaneously, even if the consumer only needs to replace one. Separate interfaces allow
independent replacement and independent testing.

### Reusing the interaction context store from ADR 0005

**Rejected.** The interaction context store (backed by `IDistributedCache` or the interaction
cookie) was considered as a possible home for short-lived authorization codes, since both
are short-lived and produced by the authorization endpoint.

The interaction context has no revocation requirement: it expires naturally and is cleaned up
on use. Placing authorization codes in the interaction context store would couple their
lifecycle management, complicate the store's expiry semantics (interaction contexts and codes
have different TTLs and different tombstone requirements), and require the interaction context
store to support the `AlreadyRedeemed` state — a concern entirely foreign to its current
contract.

More fundamentally, mixing the two would prevent independent upgrade of one without the other.
A consumer running the interaction context in a cookie-backed store (the ADR 0005 default) but
wanting a SQL-backed authorization code store would find the stores inseparable.

---

## Consequences

### Positive

- **Spec compliance is expressed in the interface contract**, not scattered through token
  endpoint logic. `TryRedeemAsync` returning `AlreadyRedeemed` is the direct, typed
  expression of RFC 9700 §2.1.1, and the `FamilyId` on that outcome is guaranteed
  non-null by the pre-commit shape (§2), so the token endpoint cannot accidentally omit
  family revocation. The separate `ClientMismatch` and `Revoked` cases prevent the
  family-revocation DoS where an attacker burns the legitimate user's session by
  presenting a captured handle under a different `client_id`.
- **The two stores are independently replaceable.** A consumer can replace only
  `IRefreshTokenStore` with a durable SQL-backed implementation without touching the
  authorization code store. Stores are registered independently via `IServiceCollection`,
  and the builder methods register both; overriding one after the builder call leaves the
  other unchanged.
- **Explicit registration prevents silent misconfiguration.** Neither store is
  auto-registered. `AddZeeKayDaAuth` fails at startup with a `ZeeKayDaConfigurationException`
  if either store is missing, naming the interface and pointing to the docs. The easy path
  (`.AddInMemoryStores()`) emits a mandatory startup warning so that development configurations
  are never silently promoted to production. Multi-instance and durable stores are opt-in
  via `.AddDistributedCacheTokenStores()` or a custom registration.
- **No new dependencies beyond the [ADR 0001 §3](0001-endpoint-architecture-pattern.md#3-layering-strict-core--aspnetcore-boundary) allowlist.** Defaults use
  `Microsoft.Extensions.Caching.Memory`, `Microsoft.Extensions.Caching.Abstractions`,
  and `Microsoft.AspNetCore.DataProtection.Abstractions` — all on the namespace-level
  allowlist.
- **Hot-path allocation-free on cache hit.** `TryRedeemAsync` / `TryConsumeAsync` /
  `FindAsync` return `ValueTask<T>`; synchronous cache hits do not allocate a `Task`.
- **Telemetry-friendly.** Rich outcome cases (`ClientMismatch`, `AlreadyConsumed`,
  `Revoked`) let an observability decorator distinguish attack signals from benign
  failures without a second round-trip.
- **Testability is preserved.** Both interfaces are minimal and side-effect-free in the
  failure paths. Token-endpoint tests use the in-memory default directly; store tests
  exercise the redemption contract without an HTTP context.
- **Data Protection key-sharing requirements are unchanged** from ADR 0005, with the
  added explicit retention requirement (≥ `RefreshTokenLifetime`).

### Negative / Trade-offs

- **TOCTOU window in the distributed default.** The `IDistributedCache`-backed
  implementations cannot atomically enforce single-use; concurrent code/token
  presentations could both pass the tombstone check. The in-memory default closes this
  via per-handle `SemaphoreSlim`. Multi-instance production must replace the distributed
  default with Redis+Lua or SQL+optimistic concurrency (§8). The previous draft's claim
  that single-instance was sequential-and-safe was wrong and has been removed (Kestrel
  serves concurrent requests).
- **Family revocation marker race on the distributed default — measurable bypass.** As
  documented in §4d, an attacker who races the marker write against a legitimate
  rotation can obtain one fresh refresh token in a revoked family before reuse detection
  closes the window. This is not benign — it is the reason the distributed default is
  dev/test-only and §8's atomic replacement is mandatory for multi-instance production.
- **Family revocation marker churn.** The marker strategy avoids enumerating individual
  token entries (impossible on `IDistributedCache`) at the cost of a marker that lives
  `RefreshTokenLifetime + grace` — bounded, but for very long token lifetimes in
  high-churn deployments this is non-trivial.
- **Token endpoint owns `familyId` minting.** The pre-commit shape (§2) requires the
  token endpoint to mint `familyId` before calling `TryRedeemAsync`. This is a one-line
  responsibility but it is a contract the endpoint must honour for the security
  guarantee. The alternative (two-phase commit) was strictly worse — see "Rejected
  alternatives".
- **Two interfaces and several types to implement for a custom store.** Consumers
  replacing both defaults must implement two interfaces. The alternative (one
  `ITokenStore`) would reduce the surface at the cost of a leaky abstraction (see
  Rejected Alternatives). Accepted.
- **Explicit registration required.** Consumers must call `.AddInMemoryStores()`,
  `.AddDistributedCacheTokenStores()`, or register a custom store before the application
  starts. Failing to do so produces a startup exception. This is by design — silent
  defaults prevent the mandatory startup warning from firing — but it does add a required
  step that was not present in the original design. The startup exception message names
  the missing interface and points to the docs to minimise friction.
- **`IRefreshTokenStore` will grow via default interface methods.** `RevokeAsync` and
  `RevokeBySessionAsync` will ship as DIMs that throw `NotSupportedException` by
  default (§3a). Custom stores compile cleanly across additions but operators must
  opt their store in to the new capability before the dependent endpoint becomes
  functional.

---

## Security Considerations

### Client binding enforced atomically with consumption (RFC 6749 §10.4)

Both `TryRedeemAsync` and `TryConsumeAsync` take `clientId` and perform the binding check
inside the atomic consume step. On mismatch the store returns `ClientMismatch` and does
**not** consume the entry. Consuming on mismatch would create a DoS path: an attacker
who captures a code or refresh token but does not know the legitimate `client_id` could
present it under their own `client_id` to burn the credential and (for refresh tokens)
trigger family revocation on the legitimate user. By returning `ClientMismatch` without
consuming, the legitimate client's next presentation still succeeds; the attacker has
only revealed themselves to telemetry.

### Scope downgrade on refresh (RFC 6749 §6)

Scope on a rotated refresh token MUST NOT exceed the scope of the original. The token
endpoint enforces this **before** calling `IRefreshTokenStore.StoreAsync(newEntry)`; the
store has no opinion on scope semantics. A custom store that rewrites `Scope` server-side
to widen it MUST NOT do so silently — this is a security-relevant contract documented in
the XML doc on `RefreshTokenEntry.Scope`.

### Handle hashing in cache keys

Token handles are bearer credentials. Default implementations derive cache keys as
`SHA-256(handle)` (§4a) so that read access to cache contents — backups, log sidecars,
SIEM ingestion, ops dashboards — does not expose live credentials. Custom implementations
SHOULD do the same. Plain SHA-256 is sufficient because handles have ≥ 128 bits of input
entropy; HKDF or per-tenant salting adds no meaningful security against a preimage attack
on a high-entropy input.

### Cache backend isolation

Even with hashed keys and encrypted values, a shared cache backend must enforce
tenant/process isolation through the backend's own ACLs. Redis ACLs / per-database
selection, SQL row-level security, etc., are the operator's responsibility — the
framework does not enforce network-level access controls.

### Data Protection retention

DP key retention MUST be ≥ `RefreshTokenLifetime`. With shorter retention, DP unprotect
on stored entries fails silently after key rotation; per §7 this surfaces as `NotFound`,
which logs out every user holding a token issued under the rotated-out key. This is
fail-closed (the correct direction) but operationally surprising — operators must be
warned in deployment documentation, not just XML doc.

### I/O failure handling

See §7 for the full contract. Summary: any store I/O failure during issuance aborts the
response. Any I/O failure mid-rotation (between `TryConsumeAsync` and `StoreAsync`)
triggers `RevokeFamilyAsync` before propagating the error. Defaults wrap backend
exceptions in `ZeeKayDaStoreException` (per ADR 0006); custom implementations SHOULD do
the same. The framework MUST NOT downgrade a transport failure to a "treat as NotFound"
fallback — that would convert backend unavailability into an attacker-friendly silent
success.

### Single-use enforcement and replay detection (RFC 9700 §2.1.1)

An authorization code is a bearer credential. Anyone who obtains it can exchange it for
tokens. The spec's single-use requirement is therefore a critical security control, not a
recommended practice. The store design makes this control structural: `TryRedeemAsync`
cannot return `Redeemed` twice for the same handle. Any implementation that does — by
deleting the entry on redemption rather than tombstoning it — silently degrades the
security of the entire code exchange.

The distinction between `AlreadyRedeemed` and `NotFound` is load-bearing for the attacker
scenario described in RFC 9700 §2.1.1: an attacker who captures an authorization code and
presents it after the legitimate client has already exchanged it should trigger revocation
of any tokens that were issued in that exchange. Tombstone retention is set to
`RefreshTokenLifetime` (§6) so that even a delayed replay — within the window in which a
useful refresh token could still exist — still produces `AlreadyRedeemed` and not
`NotFound`. Because §2's pre-commit design writes the `familyId` into the tombstone
atomically with the redemption, every `AlreadyRedeemed` outcome carries a non-null
`FamilyId` for the caller to revoke — there is no null-`FamilyId` race window. The
previous draft's 120-second tombstone window allowed an attacker who delayed beyond two
minutes to escape family revocation entirely; this is fixed.

### Refresh token reuse detection and family revocation (RFC 9700 §4.13)

Rotation — issuing a new handle and invalidating the old one on each use — is
non-configurable in v1. RFC 9700 §4.14.2 permits sender-constrained tokens as an
alternative replay-detection mechanism for public clients, but ZeeKayDa.Auth does not
implement sender-constrained tokens in this release (see issue #100). Rotation is
therefore applied universally.

The purpose of `TryConsumeAsync` returning `AlreadyConsumed` (or `Revoked`) rather than
`NotFound` for a previously used token is to detect the scenario where the original token
was captured by an attacker: if both the legitimate client and the attacker present the
token, one will see `Consumed` and the other `AlreadyConsumed`. The response to
`AlreadyConsumed` is family revocation, which invalidates all tokens the legitimate
client may have obtained since the theft — forcing re-authentication and removing the
attacker's foothold. `Revoked` is the same outcome from the client's perspective but a
distinct telemetry signal: a token presented after the family is already revoked is a
strong attack indicator.

`RevokeFamilyAsync` must be idempotent and must not fail silently. An implementation that
throws on a double-revocation call risks leaving the revocation incomplete if the token
endpoint has already begun issuing an error response. Callers should be designed to
tolerate a `RevokeFamilyAsync` call that arrives after the family is already revoked.

**Acknowledged race in the distributed default:** the marker-check and consume steps in
`TryConsumeAsync` are not atomic with `RevokeFamilyAsync`. As detailed in §4d, the
staggered-rotation scenario permits an attacker who races correctly to extend the
revocation window by exactly one rotation cycle (≈ one cache RTT) — they obtain one
freshly-issued refresh token in a now-revoked family before reuse detection closes the
window on their next rotation. **This is a measurable bypass, not a benign timing
curiosity.** The in-memory default closes this via the per-handle semaphore; atomic
backends (Redis+Lua, SQL with single transaction) close it natively. The distributed
default documents but does not fix it. Multi-instance production MUST replace it (§8).

### `familyId` entropy

`familyId` must be generated with the same entropy requirements as token handles and
authorization codes: ≥ 128 bits from `RandomNumberGenerator`. `familyId` is never
returned to clients through the public protocol, so the threat is not direct
enumeration by an unprivileged attacker; the entropy requirement defends against three
realistic scenarios:

1. **Partial cache read access.** An attacker who can read individual refresh-token
   entries (e.g. a partially-compromised cache backend, a misconfigured shared Redis
   ACL) learns `familyId` directly from the entry value. A predictable scheme would
   then let them enumerate or correlate *sibling* families without further reads. High
   entropy ensures observation of one `familyId` reveals nothing about others.
2. **Cache write access against guessed families.** An attacker with cache *write*
   access but limited read access could forge `zkd:rt:family:{H(guessed)}:revoked`
   markers against guessed `familyId`s to DoS arbitrary user sessions. (Write access
   to the token cache is largely game-over already; the entropy bar removes the
   guess-and-poison cheap-amplification path.)
3. **Log correlation.** An attacker (or curious operator) with access to logs that
   include `familyId` cannot reverse-engineer or predict siblings — see
   §"`familyId` logging hygiene" for the further hashing recommendation.

### Handle comparison

The default implementations perform comparison by cache key lookup on the SHA-256 hash
of the handle (§4a). There is no plaintext-handle comparison step in the default code
path, because the entry no longer stores the raw handle (§2, §3). `FixedTimeEquals` is
therefore not required in the defaults — there is nothing to compare in constant time.

Custom implementations that retain raw handles (e.g. a legacy SQL schema where the
handle is the primary key, or a store that performs in-memory LINQ filtering across a
list of entries) MUST use `CryptographicOperations.FixedTimeEquals` for any handle
comparison performed in application code. The same guidance applies uniformly to
authorization-code handles and refresh-token handles.

### `familyId` logging hygiene

`familyId` is not a bearer credential — it cannot be exchanged for tokens — but it is a
correlator that links every token in a chain. If `familyId` is written to logs that
leave the trust boundary (centralised log aggregation, third-party SIEM ingestion,
crash-dump telemetry), the operator can correlate a user's session activity across
arbitrary windows. This is not catastrophic but it is more disclosure than is needed.

If `familyId` must be logged for forensic purposes, log `H(familyId)` truncated to
≥ 64 bits (e.g. the first 11 characters of `Base64Url(SHA-256(familyId))`). This
preserves the correlation property within the operator's logs but prevents
cross-correlation with the live cache state, applying the same principle as the §4a
cache-key hashing. The same guidance applies to raw token handles in any log line.

### Sensitive data in cache entries

Stored entries contain `sub`, `scope`, and session identifiers. If the cache backend is
accessible to other tenants, processes, or services, these values constitute a data
exposure risk. The default implementations encrypt entries using `IDataProtectionProvider`
(§4b) as a baseline. Consumers using a shared Redis cluster must also configure Redis
ACLs or separate namespacing to prevent cross-tenant key enumeration.

### Clock skew tolerance

In load-balanced deployments, node clocks can drift. The `ExpiresAt` liveness check in
`TryRedeemAsync` (`entry.ExpiresAt > now`) could reject a valid authorization code on a
node whose clock is slightly ahead of the issuing node. `ClockSkewTolerance` (default:
5 seconds) is applied as a grace window on this check (`entry.ExpiresAt + tolerance > now`)
to avoid spurious `NotFound` outcomes caused by inter-node clock drift.

The tolerance applies to the `ExpiresAt` liveness check in any store implementation that
operates across multiple nodes. It does not affect the in-memory store — that store is a
single-instance deployment invariant (one process, one clock) and inter-node skew is
structurally impossible — and it does not affect tombstone TTL (the `RefreshTokenLifetime`
value dominates any reasonable skew by orders of magnitude). Any other store — distributed
cache, SQL, Cosmos DB, or a custom persistent store — running in a load-balanced deployment
is subject to inter-node clock drift and should apply the tolerance.

The default of 5 seconds is intentionally small. JWT validation conventionally tolerates
5 minutes of clock skew; that figure is appropriate for tokens that circulate across
unknown networks. Authorization codes are short-lived (60 seconds default), travel only
server-to-server within a single deployment, and are exchanged against a store with a
hard `ExpiresAt` value — a 5-minute tolerance would effectively double the usable lifetime
and is not warranted. Operators with unusual infrastructure (slow NTP convergence, satellite
links) may increase the value, but MUST treat a `ClockSkewTolerance` approaching
`AuthorizationCodeLifetime` as a security misconfiguration: at that point the code's
expiry guarantee is effectively nullified. The startup validator SHOULD warn if
`ClockSkewTolerance >= AuthorizationCodeLifetime / 2`.

---

## Amendments

- **2026-06-20 — Remove `AuthorizationCodeTombstoneRetention` as a configurable option** — The `AuthorizationCodeTombstoneRetention` property was listed in §6's configuration table as an operator-configurable option on `DistributedCacheTokenStoreOptions`. It is removed. Tombstone TTL is now hardcoded to `RefreshTokenLifetime` with no operator override. The only safe direction to adjust tombstone TTL is upward (longer), but exposing the knob invites operators to set it downward, silently defeating the RFC 9700 §2.1.1 replay-detection guarantee: a tombstone TTL shorter than `AuthorizationCodeLifetime` causes a delayed replay to return `NotFound` instead of `AlreadyRedeemed`, bypassing family revocation with no startup error. The `max(RefreshTokenLifetime, remaining ExpiresAt)` formula from earlier drafts simplifies to just `RefreshTokenLifetime` given the startup-validator rule AC-4d (`RefreshTokenLifetime >= AuthorizationCodeLifetime`), which guarantees that `RefreshTokenLifetime` always dominates the second term. This simplification is only correct because AC-4d is enforced at startup; if that invariant were ever relaxed, the simplification would silently become unsafe and the full `max(...)` formula would need to be reinstated. For clients that do not issue refresh tokens, `RefreshTokenLifetime` produces a tombstone that lives slightly longer than strictly necessary — harmless, and erring in the safe direction. The option can be reintroduced in a future release if a genuine use case emerges. §6 table and surrounding prose updated accordingly. Reference: issue #245 (startup-validator rule for tombstone TTL — closed as won't-implement as a result of this decision).

- **2026-06-20 — Add `ClockSkewTolerance` to `AuthorizationServerOptions`** — A `ClockSkewTolerance` property (type `TimeSpan`, default `5 s`) is added to `AuthorizationServerOptions`. In load-balanced deployments, node clocks can drift; the `ExpiresAt` liveness check in `TryRedeemAsync` (`entry.ExpiresAt > now`) could reject a valid authorization code on a node whose clock is slightly ahead of the issuing node. The tolerance is applied as a grace window (`entry.ExpiresAt + tolerance > now`) in any store implementation that operates across multiple nodes — the in-memory store is excluded because it is a single-instance deployment invariant (one process, one clock; inter-node skew is structurally impossible) and tombstone TTL is unaffected (dominated by `RefreshTokenLifetime`). The property lives on `AuthorizationServerOptions` rather than `DistributedCacheTokenStoreOptions` because clock skew is a deployment property, not a store implementation detail: a custom SQL store or Redis store would need the same grace window and should not have to rediscover the value on a store-specific option. The default of 5 seconds is intentionally small — unlike JWT validation (5-minute convention), authorization codes are short-lived, server-to-server, and exchange against a hard `ExpiresAt`; a large tolerance weakens the expiry guarantee. The startup validator SHOULD warn if `ClockSkewTolerance >= AuthorizationCodeLifetime / 2`. §6 table and §"Security Considerations — Clock skew tolerance" added accordingly.

- **2026-06-20 — Explicit opt-in store registration; no auto-registration; `.AddInMemoryStores()` with mandatory startup warning** — The previously-accepted §5 decision registered both `IAuthorizationCodeStore` and `IRefreshTokenStore` automatically via `TryAddSingleton` inside `AddZeeKayDaAuth`. That decision is overturned. `AddZeeKayDaAuth` now leaves both interfaces unregistered. Startup validation (`ZeeKayDaConfigurationException`) fails if either is absent, naming the missing interface and pointing to the docs. The builder gains two explicit opt-in methods: `.AddInMemoryStores()` (registers both in-memory implementations; development and testing only; emits a mandatory `LogLevel.Warning` before the first request via `IHostedService` or `IStartupFilter`; the exact warning text is recorded in §5) and `.AddDistributedCacheTokenStores()` (unchanged from prior decision). Custom implementations are registered directly on `IServiceCollection` and the two stores remain independently replaceable. §4, §5, §9, §11, and the Consequences section updated accordingly. **Rejected alternative — asymmetric registration (auto-register auth codes, explicit refresh tokens):** The argument that authorization codes are short-lived and therefore harmless to lose on restart was considered as a basis for auto-registering only the auth code store while requiring explicit opt-in for the refresh token store. This was rejected for two reasons: (1) In multi-instance deployments a code issued on instance A validated on instance B silently fails, the same correctness violation as losing a refresh token across instances — the "short-lived so harmless" argument breaks down at the multi-instance boundary. (2) Asymmetric registration is a discoverability trap: a developer who understands how one store is wired assumes the other follows the same pattern. Discovering that they behave differently only when the application breaks in production is a footgun that a consistent explicit-opt-in model eliminates.
