# ADR 0008 — Authorization Code and Refresh Token Store

Status: Accepted   ·   Date: 2026-06-07   ·   Issue: #337

**Amends ADR 0005's interaction-context storage** — extends the authorization-code bound-parameter
list with `AuthTime`, `Acr`, and `Amr` (parameters fixed at authentication time are captured on
the code, not re-read from the SSO session at redemption — same pattern already applied to
`nonce`).

## Decision

Two purpose-specific coordinator interfaces, `IAuthorizationCodeStore` and `IRefreshTokenStore`,
live in `ZeeKayDa.Auth` (core) — not `IDistributedCache` used directly, unlike the interaction
context store (ADR 0005). Each coordinator is **framework-sealed**: it carries an internal member
that only `[InternalsVisibleTo]` assemblies can satisfy, so only the framework's own
`AuthorizationCodeStore`/`RefreshTokenStore` implement it, even though the interface stays
`public` for injection. The real extension point for a new persistence technology is a second,
fully public interface per store — `IAuthorizationCodeBackingStore` and
`IRefreshTokenGrantStore` — that the sealed coordinator delegates to for storage while owning the
atomicity, hashing, and tombstone semantics itself. Default `InMemory*`/`DistributedCache*`
backing-store implementations of both ship in core, since neither touches `HttpContext`
(ADR 0001's core/AspNetCore split).

```csharp
namespace ZeeKayDa.Auth.Stores;

public interface IAuthorizationCodeStore
{
    Task StoreAsync(string code, AuthorizationCodeEntry entry, CancellationToken ct);

    // familyId is minted by the caller BEFORE this call and written into the tombstone
    // atomically with redemption — see "Pre-commit familyId" below.
    ValueTask<AuthorizationCodeRedemptionResult> TryRedeemAsync(
        string code, string clientId, string familyId, CancellationToken ct);

    // Reserved: satisfying this member requires internal access, so only the framework's
    // own coordinator can implement IAuthorizationCodeStore. Custom persistence implements
    // IAuthorizationCodeBackingStore instead.
    internal void SealAsFrameworkOwnedProtocol();
}

public abstract class AuthorizationCodeRedemptionResult
{
    private AuthorizationCodeRedemptionResult() { }
    public sealed class Redeemed : AuthorizationCodeRedemptionResult { public required AuthorizationCodeEntry Entry { get; init; } }
    public sealed class ClientMismatch : AuthorizationCodeRedemptionResult { }        // NOT consumed
    public sealed class AlreadyRedeemed : AuthorizationCodeRedemptionResult { public required string FamilyId { get; init; } }
    public sealed class NotFound : AuthorizationCodeRedemptionResult { }
}
```

`IRefreshTokenStore` mirrors the shape (`StoreAsync(tokenHandle, entry, ct)`, non-destructive
`FindAsync`, `TryConsumeAsync` returning a closed `RefreshTokenConsumptionResult` with `Consumed` /
`ClientMismatch` / `AlreadyConsumed(FamilyId)` / `Revoked(FamilyId)` / `NotFound`, and
`RevokeFamilyAsync(familyId)`, idempotent) and is framework-sealed the same way, with
`IRefreshTokenGrantStore` as its own backing-store extension point. `AlreadyConsumed` and
`Revoked` produce the identical client-visible `invalid_grant`, but are kept as distinct cases so
telemetry can tell the triggering reuse event (`AlreadyConsumed`) apart from a token presented
after its family was already closed (`Revoked` — a stronger attack indicator) without a second
store round-trip. Both outcome hierarchies use the sealed nested-class + private-constructor
closed-union idiom so a switch is exhaustive by construction. Neither entry type stores the raw
handle — only `SHA-256(handle)` is used as the cache key (see key derivation below), so a
data-at-rest compromise doesn't also expose the bearer credential. Rotation must not widen scope
(RFC 6749 §6): the token endpoint enforces this before calling `StoreAsync` on the new entry —
the store itself has no opinion on scope semantics.

**Why not `IDistributedCache` directly?** The interaction context (ADR 0005) is genuinely
write-once/read-once/expire — `IDistributedCache` fits. Token stores need semantics
`IDistributedCache` cannot express: distinguishing *valid-unredeemed* / *tombstoned* / *not-found*
for single-use enforcement (RFC 9700 §2.1.1), and revoking every token sharing a `familyId` in one
operation (RFC 9700 §4.13, no set-query primitive exists on `IDistributedCache`). Encoding these
in the endpoint via raw cache keys would leak key-space convention into protocol logic and block
swapping in a Redis-Lua or SQL store without touching the endpoint.

**Pre-commit `familyId` — single-phase redemption.** The token endpoint mints `familyId` (≥128-bit
CSPRNG) *before* calling `TryRedeemAsync` and passes it in; on success the tombstone is written
with that `familyId` in the same atomic step, so every future `AlreadyRedeemed` is guaranteed to
carry a non-null, revocable `FamilyId`. This replaced an earlier two-phase design:

```csharp
// Rejected: two-phase commit
var token = await codeStore.TryRedeemAsync(code, clientId);      // tombstone written, FamilyId = null
// ... process crashes / cache drops here ...
await codeStore.CompleteRedemptionAsync(token, familyId);        // never runs
// A replay now sees AlreadyRedeemed(FamilyId: null) — nothing to revoke. RFC 9700 §2.1.1 violated,
// on ANY backend, because the durability gap is in the interface shape, not a specific store.

// Chosen: pre-commit, single-phase
var familyId = GenerateFamilyId();
var outcome = await codeStore.TryRedeemAsync(code, clientId, familyId, ct); // tombstone+familyId atomic
```

Single-use is a *record of redemption*, not deletion — deleting on first use would make a replay
indistinguishable from `NotFound`, defeating family revocation. The tombstone's retention is
fixed at `RefreshTokenLifetime` (not a short "60s + grace" window): a shorter window lets a
delayed replay silently escape revocation once the tombstone expires.

**Client binding is atomic with consumption**, on both stores. A mismatch returns
`ClientMismatch` **without** consuming the entry — consuming on mismatch would let an attacker
who captured a code/token but not the `client_id` burn the legitimate client's credential (and,
for refresh tokens, trigger unwarranted family revocation) as a DoS.

**Refresh token rotation is mandatory and non-configurable** for all client types — RFC 9700
§4.14.2 requires rotation *or* sender-constrained tokens for public clients; ZeeKayDa doesn't
implement sender-constrained tokens (DPoP/mTLS) yet, so rotation is the only mechanism and making
it optional would remove the framework's only replay defence. `PreviousTokenHandleHash` (a hash,
never the raw handle) links a forensic rotation chain; it's never used for authorization.

**Key derivation.** All cache keys are `zkd:{segment}:{Base64Url(SHA256(handle))}` — never the
raw handle, since the handle is itself a bearer credential and cache read access (Redis ops,
backups, log sidecars) shouldn't expose it (RFC 6819 §5.1.4.1.3; matches OpenIddict/Duende
practice). The family-revocation marker is instead keyed by `familyId`
(`zkd:rt:family:{H(familyId)}:revoked`) since `IDistributedCache` cannot enumerate — it carries a
TTL of `RefreshTokenLifetime + 5 min` grace, hardcoded, not operator-configurable (see Why). The
exact key-space layout is implementation detail of the default stores, not part of the interface
contract — a custom `IDistributedCache`-backed store is free to use a different layout, and
downstream code must not depend on these shapes. Custom stores that retain raw handles instead of
hashing them (e.g. a legacy SQL schema keyed on the handle) must compare them with
`CryptographicOperations.FixedTimeEquals`; the shipped defaults never compare a plaintext handle
at all, since the hashed cache-key lookup *is* the comparison.

**Encryption at rest.** Entry values (containing `sub`, `scope`, session IDs) are Data
Protection-encrypted before storage; a DP unprotect failure on an entry **must** be treated as
`NotFound` (fail-closed), never as an empty read. Family-revocation markers, which carry no
secret payload, are stored plaintext deliberately — a DP failure on a marker must fail toward
"still revoked," not "not revoked." Operators must retain DP keys for ≥ `RefreshTokenLifetime`,
or key rotation silently logs users out.

**Two ship-with-caveats defaults, neither auto-registered:**

| Default | Backing | Atomic? | Suitable for |
|---|---|---|---|
| `InMemory{AuthorizationCode,RefreshToken}Store` | `IMemoryCache` + per-handle `SemaphoreSlim` | Yes, within one process | Dev/test only; single-instance is a hard deployment invariant, not a recommendation — multi-instance silently disables single-use/reuse detection entirely |
| `DistributedCache{...}Store` | `IDistributedCache` | **No** — check-then-set race | Dev/test against `AddDistributedMemoryCache`; **not production-grade at any instance count** (Kestrel serves requests concurrently even on one instance) |

`AddZeeKayDaAuth()` registers neither store. A `TokenStorePresenceValidator`
(`IStartupVerifier`, ADR 0016) fails startup with `ZeeKayDaConfigurationException` if either
interface is unregistered. Every `.AddInMemory*()` registration method emits a mandatory,
un-suppressible startup warning (escalating to `Critical` and requiring an explicit
`allowOutsideDevelopment: true` parameter outside `Development` — the flag lives on the
registration call, not on `AuthorizationServerOptions`, since it's meaningless without the call
that needs it). `.AddAuthorizationCodeStore<T>()` / `.AddRefreshTokenStore<T>()` are the typed
paths for custom stores; every registration method throws `InvalidOperationException` on double
registration rather than silently letting an earlier call win. Multi-instance production **must**
supply a custom atomic store (Redis+Lua or SQL with optimistic concurrency) — the framework
documents the pattern but ships neither, to avoid forcing a `StackExchange.Redis` or EF Core
dependency onto every consumer.

**Options placement** (per ADR 0002's grouping rule): `AuthorizationCodeLifetime` (60s default)
on `AuthorizationEndpoint`; `RefreshTokenLifetime` (14 days default, **no enforced upper bound** —
operators own the trade-off for long-lived integrations) on `TokenEndpoint`; `ClockSkewTolerance`
(5s default) on the shared root, applied only to multi-node `ExpiresAt` liveness checks (the
in-memory store is single-process by invariant, so skew is structurally impossible there).

**Exception contract** (per ADR 0006): store transport failures throw `ZeeKayDaStoreException`
(unsealed, root namespace). Any I/O failure during issuance aborts the response — nothing is
returned to a client whose credential the framework failed to persist. A cache backend outage on
`TryRedeemAsync`/`TryConsumeAsync` **must** throw, never silently degrade to `NotFound` — that
would hand an attacker a free pass by erasing the replay signal. If persisting a rotated refresh
token fails after the old one was already consumed, the endpoint calls `RevokeFamilyAsync` before
propagating — a partially-applied rotation becomes a fully-revoked family, not an indeterminate
token.

**Forward compatibility.** `IRefreshTokenStore` will grow (RFC 7009 revocation, back-channel
logout session revocation) via `default` interface methods that throw `NotSupportedException`
until a store opts in — chosen over splitting capabilities into separate interfaces
(`IRevocableRefreshTokenStore`, …), which would force most stores to implement all of them anyway
and push runtime `is`-check capability detection onto every caller.

## Why

- **Purpose-specific interfaces over raw `IDistributedCache`** — see Decision; the two stores need
  atomic tombstone/replay semantics `IDistributedCache` structurally cannot express.
- **Self-contained encrypted-JWT codes with no server-side store** (rejected) — cannot satisfy
  RFC 9700 §2.1.1 single-use: a stolen self-contained code could be replayed indefinitely within
  its lifetime, and the only fix (a server-side "seen codes" set) reintroduces the store this
  design avoids, with none of its benefits.
- **A single combined `ITokenStore`** (rejected) — codes and refresh tokens have incompatible
  lifecycles (60s vs. days; redeem-once vs. rotate-repeatedly; no family concept for codes) —
  forcing one interface to cover both would be a leaky abstraction that every custom
  implementation has to work around even when only one side needs replacing.
- **Reusing the ADR 0005 interaction-context store for codes** (rejected) — the interaction
  context has no revocation state and different TTL/tombstone needs; coupling the two would block
  independently upgrading either.
- **Auto-registering both stores via `TryAddSingleton`** (rejected, previously shipped then
  reverted) — silently promoted a dev-grade default into production. A weaker variant —
  auto-registering only the (short-lived, "harmless to lose") code store — was also rejected: in
  a multi-instance deployment, a code issued on one instance and redeemed on another silently
  fails exactly like a lost refresh token, and asymmetric wiring is a discoverability trap.
- **Operator-configurable tombstone / family-marker TTLs** (rejected, previously shipped then
  removed) — the only off-default values an operator can set are either harmful (shorter than
  `RefreshTokenLifetime`, silently defeating replay detection with no startup error) or useless
  (longer, wasting cache space). Both are now derived invariants, not options; removing the last
  option left an empty options class, which was deleted rather than shipped as a SemVer surface
  with no behaviour behind it.
- **`AllowInMemoryStoresOutsideDevelopment` as a flag on the shared `AuthorizationServerOptions`
  root** (rejected, previously shipped then reverted) — inert unless a specific registration
  method was also called, the same discoverability trap as auto-registration; moved onto each
  registration method's own parameter instead (mirrors ADR 0011's equivalent move for its
  development-signing-key escape hatch).

## Consequences

Multi-instance production is out of scope for the shipped defaults and requires a custom atomic
store — accepted, since the two viable options (Redis+Lua, SQL+optimistic-concurrency) each pull
in a dependency the framework won't force on every consumer. The distributed default's
check-then-set race is a *measurable* bypass, not a benign curiosity: an attacker racing a
legitimate rotation can extend a revoked family's usable window by one rotation cycle; this is
why it's positioned as dev/test-only rather than "acceptable for single-instance production."
Losing in-memory refresh tokens on restart is unavoidable and why the store requires explicit
opt-in plus a mandatory, non-suppressible warning. Tombstone storage scales with
`issuance-rate × RefreshTokenLifetime` (~5GB at 10 codes/sec over 14 days) — worth capacity
planning, not a blocker. Multi-tenant key-space isolation is entirely the custom store's
responsibility; the framework carries no `TenantId` today. `familyId` requires the same ≥128-bit
CSPRNG entropy as handles even though it's never returned to clients, to resist partial-cache-
read correlation and cache-write-access poisoning of guessed families; if logged for forensics,
log a truncated hash of it, not the raw value, for the same reason cache keys are hashed.
Consumers implementing a custom store directly against columns with their own encryption (SQL
column-level, Redis at-rest) don't need `IDataProtectionProvider` at all — the interface has no
opinion on at-rest protection.
