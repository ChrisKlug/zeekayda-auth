# ADR 0013 — Authorization-Code Store: Protocol / Persistence Split

Status: Accepted   ·   Date: 2026-07-15   ·   Issue: #375

> **Scope: the authorization-code store, plus the store rules shared with the refresh-token
> store** — registration policy, options placement, and the store exception contract. The
> refresh-token store's own reshape (family metadata, whole-family revocation, absolute-lifetime
> caps) is [ADR 0014](./0014-refresh-token-grant-store.md), which reuses the `StoreKey` type this
> ADR introduces but diverges from its opaque key-value shape.
>
> **Supersedes ADR 0008.** ADR 0008 defined the original contract for both token stores. Its
> refresh-token half is superseded by [ADR 0014](./0014-refresh-token-grant-store.md); its
> authorization-code half and the rules shared by both stores are carried here. This ADR states
> the redemption protocol in full — single-use enforcement, replay/reuse detection, handle
> hashing, at-rest encryption, fail-closed I/O, and clock-skew-tolerant logical expiry — rather
> than pointing elsewhere for it.
>
> **Security sign-off (2026-07-15): ✅ granted, for the authorization-code store only.** This ADR
> changes one ADR 0008 behaviour: the redemption tombstone becomes a small envelope with a
> plaintext `FamilyId` (see Decision), replacing the all-ciphertext tombstone, so that
> `AlreadyRedeemed{FamilyId}` (RFC 9700 §2.1.1 replay handling) survives a Data-Protection key
> rotation. Security reviewed and approved the plaintext `FamilyId` on its own merits: `FamilyId`
> is a random GUID used only as a non-secret correlation/revocation-lookup identifier — revocation
> is driven only by the plaintext `FamilyId` value itself, never by the raw code handle, and
> `RevokeFamilyAsync` is framework-internal, unreachable by a read-only store observer — a leaked
> `FamilyId` grants no capability, forges no token, enables no redemption — so this discloses
> correlation, not a bearer credential. Two facts specific to the
> *code* store make the trade clearly correct: the tombstone's backend TTL is the code's own
> seconds-to-minutes lifetime, so the cleartext exists only briefly; and each authorization code
> maps to a distinct, freshly-minted family, so a `FamilyId` appears in at most one code tombstone
> — there is no rotation chain to correlate (chains exist only in the refresh-token store, which
> requires its own, separate sign-off — see ADR 0014). The rotation-survival benefit is a strict
> security improvement and outweighs this narrow, short-lived correlation surface.

## Decision

`IAuthorizationCodeStore` stops being a third-party extension point and becomes
**framework-sealed**: it stays `public` (so `ZeeKayDa.Auth.AspNetCore` can inject it
cross-assembly) but gains an `internal` interface member that only `[InternalsVisibleTo]`
assemblies can satisfy, so a third party attempting to implement it gets a compile error. The
framework ships one sealed coordinator, `AuthorizationCodeStore`, that owns everything
protocol-critical listed above.

The one thing a third party still implements is `IAuthorizationCodeBackingStore` — a narrow,
"dumb" key-value primitive with three methods (`TryInsertAsync`, `GetAsync`, `RemoveAsync`) that
stores opaque, already-encrypted bytes under already-hashed keys (`StoreKey`, a struct whose
constructor is framework-internal, so a backing store can never fabricate a key from a raw
handle). The one hard invariant is that `TryInsertAsync`'s insert-if-absent test and write MUST be
a single atomic operation (Redis `SET NX`, a unique-constraint `INSERT`, a conditional Cosmos
create) — single-use enforcement rides entirely on it. `GetAsync` MUST NOT catch a transport fault
and return `null`; only a confirmed-absent key returns `null` (a swallowed fault read as "no
tombstone" would silently reopen a replay window). The framework wraps every thrown exception as
`ZeeKayDaStoreException` (ADR 0006) and rethrows `OperationCanceledException` unwrapped.

The redemption tombstone becomes an envelope — `{ FamilyId: plaintext string, ProtectedSecret:
DP-ciphertext }` — instead of a single opaque blob (see security sign-off above). The coordinator
catches `Unprotect` failures at two sites with opposite outcomes: an undecryptable *entry* is
unusable, so it returns `NotFound`; an undecryptable tombstone's `ProtectedSecret` still yields the
cleartext `FamilyId`, so it returns `AlreadyRedeemed{FamilyId}` — replay detection and family
revocation survive even when the DP key has rotated.

`AddAuthorizationCodeStore<T>()` and the two first-party registration methods keep their names but
now require `T : IAuthorizationCodeBackingStore` and wire the sealed coordinator over it. The
public outcome type is renamed `AuthorizationCodeRedemptionOutcome` →
`AuthorizationCodeRedemptionResult` for consistency with `ClientAuthenticationResult` /
`SigningResult` (pre-1.0 rename, no compatibility impact). The conformance kit for the one residual
invariant (`TryInsertAsync` atomicity, `GetAsync` fail-closed) ships in a separate package,
`ZeeKayDa.Auth.TestKit`, so a third party can derive and run it without needing
`[InternalsVisibleTo]` access to `ZeeKayDa.Auth` itself.

**Pre-commit `familyId` — single-phase redemption.** `TryRedeemAsync(string code, string clientId,
string familyId, CancellationToken ct)` requires the caller to mint `familyId` *before* the call;
on success the tombstone is written with that `familyId` in the same atomic
`TryInsertAsync`, so every future `AlreadyRedeemed` is guaranteed to carry a non-null, revocable
`FamilyId`. This replaced a rejected two-phase design (`TryRedeemAsync` followed by a separate
`CompleteRedemptionAsync(token, familyId)` call): a crash or dropped connection between the two
calls leaves a tombstone with `FamilyId: null`, so a later replay resolves `AlreadyRedeemed(null)`
— nothing to revoke, RFC 9700 §2.1.1 violated. The durability gap is in the two-phase interface
*shape* itself, not in any one backend's implementation of it, so no backing store could fix it —
only removing the second phase does. Single-use is a *record of redemption*, not deletion:
deleting the entry on first use would make a replay indistinguishable from `NotFound`, defeating
family revocation entirely.

**Client binding is atomic with consumption.** A mismatch between the presented `clientId` and the
entry's `ClientId` returns `ClientMismatch` **without** consuming the entry. Consuming on mismatch
would let an attacker who captured a code (or refresh token) but not the legitimate `client_id`
burn that client's credential as a denial of service — and, on the refresh-token store, additionally
trigger an unwarranted family revocation the legitimate client never asked for.

**Tombstone retention is the code's own lifetime, not the refresh token's.** `AuthorizationCodeStore`
computes the tombstone's expiry as `entry.ExpiresAt + ClockSkewTolerance` — the authorization code's
own short (default 60s) lifetime plus clock-skew grace — not `RefreshTokenLifetime`. This is
confirmed-shipped, security-reviewed-and-accepted behaviour, not a gap to close. The accepted
residual: a code replayed *after* the tombstone has expired resolves `NotFound` rather than
`AlreadyRedeemed{FamilyId}`, so no family revocation fires for a late-surfacing interception/replay
of an already-expired code. This is accepted as **Low severity** because the code itself is by then
unredeemable regardless of which outcome is returned — the missed revocation costs nothing an
attacker could exploit, since the code that would have driven it can no longer mint a token.

**Endpoint requirement: one code, one family.** The plaintext-`FamilyId` sign-off above is
predicated on each authorization code mapping to a distinct, freshly-minted family, so a leaked
`FamilyId` has nothing else to correlate against. Nothing inside the store enforces this —
`TryRedeemAsync` accepts whatever `familyId` string the caller supplies. The token-issuing endpoint
(not yet built) **MUST** mint a fresh, never-reused `familyId` per authorization code; reusing a
`familyId` across codes would extend a "single code, single family" correlation surface into a
multi-code chain the security sign-off did not evaluate.

**`familyId` MUST be minted via a CSPRNG, never `Guid.NewGuid()`.** Concretely: `familyId` must come
from `StoreKeyGenerator.Generate()` (or an equivalent CSPRNG source producing at least 128 bits of
entropy), never `Guid.NewGuid()` — a GUID carries only ~122 bits of entropy in its random variant
and is not a documented CSPRNG source. `StoreKeyGenerator.Generate()` already ships in
`ZeeKayDa.Auth.Stores` as a 256-bit `RandomNumberGenerator`-backed generator with remarks
prohibiting `System.Random`/`Guid.NewGuid()`/`Random.Shared`; this is the same primitive the
`familyId`-minting endpoint should reuse when it is built. (This is a concrete strengthening of the
"random GUID" phrasing in the security sign-off banner above — that banner is the historical
approval record and is left as written; this paragraph is the operative minting requirement.)

**Key derivation.** Cache keys are never the raw handle — the handle is itself a bearer credential,
and cache read access (Redis ops, backups, log sidecars) must not expose it (RFC 6819 §5.1.4.1.3;
matches OpenIddict/Duende practice). The handle is hashed before it is used to key any store
lookup. This is now structurally enforced, not just documented: `StoreKey`'s constructor is
framework-internal, so a backing store can never construct one from a raw handle and can never
fabricate a lookup key that bypasses hashing. The exact key-space layout (hash algorithm, encoding,
namespacing) is an implementation detail of the default stores, not part of the interface contract
— it may differ between the authorization-code store and the refresh-token store, and downstream
code must not depend on either shape.

**Registration policy — no auto-registration, fail closed on absence.** Neither the
authorization-code store nor the refresh-token store is auto-registered by `AddZeeKayDaAuth()`.
A startup verifier (`TokenStorePresenceValidator`, ADR 0016) fails startup with
`ZeeKayDaConfigurationException` when either interface is unregistered. Every `.AddInMemory*()`
registration method emits a mandatory, non-suppressible startup warning
(`InMemoryStoreVerifier`); outside a `Development` environment this **fails startup** unless the
registration call was made with `allowOutsideDevelopment: true`, in which case it instead emits a
`Critical`-level warning. The `allowOutsideDevelopment` flag lives on each registration method's
own parameter, never on a shared options type — it is meaningless without the specific call that
needs it. `.AddAuthorizationCodeStore<T>()` / `.AddRefreshTokenGrantStore<T>()` are the typed paths
for custom stores. Every registration method throws `InvalidOperationException` on double
registration rather than silently letting an earlier call win.

**Options placement** (per ADR 0002's grouping rule): `AuthorizationCodeLifetime` (60s default) on
`AuthorizationEndpoint`; `RefreshTokenLifetime` (14 days default, no enforced upper bound —
operators own the trade-off for long-lived integrations) on `TokenEndpoint`; `ClockSkewTolerance`
(5s default) on the shared root, applied to multi-node `ExpiresAt` liveness checks.

**Exception contract** (per ADR 0006): store transport failures throw `ZeeKayDaStoreException`
(unsealed, root namespace). Any I/O failure during issuance aborts the response — nothing is
returned to a client whose credential the framework failed to persist. A backend outage during
redeem/consume **MUST** throw, never silently degrade to `NotFound` — that would hand an attacker
a free pass by erasing the replay signal.

**Operator responsibility: retain Data Protection keys for at least `RefreshTokenLifetime`.** A key
that is removed from the ring before every refresh token it protected has expired makes those
tokens permanently undecryptable; because a decrypt failure on an entry is treated as `NotFound`
(fail-closed), the operator-visible symptom is affected users being silently logged out with no
error. See [Configure Data Protection](../how-to/configure-data-protection.md) for the operational
guidance.

**Forward compatibility.** `IRefreshTokenStore` grows over time (RFC 7009 revocation, back-channel
logout session revocation) via `default` interface methods that throw `NotSupportedException`
until a store opts in — chosen over splitting capabilities into separate interfaces
(`IRevocableRefreshTokenStore`, …), which would force most stores to implement all of them anyway
and push runtime `is`-check capability detection onto every caller. In practice, pre-1.0, the
interface has so far just grown outright rather than exercising this mechanism — issue #386 added
a sixth method (`IsFamilyRevokedAsync`) directly to `IRefreshTokenGrantStore` rather than via a
`default`-throwing member — so this is a documented intent for the growth path, not (yet) an
exercised one.

## Why

The epic #352 extension-API review ran the "hand `IAuthorizationCodeStore` to a competent .NET dev
who has never seen this codebase and say *implement a new one*" test, and it failed: an
implementer had to independently get right several correctness-bearing MUST/MUST-NOT clauses
carried only in prose doc-comments, at least three of them directly security-critical (hash the
handle before keying on it; encrypt the entry at rest; perform check-and-consume atomically). Per
Design Principle 6 ("docs are not a mitigation"), that many naive-implementation-violates-while-
compiling invariants on one extension point is an API-design problem. The only thing a third party
legitimately wants to vary is *where the bytes live* — everything else is fixed protocol.

- **Keep the open interface plus a whole-store conformance kit (rejected).** A kit still requires
  the implementer to know it exists and run it, and does nothing for invariants the CLR can't
  express as a test (e.g. "encrypt entries"). The reshape makes those invariants structurally
  unrepresentable instead, shrinking the residual test target to one primitive's atomicity plus its
  fail-closed contract.
- **Make `IAuthorizationCodeStore` `internal` to seal it (rejected).** `ZeeKayDa.Auth.AspNetCore` is
  a separate assembly that must consume (inject) the interface; an `internal` interface would break
  that. The internal-member seal blocks implementation by non-friend assemblies while leaving
  consumption open — the asymmetry actually needed.
- **A single shared backing interface for both the code and refresh-token stores (rejected).** The
  two stores diverge on lifetime (seconds vs. months) and durability pressure (a lost code just
  fails one authorization; lost refresh tokens force mass re-authentication). Forcing one
  registration would push consumers to over- or under-provision; the two stores are free to
  diverge on backing shape independently.
- **Encrypt `FamilyId` too and add an `AlreadyRedeemed.FamilyUnrecoverable` case (rejected).**
  `FamilyId` is a non-secret random GUID, so encrypting it buys nothing; leaving it cleartext lets
  replay detection and family revocation both survive a DP key rotation, strictly better, with no
  churn to the public outcome union.
- Naming the backing-store interface went through several rejected candidates —
  `IExpiringKeyValueStore` (too generic, invites one shared instance across incompatible stores),
  `IAuthorizationCodeRepository` (implies DDD/EF-Core query/unit-of-work machinery this type doesn't
  have), `*Persister`/`*Persistence` (non-idiomatic, foregrounds the act over the thing, reads as
  write-only). `BackingStore` is the established .NET term for "where the bytes live behind a
  richer abstraction," which is exactly this type's role.
- **Operator-configurable tombstone TTL (rejected, previously shipped then removed).** The only
  off-default value an operator could set is either harmful (shorter than the code's own lifetime,
  silently defeating replay detection with no startup error) or useless (longer, wasting cache
  space for a code that already can't be redeemed). The tombstone TTL is now a derived invariant,
  not an option.

## Consequences

Pre-publication blast radius (acceptable — nothing is published, see `CONTRIBUTING.md`'s Pre-1.0
Stability Policy): introduces `StoreKey` and `IAuthorizationCodeBackingStore`; makes
`IAuthorizationCodeStore` framework-sealed; renames the outcome type; rewrites the first-party
`InMemory*`/`DistributedCache*` stores as thin backing adapters; changes the tombstone shape.
Endpoint callers are unaffected.

The CLR cannot prove a given `TryInsertAsync` implementation is actually atomic — that ceiling is
irreducible and is mitigated only by mapping guidance (Redis `SET NX`, SQL unique-constraint
`INSERT`, Cosmos conditional create, etc.) and the `ZeeKayDa.Auth.TestKit` conformance case, not
eliminated.

A read-only store observer can now correlate a redeemed code's tombstone to its refresh-token
family via the cleartext `FamilyId` — accepted per the security sign-off above (non-bearer GUID,
short-lived, one family per code).

Multi-instance production is out of scope for the shipped `InMemory*`/`DistributedCache*` defaults
and requires a custom atomic backing store — accepted, since the two viable options (Redis+Lua,
SQL+optimistic-concurrency) each pull in a dependency the framework won't force on every consumer.
The distributed-cache default's check-then-set race is a *measurable* bypass, not a benign
curiosity: an attacker racing a legitimate rotation can extend a revoked family's usable window by
one rotation cycle, which is why it is positioned as dev/test-only rather than "acceptable for
single-instance production." Losing in-memory tokens on restart is unavoidable and is why the
in-memory store requires explicit opt-in outside Development plus a mandatory, non-suppressible
warning.
