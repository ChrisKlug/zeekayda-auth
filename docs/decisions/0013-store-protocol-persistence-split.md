# ADR 0013 — Authorization-Code Store: Protocol / Persistence Split

**Status:** Accepted
**Date:** 2026-07-15 (issue #375, from the epic #352 extension-API review)

> **Relationship to ADR 0008.** This ADR does **not** restate the redemption protocol that
> [ADR 0008](./0008-authorization-code-and-refresh-token-store.md) already settles (single-use
> enforcement, replay/reuse detection, handle hashing, at-rest encryption, fail-closed I/O,
> clock-skew-tolerant logical expiry). It re-homes *where that protocol lives* — into
> framework-owned code — and reshapes *what a third party implements* down to a dumb key-value
> primitive. Read alongside ADR 0008; where the two appear to disagree about who implements the
> state machine, this ADR governs for the authorization-code store.
>
> **Scope: authorization-code store only.** The refresh-token store is a separate, later reshape
> (family metadata, whole-family revocation markers, absolute-lifetime caps) that reuses the same
> `StoreKey` / backing-store shape but adds machinery a code store does not need. That work is out
> of scope here; this ADR references it only as a forward pointer where the two designs touch.

> **Security sign-off:** this ADR moves every authorization-code trust-boundary control — handle
> hashing, at-rest encryption, single-use enforcement and its atomicity, fail-closed I/O, logical
> expiry, and redemption-outcome selection — out of the third-party extension point and into a
> framework-sealed coordinator. It changes one settled ADR 0008 behaviour: the redemption
> **tombstone becomes a small envelope with a plaintext `FamilyId`** (§7), replacing the
> all-ciphertext tombstone, so that `AlreadyRedeemed{FamilyId}` (RFC 9700 §2.1.1 replay handling)
> survives a Data-Protection key rotation. That specific change requires security sign-off before
> #375's implementation lands.
>
> **Security sign-off status (2026-07-15): ✅ granted for the authorization-code-store scope of
> §7.** Reviewed as its own decision (not inherited from the parked refresh-token draft on
> `arch/extension-api-review`). The plaintext-`FamilyId` envelope is approved for the *code* store:
> `FamilyId` is a random GUID used only as a non-secret correlation/revocation-lookup identifier
> (verified: revocation markers key on `Hash(FamilyId)`, and `RevokeFamilyAsync` is a
> framework-internal call unreachable by a read-only store observer — a leaked `FamilyId` grants no
> capability, forges no token, and enables no redemption), so this discloses correlation, not a
> bearer credential. Two code-store-specific facts make the trade clearly correct here (see §7
> "Residual disclosure"): (a) the code tombstone's backend TTL is the code's own
> seconds-to-minutes lifetime, so the cleartext surface exists only briefly, not for months as in
> the refresh-token store; and (b) each authorization code maps to a *distinct, freshly-minted*
> family, so a `FamilyId` appears in at most one code tombstone — there is no rotation *chain* to
> correlate across code records (chains live in the refresh-token store). The rotation-survival
> benefit (preserving family revocability on a real replay across a DP key rotation) is a strict
> security improvement and outweighs the narrow, short-lived correlation surface. This sign-off
> covers §7 for the authorization-code store only; the refresh-token store reshape is out of scope
> and must be signed off separately when it lands.

---

## Context

[ADR 0008](./0008-authorization-code-and-refresh-token-store.md) defined
`IAuthorizationCodeStore` as the *third-party extension point*: a consumer wanting
Redis/SQL/Cosmos persistence implements `StoreAsync` / `TryRedeemAsync` directly. ADR 0008 is
correct about the *protocol*. The problem this ADR fixes is not the protocol — it is *who is on
the hook to reimplement the protocol correctly for every new backend*.

The epic #352 extension-API review ran the "hand `IAuthorizationCodeStore` to a competent .NET dev
who has never seen this codebase and say *implement a new one*" test. They fail it. To back a new
store correctly an implementer must independently get right, carried only by the interface's prose
doc-comments, several correctness-bearing MUST/MUST-NOT clauses, at least three of them directly
security-critical:

1. **Hash the raw handle** to `Base64Url(SHA-256(handle))` and key on the hash, never the raw
   handle (a store breach must not yield redeemable codes). A newcomer writing a SQL store
   overwhelmingly uses the code as the primary key.
2. **Encrypt the entry at rest** with Data Protection — an invariant the interface does not
   mention in its method signatures at all; you discover it only by reading the in-memory
   implementation. A newcomer stores `sub` / `scope` / `redirect_uri` as plaintext columns.
3. **Perform check-and-consume atomically** across read-tombstone → check-client → check-expiry →
   write-tombstone → remove-entry. A newcomer writes `GET`+`SET` → TOCTOU → double redemption.
   Even the first-party `DistributedCache*` store cannot satisfy this today and is documented
   "not for production."
4. **Fail closed:** any I/O error MUST throw, MUST NOT degrade to `NotFound`. The idiomatic
   `try { … } catch { return NotFound; }` silently disables replay detection.
5. Honour **logical expiry** and `ClockSkewTolerance` even when the backend has not evicted.
6. Write the token endpoint's `familyId` into the tombstone atomically and hand it back on the
   replay path, and **select the correct outcome** among four states — several security-distinct
   (`ClientMismatch` must NOT consume; `AlreadyRedeemed` MUST let the caller revoke the family).

Per Design Principle 6 ("docs are not a mitigation"), an extension point carrying this many
naive-implementation-violates-while-compiling invariants is an open API-design problem, not a
documentation problem. The only thing a third party legitimately wants to *vary* here is **where
the bytes live** — Redis vs. SQL vs. Cosmos. Everything else is fixed protocol. This ADR reshapes
the extension point down to exactly that.

### Constraints and prior decisions that shape this ADR

- **ADR 0008** owns the redemption protocol contract, the four-case redemption outcome type, the
  `AddXxx()`-on-`ZeeKayDaAuthBuilder` registration idiom and its double-registration guard, and
  the `AuthorizationCodeEntry` shape. This ADR keeps all of that and changes only the
  extension-point shape and the one tombstone behaviour called out in the sign-off banner.
- **ADR 0006** (exception hierarchy): store I/O faults surface as `ZeeKayDaStoreException`. This
  ADR makes *producing* that exception a framework responsibility, not the implementer's.
- **ADR 0007 / the extension-API review** established the "reserved variant unnameable by third
  parties via an `internal` member" pattern (`ClientAuthMethod`). This ADR applies the same
  internal-member idea to seal `IAuthorizationCodeStore` against third-party implementation while
  leaving it public for cross-assembly consumption (§1).
- Nothing is published yet (pre-1.0, see `CONTRIBUTING.md`'s Pre-1.0 Stability Policy), so the
  cost of reshaping the extension point now is this ADR plus a re-parenting of the first-party
  stores — the cost of shipping the current shape is a permanent public API that fails the
  newcomer test.

---

## Current State

### 1. The split: framework-owned protocol vs. third-party persistence

The authorization-code store surface is split into two layers with a hard boundary between them:

- **Protocol (framework-owned, sealed).** `IAuthorizationCodeStore` remains the type the token and
  authorization endpoints depend on and inject, but it becomes **framework-sealed** — it stops
  being a third-party extension point. The framework ships one sealed coordinator,
  `AuthorizationCodeStore`, that implements it and owns *everything* protocol-critical: handle
  hashing, Data-Protection encryption, the check-and-consume state machine and its atomicity,
  fail-closed I/O, logical expiry / clock-skew, outcome selection, and tombstone bookkeeping.
- **Persistence (the one new extension point).** A narrow, "dumb" key-value primitive,
  `IAuthorizationCodeBackingStore`, that stores opaque, already-encrypted bytes under
  already-hashed keys and has zero knowledge of OAuth, tombstones, encryption, or expiry
  semantics. This is now the *only* thing a third party implements to add a backend.

The coordinator logic already existed in spirit — it was duplicated across the first-party
in-memory and distributed-cache stores. This ADR makes it explicit framework code and stops asking
third parties to re-derive it.

**Sealing mechanism.** `IAuthorizationCodeStore` stays `public` (so `ZeeKayDa.Auth.AspNetCore`, a
separate assembly, can inject and consume it), but gains an `internal` interface member that only
friend assemblies — those named in `[assembly: InternalsVisibleTo]` — can satisfy. A third-party
assembly attempting `class MyStore : IAuthorizationCodeStore` gets a **compile error** (it cannot
implement the internal member), while any assembly consuming `IAuthorizationCodeStore` via DI is
completely unaffected. This mirrors the `ClientAuthMethod` "reserved-variant-via-internal-member"
pattern from the extension-API review — the wrong thing (a hand-rolled protocol store) becomes
structurally unrepresentable outside the framework, rather than merely discouraged in prose.
Making the interface `internal` was rejected because `ZeeKayDa.Auth.AspNetCore` depends on it
cross-assembly (see Alternatives).

### 2. `StoreKey` — an opaque, already-hashed key

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// An opaque, already-hashed persistence key. Constructed ONLY by the framework, from a raw
/// code handle, via SHA-256. A backing-store implementation receives StoreKey values and can
/// persist them, use them as dictionary/row keys, and compare them — but can never recover the
/// raw handle, and so can never persist a redeemable secret even by accident.
/// </summary>
public readonly struct StoreKey : IEquatable<StoreKey>
{
    private readonly string _value;                      // e.g. "zkd:code:e:<hex(sha256(handle))>"
    internal StoreKey(string value) => _value = value;  // framework-only constructor

    /// The safe, hashed string form — suitable as a Redis key or SQL primary key. Never the raw handle.
    public override string ToString() => _value;
    public bool Equals(StoreKey other) => string.Equals(_value, other._value, StringComparison.Ordinal);
    public override bool Equals(object? obj) => obj is StoreKey k && Equals(k);
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(_value);
}
```

The constructor is `internal`: a backing store cannot fabricate a `StoreKey` from a raw handle, so
invariant #1 (hash the handle) becomes structurally unrepresentable in third-party code.

### 3. `IAuthorizationCodeBackingStore` — three methods, one hard invariant

```csharp
namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// The single extension point for durable storage behind the authorization-code store.
/// Implement this to put records in Redis, SQL, Cosmos, etc. It has NO knowledge of OAuth,
/// tombstones, encryption, or expiry semantics — it stores opaque, already-encrypted bytes
/// under already-hashed keys. The correctness of the redemption protocol does not depend on
/// this implementation beyond the ONE atomicity invariant on <see cref="TryInsertAsync"/>.
/// Implementations MAY throw their native exceptions freely; the framework wraps them (see §8).
/// </summary>
public interface IAuthorizationCodeBackingStore
{
    /// <summary>
    /// Atomically insert <paramref name="value"/> at <paramref name="key"/> only if no value
    /// exists at the key. Returns true if it was inserted, false if a value already existed.
    /// (Logical expiry is the coordinator's concern, not this primitive's — so "no value exists"
    /// means physically absent, not "no *live* value"; handles are 256-bit random, so a key is
    /// never legitimately reused and a physically-present value always means a genuine collision.)
    /// This is the ONE hard invariant: the insert-if-absent test and the write MUST be a single
    /// atomic operation (Redis SET NX, a unique-constraint INSERT, a conditional Cosmos create).
    /// If it is not atomic, single-use enforcement is lost.
    /// </summary>
    ValueTask<bool> TryInsertAsync(StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken ct);

    /// <summary>
    /// Return the stored bytes, or <c>null</c> if the key is confirmed absent. Read-only; never
    /// mutates. <b>Fail-closed contract:</b> return <c>null</c> ONLY for a confirmed-absent key.
    /// On ANY transport/backend failure (timeout, connection drop, deserialization error, auth
    /// failure) you MUST let the exception propagate — you MUST NOT catch it and return
    /// <c>null</c>. A swallowed fault that returns <c>null</c> is read by the coordinator as
    /// "no tombstone ⇒ code not yet redeemed," silently re-opening a replay window. The framework
    /// wraps any thrown exception as <c>ZeeKayDaStoreException</c> (§8); swallowing it defeats that
    /// guarantee. Throwing on fault is a contractual obligation, not a nicety.
    /// </summary>
    ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken ct);

    /// <summary>Remove the value at <paramref name="key"/> if present. Idempotent.</summary>
    ValueTask RemoveAsync(StoreKey key, CancellationToken ct);
}
```

The `expiresAt` argument lets a backend that supports native TTL (Redis, Cosmos) evict on its own
schedule. The coordinator does **not** rely on that eviction — it enforces expiry logically (§6) —
so a backend that ignores `expiresAt` and keeps stale bytes forever is still correct, just less
tidy. `GetAsync` deliberately does **not** filter on `expiresAt`: expiry is a protocol concern the
coordinator owns, not a persistence concern.

### 4. Registration — coordinator wired over the backing store

The existing builder methods keep their names; only what they wire changes.

- `AddAuthorizationCodeStore<T>()` keeps its name, but its generic constraint changes from
  `T : IAuthorizationCodeStore` to `T : IAuthorizationCodeBackingStore`. Internally it registers
  `T` as `IAuthorizationCodeBackingStore` **and** registers the framework's sealed
  `AuthorizationCodeStore` coordinator as `IAuthorizationCodeStore`. There is no way for a consumer
  to register `IAuthorizationCodeStore` directly — that type is framework-sealed (§1).
- `AddInMemoryAuthorizationCodeStore()` and `AddDistributedCacheAuthorizationCodeStore()` keep
  their names but become thin `IAuthorizationCodeBackingStore` implementations wired the same way
  (register the first-party backing store, then the coordinator). Both remain subject to the
  existing in-memory-outside-development gate (ADR 0008 / PR #345).

### 5. Encryption ownership sits with the framework

The coordinator owns the crypto decision entirely; the backing store stores opaque bytes and never
makes a fail-open/closed call:

- **Entries are encrypted.** The bytes crossing `TryInsertAsync` for an entry are Data-Protection
  ciphertext of the serialized `AuthorizationCodeEntry`. Storing plaintext claims / `redirect_uri`
  is unrepresentable in backing-store code — it only ever sees ciphertext.
- **The tombstone is an envelope** whose `FamilyId` is cleartext and whose `ProtectedSecret` is
  Data-Protection ciphertext, so replay detection survives a DP key rotation (§7).

Because the implementer stores opaque bytes either way and the framework decides which values are
ciphertext, invariant #2 (encrypt entries) is no longer an implementer decision at all.

### 6. Logical expiry, owned by the coordinator

The coordinator enforces expiry logically, not by trusting backend eviction. **Canonical rule:** a
record is logically expired when `now >= ExpiresAt + ClockSkewTolerance`. This is the
**accept-grace** direction, matching ADR 0008's existing liveness check — a code stays live for a
`ClockSkewTolerance` window *past* its nominal `ExpiresAt`, so a node whose clock runs slightly
ahead of the issuing node does not reject a still-valid code early. Backend TTLs (`expiresAt` on
`TryInsertAsync`) are written as `entry.ExpiresAt + ClockSkewTolerance` so a backend whose native
TTL clock runs ahead does not physically evict a record the coordinator still considers live.
Logical expiry remains authoritative; the padding only prevents premature *physical* eviction.

### 7. The tombstone is an envelope with a plaintext `FamilyId` (change from ADR 0008)

The tombstone written on redemption records the associated refresh-token `FamilyId` (so a
subsequent replay returns `AlreadyRedeemed { FamilyId }` and the endpoint can revoke the rest of
that family). The tombstone is a small **envelope**, not a single opaque ciphertext blob:

```
Tombstone {
    string  FamilyId;         // plaintext — a random GUID, not a secret
    byte[]  ProtectedSecret;  // Data-Protection ciphertext of any secret payload, if any
}
```

The load-bearing field is `FamilyId`, recoverable **without a successful Data-Protection
unprotect** because it lives in the cleartext part of the envelope. This is what lets replay
detection survive a DP key rotation: even when `ProtectedSecret` can no longer be unprotected, the
coordinator still reads `FamilyId`, returns `AlreadyRedeemed{FamilyId}`, and the endpoint can
revoke the family. ADR 0008's all-ciphertext tombstone degraded a post-rotation replay to
`NotFound` with the family no longer revocable; this envelope is strictly better.

The code store has no family-revocation path of its own and nothing to size from a
`FamilyAbsoluteExpiry`-shaped field, so the envelope carries only what this store actually uses.
The (out-of-scope, later) refresh-token reshape gets its own tombstone shape when it lands, sized
to what *its* revocation-marker horizon needs — this ADR deliberately does not pre-shape that field
here just to match a future envelope.

**The real `IDataProtector.Unprotect` throws — it does not return null.** On a rotated/unknown key
it throws `CryptographicException`. The coordinator catches that at **two distinct sites with
opposite semantics**, and this asymmetry is deliberate:

- **Entry decrypt failure → `NotFound`.** If the *entry* payload can't be unprotected, the entry is
  unusable — there is nothing to hand back — so the redeem path returns `NotFound`.
- **Tombstone `ProtectedSecret` decrypt failure → *still* `AlreadyRedeemed { FamilyId }`.** A
  present tombstone means the code was already redeemed; the plaintext `FamilyId` is right there, so
  replay is detected and the family is still revocable **even though the ciphertext part failed to
  unprotect**. Falling through to `NotFound` here would silently re-open a replay window.

Both are the *coordinator's* semantic responsibility and are DISTINCT from the `Guarded(...)`
transport-exception path (§8): a `CryptographicException` from `Unprotect` is a crypto-state
outcome the coordinator interprets, not a backend I/O fault to wrap as `ZeeKayDaStoreException`.
This two-catch-site asymmetry is itself an invariant a well-meaning refactor could silently
collapse (e.g. by hoisting both catches into one shared `catch (CryptographicException) =>
NotFound`), so the implementation MUST carry a test pinning **both** outcomes independently:
entry-unprotect-fails ⇒ `NotFound`, tombstone-unprotect-fails ⇒ `AlreadyRedeemed{FamilyId}`. A side
effect of the envelope is that ADR 0008's `AlreadyRedeemed.FamilyId == string.Empty`
"unrecoverable" sentinel path becomes rare — it now only occurs if the tombstone itself is lost,
not merely undecryptable.

**Residual disclosure (honest note).** Storing `FamilyId` in cleartext lets a read-only observer of
the store link a redeemed code's tombstone to its refresh-token family. This is non-blocking:
`FamilyId` is a random GUID, not a bearer credential, and the DP-rotation-survival benefit
outweighs the correlation surface. Two code-store specifics keep the surface narrow — and were the
basis of the §7 security sign-off (see banner): (a) **short-lived** — the code tombstone's backend
TTL is the code's own seconds-to-minutes lifetime (`entry.ExpiresAt + ClockSkewTolerance`, §9), so
the cleartext `FamilyId` sits at rest only briefly, unlike the refresh-token store where analogous
records live for months; and (b) **no chain to correlate** — each authorization code maps to a
distinct, freshly-minted family, so a `FamilyId` appears in at most one code tombstone. The
"correlate a rotation chain across records" concern is a refresh-token-store property (rotations
happen at the refresh endpoint); in the code store there is no cross-record chain to reconstruct.
This sits in mild tension with ADR 0008's `FamilyId`-logging-hygiene guidance (treat `FamilyId` as
sensitive-for-correlation) — the same value is now correlatable at rest — so read that guidance as
"minimise avoidable exposure," not "never persist in clear."

### 8. Fail-closed is a shared obligation — framework wraps thrown faults, the contract forbids swallowing

The coordinator wraps every backing-store call in a `Guarded(...)` helper that converts any native
exception *thrown* from the implementation into `ZeeKayDaStoreException` (ADR 0006). Because the
implementer never produces an *outcome*, the idiomatic-but-fatal `try { … } catch { return
NotFound; }` (invariant #4) is not expressible in backing-store code — there is no `NotFound` for
them to return.

But fail-closed is a *shared* obligation, not something the framework can guarantee alone:

- **The framework's half:** every exception that crosses the primitive boundary is wrapped as
  `ZeeKayDaStoreException`, so a *thrown* transport fault can never be misread as a store outcome.
- **The implementer's half** (enforced by the `GetAsync` contract in §3): a backing store that
  *swallows* a transport error and returns `null` reintroduces fail-*open* on the security-critical
  read — the coordinator reads `Get(tombstoneKey) is null` as "code not yet redeemed" on the replay
  path, so a swallowed timeout that returns `null` silently re-opens a replay window. The framework
  cannot tell a genuine absent key from a fault-masked-as-absent, so the contract MUST forbid the
  swallow: `GetAsync` returns `null` only for a confirmed-absent key and throws on any transport
  failure.

So the residual obligation on the implementer shrinks from ADR 0008's "select the right outcome on
error" to the single, inspectable rule "don't catch-and-return-null" — small enough to pin with a
fault-injection conformance test (§10).

**Cancellation is not a store fault.** `Guarded(...)` MUST rethrow `OperationCanceledException`
unwrapped when the supplied `CancellationToken` is cancelled, rather than classifying a cancelled
operation as a `ZeeKayDaStoreException`. Misclassifying cancellation as a store fault would mislead
callers (a client disconnect is not a storage outage) and pollute fault telemetry.

### 9. Key layout and what each operation does

Two key namespaces; `H(x)` is `Hex(SHA-256(UTF8(x)))`, performed by the framework. There is **no**
family-metadata or family-revocation key — a code has no family of its own; a code's family is
revoked via the refresh-token store when a descendant refresh token is reused.

| Namespace | Key | Value |
|---|---|---|
| entry | `zkd:code:e:{H(code)}` | Data-Protection ciphertext of `AuthorizationCodeEntry`; removed on redeem |
| tombstone | `zkd:code:t:{H(code)}` | envelope `{ plaintext FamilyId, DP-encrypted ProtectedSecret }` (§7); written on redeem; backend TTL `entry.ExpiresAt + ClockSkewTolerance` |

- **`StoreAsync(code, entry)`** — `TryInsertAsync(entryKey, protect(entry), entry.ExpiresAt + skew)`.
- **`TryRedeemAsync(code, clientId, familyId)`** — `Get(entryKey)`; if absent, resolve via the
  tombstone (below). Else decrypt (an entry `CryptographicException` → `NotFound`, §7); `NotFound`
  if logically expired (§6); `ClientMismatch` if `clientId` differs from the entry's bound client
  (does **not** consume); otherwise the single-use pivot:
  `TryInsertAsync(tombstoneKey, tombstoneEnvelope(familyId), entry.ExpiresAt + skew)` — if it
  returns false, someone else won the race, resolve via the tombstone; if true, `Remove(entryKey)`
  and return `Redeemed{Entry}`.
- **resolve-via-tombstone** — `Get(tombstoneKey)`; null → `NotFound`; else read the plaintext
  `FamilyId` from the envelope (recoverable even if `ProtectedSecret` unprotect throws, §7) →
  `AlreadyRedeemed{FamilyId}`.

Single-use enforcement (RFC 9700 §2.1.1) rides entirely on the one atomic
`TryInsertAsync(tombstoneKey, …)`: two concurrent redeemers both read the entry as valid, both
attempt the tombstone insert, the primitive guarantees exactly one wins, the loser reads the
tombstone and returns `AlreadyRedeemed`. This is the whole state machine, and it is framework code.

### 10. Extension sketch, and a conformance kit for the one invariant

This is the whole thing a docs-ignorant .NET developer writes to put authorization codes in SQL.
There is no OAuth, no crypto, no state machine, no fail-closed handling, no outcome to select — only
an atomic insert-if-absent, a get, and a delete:

```csharp
public sealed class SqlAuthorizationCodeBackingStore(NpgsqlDataSource db) : IAuthorizationCodeBackingStore
{
    // Table: auth_codes(key TEXT PRIMARY KEY, value BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL)
    // The PRIMARY KEY is what makes the insert atomic; nothing else here is security-relevant.

    public async ValueTask<bool> TryInsertAsync(
        StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand(
            "INSERT INTO auth_codes (key, value, expires_at) VALUES ($1, $2, $3) " +
            "ON CONFLICT (key) DO NOTHING");                 // <-- the one atomic insert-if-absent
        cmd.Parameters.Add(new() { Value = key.ToString() });
        cmd.Parameters.Add(new() { Value = value.ToArray() });
        cmd.Parameters.Add(new() { Value = expiresAt });
        return await cmd.ExecuteNonQueryAsync(ct) == 1;       // 1 row => inserted; 0 => key already present
    }

    public async ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("SELECT value FROM auth_codes WHERE key = $1");
        cmd.Parameters.Add(new() { Value = key.ToString() });
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is byte[] bytes ? bytes : null;         // no expiry filtering — the framework owns expiry
    }

    public async ValueTask RemoveAsync(StoreKey key, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("DELETE FROM auth_codes WHERE key = $1");
        cmd.Parameters.Add(new() { Value = key.ToString() });
        await cmd.ExecuteNonQueryAsync(ct);                   // idempotent by nature
    }
}
```

What the implementer cannot get wrong, because none of it is theirs: hashing (they only ever see a
`StoreKey`), encryption (they only ever see ciphertext bytes), the redeem state machine and its
atomicity (they provide one atomic insert-if-absent; the framework composes it), fail-closed (a
thrown `NpgsqlException` is wrapped by the coordinator's `Guarded`), expiry, `FamilyId` handling,
and outcome selection. The one thing they must get right — that `ON CONFLICT DO NOTHING` on a
primary key is atomic insert-if-absent — is a single primitive their backend provides natively.

**Conformance kit.** Two invariant families remain that the CLR cannot enforce structurally, so
they are the residual tier-3 target left after the reshape dissolved everything else (per the
"docs are not a mitigation" ordering). The framework ships a **ready-to-derive xUnit base class**
(an abstract fixture the implementer subclasses, supplying a factory for their backend); running it
is a **MUST for any production backend**:

1. **Atomicity** — a concurrent-insert race proving exactly one of N simultaneous `TryInsertAsync`
   calls to the same key returns `true`.
2. **Fail-closed** — fault-injection cases proving that when the backend throws, the fault surfaces
   as `ZeeKayDaStoreException` on all three operations, and specifically that `GetAsync`
   **throws-not-swallows** on a transport fault (it does NOT catch-and-return-null, §3/§8).

Atomicity-to-backend mappings the kit exercises: Redis `SET key value NX PX <ttl>`; relational SQL
`INSERT` against a `PRIMARY KEY`/`UNIQUE` constraint (or `ON CONFLICT DO NOTHING` returning 0
rows); Cosmos `CreateItemAsync` (409 on conflict); Azure Table `AddEntity` (409); in-memory
`ConcurrentDictionary.TryAdd`. The anti-pattern named explicitly: a non-atomic
`if (!Exists(key)) Insert(key)` has a TOCTOU window and **loses single-use enforcement** — use the
backend's native conditional write, never a read-then-write.

### 11. Rename: `AuthorizationCodeRedemptionOutcome` → `AuthorizationCodeRedemptionResult`

The public outcome type is renamed to `AuthorizationCodeRedemptionResult` for consistency with
`ClientAuthenticationResult` / `SigningResult`. The four nested cases (`Redeemed`, `ClientMismatch`,
`AlreadyRedeemed`, `NotFound`) keep their names, and `AlreadyRedeemed` still carries `FamilyId`.
Pre-1.0 rename with no compatibility impact (nothing is published).

---

## Considered and Rejected Alternatives

### Keep `IAuthorizationCodeStore` as an open extension point + a conformance kit

The status quo the epic #352 originally leaned toward (a whole-store conformance test-kit).
Rejected as a tier-3 fix for a problem a tier-1 reshape dissolves. A conformance kit still requires
the implementer to know it exists, run it, and interpret failures; it does nothing for the
invariants the CLR can't express as a test (e.g. "encrypt entries") and it leaves the full set of
prose MUSTs live on a public interface. The reshape makes hashing, encryption, fail-closed, expiry,
and outcome selection *unrepresentable* to get wrong, shrinking the residual test target from a
whole store to the single `TryInsertAsync` atomicity primitive plus its fail-closed contract. Per
Design Principle 6, a test/kit is the last resort, reached only after reshape is proven impossible
— here reshape was not merely possible, it was cheaper.

### Make `IAuthorizationCodeStore` `internal` to seal it

The obvious way to stop third parties implementing the protocol interface is to make it `internal`.
Rejected because `ZeeKayDa.Auth.AspNetCore` is a separate assembly that must *consume* (inject)
`IAuthorizationCodeStore` — e.g. a consumer writing a custom token endpoint injects it to reuse the
redemption protocol. An `internal` interface breaks that cross-assembly consumption. The
internal-member seal (§1) blocks *implementation* by non-friend assemblies while leaving
*consumption* completely open, which is exactly the asymmetry required.

### Naming the backing-store extension point

The backing-store primitive went through four candidate names before `IAuthorizationCodeBackingStore`:

- **`IExpiringKeyValueStore`** (the draft ADR's name). Rejected as *too generic*. It reads as a
  reusable general-purpose cache abstraction and invites a consumer to register one shared instance
  for "all the expiring key-value needs" — but the authorization-code store and the (future)
  refresh-token store deliberately do **not** share one backing interface: they diverge on lifetime
  (codes live seconds and are disposable; refresh tokens live months and carry family
  relationships) and on durability pressure (a lost code fails one authorization and the user
  retries; lost refresh tokens force mass re-authentication and a multi-instance deployment
  *requires* a shared backend). A name that reads as "one generic KV store" actively works against
  that separation. `IAuthorizationCodeBackingStore` names *what it backs*, so the two stores read as
  two distinct, independently-registered extension points — which is what they are.
- **`IAuthorizationCodeRepository`.** Rejected because "Repository" carries DDD/EF-Core baggage —
  it implies a richer, query-capable, domain-aware collection abstraction (find-by-predicate,
  unit-of-work, change tracking). This type is the opposite: three dumb byte-oriented operations
  with no query surface and no domain knowledge. "Repository" would over-promise the shape.
- **`IAuthorizationCodePersister`.** Rejected as an awkward, non-idiomatic .NET agent-noun that
  doesn't appear in the BCL or common libraries, and — like "Persister"/"Persistence" generally —
  it foregrounds the *act of persisting* rather than *the thing being implemented*. It also reads as
  write-only, obscuring that the type is equally a reader (`GetAsync`).
- **`IAuthorizationCodePersistence`.** Rejected for the same "foregrounds the act, not the thing"
  reason, plus it's an abstract mass-noun — an interface a consumer *implements* reads better as a
  concrete thing ("a backing store") than as an abstraction ("persistence"). "BackingStore" is an
  established .NET term (property backing fields, backing stores for caches) for "the place the real
  bytes live behind a richer abstraction," which is precisely this type's role behind the sealed
  coordinator.

### A single shared backing interface for codes and refresh tokens

Wire one backing interface and use it for both stores. Rejected for the divergence reasons above
(lifetime, durability pressure). Forcing one registration would push consumers to either
over-provision a durable backend for disposable codes or under-provision a per-instance cache for
refresh tokens. The refresh-token store is out of scope here, but this ADR deliberately does not
introduce a shared base that would prejudge that decision — the refresh-token reshape gets its own
backing-store type when it lands. (This is settled and consistent with the extension-API review.)

### Add an `AlreadyRedeemed.FamilyUnrecoverable` union case instead of a plaintext `FamilyId`

When a Data-Protection key rotation makes the tombstone payload undecryptable, ADR 0008 degraded a
replay to `NotFound`. One option was to encrypt the tombstone's `FamilyId` too and add a new
`AlreadyRedeemed.FamilyUnrecoverable` case so callers explicitly handle "replay detected but family
unrecoverable." Rejected in favour of storing `FamilyId` unencrypted (§7): it is a non-secret
random GUID, so encrypting it buys nothing, and leaving it in clear means replay detection *and*
family revocation survive a DP key rotation — strictly better — while requiring **no change to the
public outcome union**. Adding a union case would have churned a public type to model a failure the
unencrypted approach simply prevents.

### Two-phase commit / `CommitToken` handoff

Rejected already in ADR 0008 for the store surface and not reconsidered here: the atomic
`TryInsertAsync(tombstone)` pivot achieves single-use with one round trip and no cross-call state,
so a two-phase protocol would add surface area and a dangling-commit failure mode for no gain.

---

## Consequences

### Positive

- The store extension point goes from several prose MUSTs (three security-critical) to one
  primitive with one atomicity invariant. Handle hashing and plaintext-entry storage become
  *unrepresentable* in third-party code; fail-closed and encryption stop being implementer
  decisions.
- Replay detection now survives a Data-Protection key rotation (§7) — a strict security
  improvement over ADR 0008 — via a cleartext tombstone envelope whose `FamilyId` is recoverable
  without a successful unprotect.
- The residual conformance target shrinks dramatically: from a whole-store kit to a derive-and-run
  xUnit kit covering just the primitive's atomicity and fail-closed contract (§10).
- The `StoreKey` / backing-store shape is reusable by the later refresh-token reshape without
  re-litigating the persistence boundary.

### Negative / Trade-offs

- **Pre-publication blast radius.** Introduces `StoreKey` and `IAuthorizationCodeBackingStore`;
  makes `IAuthorizationCodeStore` framework-sealed via an internal member; renames the redemption
  outcome type; rewrites the first-party `InMemory*` / `DistributedCache*` stores as thin backing
  adapters (smaller than today); and changes the tombstone from a single ciphertext blob to a small
  envelope. Endpoint callers are unaffected. Acceptable because nothing is published (pre-1.0).
- **The atomicity invariant is irreducible.** The CLR cannot prove a given Redis/SQL
  implementation's `TryInsertAsync` is atomic. This is the honest ceiling — mitigated by the
  mapping guidance and the narrow conformance test (§10), and a far smaller target than the
  whole-store surface it replaces.
- **A behavioural change to the tombstone** (plaintext `FamilyId`, §7): a read-only store observer
  can now correlate rotation chains by `FamilyId`. Non-blocking (random GUID, not a bearer
  credential) but named honestly and flagged for security sign-off.

---

## Security Considerations

- **Single-use enforcement (RFC 9700 §2.1.1)** rides entirely on the one atomic
  `TryInsertAsync(tombstoneKey, …)` pivot; the coordinator, not the implementer, owns the state
  machine.
- **Replay detection** survives a Data-Protection key rotation because the tombstone envelope's
  `FamilyId` is an unencrypted non-secret recoverable without a successful unprotect (§5, §7). The
  real `IDataProtector.Unprotect` **throws** `CryptographicException` on a rotated/unknown key; the
  coordinator catches it at two distinct sites with opposite semantics — entry decrypt failure →
  `NotFound`, tombstone `ProtectedSecret` decrypt failure → *still* `AlreadyRedeemed{FamilyId}`. A
  refactor could silently collapse this into a single catch, so the impl MUST carry a test pinning
  **both** outcomes independently (§7).
- **Handle confidentiality:** the raw code never reaches backing-store code — only `StoreKey`
  (SHA-256 hash). A persistence breach yields no redeemable codes.
- **At-rest confidentiality:** entries are Data-Protection ciphertext before they cross the
  primitive boundary; backing-store code cannot store plaintext claims. One cleartext non-secret
  surface is disclosed by design: the tombstone's `FamilyId` (§7), a non-bearer GUID a store
  observer can correlate across a rotation chain — mild and non-blocking.
- **Fail-closed I/O is a shared obligation (§8):** the framework wraps every *thrown* backing-store
  exception as `ZeeKayDaStoreException`, but the `GetAsync` contract (§3) additionally FORBIDS
  swallowing a transport fault and returning `null` — a fault-masked-as-absent tombstone read fails
  *open* on the replay path. A fault-injection conformance case pins it (§10).
- **Cancellation is not a store fault:** `Guarded(...)` rethrows `OperationCanceledException`
  unwrapped on token cancellation rather than misclassifying it as `ZeeKayDaStoreException` (§8).

---

## Changelog

- 2026-07-15 — issue #375 (epic #352) — ADR created. Records the authorization-code store
  protocol/persistence split: `StoreKey` + `IAuthorizationCodeBackingStore` as the sole persistence
  extension point; `IAuthorizationCodeStore` becomes a framework-sealed coordinator
  (`AuthorizationCodeStore`) via an internal interface member. Re-homes the ADR 0008 redemption
  protocol into the framework and changes one ADR 0008 behaviour: the redemption tombstone becomes
  an envelope with a plaintext `FamilyId` so `AlreadyRedeemed{FamilyId}` survives a Data-Protection
  key rotation. Renames `AuthorizationCodeRedemptionOutcome` → `AuthorizationCodeRedemptionResult`.
  The refresh-token store reshape (family metadata, whole-family revocation, absolute-lifetime cap)
  is deliberately out of scope and left for later work.
- 2026-07-15 — security review — **§7 plaintext-`FamilyId` tombstone: signed off (authorization-code-store
  scope only).** Reviewed independently of the parked refresh-token draft. Verified against `src/`
  that `FamilyId` is used only as a non-secret correlation/revocation-lookup identifier (revocation
  markers key on `Hash(FamilyId)`; `RevokeFamilyAsync` is framework-internal, unreachable by a
  read-only store observer), so the disclosure is correlation, not a bearer credential. The trade is
  clearly correct for codes: the cleartext surface is short-lived (code-lifetime TTL) and degenerate
  (one distinct family per code tombstone, so no rotation chain to correlate), while rotation-survival
  is a strict security gain. Banner and §7 residual-disclosure note updated to record this. Refresh-token
  store §7 analogue remains out of scope and requires its own sign-off.
