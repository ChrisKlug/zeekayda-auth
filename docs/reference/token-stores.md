---
title: "Token stores"
description: "Reference for the authorization-code and refresh-token stores, the IAuthorizationCodeBackingStore and IRefreshTokenBackingStore extension points, lifetime options, built-in implementations, and ZeeKayDaStoreException."
parent: "Reference"
nav_order: 5
---

*Added in Unreleased.*

ZeeKayDa.Auth requires three stores to be registered before the application starts:

- The authorization code store — persists short-lived authorization codes, enforces single-use redemption per [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1), and guarantees at most one code per authorization request.
- The refresh token store — persists long-lived refresh tokens, enforces rotation and reuse detection per [RFC 9700 §4.13](https://www.rfc-editor.org/rfc/rfc9700#section-4.13), and supports family-level revocation.
- The interaction store — holds each in-flight authorization request between `/connect/authorize` and the response to the client, one entry per request, so any number can be in flight in one browser. It has no public interface: register the per-process implementation or the one over your `IDistributedCache`.

`AddZeeKayDaAuth` registers the framework side of both token stores — single-use redemption, rotation and reuse detection — but none of the three storage implementations. You must choose one for each using the builder methods below, or register a custom backing store for the token stores. If any store is missing at startup, the application fails with `ZeeKayDaConfigurationException` naming what is missing.

For step-by-step registration instructions, see [Configure token stores](../how-to/configure-token-stores.md).

---

## Choosing the right store

| Scenario | Authorization code store | Refresh token store |
|---|---|---|
| Local development | `.AddInMemoryAuthorizationCodeStore()` | `.AddInMemoryRefreshTokenStore()` |
| Integration tests | `.AddInMemoryAuthorizationCodeStore()` | `.AddInMemoryRefreshTokenStore()` |
| Production | Custom atomic store (Redis + Lua, SQL with optimistic concurrency) | Custom atomic store (same backends) |

> ⚠️ **Warning:** Both in-memory stores are development and testing only. They lose all tokens on restart and silently disable single-use enforcement and reuse detection across multiple instances. Outside a `Development` environment the framework refuses to start with in-memory stores unless `allowOutsideDevelopment: true` is passed to the registration call.

---

## Registration API

All store registration goes through the `ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth`. Each method checks at registration time that the targeted interface is not already registered; a second registration for the same interface throws `InvalidOperationException` immediately, naming the conflict.

### `.AddInMemoryStores(bool allowOutsideDevelopment = false)`

Registers all three in-memory stores — `InMemoryAuthorizationCodeBackingStore` and `InMemoryRefreshTokenBackingStore` wired underneath the framework's sealed `AuthorizationCodeStore` and `RefreshTokenStore` coordinators, and the per-process interaction store. In a `Development` environment, logs one `LogLevel.Information` message per store at startup. Outside a `Development` environment, startup fails with `ZeeKayDaConfigurationException` unless `allowOutsideDevelopment` is `true`. The value is passed through to `.AddInMemoryAuthorizationCodeStore()`, `.AddInMemoryRefreshTokenStore()` and `.AddInMemoryInteractionStore()`, each of which gates on it independently.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryStores();
```

### `.AddInMemoryAuthorizationCodeStore(bool allowOutsideDevelopment = false)`

Registers `InMemoryAuthorizationCodeBackingStore` as the backing store, wired underneath the framework's own `AuthorizationCodeStore`. Logs the same startup message as `.AddInMemoryStores()`. The environment check applies, gated on this method's own `allowOutsideDevelopment` value — independent of any other in-memory store registration on the same builder.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryAuthorizationCodeStore()
    .AddRefreshTokenStore<MyPersistentRefreshTokenBackingStore>();
```

### `.AddInMemoryRefreshTokenStore(bool allowOutsideDevelopment = false)`

Registers `InMemoryRefreshTokenBackingStore` as the backing store, wired underneath the framework's own `RefreshTokenStore`. Logs the same startup message as `.AddInMemoryStores()`. The environment check applies, gated on this method's own `allowOutsideDevelopment` value — independent of any other in-memory store registration on the same builder.

### `.AddInMemoryInteractionStore(bool allowOutsideDevelopment = false)`

Registers the per-process interaction store. An authorization request started on one instance cannot be completed by another, so this is for development and testing only, with the same environment gate and `allowOutsideDevelopment` override as the in-memory token stores. Included in `.AddInMemoryStores()`.

### `.AddDistributedCacheInteractionStore(bool allowMemoryCacheOutsideDevelopment = false)`

Registers the interaction store over the host's `IDistributedCache`. Requires an `IDistributedCache`; startup fails without one. The interaction store needs only set, get and remove, so a shared cache — Redis, SQL Server, any `IDistributedCache` implementation — is a complete production answer: the one race in the flow, two responses completing one request, is decided by the authorization code store's interaction claim, not here.

The exception is the per-process `MemoryDistributedCache` from `AddDistributedMemoryCache()`, which is shared with nothing. Outside a `Development` environment startup fails when the store resolves that cache, unless `allowMemoryCacheOutsideDevelopment` is `true`, which downgrades the failure to a `LogLevel.Critical` warning on every start.

```csharp
builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "...");
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyRedisAuthorizationCodeBackingStore>()
    .AddRefreshTokenStore<MyRedisRefreshTokenBackingStore>()
    .AddDistributedCacheInteractionStore();
```

### `.AddAuthorizationCodeStore<T>()`

Registers a custom `T : class, IAuthorizationCodeBackingStore` as the singleton backing store, wired underneath the framework's own `AuthorizationCodeStore`. This is the registration path for production custom stores — see [The backing store contracts](#the-backing-store-contracts) below.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyRedisAuthorizationCodeBackingStore>()
    .AddRefreshTokenStore<MyRedisRefreshTokenBackingStore>();
```

`T` must be a concrete reference type with a publicly accessible constructor so the DI container can instantiate it.

### `.AddRefreshTokenStore<T>()`

Registers a custom `T : class, IRefreshTokenBackingStore` as the singleton backing store, wired underneath the framework's own `RefreshTokenStore` — see [The backing store contracts](#the-backing-store-contracts) below.

---

## Lifetime options

### `AuthorizationEndpoint.AuthorizationCodeLifetime`

| Attribute | Value |
|---|---|
| Type | `TimeSpan` |
| Default | `60 seconds` |
| Valid range | `> 0` and `≤ 600 seconds` |
| Location | `AuthorizationServerOptions.AuthorizationEndpoint.AuthorizationCodeLifetime` |

Controls how long an issued authorization code remains valid. [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) requires codes to be short-lived; 60 seconds is the default and the industry standard. Values above 600 seconds (10 minutes) are rejected at startup.

```csharp
options.AuthorizationEndpoint.AuthorizationCodeLifetime = TimeSpan.FromSeconds(60);
```

### `TokenEndpoint.RefreshTokenLifetime`

| Attribute | Value |
|---|---|
| Type | `TimeSpan` |
| Default | `14 days` |
| Valid range | `> 0` (no upper bound enforced) |
| Location | `AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime` |

Controls how long an issued refresh token remains valid before expiring naturally. No upper bound is enforced; operators are responsible for choosing a value appropriate to their threat model. Longer lifetimes reduce re-authentication friction but increase the window in which a compromised token or an undetected family-revocation failure is exploitable.

```csharp
options.TokenEndpoint.RefreshTokenLifetime = TimeSpan.FromDays(14);
```

> 💡 **Tip:** `RefreshTokenLifetime` is an **idle timeout**, not an absolute session duration. Refresh tokens rotate on every use: each successful token refresh tombstones the old token and issues a new one with a fresh `RefreshTokenLifetime` window. A user who refreshes regularly can therefore maintain their session indefinitely. To enforce an absolute session cap you would need a mechanism outside `RefreshTokenLifetime` — ZeeKayDa.Auth does not currently provide one.

`RefreshTokenLifetime` does **not** govern authorization code tombstone retention. A tombstone (the record that a code was redeemed) is kept only until the authorization code's own expiry plus `ClockSkewTolerance` — the same short-lived window as the code itself (see [`AuthorizationCodeLifetime`](#authorizationendpointauthorizationcodelifetime), default 60 seconds, capped at 600). This is intentionally short and unrelated to how long the refresh token issued from that code lives: replay detection for an authorization code only needs to outlive the code's own validity window, because once that window has passed a `NotFound` result for a replayed code is behaviourally indistinguishable from `AlreadyRedeemed` to an attacker — the code cannot be exchanged for tokens either way.

> ⚠️ **Warning:** ASP.NET Core Data Protection key retention must be at least `RefreshTokenLifetime`. Shorter retention causes stored token entries to become unreadable after key rotation, which surfaces as `NotFound` at request time and silently logs out every user holding a token issued under the rotated key. Configure key persistence and retention duration accordingly before deploying to production.

### `ClockSkewTolerance`

| Attribute | Value |
|---|---|
| Type | `TimeSpan` |
| Default | `5 seconds` |
| Valid range | `≥ 0` and `< AuthorizationCodeLifetime / 2` |
| Location | `AuthorizationServerOptions.ClockSkewTolerance` |

A grace window added to `ExpiresAt` checks to absorb clock drift between hosts (`entry.ExpiresAt + ClockSkewTolerance > now`). This check is applied by the framework's `AuthorizationCodeStore` and `RefreshTokenStore` coordinators, not by the backing store — so it applies uniformly to every registered backing store, including the in-memory ones, even though a single-instance in-memory deployment has no actual inter-node clock drift to absorb. Authorization code tombstone expiry uses the same `ExpiresAt + ClockSkewTolerance` formula (see the tombstone retention note above); it is not a separately configurable TTL.

The default is intentionally small. Values approaching half of `AuthorizationCodeLifetime` effectively nullify the code expiry guarantee; the startup validator rejects any value ≥ `AuthorizationCodeLifetime / 2`.

---

## In-memory stores

`InMemoryAuthorizationCodeBackingStore` and `InMemoryRefreshTokenBackingStore` are the backing stores wired underneath the `AuthorizationCodeStore` and `RefreshTokenStore` coordinators when you register in-memory stores. Both are backed by a plain `ConcurrentDictionary<StoreKey, ...>` — there is no `IMemoryCache` and no `SemaphoreSlim` locking involved. Each provides its one required atomicity guarantee natively: `InMemoryAuthorizationCodeBackingStore.TryInsertAsync` uses `ConcurrentDictionary.TryAdd`, and `InMemoryRefreshTokenBackingStore.TryMarkConsumedAsync` uses `ConcurrentDictionary.TryUpdate` as its compare-and-set. `InMemoryRefreshTokenBackingStore` additionally holds a `ReaderWriterLockSlim` around family/subject revocation scans so that a grant inserted concurrently with a revoke call is never missed.

**Limitations:**

- **Single-instance is a deployment invariant, not a recommendation.** Running multiple instances with in-memory stores silently disables single-use enforcement ([RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1)) and reuse detection ([RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2)). Codes and tokens issued by instance A are invisible to instance B.
- **All tokens are lost on process restart.** Authorization code loss is operationally acceptable (60-second lifetime); refresh token loss forces every active user to re-authenticate.
- **Entries are never evicted while the process runs.** Neither backing store removes expired data on a timer or on read. An authorization code's entry is removed only when it is successfully redeemed; a redemption tombstone, once written, is never removed at all. Refresh token grants (including consumed and revoked ones) and the records of revoked families are likewise never removed. On a long-running process this means the in-memory dictionaries grow monotonically with the number of codes and tokens ever issued — acceptable for development and short-lived test hosts, but a memory-growth characteristic to be aware of before using these stores for anything longer-running.
- **Development and testing only.** In-memory stores are never an acceptable production choice. Outside a `Development` host environment the framework refuses to start unless the registration call's `allowOutsideDevelopment` parameter is set to `true` (intended only for integration test hosts that intentionally run under a non-`Development` environment name). Each of `.AddInMemoryStores()`, `.AddInMemoryAuthorizationCodeStore()`, and `.AddInMemoryRefreshTokenStore()` gates on its own `allowOutsideDevelopment` value independently.

**Startup message text (logged at `LogLevel.Information` in `Development`, once per store, naming it):**

```text
ZeeKayDa.Auth: the in-memory authorization code store is active. Its contents are lost
on process restart and invisible to other instances: issued tokens, single-use
enforcement and reuse detection do not survive a restart or span a multi-instance
deployment, and an in-flight authorization request cannot be completed by another
instance. This configuration is intended for development and testing only and must not
be used in production.
```

**Data Protection.** Authorization code entries are serialised to JSON and encrypted using `IDataProtectionProvider` (purposes: `ZeeKayDa.Auth:AuthorizationCodeStore` and `ZeeKayDa.Auth:RefreshTokenStore`). Refresh token grants are only partially encrypted: `FamilyId`, `Subject`, `ClientId`, the expiry timestamps, and — critically — the `Status` column (`Active`/`Consumed`/`Revoked`) are stored as cleartext columns on the grant row; only the `ProtectedPayload` field (the serialized `RefreshTokenEntry`) is Data-Protection-encrypted. This is deliberate: revocation is decided from cleartext only — a grant's own `Status` column, and the backing store's separate record of revoked families, which also covers a family revoked before it had any grant and a successor stored after the revoke — so a Data Protection failure can never cause a revoked family to silently appear unrevoked. There is no encrypted revocation state to fail to decrypt.

---

## `ZeeKayDaStoreException`

`ZeeKayDaStoreException` is thrown by the framework's authorization-code and refresh-token stores when an underlying transport fails — a cache unavailability, database timeout, or network error. It derives from `ZeeKayDaException`.

```csharp
public class ZeeKayDaStoreException : ZeeKayDaException
{
    public ZeeKayDaStoreException(string message) : base(message) { }
    public ZeeKayDaStoreException(string message, Exception innerException)
        : base(message, innerException) { }
}
```

`ZeeKayDaStoreException` is distinct from `ZeeKayDaConfigurationException`. Configuration errors are raised at startup; store exceptions are raised at request time during token operations.

`ZeeKayDaStoreException` is not sealed. Custom store implementations may subclass it to carry backend-specific context (for example, a `RedisStoreException` carrying connection state or retry count) while remaining compatible with callers that catch the base type.

**What throws it.** Any of the store interface methods — `StoreAsync`, `TryRedeemAsync`, `TryConsumeAsync`, `FindAsync`, `RevokeFamilyAsync` — may throw `ZeeKayDaStoreException` when the backing transport fails. The built-in implementations wrap raw infrastructure exceptions as `InnerException`. Custom implementations should do the same.

**What does not throw it.** Semantic outcomes such as `NotFound`, `AlreadyRedeemed`, `AlreadyConsumed`, and `Revoked` are returned values, not exceptions. Only infrastructure failures are thrown.

**Fail-closed semantics.** Store implementations must never swallow transport failures or convert them to semantic outcomes:

- A transport failure on `StoreAsync` must throw; the authorization or token endpoint aborts the response. A code or token that was not successfully persisted must never be returned to the client.
- A transport failure on `TryRedeemAsync` or `TryConsumeAsync` must throw; the endpoint returns `error=server_error`. Converting a transport failure to `NotFound` would suppress reuse detection and potentially allow an attacker to evade family revocation.

**Application response.** The ZeeKayDa.Auth framework catches `ZeeKayDaStoreException` internally and returns an appropriate OAuth error response to the client (`error=server_error`). Host applications do not need to catch it at the middleware level, but may do so in a global exception handler to emit operational telemetry or circuit-breaker logic.

---

## Implementing a custom store

A production custom store implements a backing store only. The framework's own stores own the redemption protocol — single-use enforcement, replay/reuse detection, at-rest encryption, clock-skew-tolerant expiry — and only delegates the question of *where the bytes live* to a backing store you write. The two backing-store contracts are:

- `IAuthorizationCodeBackingStore` — sits underneath the framework's authorization code store. It has no knowledge of OAuth, tombstones, encryption, or expiry semantics; it stores opaque, already-encrypted bytes under already-hashed keys.
- `IRefreshTokenBackingStore` — sits underneath the framework's refresh token store. It has no hashing, no encryption, and no single-use state machine beyond one atomic invariant; it stores rows and runs equality queries over their non-secret columns.

Register a custom implementation of either with the typed builder methods, exactly as for the built-in stores:

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyAtomicCodeBackingStore>()
    .AddRefreshTokenStore<MyAtomicRefreshTokenBackingStore>();
```

> 💡 **Tip:** The two stores are independently replaceable. You can mix an in-memory authorization code store (acceptable during development) with a custom persistent refresh-token grant store by calling `.AddInMemoryAuthorizationCodeStore()` and `.AddRefreshTokenStore<T>()` on the same builder chain.

### `StoreKey`

Both backing-store contracts receive keys as `StoreKey`, not as raw strings — a `readonly struct` wrapping an opaque, already-hashed string. Its constructor is internal: only the framework can produce a `StoreKey`, by hashing a raw code or token handle. A backing store can persist a `StoreKey` (as a Redis key, a SQL primary key, a Cosmos document ID), compare it, and call `ToString()` to get the safe hashed-string form — but it can never fabricate one from a raw handle, and it can never recover a raw handle from one. This makes "the backing store never sees a raw bearer credential" structurally true rather than merely documented.

```csharp
public readonly struct StoreKey : IEquatable<StoreKey>
{
    public override string ToString(); // the safe, hashed string form
    public bool Equals(StoreKey other);
    // == and != operators
}
```

### The backing store contracts

#### `IAuthorizationCodeBackingStore`

```csharp
public interface IAuthorizationCodeBackingStore
{
    ValueTask<bool> TryInsertAsync(
        StoreKey key, ReadOnlyMemory<byte> value, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    ValueTask<ReadOnlyMemory<byte>?> GetAsync(StoreKey key, CancellationToken cancellationToken);

    ValueTask RemoveAsync(StoreKey key, CancellationToken cancellationToken);
}
```

| Member | Contract |
|---|---|
| `TryInsertAsync` | **MUST be a single atomic insert-if-absent operation** — a Redis `SET NX`, a SQL unique-constraint `INSERT`, a conditional Cosmos create. Returns `true` if inserted, `false` if a value already existed at `key`. A non-atomic `if (!Exists(key)) Insert(key)` has a TOCTOU window that lets two concurrent redemptions of the same code both succeed. `expiresAt` is advisory — the coordinator enforces expiry logically and does not depend on backend eviction, so a backend without native TTL support may ignore it. |
| `GetAsync` | Read-only; never mutates. **MUST return `null` only for a confirmed-absent key.** On any transport or backend failure (timeout, connection drop, deserialization error, auth failure) the implementation **MUST let the exception propagate** — it must never catch the fault and return `null`. A swallowed fault that returns `null` is read by the coordinator as "no tombstone ⇒ code not yet redeemed," silently re-opening a replay window. |
| `RemoveAsync` | Removes the value at `key` if present. **Idempotent** — removing an absent key is a successful no-op, not an error. |

> ⚠️ **Warning:** `TryInsertAsync` is the one hard atomicity invariant on this interface. If your backend cannot express insert-if-absent as a single operation, do not implement this interface against it directly — use a backend that can, or a first-party adapter.

#### `IRefreshTokenBackingStore`

```csharp
public interface IRefreshTokenBackingStore
{
    ValueTask InsertAsync(RefreshTokenGrant grant, CancellationToken cancellationToken);

    ValueTask<RefreshTokenGrant?> FindByHandleAsync(StoreKey handleHash, CancellationToken cancellationToken);

    ValueTask<bool> TryMarkConsumedAsync(StoreKey handleHash, CancellationToken cancellationToken);

    ValueTask RevokeFamilyAsync(string familyId, DateTimeOffset rememberUntil, CancellationToken cancellationToken);

    ValueTask RevokeBySubjectAsync(string subject, CancellationToken cancellationToken);

    ValueTask<bool> IsFamilyRevokedAsync(string familyId, CancellationToken cancellationToken);
}
```

The interface is deliberately limited to exactly these six methods — there is no bulk remove/cleanup method and no bulk-read-by-family/subject.

| Member | Contract |
|---|---|
| `InsertAsync` | Inserts a new grant. `HandleHash` is derived from a 256-bit random handle, so a primary-key collision is a genuine duplicate or bug — let a unique-constraint violation propagate; the coordinator wraps it. |
| `FindByHandleAsync` | Read-only. **MUST return `null` only for a confirmed-absent handle.** Same fail-closed contract as `IAuthorizationCodeBackingStore.GetAsync` — on any transport/backend fault the implementation **MUST let the exception propagate**, never catch it and return `null`. A fault masked as `null` reads as "no such token" and silently defeats reuse detection. |
| `TryMarkConsumedAsync` | **The one hard atomicity invariant on this interface.** Transitions the grant from `Active` to `Consumed` as a single atomic operation and returns whether *this call* performed the transition: `true` iff the row was `Active` and is now `Consumed` because of this call; `false` if the row was already non-`Active` or is absent. SQL: `UPDATE ... SET status=Consumed WHERE handle=@h AND status=Active`, check `rowsAffected==1`. Cosmos: conditional replace with `IfMatch=etag`. Redis: a Lua script or `WATCH`/`MULTI`/`EXEC`. Without atomicity, two concurrent consumers can both transition the same grant, breaking single-use enforcement. |
| `RevokeFamilyAsync` | Records that `familyId` is revoked, then sets every grant whose `FamilyId` equals `familyId`, and that already exists at the moment the call evaluates its predicate, to `Revoked`. **Idempotent.** The correctness bar is completeness over existing rows, per [RFC 9700 §4.13](https://www.rfc-editor.org/rfc/rfc9700#section-4.13): every grant already in the family — including one inserted concurrently with, but not strictly after, this call — must end up `Revoked`. Mark, do not delete: a still-live token in a revoked family must remain findable and read as `Revoked`. The record is **not a grant**: keep it in its own table, container or key space, never as a row `FindByHandleAsync` can return. Commit it before marking any row, not in the same transaction: a fault while marking then still leaves the family revoked, where a rolled-back transaction would take the record with it. Keep it at least until `rememberUntil` — the family's absolute lifetime plus clock skew, after which no grant of the family can be live — and never shorten it on a repeat call. The family may have no grants yet: an authorization code replayed before its first refresh token is stored revokes an empty family. SQL: `INSERT INTO revoked_families (family_id, remember_until) ... ON CONFLICT DO UPDATE SET remember_until = GREATEST(...)`, then `UPDATE grants SET status=Revoked WHERE family_id=@f`. |
| `RevokeBySubjectAsync` | Same completeness bar as `RevokeFamilyAsync`, keyed on `Subject`. Present so a future subject-level logout-all is possible; no coordinator method calls it yet. `subject` arrives as cleartext (a plain equality predicate, not a hashed key) — this control must never fail to match, which is why the subject is not peppered or keyed. |
| `IsFamilyRevokedAsync` | Read-only, no side effects. Returns `true` iff `RevokeFamilyAsync` has recorded `familyId` as revoked and the record is still kept — whether or not the family has any grants. **MUST be a strongly-consistent / primary read** — a stale-replica read that misses a just-committed revoke fails open. **MUST throw on fault**; a fault masked as `false` reads as "not revoked" and defeats the gate. The coordinator calls this before honouring a grant's own `Active` status, so a successor inserted after `RevokeFamilyAsync` is still caught at consume time. |

> ⚠️ **Warning:** Three obligations here are security-critical and invisible to the compiler: `TryMarkConsumedAsync`'s atomicity, the fail-closed (throw, don't swallow) behaviour of every read path, and revocation completeness including grants inserted mid-revoke. A naive implementation compiles and passes a happy-path smoke test while violating all three. Run the [conformance kit](#conformance-kit) against your implementation before deploying it.

### `RefreshTokenGrant`

The persisted row shape `IRefreshTokenBackingStore` operates on. The framework constructs and consumes these; a backend only stores, retrieves, and runs equality queries over them.

```csharp
public sealed record RefreshTokenGrant
{
    public required StoreKey HandleHash { get; init; }
    public required string FamilyId { get; init; }
    public required string Subject { get; init; }
    public required string ClientId { get; init; }
    public required DateTimeOffset FamilyAbsoluteExpiry { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public required RefreshGrantStatus Status { get; init; }
    public required ReadOnlyMemory<byte> ProtectedPayload { get; init; }
}

public enum RefreshGrantStatus
{
    Active = 0,
    Consumed = 1,
    Revoked = 2,
}
```

| Column | Meaning |
|---|---|
| `HandleHash` | Primary key. The framework's hash of the raw refresh-token handle. Never the raw handle — see [`StoreKey`](#storekey). |
| `FamilyId` | Cleartext, non-secret random GUID shared across a rotation chain. Queryable — index this column; `RevokeFamilyAsync` filters on it. |
| `Subject` | Cleartext subject identifier. PII, but not a bearer credential — deliberately *not* a `StoreKey`, because `RevokeBySubjectAsync` needs a plain equality predicate. Protect it with database access control and encryption at rest; index this column too. |
| `ClientId` | Cleartext `client_id` (public, not secret) the grant is bound to. Queryable. |
| `FamilyAbsoluteExpiry` | Non-secret. The absolute wall-clock time at which the whole rotation family expires, regardless of individual token activity. Drives cleanup. |
| `ExpiresAt` | Non-secret. This token's own logical expiry. The coordinator applies `ClockSkewTolerance` on top when checking it — see [`ClockSkewTolerance`](#clockskewtolerance). |
| `Status` | Lifecycle state (`Active`, `Consumed`, `Revoked`). The single-use pivot is a compare-and-swap on this column, performed by `TryMarkConsumedAsync`. |
| `ProtectedPayload` | Opaque Data-Protection ciphertext of the token's serialized entry. Store verbatim — a backend can never read the subject, scope, or session claims inside it. |

`FamilyId` and `Subject` are deliberately cleartext rather than `StoreKey` values so they remain plain, indexable equality predicates for `RevokeFamilyAsync` and `RevokeBySubjectAsync`.

### Backend suitability

Which backends can implement `IRefreshTokenBackingStore` correctly without extra machinery:

| Backend | Insert | Find-by-handle | CAS consume | Revoke by family / subject | Verdict |
|---|---|---|---|---|---|
| Relational SQL | `INSERT`, primary key on handle | `SELECT WHERE handle=@h` | `UPDATE ... WHERE handle=@h AND status=Active`, check `rowsAffected==1` | `UPDATE ... WHERE family_id=@f` (indexed) | **Native. First-class.** The one atomicity invariant is a single-statement atomic CAS under row locking; revocation is one `UPDATE`, complete by construction. |
| Cosmos DB | `CreateItemAsync` | point read | conditional replace with `IfMatch=etag` | query + patch | **Native, correctness-safe.** Partition-key choice affects cost, not correctness — a suboptimal key is slow, never wrong. |
| Redis | grant key **plus hand-maintained family/subject index sets** | `GET` on the grant key | Lua script or `WATCH`/`MULTI`/`EXEC` | `SMEMBERS` then update each member — **only as complete as the index** | **Not first-class.** Redis has no `WHERE family_id = X`; a Redis-backed implementation must maintain its own secondary indexes as a non-transactional dual write, which can drift on a partial-write crash and silently reopen the reuse window `RevokeFamilyAsync` exists to close. Prefer a natively queryable backend for production. |

The same shape of trade-off applies to `IAuthorizationCodeBackingStore`: relational SQL and Cosmos DB support the atomic insert-if-absent primitive natively; a KV store without an atomic compare-and-set (a plain `IDistributedCache`, for instance) cannot guarantee it, which is why no token store is offered over `IDistributedCache`.

### Conformance kit

`ZeeKayDa.Auth.TestKit` ships ready-to-derive xUnit fixtures for both backing-store contracts: `AuthorizationCodeBackingStoreConformanceTests` and `RefreshTokenBackingStoreConformanceTests`. Running the matching fixture against your implementation is a **MUST** before deploying it — it exercises the invariants the compiler cannot check:

- **Atomicity** — a 50-way concurrent race against the same key/handle, asserting exactly one caller wins `TryInsertAsync` or `TryMarkConsumedAsync`.
- **Revocation completeness** — insert grants across a family (or subject), call `RevokeFamilyAsync` (or `RevokeBySubjectAsync`), and assert every grant reads `Revoked`, including one inserted concurrently with the revoke call — the race a drifting secondary index loses.
- **Post-revoke insert completeness** — revoke a family, then insert a new grant into it strictly after the revoke returns, and assert `IsFamilyRevokedAsync` still reports the family revoked.
- **Empty-family revocation** — revoking a family that has no grants yet must make `IsFamilyRevokedAsync` report it revoked, and a family never revoked must not read as revoked.
- **`rememberUntil` never shrinks** — a repeat `RevokeFamilyAsync` carrying an earlier `rememberUntil` must not shorten the record.
- **Fail-closed / throws-not-swallows** — fault injection proving a transport failure surfaces (raw or wrapped in `ZeeKayDaStoreException`), never as a swallowed `null` or `false`.
- **Round-trip correctness** — a stored value or grant reads back unchanged.

Reference `ZeeKayDa.Auth.TestKit` from your own test project and derive the abstract class, implementing `CreateStore()` to return your store:

```csharp
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

public sealed class MyRefreshTokenBackingStoreConformanceTests : RefreshTokenBackingStoreConformanceTests
{
    protected override IRefreshTokenBackingStore CreateStore() => new MyRefreshTokenBackingStore(/* ... */);
}
```

The atomicity tests cannot be switched off. One protected property lets a dev/test backend opt out of a test it cannot pass:

- `SupportsMidRevokeInsertCompleteness` — override to `false` only for a non-transactional secondary-index backend whose revocation cannot be proven complete against a grant inserted concurrently with the revoke call. Production backends must support this.

Override `CreateFaultInjectedStore(Exception fault)` to return a store whose transport always throws `fault`, so the fail-closed tests can verify the fault propagates rather than being swallowed. Return `null` (the default) if your backend has no injectable failure point; the fault-injection tests are then skipped for that fixture.

---

## Related pages

- [Configure token stores](../how-to/configure-token-stores.md) — step-by-step setup guide
- [AuthorizationServerOptions reference](configuration.md) — full options reference including `AuthorizationCodeLifetime`, `RefreshTokenLifetime`, and `ClockSkewTolerance`
