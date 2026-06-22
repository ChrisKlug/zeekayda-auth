---
title: "Token stores"
description: "Reference for IAuthorizationCodeStore, IRefreshTokenStore, lifetime options, built-in implementations, and ZeeKayDaStoreException."
parent: "Reference"
nav_order: 5
---

*Added in Unreleased.*

ZeeKayDa.Auth requires two stores to be registered before the application starts:

- `IAuthorizationCodeStore` — persists short-lived authorization codes and enforces single-use redemption per [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1).
- `IRefreshTokenStore` — persists long-lived refresh tokens, enforces rotation and reuse detection per [RFC 9700 §4.13](https://www.rfc-editor.org/rfc/rfc9700#section-4.13), and supports family-level revocation.

Neither store is registered automatically by `AddZeeKayDaAuth`. You must choose an implementation for each using the builder methods below, or register a custom type. If either store is missing at startup, the application fails with `ZeeKayDaConfigurationException` naming the missing interface.

For step-by-step registration instructions, see [Configure token stores](../how-to/configure-token-stores.md).

---

## Choosing the right store

| Scenario | `IAuthorizationCodeStore` | `IRefreshTokenStore` |
|---|---|---|
| Local development | `.AddInMemoryAuthorizationCodeStore()` | `.AddInMemoryRefreshTokenStore()` |
| Integration tests | `.AddInMemoryAuthorizationCodeStore()` | `.AddInMemoryRefreshTokenStore()` |
| Production (any instance count) where the concurrent-redemption race and eviction risk are explicitly accepted | `.AddDistributedCacheAuthorizationCodeStore()` — the TOCTOU race applies on any deployment (see [Distributed-cache stores](#distributed-cache-backed-stores)); ensure cache is configured with `noeviction` or `volatile-ttl` with adequate memory | `.AddDistributedCacheRefreshTokenStore()` — same trade-offs apply |
| Production where replay attacks are in the threat model, or any deployment with an evicting cache under memory pressure | Custom atomic store (Redis + Lua, SQL with optimistic concurrency) | Custom atomic store (same backends) |

> ⚠️ **Warning:** Both in-memory stores are development and testing only. They lose all tokens on restart and silently disable single-use enforcement and reuse detection across multiple instances. Outside a `Development` environment the framework refuses to start with in-memory stores unless `AllowInMemoryStoresOutsideDevelopment` is set to `true`.

The distributed-cache stores have two concrete limitations that determine whether they are appropriate for a given production deployment — see [Distributed-cache stores](#distributed-cache-backed-stores) for the full trade-off analysis.

---

## Registration API

All store registration goes through the `ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth`. Each method checks at registration time that the targeted interface is not already registered; a second registration for the same interface throws `InvalidOperationException` immediately, naming the conflict.

### `.AddInMemoryStores()`

Registers both `InMemoryAuthorizationCodeStore` and `InMemoryRefreshTokenStore`. Emits a `LogLevel.Warning` at startup. Outside a `Development` environment, startup fails with `ZeeKayDaConfigurationException` unless `AuthorizationServerOptions.AllowInMemoryStoresOutsideDevelopment` is `true`.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryStores();
```

### `.AddInMemoryAuthorizationCodeStore()`

Registers only `InMemoryAuthorizationCodeStore` as `IAuthorizationCodeStore`. Emits the same startup warning as `.AddInMemoryStores()`. The environment check applies.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryAuthorizationCodeStore()
    .AddRefreshTokenStore<MyPersistentRefreshTokenStore>();
```

### `.AddInMemoryRefreshTokenStore()`

Registers only `InMemoryRefreshTokenStore` as `IRefreshTokenStore`. Emits the same startup warning as `.AddInMemoryStores()`. The environment check applies.

### `.AddDistributedCacheTokenStores()`

Registers both `DistributedCacheAuthorizationCodeStore` and `DistributedCacheRefreshTokenStore`. Requires `IDistributedCache` to be registered; fails fast with `ZeeKayDaConfigurationException` if it is missing. When the resolved `IDistributedCache` implementation is anything other than `MemoryDistributedCache`, a `LogLevel.Warning` is emitted at startup.

```csharp
builder.Services.AddDistributedMemoryCache(); // or AddStackExchangeRedisCache(...)
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddDistributedCacheTokenStores();
```

### `.AddDistributedCacheAuthorizationCodeStore()`

Registers only `DistributedCacheAuthorizationCodeStore` as `IAuthorizationCodeStore`. Requires `IDistributedCache`.

### `.AddDistributedCacheRefreshTokenStore()`

Registers only `DistributedCacheRefreshTokenStore` as `IRefreshTokenStore`. Requires `IDistributedCache`.

### `.AddAuthorizationCodeStore<T>()`

Registers a custom `T : class, IAuthorizationCodeStore` as a singleton. This is the recommended registration path for production custom stores.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyRedisAuthorizationCodeStore>()
    .AddRefreshTokenStore<MyRedisRefreshTokenStore>();
```

`T` must be a concrete reference type with a publicly accessible constructor so the DI container can instantiate it.

### `.AddRefreshTokenStore<T>()`

Registers a custom `T : class, IRefreshTokenStore` as a singleton.

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

`RefreshTokenLifetime` also governs tombstone retention for both store implementations: authorization code tombstones (records of redemption) are kept for `RefreshTokenLifetime` so that a replay of a redeemed code always produces `AlreadyRedeemed`, not `NotFound`, within the window in which the issued refresh token could still be alive.

> ⚠️ **Warning:** ASP.NET Core Data Protection key retention must be at least `RefreshTokenLifetime`. Shorter retention causes stored token entries to become unreadable after key rotation, which surfaces as `NotFound` at request time and silently logs out every user holding a token issued under the rotated key. Configure key persistence and retention duration accordingly before deploying to production.

### `ClockSkewTolerance`

| Attribute | Value |
|---|---|
| Type | `TimeSpan` |
| Default | `5 seconds` |
| Valid range | `≥ 0` and `< AuthorizationCodeLifetime / 2` |
| Location | `AuthorizationServerOptions.ClockSkewTolerance` |

A grace window added to `ExpiresAt` checks in multi-node store implementations to absorb clock drift between hosts (`entry.ExpiresAt + ClockSkewTolerance > now`). The in-memory stores ignore this value because they are single-instance by design and have no inter-node clock drift. Tombstone TTLs are unaffected.

The default is intentionally small. Values approaching half of `AuthorizationCodeLifetime` effectively nullify the code expiry guarantee; the startup validator rejects any value ≥ `AuthorizationCodeLifetime / 2`.

---

## In-memory stores

`InMemoryAuthorizationCodeStore` and `InMemoryRefreshTokenStore` are backed by `IMemoryCache` with per-handle `SemaphoreSlim` locks. They provide genuine atomicity for single-use and reuse-detection within a single process.

**Limitations:**

- **Single-instance is a deployment invariant, not a recommendation.** Running multiple instances with in-memory stores silently disables single-use enforcement ([RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1)) and reuse detection ([RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2)). Codes and tokens issued by instance A are invisible to instance B.
- **All tokens are lost on process restart.** Authorization code loss is operationally acceptable (60-second lifetime); refresh token loss forces every active user to re-authenticate.
- **Development and testing only.** In-memory stores are never an acceptable production choice. Outside a `Development` host environment the framework refuses to start unless `AuthorizationServerOptions.AllowInMemoryStoresOutsideDevelopment` is set to `true` (intended only for integration test hosts that intentionally run under a non-`Development` environment name).

**Startup warning text (emitted at `LogLevel.Warning`):**

```text
ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on
process restart, and single-use enforcement and reuse detection are disabled across
multiple instances. This configuration is intended for development and testing only
and must not be used in production.
```

**Data Protection.** Entry and tombstone values are serialised to JSON and encrypted using `IDataProtectionProvider` (purposes: `ZeeKayDa.Auth:AuthorizationCodeStore` and `ZeeKayDa.Auth:RefreshTokenStore`). Family revocation markers are stored without encryption so that a Data Protection failure does not cause a revoked family to silently appear unrevoked.

---

## Distributed-cache-backed stores

`DistributedCacheAuthorizationCodeStore` and `DistributedCacheRefreshTokenStore` are backed by `IDistributedCache`. They require `IDistributedCache` to be registered before `AddDistributedCacheTokenStores()` is called; missing registration is a startup failure.

**Supported development setup:**

```csharp
builder.Services.AddDistributedMemoryCache();
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddDistributedCacheTokenStores();
```

> ⚠️ **Warning:** `AddDistributedMemoryCache()` adds an in-process `MemoryDistributedCache`. Do not use `AddDistributedMemoryCache()` with the distributed-cache stores in production; it provides no persistence and no atomicity beyond what the in-memory stores already offer, with additional overhead.

**Atomicity trade-offs.** The distributed-cache stores use `IDistributedCache`, which does not provide an atomic check-and-set primitive. This creates two concrete gaps that operators must evaluate before choosing these stores for production:

**1. TOCTOU on single-use code redemption.** `TryRedeemAsync` performs a read-then-write using two separate `IDistributedCache` calls. Because ASP.NET Core / Kestrel serves concurrent requests across the thread pool, two concurrent requests for the same authorization code can both read "not yet redeemed" before either writes the tombstone, allowing double-redemption. The window spans two round-trips to the cache backend. This race exists on any deployment — single or multi-instance — whenever the application processes concurrent requests.

*This matters when:* an adversary or buggy client can race concurrent redemption requests. The risk may be acceptable for low-traffic internal applications where simultaneous authorization code redemption is implausible, but it cannot be eliminated by reducing instance count alone.

**2. Tombstone and revocation marker eviction.** `IDistributedCache` can evict entries under memory pressure before their configured TTL expires. If a tombstone (for a replayed authorization code) or a family revocation marker is evicted early, the protection it provides disappears — a replayed code appears fresh, or a revoked family token appears valid.

*This matters when:* your cache backend has a memory limit and can evict data. Redis configured with `maxmemory-policy allkeys-lru` is the common case where this risk applies. A Redis instance configured with `noeviction` (or `volatile-ttl` with a memory allocation large enough to hold all active entries) eliminates this risk.

**When the distributed-cache stores are acceptable for production:**

- Any deployment where the TOCTOU concurrent-redemption race is within the accepted threat model (for example, an internal tool with trusted clients and no adversarial replay risk) AND the cache backend is configured to never evict entries under memory pressure.
- Any deployment where both limitations above are within the accepted threat model.

**When they are not appropriate:**

- Any deployment where replay attacks are in the threat model and concurrent token requests are possible — which is true of any non-trivial deployment regardless of instance count.
- Any deployment backed by a cache with an evicting `maxmemory-policy` and no margin to guarantee all tombstones and revocation markers are retained for their full TTL.

> ⚠️ **Warning:** If both limitations above apply to your deployment, use a custom atomic store (Redis + Lua, SQL with optimistic concurrency, or equivalent) instead. The distributed-cache stores do not provide the atomicity guarantees required by [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) and [RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2) under those conditions.

**Real distributed backend warning.** When the registered `IDistributedCache` implementation is anything other than `MemoryDistributedCache` (for example, Redis or SQL Server), ZeeKayDa.Auth emits a `LogLevel.Warning` at startup noting that the distributed-cache stores are running against a real shared backend. Review the two trade-offs above before accepting this warning in production.

**Data Protection.** Entry and tombstone values are encrypted using `IDataProtectionProvider` (same purpose strings as the in-memory stores). Cache keys are derived as `Base64Url(SHA-256(handle))` — raw token handles are never used as cache keys, so cache read access does not expose live bearer credentials. Family revocation markers are stored without encryption (fail-safe: a DP failure on a marker would cause a revoked family to appear unrevoked).

**Key format:**

| Entry type | Cache key |
|---|---|
| Authorization code entry (unredeemed) | `zkd:code:{Base64Url(SHA-256(handle))}` |
| Authorization code tombstone (redeemed) | `zkd:code:{Base64Url(SHA-256(handle))}:redeemed` |
| Refresh token entry or tombstone | `zkd:rt:{Base64Url(SHA-256(handle))}` |
| Family revocation marker | `zkd:rt:family:{Base64Url(SHA-256(familyId))}:revoked` |

These key shapes are implementation details of the built-in stores, not part of the `IAuthorizationCodeStore` or `IRefreshTokenStore` interface contracts. Custom stores may use any key layout.

---

## `ZeeKayDaStoreException`

`ZeeKayDaStoreException` is thrown by `IAuthorizationCodeStore` and `IRefreshTokenStore` implementations when an underlying transport fails — a cache unavailability, database timeout, or network error. It derives from `ZeeKayDaException`.

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

Custom store implementations must satisfy the interface contract documented in XML doc comments on each method. Key requirements:

1. **Fail closed.** Wrap infrastructure exceptions in `ZeeKayDaStoreException`. Never return a semantic outcome on a transport failure.
2. **Atomic single-use enforcement.** `TryRedeemAsync` and `TryConsumeAsync` must perform the check-and-mark step atomically. For Redis, use a Lua script. For SQL, use a single `UPDATE … WHERE redeemed_at IS NULL` inside a transaction. Without atomicity, two concurrent requests for the same handle can both succeed, violating [RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1) and [RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2).
3. **Pre-committed `familyId`.** `TryRedeemAsync` receives `familyId` as a parameter and must write it into the tombstone atomically with the redemption mark. Every `AlreadyRedeemed` outcome must carry the `FamilyId` that was committed into the tombstone — never `null` — so the token endpoint can revoke the correct family on a replay.
4. **Derive storage keys from handles using a collision-resistant one-way function.** Raw token handles are bearer credentials; using them directly as storage keys exposes live credentials to anyone with read access to the backing store (Redis ops, database queries, log sidecars). The key derivation algorithm is your store's choice — SHA-256, HMAC-SHA-256, or any other collision-resistant construction all satisfy the contract. What is required is that the function is one-way (the raw handle cannot be recovered from the key) and collision-resistant (two distinct handles must not produce the same key). The `Base64Url(SHA-256(handle))` formula used by the built-in stores meets these requirements, but it is their internal implementation detail and is not part of the interface contract ([ADR 0008 §4a](../decisions/0008-authorization-code-and-refresh-token-store.md#4a-key-derivation-cache-keys-must-be-sha-256handle-never-the-raw-handle)).
5. **Idempotent `RevokeFamilyAsync`.** A double-revocation call must not throw. A call with a `familyId` that has no associated entries is a successful no-op.
6. **Tombstone retention = `RefreshTokenLifetime`.** Authorization code tombstones must remain alive for at least `RefreshTokenLifetime` so that a replay within the token's validity window always produces `AlreadyRedeemed`, not `NotFound`.

Register the custom implementation using the typed builder methods:

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyAtomicCodeStore>()
    .AddRefreshTokenStore<MyAtomicRefreshTokenStore>();
```

> 💡 **Tip:** The two stores are independently replaceable. You can mix an in-memory authorization code store (acceptable during development) with a custom persistent refresh token store by calling `.AddInMemoryAuthorizationCodeStore()` and `.AddRefreshTokenStore<T>()` on the same builder chain.

---

## Related pages

- [Configure token stores](../how-to/configure-token-stores.md) — step-by-step setup guide
- [AuthorizationServerOptions reference](configuration.md) — full options reference including `AuthorizationCodeLifetime`, `RefreshTokenLifetime`, and `ClockSkewTolerance`
