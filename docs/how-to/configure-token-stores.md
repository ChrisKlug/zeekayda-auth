---
title: "Configure token stores"
description: "How to register and configure the authorization code store and refresh token store in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 6
---

*Added in Unreleased.*

ZeeKayDa.Auth requires an `IAuthorizationCodeStore` and an `IRefreshTokenStore` to be registered before the application starts. Neither is registered automatically; you must opt in using the builder methods on `ZeeKayDaAuthBuilder`.

For the full API reference, see [Token stores](../reference/token-stores.md).

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- Choose a store option from the table below before continuing.

## Choosing a store for your environment

| Environment | Recommended option |
|---|---|
| Local development | `.AddInMemoryStores()` |
| Integration tests | `.AddInMemoryStores()` |
| Production (any instance count) where concurrent-redemption race and eviction risk are explicitly accepted | `.AddDistributedCacheTokenStores()` — see trade-offs below |
| Production where replay attacks are in the threat model, or any deployment with an evicting cache | Custom atomic stores |

> ⚠️ **Warning:** The in-memory stores are development and testing only — they lose all tokens on restart and disable reuse detection across instances. The distributed-cache stores have two concrete atomicity limitations; see [Option 2](#option-2--distributed-cache-stores) for a full trade-off analysis so you can decide whether they are right for your deployment.

---

## Option 1 — In-memory stores (development and testing only)

Call `.AddInMemoryStores()` on the builder to register both stores in one step:

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddInMemoryStores();

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

At startup, ZeeKayDa.Auth emits a `LogLevel.Warning` to confirm the stores are active and remind you not to use them in production. Outside a `Development` environment the application refuses to start unless you explicitly set `AllowInMemoryStoresOutsideDevelopment = true`.

> 💡 **Tip:** For integration tests running under a non-`Development` environment name, set `AllowInMemoryStoresOutsideDevelopment = true` in the test host configuration:
>
> ```csharp
> options.AllowInMemoryStoresOutsideDevelopment = true;
> ```

---

## Option 2 — Distributed-cache stores

Use `.AddDistributedCacheTokenStores()` when you need a store backed by `IDistributedCache`. You must register an `IDistributedCache` implementation first.

```csharp
builder.Services.AddDistributedMemoryCache(); // or AddStackExchangeRedisCache(...)

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddDistributedCacheTokenStores();
```

> ⚠️ **Warning:** `AddDistributedMemoryCache()` adds a single-process in-memory cache. This adds no durability or atomicity benefit over `.AddInMemoryStores()`. Use it only during development to exercise the `IDistributedCache` code path.

### Trade-offs to evaluate before using in production

The distributed-cache stores have two atomicity gaps. You need to decide whether they apply to your deployment.

**TOCTOU on single-use code redemption.** `TryRedeemAsync` performs a read-then-write as two separate cache calls. Because ASP.NET Core / Kestrel serves concurrent requests across the thread pool, two requests can both read the same code as "not yet redeemed" before either writes the tombstone, causing double-redemption. This race exists on any deployment — single or multi-instance — whenever the application handles concurrent requests. The window spans two round-trips to the cache backend and may be an acceptable risk for low-traffic internal applications where concurrent authorization code redemption is implausible, but it cannot be ruled out by instance count alone.

**Tombstone and revocation marker eviction.** If your cache backend evicts entries under memory pressure before their TTL expires (for example, Redis with `maxmemory-policy allkeys-lru`), tombstones and family revocation markers can disappear early. A replayed authorization code would then appear fresh, or a revoked refresh token family would appear valid.

Every entry the distributed-cache stores write carries an absolute expiry, making each entry "volatile" in Redis terminology. Under `volatile-ttl`, Redis evicts volatile keys with the nearest TTL first under memory pressure — tombstones and revocation markers are candidates for eviction, not protected from it. Only `noeviction` actually prevents this: instead of silently discarding data, Redis refuses writes, which the stores surface as `ZeeKayDaStoreException` (fail-closed). Configuring Redis with `noeviction` is the only policy that eliminates this risk.

**Acceptable configurations (you decide):**

- Any deployment where the TOCTOU concurrent-redemption window is within the accepted threat model (for example, an internal tool with trusted clients and no adversarial replay risk) AND the cache backend is configured to never evict entries under memory pressure.
- Any deployment where both limitations above are within the accepted threat model.

**Not acceptable:**

- Any deployment where replay attacks are in the threat model and concurrent token requests are possible — which is true of any non-trivial deployment. Use a custom atomic store instead.
- Any deployment backed by an evicting cache (e.g. Redis `allkeys-lru`) without sufficient memory headroom to guarantee tombstones and revocation markers are never evicted.

For the full reference, see [Distributed-cache stores — atomicity trade-offs](../reference/token-stores.md#distributed-cache-backed-stores).

If you point the distributed-cache stores at a real shared backend such as Redis, ZeeKayDa.Auth emits a `LogLevel.Warning` at startup. Review the trade-offs above before accepting this warning in production.

---

## Option 3 — Custom stores (production)

Implement `IAuthorizationCodeStore` and `IRefreshTokenStore`, then register them using the typed builder methods:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddAuthorizationCodeStore<MyAtomicAuthorizationCodeStore>()
    .AddRefreshTokenStore<MyAtomicRefreshTokenStore>();
```

Your implementations receive their dependencies via constructor injection like any other singleton service.

For multi-instance production, the critical requirement is **atomicity**: `TryRedeemAsync` (authorization code) and `TryConsumeAsync` (refresh token) must perform the check-and-mark step in a single atomic operation. For Redis, implement the operation as a Lua script. For SQL Server or PostgreSQL, execute a single `UPDATE … WHERE consumed_at IS NULL` inside a serializable transaction and inspect the row count.

See [Implementing a custom store](../reference/token-stores.md#implementing-a-custom-store) in the reference for the full contract requirements.

---

## Mixing stores

The two stores are independently replaceable. A common pattern during a migration is to use the in-memory authorization code store (acceptable because codes are short-lived) alongside a custom persistent refresh token store:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddInMemoryAuthorizationCodeStore()  // dev/test; emits startup warning
    .AddRefreshTokenStore<MyPersistentRefreshTokenStore>();
```

> ⚠️ **Warning:** `.AddInMemoryAuthorizationCodeStore()` still emits a startup warning and is still subject to the `Development`-environment check. This pattern is useful during development while building a persistent refresh token store; it is not a production configuration.

---

## Configuring lifetimes

Authorization code and refresh token lifetimes are properties of `AuthorizationServerOptions`, not of the store implementations. Configure them in the `AddZeeKayDaAuth(...)` lambda:

```csharp
builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";

    // Authorization code lifetime: default 60 s, max 600 s (RFC 9700 §2.1.1)
    options.AuthorizationEndpoint.AuthorizationCodeLifetime = TimeSpan.FromSeconds(60);

    // Refresh token lifetime: default 14 days, no upper bound enforced
    options.TokenEndpoint.RefreshTokenLifetime = TimeSpan.FromDays(14);

    // Clock skew grace window for multi-node deployments: default 5 s
    // Must be less than half of AuthorizationCodeLifetime
    options.ClockSkewTolerance = TimeSpan.FromSeconds(5);
});
```

> 💡 **Tip:** `RefreshTokenLifetime` is an **idle timeout**, not an absolute session duration. Refresh tokens rotate on every use — each successful token refresh tombstones the old token and issues a new one with a fresh `RefreshTokenLifetime` window. A user who refreshes regularly can therefore maintain their session indefinitely. To enforce an absolute session cap you would need a mechanism outside `RefreshTokenLifetime`; ZeeKayDa.Auth does not currently provide one.

For the valid ranges and the security trade-offs of each value, see [Token stores — Lifetime options](../reference/token-stores.md#lifetime-options).

---

## Data Protection key retention

The built-in stores encrypt stored token entries using `IDataProtectionProvider`. Key retention must be at least `RefreshTokenLifetime`. Shorter retention causes entries to become unreadable after a key rotation, which surfaces as `NotFound` at request time and silently logs out every user holding a token issued under the rotated key.

Configure key persistence and retention before deploying to a non-ephemeral environment:

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToAzureBlobStorage(/* ... */)
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90)); // must be ≥ RefreshTokenLifetime
```

> 💡 **Tip:** A typical `RefreshTokenLifetime` of 14 days means keys must remain valid for at least 14 days. A key lifetime of 90 days is a safe starting point for most deployments.

---

## Related pages

- [Token stores reference](../reference/token-stores.md) — API reference, interface contracts, and custom store requirements
- [AuthorizationServerOptions reference](../reference/configuration.md) — full options reference
