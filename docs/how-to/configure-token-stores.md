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
| Single-instance production | Custom persistent stores |
| Multi-instance production | Custom atomic stores |

> ⚠️ **Warning:** The in-memory and distributed-cache stores are not production-grade. The in-memory stores lose all tokens on restart and disable reuse detection across instances. The distributed-cache stores have a non-atomic check-then-write window exploitable by concurrent requests. Use custom stores for production.

---

## Option 1 — In-memory stores (development and testing only)

Call `.AddInMemoryStores()` on the builder to register both stores in one step:

```csharp
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

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

## Option 2 — Distributed-cache stores (dev/test with shared cache, or as a custom store starting point)

Use `.AddDistributedCacheTokenStores()` when you need a store backed by `IDistributedCache`. You must register an `IDistributedCache` implementation first.

For local development against an in-process cache:

```csharp
builder.Services.AddDistributedMemoryCache();

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddDistributedCacheTokenStores();
```

> ⚠️ **Warning:** `AddDistributedMemoryCache()` adds a single-process in-memory cache. This adds no durability or atomicity benefit over `.AddInMemoryStores()`. Use it only during development to exercise the `IDistributedCache` code path, not for any production scenario.

If you point the distributed-cache stores at a real shared backend such as Redis, ZeeKayDa.Auth emits a `LogLevel.Warning` at startup noting the non-atomic TOCTOU risk. The distributed-cache stores are not safe for production without an atomic replacement.

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
