---
title: "Configure token stores"
description: "How to register and configure the authorization code store and refresh token store in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 6
---

*Added in Unreleased.*

ZeeKayDa.Auth requires an authorization code store, a refresh token store and an interaction store to be registered before the application starts. `AddZeeKayDaAuth` registers the framework side of both token stores itself; what you choose is where each of the three stores keeps its data, using the builder methods on `ZeeKayDaAuthBuilder`. The two token stores are covered first; the interaction store, which holds authorization requests while the user signs in, has its own section [below](#the-interaction-store).

For the full API reference, see [Token stores](../reference/token-stores.md).

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- Choose a store option from the table below before continuing.

## Choosing a store for your environment

| Environment | Recommended option |
|---|---|
| Local development | `.AddInMemoryStores()` |
| Integration tests | `.AddInMemoryStores()` |
| Production | Custom atomic stores |

> ⚠️ **Warning:** The in-memory stores are development and testing only — they lose all tokens on restart and disable reuse detection across instances.

---

## Option 1 — In-memory stores (development and testing only)

Call `.AddInMemoryStores()` on the builder to register all three stores — codes, refresh tokens and interactions — in one step:

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

At startup in `Development`, ZeeKayDa.Auth logs a `LogLevel.Information` message per store to confirm it is active and remind you not to use it in production. Outside a `Development` environment the application refuses to start unless you explicitly pass `allowOutsideDevelopment: true` to the registration call.

> 💡 **Tip:** For integration tests running under a non-`Development` environment name, pass `allowOutsideDevelopment: true` to the registration call in the test host configuration:
>
> ```csharp
> .AddInMemoryStores(allowOutsideDevelopment: true);
> ```
>
> `.AddInMemoryAuthorizationCodeStore()` and `.AddInMemoryRefreshTokenStore()` each accept the
> same parameter and gate on it independently — see [Mixing stores](#mixing-stores) below.

---

## Option 2 — Custom stores (production)

Implement the two backing stores, `IAuthorizationCodeBackingStore` and `IRefreshTokenBackingStore`, then register them using the typed builder methods. The framework's own stores run on top of them and keep the protocol (single use, replay detection, hashing and encryption):

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

The critical requirement is **atomicity**: `TryInsertAsync` (authorization code) must be an atomic insert-if-absent, and `TryMarkConsumedAsync` (refresh token) an atomic compare-and-set. For Redis, implement the operation as a Lua script. For SQL Server or PostgreSQL, execute a single `UPDATE … WHERE consumed_at IS NULL` inside a serializable transaction and inspect the row count.

See [Implementing a custom store](../reference/token-stores.md#implementing-a-custom-store) in the reference for the full contract requirements.

---

## The interaction store

An authorization request lives in the interaction store from the moment `/connect/authorize` accepts it until the user has signed in and, where required, consented. Each request is one entry, bound to the browser that started it by a small `zkd.interaction.<id>` cookie, so any number of sign-ins can be in flight in one browser at once.

The interaction store needs only set, get and remove. That is exactly what a distributed cache provides, so unlike the token stores there is nothing bespoke to write for production: register a shared `IDistributedCache` and point the interaction store at it.

```csharp
builder.Services.AddStackExchangeRedisCache(o => o.Configuration = "...");

builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddAuthorizationCodeStore<MyAtomicAuthorizationCodeStore>()
    .AddRefreshTokenStore<MyAtomicRefreshTokenStore>()
    .AddDistributedCacheInteractionStore();
```

In development, `.AddInMemoryStores()` already registers a per-process interaction store; `.AddInMemoryInteractionStore()` registers it on its own, with the same `allowOutsideDevelopment` gate as the other in-memory stores.

> ⚠️ **Warning:** `AddDistributedMemoryCache()` registers a cache that, despite its name, is shared with nothing. Behind a load balancer the login POST can land on an instance that never saw the authorize request, and the failure looks like an intermittent bug in your login page. Outside a `Development` environment the framework therefore refuses to start when `.AddDistributedCacheInteractionStore()` resolves that cache, unless you pass `allowMemoryCacheOutsideDevelopment: true` for an integration test host — in which case a `Critical` log entry is emitted on every start.

---

## Mixing stores

The two token stores are independently replaceable. A common pattern during a migration is to use the in-memory authorization code store (acceptable because codes are short-lived) alongside a custom persistent refresh token store:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddInMemoryAuthorizationCodeStore()  // dev/test; logs at startup
    .AddRefreshTokenStore<MyPersistentRefreshTokenStore>();
```

> ⚠️ **Warning:** `.AddInMemoryAuthorizationCodeStore()` still logs its startup message and is still subject to the `Development`-environment check. This pattern is useful during development while building a persistent refresh token store; it is not a production configuration.

Each in-memory registration method carries its own `allowOutsideDevelopment` parameter and is gated independently — passing it on one call has no effect on another. For example, this configuration still fails to start outside `Development` because `.AddInMemoryRefreshTokenStore()` was not opted in, even though the authorization code store was:

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true)
    .AddInMemoryRefreshTokenStore(); // allowOutsideDevelopment defaults to false — still fails closed
```

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
