---
title: "Implement a custom extension point"
description: "How to write a custom IScopeRepository or IDiscoveryDocumentProvider that participates correctly in async cancellation."
parent: "How-to Guides"
nav_order: 3
---

*Added in Unreleased.*

ZeeKayDa.Auth exposes two extension points you can implement to plug in a custom scope catalog or a custom discovery document:

- [`IScopeRepository`](../reference/configuration.md) — supplies the scopes the authorization server knows about, e.g. from a database, a remote config service, or a per-tenant store.
- `IDiscoveryDocumentProvider` — supplies the OpenID Connect discovery document, e.g. when you need to merge metadata from another source or surface a dynamic key-rotation state.

Both interfaces are **fully asynchronous and cancellation-aware**. This guide shows you how to implement them correctly. The signatures look like this:

```csharp
public interface IScopeRepository
{
    ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default);
}

public interface IDiscoveryDocumentProvider
{
    ValueTask<OpenIdConfigurationDocument> GetDocumentAsync(CancellationToken cancellationToken = default);
}
```

## Why both interfaces are async

Both extension points sit on a hot request path: every call to the OpenID Connect discovery endpoint (and, in due course, every token request) reaches them. Real-world implementations are almost always I/O-bound — a database query, an HTTP call, a distributed cache lookup. Forcing those implementations to block a thread-pool thread is the well-known sync-over-async foot-gun: under load it causes thread-pool starvation, and it makes it impossible to honour request cancellation cleanly.

`ValueTask<T>` is used (rather than `Task<T>`) because in-memory implementations complete synchronously and the per-call allocation savings matter on these hot paths. If your implementation is asynchronous, just `return` the awaited result as you would with `Task<T>` and the compiler-generated state machine handles the rest.

## 1. Implement a custom scope repository

A minimal database-backed example. Note that the `CancellationToken` is propagated through to the database call so the operation can be cancelled by the client.

```csharp
public sealed class DatabaseScopeRepository : IScopeRepository
{
    private readonly IDbContextFactory<ScopeDbContext> _factory;

    public DatabaseScopeRepository(IDbContextFactory<ScopeDbContext> factory)
        => _factory = factory;

    public async ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(
        CancellationToken cancellationToken = default)
    {
        await using var db = await _factory.CreateDbContextAsync(cancellationToken);

        var rows = await db.Scopes
            .AsNoTracking()
            .ToListAsync(cancellationToken);

        return rows
            .Select(row => new ScopeDefinition
            {
                Name = row.Name,
                IsDiscoverable = row.IsDiscoverable,
                IdTokenClaims = row.IdTokenClaims,
                AccessTokenClaims = row.AccessTokenClaims,
            })
            .ToArray();
    }
}
```

Register the repository on the `ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth`:

```csharp
builder.Services.AddZeeKayDaAuth(options => options.Issuer = "https://id.example.com");
builder.Services.AddDbContextFactory<ScopeDbContext>(/* ... */);
builder.Services.AddSingleton<IScopeRepository, DatabaseScopeRepository>();
```

## 2. Implement a custom discovery document provider

```csharp
public sealed class TenantAwareDiscoveryDocumentProvider : IDiscoveryDocumentProvider
{
    private readonly ITenantContext _tenant;
    private readonly IDiscoveryMetadataClient _metadataClient;

    public TenantAwareDiscoveryDocumentProvider(
        ITenantContext tenant,
        IDiscoveryMetadataClient metadataClient)
    {
        _tenant = tenant;
        _metadataClient = metadataClient;
    }

    public async ValueTask<OpenIdConfigurationDocument> GetDocumentAsync(
        CancellationToken cancellationToken = default)
    {
        var metadata = await _metadataClient.FetchAsync(_tenant.Id, cancellationToken);

        return new OpenIdConfigurationDocument
        {
            Issuer = metadata.Issuer,
            AuthorizationEndpoint = metadata.AuthorizationEndpoint,
            TokenEndpoint = metadata.TokenEndpoint,
            JwksUri = metadata.JwksUri,
            // ...populate the remaining required fields...
        };
    }
}
```

Register the same way:

```csharp
builder.Services.AddSingleton<IDiscoveryDocumentProvider, TenantAwareDiscoveryDocumentProvider>();
```

## 3. Honour the cancellation token

The framework passes `HttpContext.RequestAborted` to your implementation. You should:

- **Pass the token through** to every async call you make (HTTP client, database, cache).
- **Call `cancellationToken.ThrowIfCancellationRequested()`** at the start of synchronous in-memory implementations so a cancelled request doesn't waste work building a response that will be discarded.
- **Never silently swallow `OperationCanceledException`**. Let it propagate — the framework treats it as a client disconnect and stops the request pipeline cleanly.

The in-tree `InMemoryScopeRepository` and `DefaultScopeRepository` demonstrate the minimum pattern for synchronous in-memory implementations:

```csharp
public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
{
    cancellationToken.ThrowIfCancellationRequested();
    return ValueTask.FromResult(_scopes);
}
```

## ⚠ Do not "sync over async"

If you only have a synchronous data source today and are tempted to wrap it like this — **don't**:

```csharp
// ❌ Don't do this.
public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
    => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>(LoadFromHttpClientSync());

private IReadOnlyCollection<ScopeDefinition> LoadFromHttpClientSync()
    => _httpClient.GetAsync("/scopes").Result.Content.ReadFromJsonAsync<ScopeDto[]>().Result;
```

`.Result` and `.GetAwaiter().GetResult()` block a thread-pool thread for the duration of the I/O. Under load, every concurrent discovery request consumes a thread until the I/O completes, and the thread pool runs out — the symptom is rising request latency and eventually deadlocks under `SynchronizationContext`-bearing hosts.

If your data source has only a synchronous API, the right answer is to put a real cache (`IMemoryCache`, `HybridCache`, `IDistributedCache`) in front of it and refresh the cache from a background `IHostedService` — then your `GetScopesAsync` returns a synchronous `ValueTask.FromResult(_cached)` and you have not introduced sync-over-async on the hot path.

## See also

- [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md) — register the framework and the minimum required options.
- [Configure discovery](configure-discovery.md) — customise the discovery document with the built-in options.
- [`AuthorizationServerOptions` reference](../reference/configuration.md) — full property list and validation rules.
- [Cancellation in managed threads](https://learn.microsoft.com/dotnet/standard/threading/cancellation-in-managed-threads) — Microsoft's reference for the cancellation pattern this framework follows.
