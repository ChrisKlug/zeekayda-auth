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

The in-tree `InMemoryScopeRepository` demonstrates the minimum pattern for synchronous in-memory implementations:

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

## 4. Implement a custom client secret hasher

ZeeKayDa.Auth ships with a PBKDF2-HMAC-SHA256 hasher (`Pbkdf2ClientSecretHasher`) that covers the
vast majority of deployments. If you need a different hashing algorithm — for example during a
migration from an existing bcrypt or Argon2 credential store — you can plug in a custom hasher by
following the four-step pattern below.

### Step 1: Define a sub-interface of `IClientSecret`

The C# type of the credential identifies which hasher handles it — no string discriminator is
needed. Define a public interface that carries the fields your algorithm needs:

```csharp
using ZeeKayDa.Auth.Clients;

public interface IBcryptClientSecret : IClientSecret
{
    string Hash { get; }
}
```

### Step 2: Define a sealed record implementing the interface

```csharp
public sealed record BcryptClientSecret(string Hash) : IBcryptClientSecret;
```

### Step 3: Subclass `ClientSecretHasher<TSecret>`

`ClientSecretHasher<TSecret>` handles all cross-cutting concerns (type dispatch, exception
swallowing, null/whitespace rejection). You only need to implement `VerifyCore` and `CreateCore`:

```csharp
using System.Security.Cryptography;
using ZeeKayDa.Auth.Clients;
// using BCrypt.Net; // replace with your chosen hashing library

public sealed class BcryptClientSecretHasher : ClientSecretHasher<IBcryptClientSecret>
{
    protected override bool VerifyCore(IBcryptClientSecret stored, ReadOnlySpan<char> presented)
    {
        if (presented.IsEmpty)
            return false;

        // Use your library's built-in constant-time verify function.
        // If the library accepts a string, allocate here with presented.ToString().
        return BCrypt.Net.BCrypt.Verify(presented.ToString(), stored.Hash);
    }

    protected override IBcryptClientSecret CreateCore(string plaintext)
    {
        string hash = BCrypt.Net.BCrypt.HashPassword(plaintext, workFactor: 12);
        return new BcryptClientSecret(hash);
    }
}
```

### Step 4: Register with `AddSecretsHasher<T>()`

Register your hasher on the builder returned by `AddZeeKayDaAuth`. When only one hasher is
registered it is automatically the default:

```csharp
auth.AddSecretsHasher<BcryptClientSecretHasher>();
```

For **credential rotation** — for example to migrate from bcrypt to PBKDF2 — register both hashers
and mark the new one as default. The composite verifier will try the correct hasher for each stored
credential, and `isDefault: true` controls which hasher creates new secrets:

```csharp
auth.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);  // creates new secrets
auth.AddSecretsHasher<BcryptClientSecretHasher>(isDefault: false);  // verifies old secrets
```

Startup validation fails if multiple hashers are registered but zero or more than one has
`isDefault: true`.

### Security contract for `VerifyCore` implementors

| Requirement | Reason |
|---|---|
| Use timing-safe comparison | Prevents timing oracles from revealing whether a client exists |
| Never throw — return `false` on error | `ClientSecretHasher<T>` swallows exceptions, but throwing leaks timing |
| Never log `presented` | Logging a plaintext secret violates confidentiality |
| Be singleton-safe | Hashers are registered as singletons and called concurrently |

> Warning: A hasher that does not use constant-time comparison undermines the timing protections
> built into `CompositeClientSecretHasher`. Use `CryptographicOperations.FixedTimeEquals` for
> raw byte comparisons, or your library's built-in constant-time verify function.

## See also

- [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md) — register the framework and the minimum required options.
- [Configure discovery](configure-discovery.md) — customise the discovery document with the built-in options.
- [`AuthorizationServerOptions` reference](../reference/configuration.md) — full property list and validation rules.
- [Client secrets reference](../reference/client-secrets.md) — `Pbkdf2ClientSecretHasherOptions` property reference.
- [Cancellation in managed threads](https://learn.microsoft.com/dotnet/standard/threading/cancellation-in-managed-threads) — Microsoft's reference for the cancellation pattern this framework follows.
