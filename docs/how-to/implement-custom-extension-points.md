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

> ⚠️ **Warning: override `CreateCore(ReadOnlySpan<char>)` to preserve the memory-safety guarantee.**
> The primary `IClientSecretHasher.Create` overload accepts `ReadOnlySpan<char>` so callers can zero
> their `char[]` buffer immediately after the call. If you only override `CreateCore(string)`, the
> base-class fallback allocates `new string(plaintext)` and delegates to it — the caller zeros their
> buffer, but a full managed string copy of the secret remains on the heap until the next GC cycle.
>
> Most .NET crypto primitives accept a span directly, so the override is usually a one-liner:
>
> ```csharp
> protected override IBcryptClientSecret CreateCore(ReadOnlySpan<char> plaintext)
> {
>     // BCrypt.Net requires a string; the ToString() allocation here is intentional and bounded.
>     string hash = BCrypt.Net.BCrypt.HashPassword(plaintext.ToString(), workFactor: 12);
>     return new BcryptClientSecret(hash);
> }
> ```
>
> Algorithms whose .NET API accepts a span natively (e.g. `Rfc2898DeriveBytes.Pbkdf2`,
> `SHA256.HashData`, `HMACSHA256.HashData`) can avoid the `ToString()` entirely. See
> `Pbkdf2ClientSecretHasher` in the source for a complete example.

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

> 💡 **Exception messages are now redacted by default.**
> `SecretSanitizingLogger` unconditionally wraps all logged exceptions in `RedactedExceptionWrapper`,
> replacing the exception `Message` with a fixed placeholder before it reaches any log sink. You no
> longer need to avoid putting credential material in exception messages as a workaround — though
> doing so remains good practice. To restore original exception messages in a development
> environment, call `DisableExceptionSanitizing()` on the builder. See
> [Configure host-level log hygiene](configure-host-log-hygiene.md) for details.

> ⚠️ **Warning: `SecretSanitizingLogger` covers ZeeKayDa.Auth's own logs only.**
> The redaction wrapper intercepts log calls made by ZeeKayDa.Auth's internal services. It has no
> effect on ASP.NET Core's `UseHttpLogging()`, Kestrel connection logging, W3CLogger, Application
> Insights telemetry, or exception-handling middleware — all of which can capture the `Authorization`
> header or a form-encoded `client_secret` entirely outside the library's scope.
>
> See [Configure host-level log hygiene](configure-host-log-hygiene.md) for the steps required to
> close this gap in the host pipeline.

## 5. Implement a custom client authenticator

`IClientAuthenticator` lets you plug a new token endpoint authentication method into the
framework's dispatch pipeline. The built-in `ClientSecretAuthenticator` handles
`client_secret_basic` and `client_secret_post`; everything else requires a custom implementation.

> ⚠️ **`CanHandle` must be a cheap shape check.** Do not perform crypto operations, database
> lookups, or any I/O in `CanHandle`. It is called for every registered authenticator on every
> token-endpoint request. A slow `CanHandle` multiplies across all registered authenticators and
> degrades every token-endpoint hit — not just requests for your authentication method.
>
> Parse a header, check a form key, or inspect a connection property. Do not call a database,
> validate a signature, or make an HTTP request. See ADR 0007 §4 for the full contract.

> **Note:** `none` is a special case — it is handled automatically by the composite dispatcher
> as a fallback for public clients and does not require an `IClientAuthenticator` implementation.
> To support public clients, add `TokenEndpointAuthMethod.None` to `AuthMethodsSupported` and
> register a client with `IsPublic = true`.

The interface has three members:

```csharp
public interface IClientAuthenticator
{
    IReadOnlySet<string> AuthenticationMethods { get; }

    bool CanHandle(TokenRequestContext context, out string? method);

    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken);
}
```

### Step 1: Define the authentication method string

Use the registered string for your method (e.g. `"private_key_jwt"`). Declare it as a constant so
`AuthenticationMethods` and `CanHandle` always return the same value:

```csharp
public sealed class PrivateKeyJwtAuthenticator : IClientAuthenticator
{
    private const string Method = "private_key_jwt";

    private static readonly IReadOnlySet<string> _methods =
        new HashSet<string>(StringComparer.Ordinal) { Method };

    public IReadOnlySet<string> AuthenticationMethods => _methods;
```

### Step 2: Implement `CanHandle` — keep it cheap

`CanHandle` is called for every token request, on every registered authenticator, before any
repository lookup. It MUST be a cheap shape check — no crypto, no database access.

```csharp
    public bool CanHandle(TokenRequestContext context, out string? method)
    {
        // Shape check only: does the request carry the expected credential material?
        if (context.Form.ContainsKey("client_assertion") &&
            context.Form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
            method = Method;
            return true;
        }

        method = null;
        return false;
    }
```

A slow `CanHandle` adds latency proportional to the number of registered authenticators on every
token request — not just for your method, but for every client. Parse a header or check a form key;
do not call a database or validate a signature here.

### Step 3: Implement `AuthenticateAsync`

`AuthenticateAsync` is only invoked after `CanHandle` returned `true` and all composite allowlist
checks have passed. The client is guaranteed to exist in the repository.

```csharp
    public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        var assertion = context.Form["client_assertion"].ToString();

        // Validate the JWT assertion against the client's registered public key.
        var valid = ValidateAssertion(assertion, context.Client, context.ClientId);

        return ValueTask.FromResult(
            valid ? ClientAuthenticationResult.Valid() : ClientAuthenticationResult.NotValid());
    }
```

### Step 4: Register the authenticator

Register on the `ZeeKayDaAuthBuilder` returned by `AddZeeKayDaAuth` and add the method to
`AuthMethodsSupported`. Startup validation fails if either is missing:

```csharp
builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    options.TokenEndpoint.AuthMethodsSupported =
    [
        TokenEndpointAuthMethod.ClientSecretBasic,
        // custom methods added to the server's supported list
    ];
})
.AddClientAuthenticator<PrivateKeyJwtAuthenticator>();
```

### Security contract for `IClientAuthenticator` implementors

| Requirement | Reason |
|---|---|
| `CanHandle` MUST be a cheap shape check — no crypto, no DB | Called on every token request for every authenticator; a slow check multiplies latency across all clients |
| `AuthenticateAsync` MUST use timing-safe comparison | Prevents timing oracles from revealing credential validity |
| Never compare secrets as plain strings | Always delegate to `IClientSecretHasher.Verify` or an equivalent constant-time function |
| Be singleton-safe | Authenticators are registered as singletons and called concurrently |
| Return `ClientAuthenticationResult.NotValid()` on failure — never throw | Throwing from `AuthenticateAsync` produces a 500 rather than a 401 |

> 💡 **Exception messages are now redacted by default.**
> `SecretSanitizingLogger` unconditionally wraps all logged exceptions in `RedactedExceptionWrapper`,
> replacing the exception `Message` with a fixed placeholder before it reaches any log sink. You no
> longer need to avoid putting credential material in exception messages as a workaround — though
> doing so remains good practice. To restore original exception messages in a development
> environment, call `DisableExceptionSanitizing()` on the builder. See
> [Configure host-level log hygiene](configure-host-log-hygiene.md) for details.

> ⚠️ **Warning: `SecretSanitizingLogger` covers ZeeKayDa.Auth's own logs only.**
> The redaction wrapper intercepts log calls made by ZeeKayDa.Auth's internal services. It has no
> effect on ASP.NET Core's `UseHttpLogging()`, Kestrel connection logging, W3CLogger, Application
> Insights telemetry, or exception-handling middleware — all of which can capture the `Authorization`
> header or a form-encoded `client_secret` entirely outside the library's scope.
>
> See [Configure host-level log hygiene](configure-host-log-hygiene.md) for the steps required to
> close this gap in the host pipeline.

## See also

- [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md) — register the framework and the minimum required options.
- [Configure discovery](configure-discovery.md) — customise the discovery document with the built-in options.
- [Configure host-level log hygiene](configure-host-log-hygiene.md) — prevent sensitive parameters from appearing in host-pipeline logs outside ZeeKayDa.Auth's redaction boundary.
- [`AuthorizationServerOptions` reference](../reference/configuration.md) — full property list and validation rules.
- [Client secrets reference](../reference/client-secrets.md) — `Pbkdf2ClientSecretHasherOptions` property reference.
- [Cancellation in managed threads](https://learn.microsoft.com/dotnet/standard/threading/cancellation-in-managed-threads) — Microsoft's reference for the cancellation pattern this framework follows.
