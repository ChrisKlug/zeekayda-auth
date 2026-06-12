---
title: "Implement a custom client repository"
description: "How to implement IClientRepository to store OAuth 2.0 client registrations in a database or other persistent store."
parent: "How-to Guides"
nav_order: 5
---

*Added in Unreleased.*

The built-in `InMemoryClientRepository` is suitable for development and simple deployments.
For production scenarios where clients are stored in a database, loaded from an external config
service, or managed via an admin API, implement `IClientRepository` directly.

## The contract

```csharp
public interface IClientRepository
{
    ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}
```

Two rules are **non-negotiable**:

1. **Return `null` for unknown clients — never throw.** Throwing from this method changes response
   timing and creates a timing oracle that enables client enumeration attacks. An unknown or
   malformed `client_id` must always produce a `null` return, never an exception.

2. **Use parameterised queries — never concatenate `clientId` into a query string.** If your
   implementation queries a database, pass `clientId` as a parameter to prevent SQL injection.

## Registering a custom repository

Register your implementation as a singleton via the standard DI API. The startup validator
detects the registration automatically — no extra flags or configuration needed:

```csharp
services.AddSingleton<IClientRepository, MyDatabaseClientRepository>();
```

Wrapping it in a builder extension is a clean pattern:

```csharp
public static ZeeKayDaAuthBuilder AddDatabaseClients(this ZeeKayDaAuthBuilder builder)
{
    builder.Services.AddSingleton<IClientRepository, MyDatabaseClientRepository>();
    return builder;
}
```

## Validating registrations

**You must call `IClientRegistrationValidator.Validate` before persisting a new or updated
client registration.** The validator enforces all redirect URI rules, the `IsPublic` consistency
check, credential integrity checks, and auth-method subset constraints. Not calling it means
your clients bypass the security checks that the framework enforces on in-memory registrations.

Inject `IClientRegistrationValidator` from DI and call it at write time:

```csharp
public sealed class MyDatabaseClientRepository : IClientRepository
{
    private readonly IClientRegistrationValidator _validator;
    private readonly MyDbContext _db;

    public MyDatabaseClientRepository(
        IClientRegistrationValidator validator,
        MyDbContext db)
    {
        _validator = validator;
        _db = db;
    }

    public async Task SaveClientAsync(IClientRegistration client)
    {
        // Throws ZeeKayDaConfigurationException with all violations in AggregatedFailures
        // if the registration is invalid — see every problem in one pass.
        _validator.Validate(client);

        // persist ...
    }

    public async ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        // Parameterised query — never concatenate clientId into the query string.
        var row = await _db.Clients
            .Where(c => c.ClientId == clientId)
            .FirstOrDefaultAsync(cancellationToken);

        return row is null ? null : MapToRegistration(row);
    }

    private static IClientRegistration MapToRegistration(ClientRow row) => new ClientRegistration
    {
        ClientId = row.ClientId,
        Credentials = row.Secrets.Select(s => new Pbkdf2ClientSecret(
            s.Iterations, s.Salt, s.Hash)).ToList<IClientCredential>(),
        IsPublic = row.IsPublic,
        RedirectUris = new HashSet<string>(row.RedirectUris, StringComparer.Ordinal),
        PostLogoutRedirectUris = new HashSet<string>(row.PostLogoutRedirectUris, StringComparer.Ordinal),
        AllowedScopes = new HashSet<string>(row.AllowedScopes, StringComparer.Ordinal),
    };
}
```

For read-mostly stores (replicated databases, caches) where the initial load happens outside the
request path, call `Validate` as registrations enter the cache — not just at the DB write that
originally created them. A registration that fails validation must not be returned from
`FindByClientIdAsync`.

## String comparison invariants

All `IReadOnlySet<string>` members on `IClientRegistration` — `RedirectUris`,
`PostLogoutRedirectUris`, `AllowedScopes`, `AllowedTokenEndpointAuthMethods` — must be enumerated
with **explicit `StringComparer.Ordinal`** semantics wherever a membership check is performed.
Do not trust the set's own comparer: a custom implementation may return a set built with a
case-insensitive or culture-aware comparer, which would silently loosen security boundaries.

```csharp
// Correct — ordinal comparison regardless of the set's comparer
var allowed = client.RedirectUris
    .Contains(incomingRedirectUri, StringComparer.Ordinal);

// Wrong — trusts the set's comparer, which may differ across implementations
var allowed = client.RedirectUris.Contains(incomingRedirectUri);
```

## See also

- [Register clients](register-clients.md) — the built-in in-memory repository for development
  and simple deployments.
- [Implement a custom extension point](implement-custom-extension-points.md) — scope repository
  and discovery document customisation.
