---
title: "Client secrets"
description: "Reference for Pbkdf2ClientSecretHasherOptions and the client secret hasher API."
parent: "Reference"
nav_order: 3
---

*Added in Unreleased.*

This page covers the configuration options and public API for ZeeKayDa.Auth's client secret
hasher infrastructure. For step-by-step setup instructions, see
[Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md). To implement a custom hasher,
see [Implement a custom extension point](../how-to/implement-custom-extension-points.md).

## `Pbkdf2ClientSecretHasherOptions`

Configuration options for `Pbkdf2ClientSecretHasher`, the built-in PBKDF2-HMAC-SHA256 hasher.

Configure via `IOptions<Pbkdf2ClientSecretHasherOptions>` at service registration time:

```csharp
builder.Services.Configure<Pbkdf2ClientSecretHasherOptions>(options =>
{
    options.Iterations = 1_200_000;
});

auth.AddSecretsHasher<Pbkdf2ClientSecretHasher>();
```

### `Iterations`

| Attribute | Value |
|---|---|
| Type | `int` |
| Default | `600_000` (`Pbkdf2ClientSecretHasherOptions.DefaultIterations`) |
| Required | No |

The PBKDF2 iteration count used when creating new hashed secrets. This value is embedded in
each stored credential and used verbatim for verification, so changing it only affects newly
created secrets — existing secrets continue to verify correctly at their original iteration count.

> **Iteration count changes and credential rotation.** Because verification uses the iteration
> count stored in the credential, raising `Iterations` does not automatically re-protect existing
> secrets. Until existing credentials are rotated (re-hashed at the new count), the unknown-client
> timing baseline — used by the token endpoint to prevent client enumeration — will diverge from
> the timing of real verifications against old credentials. For this reason, iteration count
> increases should be paired with a credential rotation step.

The minimum accepted value is **600,000**. This matches the OWASP recommendation for
PBKDF2-HMAC-SHA256 as of 2025. Configuring a lower value causes the host to fail at startup with
an `ArgumentOutOfRangeException`.

Values above **2,000,000** are clamped to 2,000,000 and a `LogWarning` is emitted at startup.
At this level a single verification takes roughly one second on typical server hardware, making
the token endpoint impractical under any real load. The clamp lets the server start safely
while signalling that reconfiguration is needed.

```csharp
// ✓ Valid: at the minimum
options.Iterations = 600_000;

// ✓ Valid: stronger than the default
options.Iterations = 1_200_000;

// ✗ Invalid: below the minimum — causes ArgumentOutOfRangeException at startup
options.Iterations = 100_000;

// ⚠ Clamped: above the maximum cap — emits LogWarning, clamped to 2,000,000
options.Iterations = 20_000_000;
```

---

## `IClientSecretHasher`

The interface all hasher implementations must satisfy.

```csharp
public interface IClientSecretHasher
{
    bool CanHandle(IClientSecret secret);
    bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);
    IClientSecret Create(ReadOnlySpan<char> plaintext);      // primary — memory-safe
    IClientSecret Create(string plaintext);                    // convenience — delegates to span overload
}
```

| Member | Behaviour |
|---|---|
| `CanHandle` | Returns `true` when this hasher can verify or create credentials of the given type. |
| `Verify` | Returns `false` on mismatch or internal error. Never throws. |
| `Create(ReadOnlySpan<char>)` | Primary overload. Creates a new hashed credential from a span. Throws `ArgumentException` for empty or whitespace-only input. Spans cannot be null. |
| `Create(string)` | Convenience overload. Delegates to the span overload after a null check. Throws `ArgumentNullException` for null input; throws `ArgumentException` for empty or whitespace-only input. |

### `ClientSecretHasher<TSecret>` abstract base class

`ClientSecretHasher<TSecret>` is the recommended base for custom implementations. It handles
type dispatch (`CanHandle`), exception swallowing (`Verify`), and input validation (`Create`).
Subclasses implement `VerifyCore` and `CreateCore(string)`. Subclasses that can consume a span
directly may additionally override `CreateCore(ReadOnlySpan<char>)` to avoid the default
fallback string allocation.

---

## `IClientSecretFactory`

*Added in Unreleased.*

`IClientSecretFactory` is the injectable seam for hashing new client secrets at runtime. It
delegates to the configured default `IClientSecretHasher` — whichever hasher was marked as
default via `AddSecretsHasher<T>(isDefault: true)` — so you never need to hard-code an
algorithm in your repository or admin layer.

```csharp
public interface IClientSecretFactory
{
    IClientSecret Create(string plaintext);
}
```

`IClientSecretFactory` is registered automatically by `AddZeeKayDaAuth` as a singleton via
`TryAddSingleton`. You do not need to call `AddSecretsHasher` before injecting it —
registration order does not matter as long as both calls occur before the host is built.

### Who should use this interface

`IClientSecretFactory` is for custom `IClientRepository` implementations that need to hash
secrets at write time — for example:

- An admin API endpoint that issues new client credentials
- A credential rotation flow that replaces an existing secret
- Future support for [RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

If your clients are registered at startup using the `AddInMemoryClients` builder, you do not
need this interface. The builder handles hashing automatically when you call `AddConfidential`:

```csharp
auth.AddInMemoryClients(clients =>
{
    clients.AddConfidential(
        clientId:               "my-api-client",
        clientSecret:           "s3cr3t",
        redirectUris:           ["https://myapp.example.com/callback"],
        postLogoutRedirectUris: ["https://myapp.example.com/signed-out"],
        allowedScopes:          ["openid", "profile", "my-api"]);
});
```

### Injecting `IClientSecretFactory`

Inject the interface through the constructor of your custom `IClientRepository`:

```csharp
public sealed class MyClientRepository : IClientRepository
{
    private readonly IClientSecretFactory _secretFactory;

    public MyClientRepository(IClientSecretFactory secretFactory)
        => _secretFactory = secretFactory;

    public async Task RegisterClientAsync(string clientId, string plaintextSecret)
    {
        IClientSecret credential = _secretFactory.Create(plaintextSecret);
        // persist credential to your store...
    }
}
```

> ⚠️ **Warning: `Create` is CPU-intensive and must not be called on a hot request path.**
> At the default iteration count of 600,000 PBKDF2-HMAC-SHA256 rounds, a single call takes
> approximately 600 ms on typical server hardware. Calling it from a token-endpoint handler or
> any other frequently-hit path will degrade throughput for all clients on the server.
>
> `Create` is intended for admin operations only. The endpoint that calls it MUST be:
> - protected by strong authentication (not the same `client_secret` being created),
> - rate-limited to prevent brute-force amplification, and
> - logged and audited.

### Lifetime

`IClientSecretFactory` is registered with `TryAddSingleton`. The `CompositeClientSecretHasher`
that backs it is also a singleton. Injecting `IClientSecretFactory` into a singleton
`IClientRepository` is safe — no captive-dependency issue arises.

### See also

- [Implement a custom client repository](../how-to/implement-custom-extension-points.md#5-implement-a-custom-client-repository) — full example with `IClientRegistrationValidator`
- [`IClientSecretHasher`](#iclientsecrethashert) — the per-algorithm interface that `IClientSecretFactory` delegates to

---

## Memory-safe secret handling

Managed `string` instances in .NET are immutable and GC-managed: their backing memory cannot be
overwritten by the caller, and the runtime does not guarantee prompt erasure after the string
becomes unreachable. A caller who converts a mutable buffer to a `string` before calling
`Create` extends the window during which the raw secret resides in managed heap memory — possibly
across multiple GC cycles — in a form they cannot erase.

`Create(ReadOnlySpan<char>)` eliminates this: the caller retains ownership of the backing
array and can zero it immediately after the call.

```csharp
char[] secret = /* decoded from a network buffer, QR code, etc. */;
IClientSecret stored;
try
{
    stored = hasher.Create(secret.AsSpan());
}
finally
{
    Array.Clear(secret); // erase the raw bytes before GC can observe them
}
```

`Verify` already accepts `ReadOnlySpan<char>`, so the same pattern applies to the
verification path:

```csharp
char[] presented = /* read from network buffer */;
bool valid;
try
{
    valid = hasher.Verify(storedSecret, presented.AsSpan());
}
finally
{
    Array.Clear(presented);
}
```

Both paths feed the same bytes into `Rfc2898DeriveBytes.Pbkdf2`, so a credential created via
the span overload and one created via the string overload are interchangeable: either hash
verifies the same presented secret.

---

## `AddSecretsHasher<THasher>` builder extension

Registers a client secret hasher with the ZeeKayDa.Auth DI container.

```csharp
public static ZeeKayDaAuthBuilder AddSecretsHasher<THasher>(
    this ZeeKayDaAuthBuilder builder,
    bool isDefault = false)
    where THasher : class, IClientSecretHasher
```

| Parameter | Type | Description |
|---|---|---|
| `builder` | `ZeeKayDaAuthBuilder` | The builder returned by `AddZeeKayDaAuth`. |
| `isDefault` | `bool` | When `true`, this hasher creates new secrets and generates the timing-pad dummy credential at startup. See below. |

**Return value:** The same `builder` for method chaining.

### `isDefault` rules

| Registered hashers | `isDefault` requirement |
|---|---|
| Exactly 1 | Auto-default — the flag is ignored |
| 2 or more | Exactly one must have `isDefault: true`; zero or multiple defaults cause a startup failure |

Startup validation is enforced by `IValidateOptions<ClientSecretHasherRegistrationOptions>` via
`ValidateOnStart()`. A misconfigured hasher registration prevents the host from starting and is
visible in the startup output.

---

## Startup validation rules

| Rule | Condition that causes failure |
|---|---|
| At least one hasher required | `AddSecretsHasher<T>()` was never called |
| Exactly one default when multiple hashers registered | 2+ hashers registered and zero or 2+ have `isDefault: true` |
| Iterations meet the minimum | `Pbkdf2ClientSecretHasherOptions.Iterations` is below 600,000 |

---

## Related pages

- [Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md) — register hashers alongside the core setup
- [Implement a custom extension point](../how-to/implement-custom-extension-points.md) — how to write a custom `IClientSecretHasher` or `IClientRepository`
- [AuthorizationServerOptions reference](configuration.md) — core authorization server configuration
