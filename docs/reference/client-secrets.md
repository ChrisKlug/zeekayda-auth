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

`AddZeeKayDaAuth` always registers the hasher. Configure it on the builder, or bind
`Pbkdf2ClientSecretHasherOptions` from configuration:

```csharp
auth.ConfigurePbkdf2ClientSecretHasher(options => options.Iterations = 1_200_000);
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

The accepted range is **600,000 to 2,000,000**; a value outside it fails startup with a
`ZeeKayDaConfigurationException` carrying the code `configuration.pbkdf2.iterations_out_of_range`. The minimum matches the OWASP recommendation for PBKDF2-HMAC-SHA256
as of 2025. At the maximum a single verification takes roughly one second on typical server
hardware, making the token endpoint impractical under any real load.

```csharp
// ✓ Valid: at the minimum
options.Iterations = 600_000;

// ✓ Valid: stronger than the default
options.Iterations = 1_200_000;

// ✗ Invalid: below the minimum — fails startup
options.Iterations = 100_000;

// ✗ Invalid: above the maximum — fails startup
options.Iterations = 20_000_000;
```

---

## `IClientSecretHasher`

The interface all hasher implementations must satisfy.

```csharp
public interface IClientSecretHasher
{
    IReadOnlySet<string> AlgorithmIds { get; }
    bool Verify(ReadOnlySpan<char> presented, ClientSecret stored);
    ClientSecret Create(ReadOnlySpan<char> plaintext);
    IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) => [];
}
```

| Member | Behaviour |
|---|---|
| `AlgorithmIds` | The PHC algorithm ids this hasher owns, for example `pbkdf2-sha256`. Each is 1–32 characters from `[a-z0-9-]`; two hashers declaring one id fail startup. |
| `Verify` | Verifies a presented secret against a stored one whose id this hasher declared. Returns `false` on mismatch or on a value it cannot read; a throw counts as a failed verification. Compare in fixed time. |
| `Create` | Hashes a new secret. The framework has already refused empty and whitespace-only input, and refuses a result whose id this hasher did not declare. |
| `ValidateStoredSecret` | Optional. What is wrong with a stored secret this hasher owns — an unreadable value, a work factor below its floor. Runs wherever a client registration is validated. |

### `ClientSecretHasher<TSecret>` abstract base class

`ClientSecretHasher<TSecret>` is the recommended base for custom implementations. It handles
type dispatch (`CanHandle`), exception swallowing (`Verify`), and input validation (`Create`).
Subclasses implement `VerifyCore` and `CreateCore(string)`. Subclasses that can consume a span
directly may additionally override `CreateCore(ReadOnlySpan<char>)` to avoid the default
fallback string allocation.

---

## `ClientSecrets`

*Added in Unreleased.*

`ClientSecrets` is the framework's service for hashing new client secrets at runtime. It is a
sealed class with an internal constructor: inject it, never implement or replace it. It
delegates to the configured default `IClientSecretHasher` — whichever hasher was marked as
default via `AddClientSecretHasher<T>(isDefault: true)` — so you never need to hard-code an
algorithm in your repository or admin layer.

```csharp
public sealed class ClientSecrets
{
    public ClientSecret Create(string plaintext);
    public ClientSecret Create(ReadOnlySpan<char> plaintext);
    public SecretVerification Verify(ReadOnlySpan<char> presented, IReadOnlyCollection<ClientSecret> stored);
}
```

`Verify` is what a custom `IClientAuthenticator` calls with `context.Client.Secrets`: it pads every
failure to one fixed cost, so the response time reveals neither whether the client exists nor how
many secrets it holds. Return its outcome with `ClientAuthenticationResult.From(...)`; refuse a
malformed request with `ClientAuthenticationResult.NotValid()`, which the token endpoint pads to the
same cost.

`ClientSecrets` is registered automatically by `AddZeeKayDaAuth` as a singleton. You do not need to call `AddClientSecretHasher` before injecting it —
registration order does not matter as long as both calls occur before the host is built.

### Who should use this service

`ClientSecrets` is for custom `IClientRepository` implementations that need to hash
secrets at write time — for example:

- An admin API endpoint that issues new client credentials
- A credential rotation flow that replaces an existing secret
- Future support for [RFC 7591 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

If your clients are registered at startup using the `AddInMemoryClients` builder, you do not
need this service. The builder handles hashing automatically when you call `AddConfidential`:

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

### Injecting `ClientSecrets`

Inject the service through the constructor of your custom `IClientRepository`:

```csharp
public sealed class MyClientRepository : IClientRepository
{
    private readonly ClientSecrets _secrets;

    public MyClientRepository(ClientSecrets secrets)
        => _secrets = secrets;

    public async Task RegisterClientAsync(string clientId, string plaintextSecret)
    {
        ClientSecret credential = _secrets.Create(plaintextSecret);
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

`ClientSecrets` is registered with `TryAddSingleton`. The registry
of hashers behind it is also a singleton. Injecting `ClientSecrets` into a singleton
`IClientRepository` is safe — no captive-dependency issue arises.

### See also

- [Implement a custom client repository](../how-to/implement-custom-extension-points.md#5-implement-a-custom-client-repository) — full example with `IClientRegistrationValidator`
- [`IClientSecretHasher`](#iclientsecrethashert) — the per-algorithm interface that `ClientSecrets` delegates to

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
    valid = hasher.Verify(presented.AsSpan(), storedSecret);
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

## `AddClientSecretHasher<THasher>` builder extension

Registers a client secret hasher with the ZeeKayDa.Auth DI container.

```csharp
public static ZeeKayDaAuthBuilder AddClientSecretHasher<THasher>(
    this ZeeKayDaAuthBuilder builder,
    bool isDefault = false)
    where THasher : class, IClientSecretHasher
```

| Parameter | Type | Description |
|---|---|---|
| `builder` | `ZeeKayDaAuthBuilder` | The builder returned by `AddZeeKayDaAuth`. |
| `isDefault` | `bool` | When `true`, this hasher creates new secrets instead of PBKDF2. See below. |

**Return value:** The same `builder` for method chaining.

### `isDefault` rules

PBKDF2 is always registered. At most one hasher may have `isDefault: true`:

| Hashers marked `isDefault: true` | Default hasher |
|---|---|
| None | PBKDF2 |
| One | That hasher; PBKDF2 stays registered and keeps verifying existing PBKDF2 secrets |
| Two or more | None — startup fails with `ZeeKayDaConfigurationException` `configuration.hashers.multiple_defaults` |

---

## Startup validation rules

| Rule | Condition that causes failure |
|---|---|
| Exactly one default | 2+ hashers are registered and zero or 2+ have `isDefault: true` |
| Iterations within range | `Pbkdf2ClientSecretHasherOptions.Iterations` is below 600,000 or above 2,000,000 |

---

## Related pages

- [Configure ZeeKayDa.Auth](../how-to/configure-zeekayda-auth.md) — register hashers alongside the core setup
- [Implement a custom extension point](../how-to/implement-custom-extension-points.md) — how to write a custom `IClientSecretHasher` or `IClientRepository`
- [AuthorizationServerOptions reference](configuration.md) — core authorization server configuration
