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
    IClientSecret Create(string plaintext);
}
```

| Member | Behaviour |
|---|---|
| `CanHandle` | Returns `true` when this hasher can verify or create credentials of the given type. |
| `Verify` | Returns `false` on mismatch or internal error. Never throws. |
| `Create` | Creates a new hashed credential. Throws `ArgumentException` for null, empty, or whitespace-only input. |

### `ClientSecretHasher<TSecret>` abstract base class

`ClientSecretHasher<TSecret>` is the recommended base for custom implementations. It handles
type dispatch (`CanHandle`), exception swallowing (`Verify`), and null/whitespace rejection
(`Create`). Subclasses implement only `VerifyCore` and `CreateCore`.

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
- [Implement a custom extension point](../how-to/implement-custom-extension-points.md) — how to write a custom `IClientSecretHasher`
- [AuthorizationServerOptions reference](configuration.md) — core authorization server configuration
