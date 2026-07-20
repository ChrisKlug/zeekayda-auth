---
title: "Implement a custom signing key provider"
description: "How to build a custom rotating signing-key provider on the three-tier options hierarchy, using Azure Key Vault as the worked example."
parent: "How-to Guides"
nav_order: 13
---

*Added in Unreleased.*

The five shipped signing-key providers (development, PEM, PFX, Windows Certificate Store, Azure
Key Vault) all derive from the same abstract base class, `JwtSigningService<TOptions>`, and the
same three-tier options hierarchy. If your organisation needs a signing provider these don't
cover — a different KMS, an HSM, an internal secrets service — you build it the same way.

This guide walks through the three-tier options hierarchy, shows a minimal worked example, and
then walks through Azure Key Vault's own implementation as the pattern to copy if your provider
needs to enforce a timing invariant of its own.

## Before you start

- You are implementing `IJwtSigningService` by deriving from `JwtSigningService<TOptions>` —
  not implementing `IJwtSigningService` directly. The base class supplies interval-throttled
  caching, single-flight refresh coalescing, key/algorithm compatibility validation, and
  deterministic disposal of superseded key material; you implement only `LoadKeysAsync`.
- You understand the retirement-window and publish-then-activate model shared by every rotating
  provider — see [Rotate signing keys](rotate-signing-keys.md) first if you haven't already. This
  guide covers the *options shapes* a provider exposes, not the rotation model itself.
- For the design rationale behind the hierarchy below, see [ADR 0011](../decisions/0011-signing-key-management.md)
  §3.4–§3.5. This guide is deliberately practical — it shows you what to derive from and what to
  copy, not why each invariant exists.

## The three-tier options hierarchy

Every provider's options type derives from one of two tiers, both of which in turn derive from a
common, effectively empty base:

```csharp
public abstract class JwtSigningServiceOptions
{
    // No rotation-shaped property at all. Deliberately empty — every rotation-related
    // knob lives on exactly one of the two tiers below, never on the shared base.
}

public abstract class StaticKeySourceOptions : JwtSigningServiceOptions
{
    // Also empty. Deriving from this tier tells the base class the key source never
    // changes at runtime.
}

public abstract class RotatingKeySourceOptions : JwtSigningServiceOptions
{
    public TimeSpan KeyRotationCheckInterval { get; set; } = TimeSpan.FromHours(1);
}
```

### `JwtSigningServiceOptions` — the shared base

You never derive from this directly. It exists purely so `JwtSigningService<TOptions>` can be
written once against a single constraint (`where TOptions : JwtSigningServiceOptions`) and still
treat static and rotating providers differently at construction time — see
[Choosing your tier](#choosing-your-tier) below.

### `StaticKeySourceOptions` — load-once providers

Derive from this tier when your key source is fixed for the lifetime of the process — generated
once at startup, or loaded from a file that is never expected to change without a restart.
`LoadKeysAsync` is called at most once; the base class never re-invokes it and never disposes the
cached key set while the service is live. `DevelopmentSigningKeyOptions` is the shipped example:
a locally-generated or file-persisted development key never changes at runtime, so there is
nothing to poll.

### `RotatingKeySourceOptions` — polling providers

Derive from this tier when your key source can change while the process runs — a KMS, an HSM, a
database, a certificate store, or a directory of files that might be replaced out from under the
process. You get `KeyRotationCheckInterval` for free: the base class re-invokes `LoadKeysAsync` (or
the cheaper `HasKeySetChangedAsync` ask, if you implement it) on this cadence, coalescing
concurrent callers behind a single-flight gate so a burst of signing or JWKS requests never fans
out into multiple simultaneous loads. This is the shared parent for all four shipped rotating
providers — File, PFX, Windows Certificate Store, and Azure Key Vault (both cached and remote
variants) — not a Key-Vault-specific type.

## Choosing your tier

Ask one question: **can the key set change without a process restart?**

| Your key source | Tier | Why |
|---|---|---|
| Generated once at startup, held in memory | `StaticKeySourceOptions` | Nothing to poll — the key set is fixed for the process lifetime. |
| A file that is only ever replaced via a redeploy/restart | `StaticKeySourceOptions` | Same reasoning — no in-process rotation to detect. |
| A KMS/HSM/secrets service with its own rotation schedule | `RotatingKeySourceOptions` | The key set can change independently of your process; you need to poll for it. |
| A certificate store, or a directory of files an operator can update live | `RotatingKeySourceOptions` | Same — an external actor can change the trusted set without restarting your process. |

Picking the wrong tier is a compile-time-visible mistake in the constructor path, not a silent
bug: the base class inspects the runtime type of your options instance to decide whether to poll
at all (see [`JwtSigningService<TOptions>`'s constructor](#worked-example-a-minimal-rotating-provider)
below), so deriving from the wrong tier changes *whether reload ever happens*, not just a default
value.

## Worked example: a minimal rotating provider

A provider whose key source is a remote HTTP-backed secrets service, with no timing invariant of
its own beyond the shared poll cadence, needs almost no options code:

```csharp
public sealed class AcmeSecretsSigningOptions : RotatingKeySourceOptions
{
    public Uri SecretsServiceUri { get; set; } = null!;

    public SigningAlgorithm Algorithm { get; set; }
}
```

`KeyRotationCheckInterval` is inherited — you did not write it, and you do not need to remember to
default it, because `RotatingKeySourceOptions` already defaults it to 1 hour. Your service
implementation only needs to provide `LoadKeysAsync`:

```csharp
internal sealed class AcmeSecretsJwtSigningService : JwtSigningService<AcmeSecretsSigningOptions>
{
    private readonly IAcmeSecretsClient _client;

    public AcmeSecretsJwtSigningService(
        IOptions<AcmeSecretsSigningOptions> options,
        IAcmeSecretsClient client,
        TimeProvider timeProvider)
        : base(options, timeProvider)
    {
        _client = client;
    }

    protected override async ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
    {
        var activeKeyPair = await _client.GetActiveKeyPairAsync(cancellationToken);
        var additionalKeyPairs = await _client.GetPublishedNotYetActiveOrRetiringKeyPairsAsync(cancellationToken);

        // The base class validates key/algorithm compatibility and minimum key strength for
        // you once this set is returned; you only need to supply the active key and every
        // other currently trusted key (published-but-not-yet-active, or still within its
        // retirement window).
        return new SigningKeySet(activeKeyPair, additionalKeyPairs);
    }
}
```

Because `AcmeSecretsSigningOptions` derives from `RotatingKeySourceOptions`, the base class's
constructor reads `KeyRotationCheckInterval` off it and re-invokes `LoadKeysAsync` on that cadence
— no extra wiring required on your part:

```csharp
protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider)
{
    _keyRotationCheckInterval = options.Value is RotatingKeySourceOptions rotating
        ? rotating.KeyRotationCheckInterval
        : null; // null = static-source mode: load once, never reload.
}
```

If this provider introduced no cross-field timing invariant beyond the shared poll cadence, you
would be done. Most providers with a genuine publish-then-activate delay, however, need one more
step — the next section walks through it using Azure Key Vault's actual implementation.

## Worked example: Azure Key Vault's enforced activation delay

Both Azure Key Vault signing options types — `AzureKeyVaultCachedSigningOptions` and
`AzureKeyVaultRemoteSigningOptions` — derive from `RotatingKeySourceOptions` and add exactly one
extra property:

```csharp
public sealed class AzureKeyVaultCachedSigningOptions : RotatingKeySourceOptions
{
    public TimeSpan? SigningKeyActivationDelay { get; set; }

    // ... CertificateIdentifier, Credential, Algorithm ...
}
```

### `KeyRotationCheckInterval` — the shared poll cadence

Inherited from `RotatingKeySourceOptions`, unchanged: how often the provider re-checks whether the
trusted certificate/key version set has changed.

### `SigningKeyActivationDelay` — the provider-specific invariant

`SigningKeyActivationDelay` is the publish-then-activate lead time: a newly rotated-in Key Vault
version must be visible in `GetSigningKeysAsync()` results — and so in the published JWKS — for at
least this long before it may become the active signer. When unset, it defaults to
`KeyRotationCheckInterval`.

> ⚠️ **Warning:** `SigningKeyActivationDelay` must never be shorter than `KeyRotationCheckInterval`.
> If it were, a newly-published key version could become the active signer before the process
> itself has polled and noticed the new version exists — a relying party that fetched the JWKS
> just before rotation would still be caching the old key set when a token signed by the new,
> unseen key arrives, and would reject it as untrusted. This is the exact race the
> publish-then-activate model exists to prevent (see [Rotate signing keys](rotate-signing-keys.md)).

This is the pattern worth studying: a provider-specific property that must satisfy a cross-field
invariant against the shared `KeyRotationCheckInterval`, enforced in more than one place.

### Where the invariant is enforced, and why in two places

The `SigningKeyActivationDelay >= KeyRotationCheckInterval` invariant is checked in exactly two
independent places in the Key Vault providers, and a custom provider that introduces an analogous
invariant should copy both, not just one.

**1. A shared validation helper, called from `IValidateOptions<TOptions>`.** Both Key Vault option
validators call the same internal helper rather than duplicating the check:

```csharp
public static string? ValidateNotShorterThanCheckInterval(
    string optionsTypeName, TimeSpan? signingKeyActivationDelay, TimeSpan keyRotationCheckInterval)
{
    if (signingKeyActivationDelay is { } delay && delay < keyRotationCheckInterval)
    {
        return $"{optionsTypeName}.SigningKeyActivationDelay ({delay}) must be greater than or " +
               $"equal to {optionsTypeName}.KeyRotationCheckInterval ({keyRotationCheckInterval}).";
    }

    return null;
}
```

Each validator's `Validate(string?, TOptions)` adds this to its aggregated error list alongside
every other option check, so a misconfigured host fails fast at `ValidateOnStart()` with every
problem reported at once, in a message written for the person configuring the app.

**2. An independent guard inside the rotation-timeline logic itself**, thrown as a
`ZeeKayDaConfigurationException` the moment the timeline is actually built:

```csharp
public static List<ActivationEntry<T>> BuildActivationTimeline<T>(
    IReadOnlyList<T> allVersions, TimeSpan signingKeyActivationDelay, TimeSpan keyRotationCheckInterval)
    where T : struct, IKeyVaultVersionInfo
{
    if (signingKeyActivationDelay < keyRotationCheckInterval)
    {
        throw new ZeeKayDaConfigurationException(/* ... */);
    }

    // ... build the timeline ...
}
```

**Neither guard alone is sufficient — each closes a gap the other leaves open:**

- **The validator alone is not enough** because it can be bypassed. `IValidateOptions<TOptions>`
  only runs when the options are bound and validated through the standard `AddOptions<TOptions>()`
  / `ValidateOnStart()` pipeline. A test, a hand-rolled DI registration, or any code path that
  constructs the options type directly and hands it straight to the rotation logic never invokes
  the validator at all — the invalid value would sail through silently.
- **The timeline guard alone is not enough**, in the other direction. If it were the *only*
  enforcement point, an invalid configuration would not be rejected until the timeline is actually
  built — inside `LoadKeysAsync`, well after startup — and it would surface as a low-level,
  un-aggregated `ZeeKayDaConfigurationException` thrown from deep inside rotation machinery, mixed
  in with none of the app's other configuration problems and none of the friendlier, aggregated
  messaging the `IValidateOptions` path gives every other option error. A host operator would get
  a confusing failure at first sign/refresh instead of a clear, complete list of problems at
  `ValidateOnStart()`.

Together, the validator gives you **fail-fast, friendly, aggregated** startup errors for the
common case (a real host, wired up normally), and the timeline guard gives you **unbypassable
defense-in-depth** for every other code path that can reach the rotation logic. Drop either one
and you lose exactly the property the other was providing.

> 💡 **Tip:** `KeyVaultActivationDelay` and `KeyVaultSigningKeyRotation` are `internal` to
> `ZeeKayDa.Auth.AzureKeyVault` — you cannot reference or call them from your own provider. Treat
> the code above as a **pattern to copy**, not an API to reuse: write your own small validation
> helper and your own independent guard inside your own timeline-building logic, shaped the same
> way.

## Adapting the pattern to a custom KMS/HSM provider

If your provider introduces its own cross-field timing invariant — an activation delay, a
minimum overlap window, anything that must be compared against `KeyRotationCheckInterval` or
against another one of your own properties — replicate the two-place shape above:

1. Add the property to your `RotatingKeySourceOptions`-derived options type, defaulting to
   `KeyRotationCheckInterval` when unset (mirroring `SigningKeyActivationDelay`), so a consumer who
   sets nothing gets safe, unsurprising behaviour.
2. Write a small validation helper (a plain static method is enough — it does not need to be
   shared across multiple option types unless you have more than one, the way Key Vault does)
   and call it from your `IValidateOptions<TOptions>` implementation, aggregating its error
   alongside your other option checks.
3. Add the same check, independently, at the start of whatever method actually computes your
   activation/retirement timeline from the invariant — so the invariant holds even for a caller
   that never went through `IValidateOptions<TOptions>`.
4. Also derive your provider's durable timeline entirely from your key store's own durable,
   per-key timestamps — never from in-memory "when did I first see this key" bookkeeping, which
   does not survive a process restart and is inconsistent across load-balanced replicas. See ADR
   0011 §3.5 for the full rationale and the two anchoring strategies the shipped providers use
   (Key Vault's `CreatedOn`, and certificate/file `NotBefore`).

## Common mistakes

- **Deriving from `JwtSigningServiceOptions` directly instead of one of the two tiers.** This
  compiles (the constraint is `where TOptions : JwtSigningServiceOptions`), but it is never the
  right choice — always derive from `StaticKeySourceOptions` or `RotatingKeySourceOptions`, so the
  base class can tell which reload behaviour you need.
- **Deriving from `StaticKeySourceOptions` for a source that actually rotates.** The base class
  will call `LoadKeysAsync` exactly once and never again — a genuinely rotating source will keep
  signing with a stale key set forever, and any warning or fail-closed behaviour your
  `LoadKeysAsync` implementation raises on a real load will never fire a second time.
- **Adding your own timing invariant with only one of the two enforcement points.** See
  [Where the invariant is enforced, and why in two places](#where-the-invariant-is-enforced-and-why-in-two-places)
  above — a validator alone can be bypassed by direct construction; a timeline guard alone gives up
  fail-fast, aggregated startup errors.
- **Deriving your rotation timeline from in-memory state instead of a durable, provider-side
  timestamp.** This breaks on restart (a fresh replica has no history) and is inconsistent across
  multiple replicas of the same process.

## See also

- [Rotate signing keys](rotate-signing-keys.md) — the retirement-window and publish-then-activate
  model every rotating provider shares.
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) — the shipped provider
  this guide's worked example is drawn from.
- [Configure file-based signing](configure-file-based-signing.md) — the other shipped example of a
  `RotatingKeySourceOptions` derivation, using `AssumedJwksPropagationDelay` instead of an
  activation delay.
- [ADR 0011: Signing key management](../decisions/0011-signing-key-management.md) — the full
  design rationale for the three-tier hierarchy and the rotation model.
