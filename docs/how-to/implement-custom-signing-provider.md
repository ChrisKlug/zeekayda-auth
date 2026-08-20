---
title: "Implement a custom signing key provider"
description: "How to build a custom signing-key provider on the KeySetOptions/KeySourceOptions options types, using Azure Key Vault as the worked example."
parent: "How-to Guides"
nav_order: 13
---

*Added in Unreleased.*

The five shipped signing-key providers (development, PEM, PFX, Windows Certificate Store, Azure
Key Vault) all derive from the same abstract base class, `JwtSigningService<TOptions>`, and the
same `KeySetOptions`/`KeySourceOptions` hierarchy. If your organisation needs a signing provider
these don't cover — a different KMS, an HSM, an internal secrets service — you build it the same
way.

This guide walks through that options hierarchy, shows a minimal worked example for each options
type, and then walks through Azure Key Vault's own implementation as the pattern to copy if your
provider needs to enforce a timing invariant of its own.

## Before you start

- You are implementing `IJwtSigningService` by deriving from `JwtSigningService<TOptions>` — not
  implementing `IJwtSigningService` directly. The base class supplies interval-throttled caching
  (`KeySourceOptions` only) or a one-time build (`KeySetOptions`), single-flight coalescing of that
  build/refresh for both, activation-timeline selection, kill-by-omission handling, key/algorithm
  compatibility validation, and deterministic disposal of superseded signers; you implement only
  `ListKeysAsync` and `CreateSignerAsync`.
- You understand the retirement-window and publish-then-activate model shared by every provider —
  see [Rotate signing keys](rotate-signing-keys.md) first if you haven't already. This guide covers
  the *options shapes* and *methods* a provider implements, not the rotation model itself.
- For the full contract and rationale behind the split below, see
  [ADR 0011](../decisions/0011-signing-key-management.md). This guide is deliberately
  practical — it shows you what to derive from and what to copy, not why each invariant exists.

## Which options type do I implement?

Ask one question:

> **Do you own the full list of keys up front? Derive from `KeySetOptions`.**
> **Does something else own the keys and you re-read them? Derive from `KeySourceOptions`.**

| Your key source | Options type | Why |
|---|---|---|
| Generated once at startup, held in memory | `KeySetOptions` | Nothing to poll — the key set is fixed for the process lifetime, and the only thing that ever advances is the wall clock crossing each key's `ActivateAt`. |
| A file, PFX, or certificate-store registration that is only ever replaced via a redeploy/restart | `KeySetOptions` | Same reasoning — the set is fixed at configuration time; there is nothing to re-read at runtime. |
| A KMS/HSM/secrets service with its own rotation schedule | `KeySourceOptions` | The key list can genuinely change between calls; you need to re-ask on a cadence. |
| A database table, or a directory of files an operator can add to live (a file-glob that discovers new files at runtime) | `KeySourceOptions` | Same — an external actor can change the trusted set without restarting your process. |

Picking the wrong options type is not a silent bug: `JwtSigningService<TOptions>`'s constructor
inspects the runtime type of your options instance (`options.Value is KeySetOptions` vs
`options.Value is KeySourceOptions`) to decide whether to ever re-invoke `ListKeysAsync` at all —
deriving from the wrong one changes *whether reload ever happens*, not just a default value.

## The options hierarchy

Every provider's options type derives from one of two base classes, both of which in turn derive
from a common, effectively empty base:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningServiceOptions
{
    // No rotation-shaped property at all. Deliberately empty — every rotation-related
    // knob lives on exactly one of the two option types below, never on the shared base.
}

public abstract class KeySetOptions : JwtSigningServiceOptions
{
    // The operator owns activation timing via each key's ActivateAt; PublicationLead is
    // advisory only here — the base class only logs a startup warning if it's violated.
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}

public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    // Defaults to RefreshInterval when left unset; must be >= RefreshInterval.
    public TimeSpan PublicationLead { get; set; }
}
```

### `JwtSigningServiceOptions` — the shared base

You never derive from this directly. It exists purely so `JwtSigningService<TOptions>` can be
written once against a single constraint (`where TOptions : JwtSigningServiceOptions`) and still
treat `KeySetOptions` and `KeySourceOptions` providers differently at construction time — see
[Which options type do I implement?](#which-options-type-do-i-implement) above.

### `KeySetOptions` — a fixed set known up front

Derive from this when your key source's complete, fixed set is supplied at configuration time
and never changes at runtime — the only thing that ever advances is the wall clock crossing each
key's `ActivateAt`. `ListKeysAsync` is called **exactly once, ever**; the base class builds one
immutable snapshot and never rebuilds it. `PemFileSigningOptions`, `PfxFileSigningOptions`, and
`WindowsCertificateStoreSigningOptions` are the shipped examples; development/in-memory signing is
a trivial degenerate case (one key, no `ActivateAt`, active from startup).

### `KeySourceOptions` — a source you re-read on a cadence

Derive from this when something else owns the key list and it can genuinely change between
calls — a KMS, an HSM, a database table, or a file-glob that discovers new files at runtime.
`ListKeysAsync` is re-invoked once per `RefreshInterval`, coalescing concurrent callers behind a
single-flight gate so a burst of signing or JWKS requests never fans out into multiple simultaneous
reads. Both Azure Key Vault providers (remote and cached) derive from this options type.

## Implementing the base class's two abstract methods

Regardless of options type, you implement exactly two methods:

```csharp
protected abstract ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

protected abstract ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);
```

- **`ListKeysAsync`** returns every currently trusted key as pure public metadata — a `KeyListing`
  per key, carrying your provider's own stable `KeyId`, the `SigningAlgorithm`, the public-only
  `PublicKeyParameters`, an `ActivateAt` (or `null`/a past instant for "eligible from startup"),
  and a hard `ExpiresAt`. Never return private key material here, and never return an empty or
  short list if your read was incomplete — throw instead (see
  [the completeness contract](#the-completeness-contract-fail-closed-on-a-partial-read) below).
- **`CreateSignerAsync`** is called by the base class only for the one `KeyId` it has already
  computed as the active signer — never for a non-active, future, or retired key. It returns an
  `ISigner` for that key. A local provider (file, PFX, certificate store, development) builds and
  returns a `LocalSigner` here; a genuinely remote provider (Key Vault remote signing, a KMS, an
  HSM) implements `ISigner` itself, with `SignAsync` making the network call — the private key
  never becomes local for that kind of provider.

The base class does everything else: it derives each key's `kid` from `PublicKeyParameters` via
`JwkThumbprint` (never from your `KeyId`), rejects a listing set with duplicate derived `kid`s
(`signing.duplicate_kid`) or duplicate `KeyId`s (`signing.duplicate_key_id`), runs
algorithm-compatibility and key-strength validation over every listing before ever calling
`CreateSignerAsync`, computes which key is active and which others still belong in the JWKS, and
disposes a superseded `ISigner` once every in-flight `SignAsync` call against it has completed.

**`CreateSignerAsync` must return a freshly created, exclusively owned `ISigner` on every call** —
never a cached or previously-returned instance, even for the same `KeyId`. The base class owns the
returned signer from that point on and disposes it once it is superseded; an instance you hand back
a second time is disposed (or still live and in use) out from under you, and the base class detects
and rejects an exact re-lend of the currently active signer with `signing.signer_reused`. See
[`ISigner`](../reference/signing-keys.md)'s `Dispose` contract.

## Worked example: a minimal KeySourceOptions provider

A provider whose key source is a remote HTTP-backed secrets service, with no timing invariant of
its own beyond the shared poll cadence, needs almost no options code:

```csharp
public sealed class AcmeSecretsSigningOptions : KeySourceOptions
{
    public Uri SecretsServiceUri { get; set; } = null!;

    public SigningAlgorithm Algorithm { get; set; }
}
```

`RefreshInterval` and `PublicationLead` are inherited — you did not write them, and you do not need
to remember to default them. Your service implementation provides `ListKeysAsync` and
`CreateSignerAsync`:

```csharp
internal sealed class AcmeSecretsJwtSigningService : JwtSigningService<AcmeSecretsSigningOptions>
{
    private readonly IOptions<AcmeSecretsSigningOptions> _options;
    private readonly IAcmeSecretsClient _client;

    public AcmeSecretsJwtSigningService(
        IOptions<AcmeSecretsSigningOptions> options,
        IAcmeSecretsClient client,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<AcmeSecretsSigningOptions>> logger)
        : base(options, timeProvider, retirementWindowProvider, logger)
    {
        _options = options;
        _client = client;
    }

    protected override async ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(
        CancellationToken cancellationToken)
    {
        // MUST throw rather than return a short list if this read is incomplete — see
        // "The completeness contract" below. A genuine client-library exception from
        // GetCurrentKeysAsync already satisfies this; do not catch and swallow it here.
        var secrets = await _client.GetCurrentKeysAsync(cancellationToken);

        return secrets
            .Select(secret => new KeyListing(
                new KeyId(secret.SecretVersionId),
                _options.Value.Algorithm,
                PublicKeyParameters.FromRsa(secret.RsaPublicParameters),
                secret.ActivateAt,
                secret.ExpiresAt))
            .ToList();
    }

    protected override async ValueTask<ISigner> CreateSignerAsync(
        KeyId id, CancellationToken cancellationToken)
    {
        var privateKey = await _client.GetPrivateKeyAsync(id.Value, cancellationToken);
        return new LocalSigner(_options.Value.Algorithm, privateKey);
    }
}
```

Because `AcmeSecretsSigningOptions` derives from `KeySourceOptions`, the base class's constructor
reads `RefreshInterval` off it and re-invokes `ListKeysAsync` on that cadence — no extra wiring
required on your part. If this provider introduced no cross-field timing invariant beyond the
shared `PublicationLead`/`RefreshInterval` relationship, you would be done. A provider with a
genuine provider-specific timing invariant needs one more step — the next section walks through it
using Azure Key Vault's actual implementation.

## Worked example: Azure Key Vault's enforced publication lead

Both Azure Key Vault signing options types — `AzureKeyVaultCachedSigningOptions` and
`AzureKeyVaultRemoteSigningOptions` — derive from `KeySourceOptions` and add no extra timing
property of their own: they reuse `PublicationLead` and `RefreshInterval` exactly as defined on the
shared base. What they add instead is *derivation logic* inside `ListKeysAsync` that maps Key
Vault's own durable timestamp onto `KeyListing.ActivateAt` so the shared invariant holds:

```csharp
private static DateTimeOffset? ComputeActivateAt(
    KeyVaultCertificateVersionInfo version, string firstEverVersion, TimeSpan publicationLead)
{
    if (version.Version == firstEverVersion && version.NotBefore is null)
        return null; // eligible from startup — no prior published JWKS state to protect

    var baseline = version.Version == firstEverVersion
        ? version.CreatedOn
        : version.CreatedOn + publicationLead;

    return version.NotBefore is { } notBefore && notBefore > baseline ? notBefore : baseline;
}
```

This is the pattern worth studying: **derive `ActivateAt` from your store's own durable, per-key
timestamp — never from in-memory "when did I first see this key" bookkeeping**, which does not
survive a process restart and is inconsistent across load-balanced replicas. Key Vault's `CreatedOn`
is immutable and identical across every replica that reads the same version; anchoring on it (as
above) is what lets `PublicationLead` mean the same thing no matter which replica computed it or
when it restarted.

### Where `PublicationLead >= RefreshInterval` is enforced, and why in two places

For a `KeySourceOptions` provider, the invariant `PublicationLead >= RefreshInterval` is
checked in exactly two independent places, and a custom provider should rely on both rather than
just one:

**1. The shared validator, called from `IValidateOptions<TOptions>`.** Both Key Vault option
validators call the shared `KeySourcePublicationLeadValidator` rather than duplicating the check:

```csharp
if (KeySourcePublicationLeadValidator.ValidateAtLeastRefreshInterval(
        nameof(AzureKeyVaultCachedSigningOptions), options) is { } leadVsRefreshError)
{
    errors.Add(leadVsRefreshError);
}
```

Each validator's `Validate(string?, TOptions)` adds this to its aggregated error list alongside
every other option check, so a misconfigured host fails fast at `ValidateOnStart()` with every
problem reported at once, in a message written for the person configuring the app.

**2. An independent, unbypassable guard on `KeySourceOptions.PublicationLead` itself.** The
property getter re-checks the invariant every time it is read (not only at options-bind time):

```csharp
public TimeSpan PublicationLead
{
    get
    {
        var effective = _publicationLead ?? RefreshInterval;

        if (_publicationLead is { } explicitLead && explicitLead < RefreshInterval)
            throw new ZeeKayDaConfigurationException(/* ... */);

        return effective;
    }
    set => _publicationLead = value;
}
```

**Neither guard alone is sufficient — each closes a gap the other leaves open:**

- **The validator alone is not enough** because it can be bypassed. `IValidateOptions<TOptions>`
  only runs when the options are bound and validated through the standard `AddOptions<TOptions>()`
  / `ValidateOnStart()` pipeline. A test, a hand-rolled DI registration, or any code path that
  constructs the options type directly and hands it straight to `ListKeysAsync` never invokes the
  validator at all — the invalid value would sail through silently.
- **The property guard alone is not enough**, in the other direction. If it were the *only*
  enforcement point, an invalid configuration would not be rejected until the value is actually
  read — inside `ListKeysAsync`, well after startup — and it would surface as a low-level,
  un-aggregated `ZeeKayDaConfigurationException`, mixed in with none of the app's other
  configuration problems and none of the friendlier, aggregated messaging the `IValidateOptions`
  path gives every other option error.

Together, the validator gives you **fail-fast, friendly, aggregated** startup errors for the common
case (a real host, wired up normally), and the property guard gives you **unbypassable
defense-in-depth** for every other code path that can reach `ListKeysAsync`. Drop either one and
you lose exactly the property the other was providing.

> 💡 **Tip:** `KeySourcePublicationLeadValidator` (`ZeeKayDa.Auth.Tokens`) is public specifically so
> your own `IValidateOptions<TOptions>` implementation can call it directly instead of re-writing
> the same check. There is no equivalent internal type to copy for the property-guard half — write
> your own small `PublicationLead` override shaped the same way as the snippet above if your
> options type does not already inherit one from `KeySourceOptions`.

## The completeness contract: fail closed on a partial read

`ListKeysAsync` carries a completeness contract (ADR 0011's kill-by-omission decision): a provider that cannot produce a
*complete* read of its current key set **must throw**, never return a short or partial list. This
matters because the base class treats an *omitted* key as **revoked** — see
[Rotate signing keys: emergency revocation](rotate-signing-keys.md#emergency-key-rotation) for the
full kill-by-omission model. If your provider's read silently drops keys during a transient store
outage instead of throwing, those keys look identically revoked from the base class's perspective,
even though nothing was actually deleted from your backing store.

A key that legitimately stops appearing in a **complete** read while still inside its retirement
window is still dropped from the JWKS immediately, but the base class logs a `Warning` rather than
staying silent — that is the accidental-early-omission detector, and it is not something you need
to implement yourself.

## Least-privilege private material: what "provider obligation" means for a bundled format

The base class only ever calls `CreateSignerAsync` for the one `KeyId` it has selected as active —
this is a structural guarantee, not something your provider has to implement. But for a **bundled
format** — a PFX file, a Windows Certificate Store entry — that yields the *whole* certificate,
private half included, the moment you read it at all, keeping non-active private material out of
process memory until `CreateSignerAsync` is actually called for the active key is **your
provider's own obligation**, not something the base class enforces for you:

- In `ListKeysAsync`, open the bundle, extract only the public parameters into `PublicKeyParameters`,
  and let the loaded private key go out of scope (and be collected/disposed) without stashing it
  anywhere the object outlives that call.
- In `CreateSignerAsync`, re-open the bundle for the one `KeyId` you were asked for, and hand the
  private key off to a `LocalSigner` — which takes ownership and disposes it when superseded.

A provider over a source that is naturally public-only until asked (Key Vault: the public key comes
from a separate, cheap read; the private half is a distinct, explicit download) gets this property
for free. A provider over a bundled format has to be deliberate about not caching the private half
between the two calls.

## Common mistakes

- **Deriving from `JwtSigningServiceOptions` directly instead of one of the two tiers.** This
  compiles (the constraint is `where TOptions : JwtSigningServiceOptions`), but it is never the
  right choice — always derive from `KeySetOptions` or `KeySourceOptions`, so the base class can
  tell which reload behaviour you need.
- **Deriving from `KeySetOptions` for a source that actually changes at runtime.** The base class
  will call `ListKeysAsync` exactly once and never again — a genuinely rotating source will keep
  signing with a stale key set forever, and any warning or fail-closed behaviour your
  `ListKeysAsync` implementation would otherwise raise on a later read will never get the chance to
  run a second time.
- **Returning a short list from `ListKeysAsync` after a partial or failed read**, instead of
  throwing. See [The completeness contract](#the-completeness-contract-fail-closed-on-a-partial-read)
  above — this is indistinguishable from a real revocation once it reaches the base class.
- **Adding your own timing invariant with only one of the two enforcement points.** See
  [Where `PublicationLead >= RefreshInterval` is enforced](#where-publicationlead--refreshinterval-is-enforced-and-why-in-two-places)
  above — a validator alone can be bypassed by direct construction; a property/timeline guard alone
  gives up fail-fast, aggregated startup errors.
- **Deriving your rotation timeline from in-memory state instead of a durable, provider-side
  timestamp.** This breaks on restart (a fresh replica has no history) and is inconsistent across
  multiple replicas of the same process.
- **Retaining private key material for a non-active key across a bundled-format read.** See
  [Least-privilege private material](#least-privilege-private-material-what-provider-obligation-means-for-a-bundled-format)
  above.
- **Caching an `ISigner` and re-lending it from a later `CreateSignerAsync` call.** The base class
  owns and disposes the signer it is handed; returning the same instance again — even for the same
  `KeyId` — either throws `signing.signer_reused` or hands back an already-disposed object.
  `CreateSignerAsync` must construct a fresh, exclusively owned `ISigner` every time it is called.

## See also

- [Rotate signing keys](rotate-signing-keys.md) — the retirement-window, publish-then-activate, and
  emergency-revocation model every provider shares.
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) — the shipped provider
  this guide's worked examples are drawn from.
- [Configure file-based signing](configure-file-based-signing.md) and
  [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md) —
  the shipped `KeySetOptions` examples.
- [Signing keys reference](../reference/signing-keys.md) — the full `IJwtSigningService` /
  `JwtSigningService<TOptions>` / `KeyListing` / `ISigner` contract this guide builds on.
- [ADR 0011: Signing Key Management and the Provider Contract](../decisions/0011-signing-key-management.md) —
  the full design rationale for the options hierarchy and the data-not-objects provider contract.
