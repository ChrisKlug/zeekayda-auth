---
title: "Signing keys"
description: "Reference for the JWT signing key abstraction in ZeeKayDa.Auth: IJwtSigningService, the options base class, and the JWKS endpoint."
parent: "Reference"
nav_order: 6
---

*Added in Unreleased.*

ZeeKayDa.Auth signs its tokens with a private key that a provider you register supplies. The
provider also exposes the corresponding public keys so relying parties can validate those
signatures via the JWKS (JSON Web Key Set) endpoint.

> 💡 **Tip:** ZeeKayDa.Auth is pre-alpha. Everything on this page — `IJwtSigningService`, every
> built-in provider, the JWKS document shape — is fully implemented and tested today. What is not
> yet implemented is `connect/token` itself, so no ID token or access token is actually issued to a
> client through this pipeline yet; see
> [Pre-alpha advertised endpoints](discovery-endpoint.md#pre-alpha-advertised-endpoints).

The core guarantee behind this abstraction is simple to state and load-bearing everywhere else in
the design: **private key material never leaves the signing component**, and **callers never
choose a key or algorithm**. The token pipeline hands the signing service a payload and gets back a
finished signature; it never touches a key, never decides which key is active, and never assembles
a JWS header by hand. This is what already lets remote signing — where the private key never
enters the process, such as [Azure Key Vault remote signing](../how-to/configure-azure-key-vault-signing.md)
— plug in as a provider like any other, and lets a third-party KMS or HSM provider do the same
without a redesign — see [`IJwtSigningService`](#ijwtsigningservice) below.

Exactly one signing provider may be registered per application. If you have not picked a provider
yet, start with [Configure signing keys: choosing a provider](../how-to/configure-signing-keys.md)
for a decision table comparing all of them. Otherwise, go straight to the how-to guide for the
provider you want:

- [Configure signing keys: choosing a provider](../how-to/configure-signing-keys.md) — start here if you haven't picked a provider yet
- [Configure development signing keys](../how-to/configure-development-signing-keys.md)
- [Configure Azure Key Vault signing](../how-to/configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](../how-to/configure-windows-certificate-store-signing.md)
- [Configure file-based signing](../how-to/configure-file-based-signing.md)
- [Rotate signing keys](../how-to/rotate-signing-keys.md)

This page documents the abstraction itself: the interface every provider implements, the optional
base class most provider authors should build on, the shared descriptor and result types, `kid`
derivation, and the JWKS endpoint they feed.

---

## `IJwtSigningService`

`IJwtSigningService` (`ZeeKayDa.Auth.Tokens`) is the single interface every signing provider
implements. It has exactly two methods:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public interface IJwtSigningService
{
    ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
        CancellationToken cancellationToken = default);

    ValueTask<SigningResult> SignAsync(
        ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default);
}
```

**`GetSigningKeysAsync`** returns every currently trusted signing key — the active key, any
not-yet-activated key already published ahead of its own activation (the publish-then-activate
lead time described below), and any retired key still inside its retirement/overlap window. It
excludes only fully retired keys — those whose retirement window has elapsed. This is exactly the
set that must appear in the JWKS ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)).

**`SignAsync`** takes the base64url-encoded payload segment — you never pass raw claims bytes or a
key selector — and returns a [`SigningResult`](#signingkeydescriptor--signingresult) with the
pre-encoded header and signature segments, ready to be joined into a compact JWS
(`header "." payload "." signature`). Internally, the service picks the active key, builds the JWS
header (`{"alg":"…","kid":"…","typ":"JWT"}` per
[RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) and
[RFC 7519 §5.1](https://www.rfc-editor.org/rfc/rfc7519#section-5.1)), forms the signing input, and
signs — all in one call. Because key selection and header construction happen in the same
operation that produces the signature, the header's `kid`/`alg` and the key that actually signed
are always consistent by construction: there is no window in which a rotation could make a token's
header disagree with the key used to sign it.

> 💡 **Tip:** `alg: none` is not representable anywhere in this pipeline — `SigningAlgorithm` has
> no `none` member. There is no code path through which ZeeKayDa.Auth can issue an unsigned token.

**Why there is no `VerifyAsync`.** This interface is for *issuing* signatures. Verifying inbound
client signatures (`private_key_jwt` client assertions, signed request objects) is a distinct
concern with a distinct trust model — it validates *client*-owned keys, not the server's own keys —
and is a separate future seam. Combining the two would conflate "sign with my key" and "verify with
someone else's key" on one interface.

**Why there is no `RotateAsync`.** Rotation is not part of the public contract. A provider backed
by a managed KMS rotates on the KMS's own schedule; a provider backed by a certificate store
rotates when an operator deploys a new certificate. ZeeKayDa.Auth is a *reader* of the currently
trusted key set, not a rotation authority — imposing a rotation method on every implementor would
force providers that do not own their own rotation lifecycle to fake one.

---

## `JwtSigningService<TOptions>`

Most provider authors should not implement `IJwtSigningService` directly. `JwtSigningService<TOptions>`
(`ZeeKayDa.Auth.Tokens`) is an optional abstract base class that implements the interface for you:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningService<TOptions> : IJwtSigningService, IAsyncDisposable
    where TOptions : JwtSigningServiceOptions
{
    // ADR 0015 (KeySetOptions/KeySourceOptions) — every built-in provider today.
    protected JwtSigningService(
        IOptions<TOptions> options,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<TOptions>> logger) { }

    protected virtual ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

    protected virtual ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);

    // ADR 0011 (StaticKeySourceOptions/RotatingKeySourceOptions) — no built-in provider left; see the tip below.
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider) { }

    protected virtual ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    protected virtual ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken);

    protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
        SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken);
}
```

**Every built-in provider today implements `ListKeysAsync`/`CreateSignerAsync` (ADR 0015's
`KeySetOptions`/`KeySourceOptions` contract) rather than the older `LoadKeysAsync`/`SigningKeySet`
contract described further below.** `ListKeysAsync` returns the currently trusted set as
`KeyListing`s — descriptor material plus an activation/expiry window — and `CreateSignerAsync` is
called lazily, only for the `KeyId` the base class has determined is currently active, to obtain
an `ISigner` capable of producing that one key's signatures. The base class does the rest:

- **Interval-throttled caching**, driven by an injected `TimeProvider` (never wall-clock reads).
  `ListKeysAsync` is called at most once per `KeySourceOptions.RefreshInterval` for a
  `KeySourceOptions` (Tier B) provider — Azure Key Vault, remote or cached, is the only production
  consumer today — or exactly once ever for a `KeySetOptions` (Tier A) provider (Windows
  Certificate Store, file-based PEM/PFX).
- **Single-flight refresh.** When the cache expires, concurrent callers are coalesced into one
  `ListKeysAsync` call rather than each triggering their own — this applies equally on the signing
  hot path and on JWKS reads (see [The JWKS endpoint](#the-jwks-endpoint) below), so a burst of
  requests against a cold cache can never thunder-herd a remote key source.
- **Activation-timeline selection and kill-by-omission.** Which `KeyId` is the active signer, which
  others still belong in the JWKS, and whether a previously-published key vanishing from a fresh
  `ListKeysAsync` result early (before its retirement window elapsed) must be logged as a
  `Warning` are all decided by the base class from the listings alone — a provider never computes
  any of this itself. See [Rotate signing keys](../how-to/rotate-signing-keys.md) for the full
  activation/retirement timing model, and ADR 0015 §6 for kill-by-omission specifically.
- **The crypto call itself.** Header construction, active-key selection, and `kid`/`alg` assignment
  always happen in a non-overridable path, so they can never drift out of sync with the actual
  signature. `CreateSignerAsync`'s returned `ISigner.SignAsync` is the one overridable step that
  actually produces bytes — a remote-signing provider (Azure Key Vault remote signing) implements
  it as a network round trip that never materializes the private key locally; a cached/local
  provider implements it by signing synchronously against an in-process private key.
- **Deterministic disposal of superseded signer resources.** When the active key changes, the base
  class disposes the superseded `ISigner` once every in-flight `SignAsync` call that still
  references it has completed — it never leaves a signer (or the private key material it may hold)
  to the garbage collector. See [`ISigner`'s own `Dispose` contract](#signingkeyset-and-signingkeypair)
  for what this means for a *shared* signer seam (e.g. Key Vault remote signing's pooled
  `CryptographyClient`), which must remain a deliberate no-op instead.

> 💡 **Tip:** An older `LoadKeysAsync`/`SigningKeySet`/`HasKeySetChangedAsync` contract still exists
> on the base class (see [`SigningKeySet` and `SigningKeyPair`](#signingkeyset-and-signingkeypair)
> and [`JwtSigningServiceOptions` and the tier hierarchy](#jwtsigningserviceoptions-and-the-tier-hierarchy)
> below) but is no longer implemented by any built-in provider — the two Azure Key Vault providers
> were the last consumers, and both migrated to `ListKeysAsync`/`CreateSignerAsync` as part of
> issue #425. It is retained for now rather than removed outright; issue #428 tracks its eventual
> deletion once nothing depends on it.

---

## `SigningKeySet` and `SigningKeyPair`

`SigningKeySet` (`ZeeKayDa.Auth.Tokens`) is the type `LoadKeysAsync` returns: the currently trusted
set of keys, together with the private key material needed to sign.

```csharp
namespace ZeeKayDa.Auth.Tokens;

public readonly struct SigningKeyPair
{
    public SigningKeyDescriptor Descriptor { get; init; }
    public AsymmetricAlgorithm PrivateKey { get; init; }
}

public sealed class SigningKeySet : IDisposable
{
    public SigningKeySet(SigningKeyPair activeKey, IEnumerable<SigningKeyPair>? additionalKeys = null);

    public IReadOnlyList<SigningKeyDescriptor> Keys { get; }
    public SigningKeyDescriptor ActiveKey { get; }
}
```

The active signing key is a **mandatory named parameter**, not inferred from list position — a
custom `LoadKeysAsync` override can never silently sign with a retired or not-yet-active key by
assembling its key list in the wrong order. Construct a set like this:

```csharp
var activeKey = new SigningKeyPair { Descriptor = activeDescriptor, PrivateKey = activeRsa };
var retiredKey = new SigningKeyPair { Descriptor = retiredDescriptor, PrivateKey = retiredRsa };

var keySet = new SigningKeySet(activeKey, additionalKeys: [retiredKey]);
```

`additionalKeys` is deliberately a single, lifecycle-neutral bucket — it covers both
not-yet-activated keys and keys still inside their retirement window, not two separate "future" and
"retired" lists. May be `null` or empty. `Keys` (and therefore the JWKS) still happens to list the
active key first, for a zero-allocation hot path and stable output order, but that ordering is an
implementation detail: `ActiveKey` always derives from the constructor's `activeKey` parameter,
never from `Keys[0]`. Duplicate `kid` values between `activeKey` and `additionalKeys` are not
rejected by the constructor; that validation stays at the base class's load path.

> ⚠️ **Warning:** `SigningKeyPair.PrivateKey` is not guaranteed to hold genuine private key
> material. A remote-signing provider (Azure Key Vault, for example) never releases a key's private
> half at all — `PrivateKey` instead holds a public-only key handle, used only to validate
> algorithm/key-type compatibility at load time. That kind of provider's `SignInputAsync` override
> signs via the remote API using the key's descriptor and never reads `PrivateKey`. If you write a
> custom provider, do not assume `PrivateKey` is safe to sign with directly unless you know your own
> provider populated it with genuine private key material.

---

## `JwtSigningServiceOptions` and the tier hierarchy

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningServiceOptions
{
}

public abstract class KeySetOptions : JwtSigningServiceOptions
{
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}

public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan PublicationLead { get; set; } // Defaults to RefreshInterval when unset.
}
```

`JwtSigningServiceOptions` itself carries no rotation-shaped property at all — every provider's
options type derives from one of the two ADR 0015 tiers below it, never directly from the base
type, and which tier it derives from is what determines `ListKeysAsync`'s reload behavior:

- **`KeySetOptions` (Tier A)** — the complete set of registered keys/certificates is fixed at
  configuration time; `ListKeysAsync` is called exactly once, ever. `PemFileSigningOptions`,
  `PfxFileSigningOptions`, and `WindowsCertificateStoreSigningOptions` derive from this tier —
  see [Configure file-based signing](../how-to/configure-file-based-signing.md) and
  [Configure Windows Certificate Store signing](../how-to/configure-windows-certificate-store-signing.md).
- **`KeySourceOptions` (Tier B)** — something else (Key Vault, a database table, a remote store)
  owns the key list and it can genuinely change between calls; `ListKeysAsync` is called at most
  once per `RefreshInterval`. `AzureKeyVaultRemoteSigningOptions` and
  `AzureKeyVaultCachedSigningOptions` derive from this tier — see
  [Configure Azure Key Vault signing](../how-to/configure-azure-key-vault-signing.md).

Both tiers share the same `PublicationLead` meaning — how long before a key's `ActivateAt` its
public half must already have been published, defaulting to one hour either way (on Tier B,
defaulting specifically to `RefreshInterval` if that has been changed from its own default) — but
resolve it differently: Tier A has no poll at all, so `PublicationLead` there is advisory only,
entirely under the operator's control via each certificate's own `NotBefore`; Tier B enforces
`PublicationLead >= RefreshInterval`, since a newly-published key must not be able to activate
before the process would even poll and notice it exists. See
[ADR 0015](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0015-signing-provider-set-source-tiers.md)
for the full contract and [Rotate signing keys](../how-to/rotate-signing-keys.md) for concrete
values per provider.

> ⚠️ **Warning:** For a `KeySourceOptions` (Tier B) provider, `RefreshInterval` is also how quickly
> an emergency revocation (e.g. disabling a compromised Key Vault key version) is noticed — a
> revoked key stops being listed, and therefore stops being trusted, only on the next poll.
> `RefreshInterval` defaults to one hour. If your incident-response plan assumes a revoked key is
> dropped within minutes, set `RefreshInterval` explicitly to a shorter value rather than relying
> on the default.

An earlier design (ADR 0011 §3.4, issue #409) used a different two-tier split — `StaticKeySourceOptions`/
`RotatingKeySourceOptions`, distinguished by whether `LoadKeysAsync`'s result could change at all,
with a `KeyRotationCheckInterval` property (default: 5 minutes) that conflated poll cadence with
publish-then-activate lead time. No built-in provider derives from either of those types any more —
both Azure Key Vault providers were the last consumers and migrated to `KeySourceOptions` as part
of issue #425 — but the base class still supports that older contract for now; issue #428 tracks
its eventual removal.

---

## `SigningKeyDescriptor` / `SigningResult`

**`SigningKeyDescriptor`** carries only what a relying party needs to trust and identify a key —
never rotation state:

| Member | Description |
|---|---|
| `Kid` | The stable key identifier. Never changes for the life of the key. |
| `Algorithm` | The `SigningAlgorithm` this key signs with. |
| `KeyType` | `Rsa` or `Ec`. |
| `RsaPublicParameters` | RSA exponent and modulus (public only) when `KeyType` is `Rsa`; otherwise `null`. |
| `EcPublicParameters` | EC curve and `Q` point (public only) when `KeyType` is `Ec`; otherwise `null`. |

There is deliberately no "is-active" or "retires-at" field: `GetSigningKeysAsync`'s contract is
precisely "the set of keys a relying party should currently trust," and that set is the only thing
the JWKS needs. Rotation bookkeeping stays inside the provider.

**`SigningResult`** is the output of one `SignAsync` call:

| Member | Description |
|---|---|
| `HeaderSegment` | The base64url-encoded JWS header. |
| `SignatureSegment` | The base64url-encoded signature. |
| `Kid` | The key identifier used to sign; matches the header's `kid`. |
| `Algorithm` | The algorithm used to sign; matches the header's `alg`. |

The caller assembles the compact JWS as `HeaderSegment + "." + payloadSegment + "." + SignatureSegment`.

---

## `kid` derivation — `JwkThumbprint`

Every built-in provider derives a key's `kid` from an [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)
JWK thumbprint of its *public* key material, using the public static utility `JwkThumbprint`
(`ZeeKayDa.Auth.Tokens`):

```csharp
public static class JwkThumbprint
{
    public static string Compute(RSAParameters rsaPublicParameters);
    public static string Compute(ECParameters ecPublicParameters);
}
```

A `kid` is always public — it appears in every issued token's header and in the published JWKS —
so it must never leak reconnaissance value about where the key actually lives. A Key Vault resource
URI, an X.509 thumbprint, or a file path would all do exactly that. A thumbprint of the public key
itself carries no such information, is stable for the life of the key, and is interoperable with
external JWK tooling that also implements RFC 7638.

`JwkThumbprint` is public — not an internal helper — specifically so that a genuinely third-party
provider (one that cannot receive `InternalsVisibleTo` access, since that mechanism can only ever
name first-party assemblies at build time) can derive a safe `kid` without hand-rolling RFC 7638
canonicalisation. The related `SigningKeyDescriptorFactory` utility builds a full
`SigningKeyDescriptor` from raw RSA/EC public key material in one call, validating that the
configured algorithm's family matches the key's actual type before doing so.

---

## The JWKS endpoint

ZeeKayDa.Auth exposes the trusted signing key set at `connect/jwks`, matching the `jwks_uri` value
[the discovery document publishes](discovery-endpoint.md) (overridable via
`AuthorizationServerOptions.JwksEndpoint.Uri` — see [`JwksEndpoint`](configuration.md#jwksendpoint)).

By design (ADR 0011 §4.3), the endpoint maps every descriptor returned by the registered
`IJwtSigningService.GetSigningKeysAsync()` to a JWK-set document
([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)), and every emitted JWK carries `"use": "sig"`
so a relying party never mistakes a signing key for an encryption key. The read path shares the
same single-flight cache as the signing path described above: an anonymous burst of requests to
`connect/jwks` cannot trigger an uncoalesced `LoadKeysAsync` call against a remote key source, even
against a cold cache.

> ⚠️ **Warning:** The full JWKS document provider described above is still in progress.
> Until it ships, `connect/jwks` returns `501 Not Implemented`. The
> endpoint path, the discovery `jwks_uri` cross-reference, and the caching/`"use": "sig"` behavior
> documented here are the fixed design (ADR 0011 §4.3) that the shipped endpoint will implement;
> this warning will be removed once it lands.

---

## Registering a provider

Every signing provider registers through a `.AddXxx(...)` extension method on `ZeeKayDaAuthBuilder`,
following the same idiom used elsewhere in ZeeKayDa.Auth (see
[token store registration](token-stores.md#registration-api)). Each such method:

- registers `IJwtSigningService` as a singleton;
- calls the shared `ThrowIfAlreadyRegistered(typeof(IJwtSigningService))` guard, so a second
  signing provider registration fails immediately with `InvalidOperationException` rather than
  silently winning or losing — **only one signing provider may be registered per application**;
- registers the provider's `IValidateOptions<TOptions>` for startup validation.

```csharp
builder.Services
    .AddZeeKayDaAuth(options => { options.Issuer = "https://id.example.com"; })
    .AddInMemoryDevelopmentJwtSigningKeys();
```

See the how-to guide for each provider's exact method signature and required setup:

- [Configure development signing keys](../how-to/configure-development-signing-keys.md) — `.AddInMemoryDevelopmentJwtSigningKeys(...)` / `.AddPersistedDevelopmentJwtSigningKeys(...)`
- [Configure Azure Key Vault signing](../how-to/configure-azure-key-vault-signing.md) — `.AddAzureKeyVaultRemoteSigning(...)` / `.AddAzureKeyVaultCachedSigning(...)`
- [Configure Windows Certificate Store signing](../how-to/configure-windows-certificate-store-signing.md) — `.AddWindowsCertificateStoreSigning(...)`
- [Configure file-based signing](../how-to/configure-file-based-signing.md) — `.AddPemFileSigning(...)` / `.AddPfxFileSigning(...)`
- [Rotate signing keys](../how-to/rotate-signing-keys.md) — registering an overlapping key per provider ahead of a rotation

---

## Extending: writing your own provider

A third-party signing provider — for a KMS or HSM ZeeKayDa.Auth does not ship support for — should
subclass `JwtSigningService<TOptions>` rather than implement `IJwtSigningService` directly. Define a
`TOptions : JwtSigningServiceOptions` for provider-specific settings, implement `LoadKeysAsync` to
return the currently trusted `SigningKeySet`, and override `SignInputAsync` only if producing a
signature requires network I/O.

Use the shared public core utilities rather than reimplementing their logic:

- **`SigningKeyRotation`** — the stateless activation-timeline derivation (which key is active,
  which others are still trusted, whether a pending activation is scheduled too soon) for providers
  that derive their trusted set from a precomputed per-key activation/expiry window.
- **`ISigningKeyRetirementWindowProvider`** — inject this (it's already registered by
  `AddZeeKayDaAuthCore`) to get the current retirement window (see
  [Rotate signing keys](../how-to/rotate-signing-keys.md) for what it means) as a `TimeSpan`,
  derived from token-lifetime configuration. Every built-in
  provider takes this as a constructor dependency and feeds it into `SigningKeyRotation`'s
  inclusion check — do the same rather than hardcoding your own retirement duration.
- **`SigningKeyDescriptorFactory`** — builds a validated `SigningKeyDescriptor` from raw RSA/EC
  public key material.
- **`JwkThumbprint`** — derives a non-leaking `kid` from public key parameters.

These utilities exist specifically because a genuine third-party provider lives in its own NuGet
package and cannot use `InternalsVisibleTo` to share ZeeKayDa's internal logic — the same reasoning
that keeps `IJwtSigningService` itself free of any Microsoft.IdentityModel or provider-specific
type.

> ⚠️ **Warning:** `LoadKeysAsync` is responsible for its own filtering — nothing above it does.
> `GetSigningKeysAsync` (and the JWKS endpoint behind it) returns whatever `SigningKeySet` your
> `LoadKeysAsync` most recently produced, verbatim: the base class does not re-check which keys are
> still within their retirement window, and does not prune a fully-retired key out for you. If your
> `LoadKeysAsync` naively returns every key it has ever seen instead of applying
> `SigningKeyRotation`'s inclusion logic, retired keys accumulate in the JWKS forever rather than
> aging out — silently widening the set of keys a relying party is told to trust, with no error or
> warning to indicate anything is wrong.

> ⚠️ **Warning:** Every call to `LoadKeysAsync` must return a genuinely new `SigningKeySet`
> wrapping genuinely new private-key objects. Neither of the following is permitted, and both are
> enforced at runtime immediately after `LoadKeysAsync` returns, before the previous set is disposed
> or the new one installed:
>
> - Returning the **same `SigningKeySet` instance** twice.
> - Returning a **genuinely new** `SigningKeySet` that nonetheless wraps one of the previous set's
>   private-key objects under a shared `kid` — for example, memoising a private key object across
>   calls to avoid re-creating it.
>
> Both mistakes throw an `InvalidOperationException` right away, with a message distinguishing
> which case was hit. Without either guard, the base class would go on to dispose the superseded
> set's private-key objects as normal, and the next signing/JWKS call against the still-current set
> would fail with a confusing, disconnected `ObjectDisposedException` instead. If nothing has
> actually changed since the last refresh cycle, override `HasKeySetChangedAsync` to report that —
> don't try to signal "unchanged" by returning the same (or an equivalent) `SigningKeySet`.

---

## Related pages

- [Configure signing keys: choosing a provider](../how-to/configure-signing-keys.md) — decision table comparing all providers
- [Configure development signing keys](../how-to/configure-development-signing-keys.md)
- [Configure Azure Key Vault signing](../how-to/configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](../how-to/configure-windows-certificate-store-signing.md)
- [Configure file-based signing](../how-to/configure-file-based-signing.md)
- [Rotate signing keys](../how-to/rotate-signing-keys.md)
- [AuthorizationServerOptions reference](configuration.md) — including `JwksEndpoint.Uri`
- [Discovery endpoint](discovery-endpoint.md) — publishes `jwks_uri` and `id_token_signing_alg_values_supported`
- [ADR 0011 — Signing Key Management](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0011-signing-key-management.md) (design rationale, `RetirementWindow` derivation, rotation model)
