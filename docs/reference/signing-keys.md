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
    protected JwtSigningService(
        IOptions<TOptions> options,
        TimeProvider timeProvider,
        ISigningKeyRetirementWindowProvider retirementWindowProvider,
        ISanitizingLogger<JwtSigningService<TOptions>> logger) { }

    protected abstract ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

    protected abstract ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);
}
```

A provider implements exactly two methods (ADR 0015): **`ListKeysAsync`** returns the currently
trusted set as `KeyListing`s — pure public metadata plus an activation/expiry window, never private
material — and **`CreateSignerAsync`** is called lazily, only for the `KeyId` the base class has
determined is currently active, to obtain an `ISigner` capable of producing that one key's
signatures. The base class does the rest:

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
  to the garbage collector. See [`ISigner`'s own `Dispose` contract](#keylisting-isigner-and-localsigner)
  for what this means for a *shared* signer seam (e.g. Key Vault remote signing's pooled
  `CryptographyClient`), which must remain a deliberate no-op instead.

---

## `KeyListing`, `ISigner`, and `LocalSigner`

`KeyListing` (`ZeeKayDa.Auth.Tokens`) is the type `ListKeysAsync` returns one of, per trusted key —
pure public data, never private material:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public sealed record KeyListing(
    KeyId Id,
    SigningAlgorithm Algorithm,
    PublicKeyParameters PublicKey,
    DateTimeOffset? ActivateAt,
    DateTimeOffset ExpiresAt);

public readonly record struct KeyId(string Value);

public sealed record PublicKeyParameters
{
    public SigningKeyType KeyType { get; }
    public RSAParameters? RsaPublicParameters { get; }
    public ECParameters? EcPublicParameters { get; }

    public static PublicKeyParameters FromRsa(RSAParameters rsaPublicParameters);
    public static PublicKeyParameters FromEc(ECParameters ecPublicParameters);
}
```

| Member | Description |
|---|---|
| `Id` | The provider's own stable identifier for this key — a certificate thumbprint, a Key Vault key-version id, a database row key, and so on. **Not** the JWKS/JWS `kid`: the base class always derives the `kid` itself from `PublicKey` via [`JwkThumbprint`](#kid-derivation--jwkthumbprint), so a provider can never leak a raw external identifier into a token header or the JWKS. |
| `Algorithm` | The `SigningAlgorithm` this key signs with. |
| `PublicKey` | The public-only RSA/EC key material — never the private half. |
| `ActivateAt` | The instant this key becomes eligible to be the active signer, or `null` (or a past instant) when it is eligible from startup/bootstrap. |
| `ExpiresAt` | The hard expiry instant (e.g. a certificate's `NotAfter`) — distinct from the derived retirement window, which the base class computes separately. |

`ListKeysAsync` must never return an empty list, and carries a **completeness contract**: a
provider that cannot produce a *complete* read of its current key set **must throw** rather than
return a short or partial list — see [Kill-by-omission](#kill-by-omission-no-enabled-flag) below
for why a partial read must never be mistaken for a revocation.

`ISigner` (`ZeeKayDa.Auth.Tokens`) is what `CreateSignerAsync` returns — a signer bound to exactly
one key activation:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public interface ISigner : IDisposable
{
    ValueTask<ReadOnlyMemory<byte>> SignAsync(
        ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);

    SigningAlgorithm Algorithm { get; }
}
```

`CreateSignerAsync` is called **only** for the `KeyId` the base class has already selected as
active — never for a non-active, future, or retired key. Immediately after `CreateSignerAsync`
returns, the base class checks `ISigner.Algorithm` against that same key's `KeyListing.Algorithm`
and rejects the signer on any mismatch, so a provider bug can never produce a JWS whose header
names one algorithm while the signature bytes were actually produced under another.

> ⚠️ **Warning:** `ISigner.Dispose` is a normative contract, not advisory prose. The base class
> calls `Dispose` on the previously active `ISigner` every time the active key changes (or at
> shutdown). `Dispose` **must** release only the per-activation handle or resource that specific
> instance introduced. A remote implementation whose `SignAsync` uses a shared, DI-owned SDK client
> (an Azure Key Vault client, say) **must not** tear that shared client down on `Dispose` — doing so
> would break every other `ISigner` instance, and every future caller, that also depends on the same
> shared client.

`LocalSigner` (`ZeeKayDa.Auth.Tokens`) is the shipped `ISigner` implementation over a local,
in-process RSA or ECDsa private key:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public sealed class LocalSigner : ISigner
{
    public LocalSigner(SigningAlgorithm algorithm, AsymmetricAlgorithm privateKey);
}
```

Local providers (development, PEM, PFX, Windows Certificate Store) construct a `LocalSigner` in
`CreateSignerAsync` and never implement `ISigner` themselves — `LocalSigner` takes ownership of
`privateKey` and disposes it unconditionally, which is safe because nothing else ever references
it. Only a genuinely remote provider (Azure Key Vault remote signing, a KMS, an HSM) implements
`ISigner` directly, because the private key never becomes local for those.

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

---

## Kill-by-omission: no `Enabled` flag

There is no `Enabled`/disabled flag anywhere in the options or the provider contract. A key stops
being trusted the moment a `KeySourceOptions` (Tier B) provider's `ListKeysAsync` stops returning
it — omission itself is the kill switch:

- Revoke, disable, or delete the key in the backing store (Key Vault, a database row, …) and the
  provider's next `ListKeysAsync` simply stops listing it; it is gone from the JWKS on the next
  refresh.
- A key vanishing *after* its derived retirement window has already closed is the normal end of
  life and is logged only routinely.
- A key vanishing *while still inside* its retirement window is still dropped immediately (the kill
  switch still fires), but the base class emits a `Warning` — this is the accidental-omission
  detector, and it is never downgraded.
- A provider that cannot produce a complete read of its current key set must throw rather than
  return a short list — `ListKeysAsync`'s completeness contract exists precisely so a transient
  read failure is never misinterpreted as "these keys were revoked."

`KeySetOptions` (Tier A) providers have no equivalent concept: the key set is fixed at
configuration time, so there is nothing to revoke by omission — remove the compromised key from
configuration and redeploy instead. See [Rotate signing keys](../how-to/rotate-signing-keys.md) for
the emergency-rotation procedure for each tier.

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
`connect/jwks` cannot trigger an uncoalesced `ListKeysAsync` call against a remote key source, even
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
`TOptions` deriving from `KeySetOptions` (Tier A — you own the full list of keys up front) or
`KeySourceOptions` (Tier B — something else owns the keys and you re-read them), implement
`ListKeysAsync` to return the currently trusted `KeyListing`s, and implement `CreateSignerAsync` to
lend an `ISigner` for the active key only. See
[Implement a custom signing key provider](../how-to/implement-custom-signing-provider.md) for a full
worked example and a decision guide for choosing between the two tiers.

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

> ⚠️ **Warning:** `ListKeysAsync` carries a **completeness contract**: it must never return a short
> or partial list. The base class trusts an omission to mean "this key is no longer trusted" (see
> [Kill-by-omission](#kill-by-omission-no-enabled-flag) above) — a provider that cannot enumerate its
> current key set completely (a transient network error, a store outage) **must throw** rather than
> return whatever subset it managed to read. A partial read that is silently treated as a full one
> would look identical to an emergency revocation and could drop keys a relying party still needs to
> validate an already-issued token.

> ⚠️ **Warning:** Keep private material out of `ListKeysAsync` entirely — it returns pure public
> `KeyListing` data, never a key object. This is what makes the base class's least-privilege
> guarantee hold: it only ever asks `CreateSignerAsync` for the one `KeyId` it has selected as
> active, never for a non-active, future, or retired key. For a **bundled format** (a PFX, a
> Windows Certificate Store entry) that yields the whole key when you read it at all, keeping
> non-active private material out of process memory until `CreateSignerAsync` actually asks for the
> active key is a **provider obligation** — extract only the public parameters in `ListKeysAsync`
> and defer opening the private half until `CreateSignerAsync` is called for that specific key.

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
- [ADR 0015 — Signing-Key Provider: KeySet/KeySource Tiers](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0015-signing-provider-set-source-tiers.md) (the current `KeySetOptions`/`KeySourceOptions` contract this page documents)
