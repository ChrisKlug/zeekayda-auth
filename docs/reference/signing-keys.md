---
title: "Signing keys"
description: "Reference for the JWT signing key abstraction in ZeeKayDa.Auth: IJwtSigningService, the options base class, and the JWKS endpoint."
parent: "Reference"
nav_order: 6
---

*Added in Unreleased.*

ZeeKayDa.Auth signs every ID token — and, in future, every JWT access token — with a private key
that a provider you register supplies. The provider also exposes the corresponding public keys so
relying parties can validate those signatures via the JWKS (JSON Web Key Set) endpoint.

The core guarantee behind this abstraction is simple to state and load-bearing everywhere else in
the design: **private key material never leaves the signing component**, and **callers never
choose a key or algorithm**. The token pipeline hands the signing service a payload and gets back a
finished signature; it never touches a key, never decides which key is active, and never assembles
a JWS header by hand. This is what makes remote signing (a cloud KMS or HSM) a non-breaking future
shape rather than a redesign — see [`IJwtSigningService`](#ijwtsigningservice) below.

Exactly one signing provider may be registered per application. For setup instructions, see the
how-to guide for the provider you want:

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

**`GetSigningKeysAsync`** returns every currently trusted signing key — the active key plus any
keys still inside their retirement/overlap window. It excludes fully retired keys and
not-yet-activated keys. This is exactly the set that must appear in the JWKS
([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)).

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
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider) { }

    protected abstract ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
        SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken);
}
```

**Implementors write exactly one method: `LoadKeysAsync`.** It returns a `SigningKeySet` — the
current trusted set, in whatever form the provider holds its keys. The base class does the rest:

- **Interval-throttled caching**, driven by an injected `TimeProvider` (never wall-clock reads).
  `LoadKeysAsync` is called at most once per `KeySourceRefreshInterval`, or exactly once ever if
  `KeySourceRefreshInterval` is `null` (static-source mode).
- **Single-flight refresh.** When the cache expires, concurrent callers are coalesced into one
  `LoadKeysAsync` call rather than each triggering their own — this applies equally on the signing
  hot path and on JWKS reads (see [The JWKS endpoint](#the-jwks-endpoint) below), so a burst of
  requests against a cold cache can never thunder-herd a remote key source.
- **The crypto call itself.** Header construction, active-key selection, and `kid`/`alg` assignment
  always happen in a non-overridable path, so they can never drift out of sync with the actual
  signature. The one overridable step is `SignInputAsync` — a `protected virtual` hook whose
  default body signs locally and synchronously with the active key's `RSA`/`ECDsa` instance.
  Override it only if producing the signature requires network I/O, such as a call to a remote
  KMS or HSM; local file/store-backed providers get correct behavior from the default body and
  never need to override it.
- **Deterministic disposal of superseded private key material.** When the cache refreshes, the
  base class disposes the previous `SigningKeySet`'s private-key objects once every in-flight
  `SignAsync` call that still references them has completed — it never leaves private key handles
  to the garbage collector.

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

*The constructor shape changed in Unreleased (issue #355).* The active signing key is now a
**mandatory named parameter**, not inferred from list position. Earlier builds took a single
positional `IReadOnlyList<SigningKeyPair>` and treated its first entry as active by convention — a
convention enforced nowhere, so a custom `LoadKeysAsync` override that assembled its key list in a
different order could silently sign every token with a retired or not-yet-active key, while the
JWKS still published every key correctly and a happy-path test still passed. Construct a set like
this:

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

## `JwtSigningServiceOptions`

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningServiceOptions
{
    public TimeSpan? KeySourceRefreshInterval { get; set; } = TimeSpan.FromMinutes(5);
}
```

`KeySourceRefreshInterval` is the only property on the base options type. Every provider-specific
options type (`DevelopmentSigningKeyOptions`, `AzureKeyVaultRemoteSigningOptions`,
`AzureKeyVaultCachedSigningOptions`, `WindowsCertificateStoreSigningOptions`,
`PemFileSigningOptions`, `PfxFileSigningOptions`) derives from it and may add its own properties.

`KeySourceRefreshInterval` is nullable: a non-null value is the finite poll cadence described
below, and `null` means "load once via `LoadKeysAsync`, never reload" — a named static-source mode
for an immutable key source, not a sentinel value. `DevelopmentSigningKeyOptions` defaults this to
`null`, since a locally-generated or file-persisted development key never changes at runtime.

> 💡 **Tip:** `KeySourceRefreshInterval` means something different depending on the provider. For a
> remote provider such as Azure Key Vault, it is the re-download cadence *and* the
> publish-then-activate lead time a rotated-in key must be visible for before it can become the
> active signer. For a local file or certificate-store provider, there is nothing remote to
> re-poll; the interval instead governs a startup-warning threshold for pending key rotations (see
> [Rotate signing keys](../how-to/rotate-signing-keys.md)). This nuance is covered in full, with
> concrete values, in each provider's how-to guide.

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

> ⚠️ **Warning:** The full JWKS document provider described above is still in progress
> (tracked by issue #188). Until it ships, `connect/jwks` returns `501 Not Implemented`. The
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
- **`SigningKeyDescriptorFactory`** — builds a validated `SigningKeyDescriptor` from raw RSA/EC
  public key material.
- **`JwkThumbprint`** — derives a non-leaking `kid` from public key parameters.

These three types exist specifically because a genuine third-party provider lives in its own NuGet
package and cannot use `InternalsVisibleTo` to share ZeeKayDa's internal logic — the same reasoning
that keeps `IJwtSigningService` itself free of any Microsoft.IdentityModel or provider-specific
type.

> ⚠️ **Warning:** Every call to `LoadKeysAsync` must return a genuinely new `SigningKeySet`
> wrapping genuinely new private-key objects. Neither of the following is permitted, and both are
> enforced at runtime immediately after `LoadKeysAsync` returns, before the previous set is disposed
> or the new one installed:
>
> - Returning the **same `SigningKeySet` instance** twice.
> - Returning a **genuinely new** `SigningKeySet` that nonetheless wraps one of the previous set's
>   private-key objects under a shared `kid` *(added in Unreleased, issue #361)* — for example,
>   memoising a private key object across calls to avoid re-creating it.
>
> Both mistakes throw an `InvalidOperationException` right away, with a message distinguishing
> which case was hit. Without either guard, the base class would go on to dispose the superseded
> set's private-key objects as normal, and the next signing/JWKS call against the still-current set
> would fail with a confusing, disconnected `ObjectDisposedException` instead. If nothing has
> actually changed since the last refresh cycle, override `HasKeySetChangedAsync` to report that —
> don't try to signal "unchanged" by returning the same (or an equivalent) `SigningKeySet`.

---

## Related pages

- [Configure development signing keys](../how-to/configure-development-signing-keys.md)
- [Configure Azure Key Vault signing](../how-to/configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](../how-to/configure-windows-certificate-store-signing.md)
- [Configure file-based signing](../how-to/configure-file-based-signing.md)
- [Rotate signing keys](../how-to/rotate-signing-keys.md)
- [AuthorizationServerOptions reference](configuration.md) — including `JwksEndpoint.Uri`
- [Discovery endpoint](discovery-endpoint.md) — publishes `jwks_uri` and `id_token_signing_alg_values_supported`
- [ADR 0011 — Signing Key Management](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0011-signing-key-management.md) (design rationale, `RetirementWindow` derivation, rotation model)
