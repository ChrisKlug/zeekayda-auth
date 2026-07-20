---
title: "Configure signing keys: choosing a provider"
description: "A decision guide to picking a JWT signing key provider in ZeeKayDa.Auth, and the concepts every provider shares."
parent: "How-to Guides"
nav_order: 7
---

*Added in Unreleased.*

ZeeKayDa.Auth needs an `IJwtSigningService` registered before it can start. Several packages each
ship one or more registration methods that satisfy that requirement, and they are built for
different situations — local development, a cloud key vault, an existing on-host certificate
store, or a plain key file. This page helps you pick the right one before you read that provider's
full how-to guide.

> ⚠️ **Warning:** Exactly one signing provider may be registered per application. Every
> registration method calls a shared `ThrowIfAlreadyRegistered(typeof(IJwtSigningService))` guard,
> so registering a second provider — or calling the same provider's method twice — fails
> immediately with `InvalidOperationException` rather than silently overwriting the first
> registration. Decide on one provider per environment (you can use a different one in development
> than in production) and register only that one.

## Which provider do you need?

| Provider | Intended for | Platform constraints | Where the private key lives / signing happens | Auto-rotation | Setup complexity |
|---|---|---|---|---|---|
| [Development, in-memory](configure-development-signing-keys.md) (`AddInMemoryDevelopmentJwtSigningKeys`) | Local development only — blocked outside `Development` by an environment gate | Cross-platform | Generated fresh in process memory on every startup; never written to disk | None — a new key replaces the old one on every restart | Zero-config |
| [Development, persisted](configure-development-signing-keys.md) (`AddPersistedDevelopmentJwtSigningKeys`) | Local development only — same environment gate | Cross-platform | Generated once, then persisted to a local unencrypted PEM file and reloaded on later startups | None — the same key is reused until the file is deleted | Zero-config (default path), or minimal (custom `persistTo`) |
| [Azure Key Vault, remote signing](configure-azure-key-vault-signing.md) (`AddAzureKeyVaultRemoteSigning`) | Production, when the private key must never leave the vault/HSM even temporarily | Cross-platform; requires an Azure Key Vault or Managed HSM | Remote only — every signature is produced by a live call into Key Vault; the private key never enters the process | Automatic — the provider discovers new Key Vault key versions itself | Higher — vault provisioning, RBAC role assignment, `TokenCredential` |
| [Azure Key Vault, cached signing](configure-azure-key-vault-signing.md) (`AddAzureKeyVaultCachedSigning`) | Production, when Key Vault latency/throughput/throttling makes local signing necessary | Cross-platform; requires an Azure Key Vault or Managed HSM, and a certificate with an exportable key policy | Downloaded once at startup and cached in process memory; signing happens locally with no per-signature round trip | Automatic — the provider discovers new certificate versions itself | Higher — certificate (not bare key) provisioning with `exportable: true`, RBAC role assignment |
| [Windows Certificate Store](configure-windows-certificate-store-signing.md) (`AddWindowsCertificateStoreSigning`) | Production, when you already manage certificates on Windows hosts | Windows-only — throws `PlatformNotSupportedException` on any other OS, and the package targets a Windows-specific TFM | Loaded from the OS certificate store at startup by thumbprint; signing happens locally, in process | None — fixed at startup; rotation requires registering an additional certificate and restarting | Moderate — thumbprint lookup, private-key ACL grant to the process identity |
| [File-based PEM](configure-file-based-signing.md) (`AddPemFileSigning`) | Production, cross-platform — the recommended choice for macOS hosts, containers, headless CI, and Linux generally | Cross-platform, no platform interop | Loaded from a local unencrypted PEM file at startup; signing happens locally, in process | None — fixed at startup; rotation requires registering an additional file and restarting | Moderate — filesystem permission hardening (`0600`/ACL), no password |
| [File-based PFX](configure-file-based-signing.md) (`AddPfxFileSigning`) | Production, cross-platform, when you want a password as defense in depth or already have a PKCS#12 bundle | Cross-platform, no platform interop | Loaded from a local password-protected PKCS#12 file at startup; signing happens locally, in process | None — fixed at startup; rotation requires registering an additional file and restarting | Moderate to higher — filesystem permission hardening plus a `PasswordSource` delegate |

> 💡 **Tip:** If you are not sure yet and just want the server to start locally, use
> [`AddInMemoryDevelopmentJwtSigningKeys()`](configure-development-signing-keys.md) — it needs no
> arguments and no provisioning step. Come back to this table when you are ready to choose a
> production provider.

## Concepts you'll meet regardless of provider

A few ideas recur across every production provider's how-to guide. This section only sketches
their shape — follow the links for the full explanation.

- **`KeyRotationCheckInterval` is the poll cadence, and a separate property is the
  publish-then-activate lead time.** Every rotating provider has `KeyRotationCheckInterval` (how
  often the base class re-evaluates whether the active/included key set has changed). Azure Key
  Vault also has `SigningKeyActivationDelay`, and the Windows Certificate Store and file-based
  providers have `AssumedJwksPropagationDelay` — the lead time a rotated-in key must be visible for
  before it can become the active signer, defaulting to `KeyRotationCheckInterval` when unset. See
  the tip under
  [`JwtSigningServiceOptions` and the three-tier hierarchy](../reference/signing-keys.md#jwtsigningserviceoptions-and-the-three-tier-hierarchy)
  for the full explanation.
- **The retirement window.** When a key stops being the active signer, its public half stays
  published in the JWKS for a while longer, so relying parties holding tokens signed with it can
  still validate them — but its private half is destroyed immediately. See
  [A retired key's public half stays published for a while — its private half does not](rotate-signing-keys.md#a-retired-keys-public-half-stays-published-for-a-while--its-private-half-does-not).
- **Publish-then-activate.** A new key must be visible in the JWKS for some lead time *before* it
  is promoted to active signer, so a relying party with a cached JWKS never sees a `kid` it has
  never observed. See
  [Publish-then-activate: a new key must be seen before it signs anything](rotate-signing-keys.md#publish-then-activate-a-new-key-must-be-seen-before-it-signs-anything).
- **The bootstrap exception.** If a provider has exactly one key or certificate registered, it is
  the active signer immediately, with no activation delay — there is no prior published JWKS state
  for it to race against. See
  [The bootstrap exception](rotate-signing-keys.md#the-bootstrap-exception).

For the full model that ties these three ideas together, see
[The model, in plain language](rotate-signing-keys.md#the-model-in-plain-language) in
[Rotate signing keys](rotate-signing-keys.md).

## Related pages

- [Configure development signing keys](configure-development-signing-keys.md)
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
- [Configure file-based signing](configure-file-based-signing.md)
- [Rotate signing keys](rotate-signing-keys.md) — the activation/retirement timing model shared
  across all production providers
- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`,
  and how keys are exposed as a JWKS document
