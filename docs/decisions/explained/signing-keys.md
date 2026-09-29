# Signing keys, explained

Explains `signing-keys.md`: where signing keys come from, how the framework decides which key signs,
how tokens get signed without any caller holding a key, and how the public keys reach relying
parties. Principles that apply beyond this part are in `principles.md`.

## What it is for

Every ID token and access token is a JWS signed with a private key. Relying parties verify it with
the public key they fetch from our JWKS endpoint. So two things must always hold: the key that signs
is one relying parties already have, and the private key never leaks, not into a token header, a
log line, or the process when it isn't needed.

## The pieces

**`ISigningKeySource`** is what a provider implements, and it has two methods. `ReadAsync` reports
public keys only. `CreateSignerAsync` lends an `ISigner` for one key, and is the only place a
private key is touched. A source never names a key publicly: it gives its own id (a file path, a
vault version), and the framework derives the `kid` from the public key (RFC 7638 thumbprint), so a
vault URL or file path cannot leak into a token or the JWKS.

**`ISigner`** signs bytes. Local providers (development, PEM, PFX, Windows) return the built-in
`LocalSigner`; only a remote signer (Key Vault remote signing) implements it. The ring owns the
signer and disposes it at shutdown.

**`SigningKeySetBuilder`** runs every reported key through one validation: RSA of at least 2048
bits, NIST curves only, the algorithm fitting the key, .NET's own import rejecting malformed
material, no duplicate ids or `kid`s. Errors name the operator's own id, never the derived `kid`.
Providers never repeat these checks.

**`StaticSigningKeyRing`** reads the source once at startup, builds the key set, opens the signer
and **self-tests** it: it signs 32 fresh random bytes and verifies the signature with the public key
that will be published, under that key's algorithm. A signer whose private key doesn't pair with
the published key, or that signs under a different algorithm, fails the host at startup. Token code
asks the ring to sign through a callback that is told which key will sign, so the header's `kid`
and `alg` always name the key that actually signed.

**The JWKS endpoint** publishes every published key as a JWK, anonymously, with `Cache-Control`
from `JwksEndpointOptions.CacheMaxAge`. Discovery's advertised algorithms come from the same set.

**Providers:** the development key (core; gated to `Development` by default, `Production` always
refused, any other environment opt-in in code and logged Critical), PEM and PFX files
(`ZeeKayDa.Auth.FileSystem`), the Windows certificate store (`ZeeKayDa.Auth.Windows`), and Azure Key
Vault with remote or cached signing (`ZeeKayDa.Auth.AzureKeyVault`). The PFX source parses the
bundle itself so listing a bundle never decrypts its key; the cached Key Vault source downloads a
private key only for the one version that signs.

## What it costs

- Each provider decides for itself which key signs: the file providers through `Previous`/`Current`/
  `Next` slots the operator rotates by hand, Key Vault through its own selector. A provider author
  has to understand key rotation.
- Rotation is restart-based: keys are read once at startup.

## Where it is going

The maintainer walked this part at code level. Each issue is in M1 before the security audit
(#537), and updates this file when it lands.

**The framework owns the timing (#823).** A source only lists its keys, each with one date every
replica agrees on (a certificate's `NotBefore`, a Key Vault version's creation date). Core then:

- publishes every unexpired key;
- signs with the newest key that has been published for the lead time (default 1 day, never shorter
  than `CacheMaxAge`);
- if no key has, signs with the oldest valid one and logs a Warning. That one rule covers a first
  deployment, a normal rotation and an emergency (remove a compromised key, restart) with no
  special cases;
- keeps an old key published until its successor took over plus the longest token lifetime.

Core hands the source a `supersededBefore` date, so Key Vault can skip fetching versions that can
no longer matter; ignoring it is only slower. The Key Vault selector moves into core, the file
providers take a plain list of files, and a certificate becomes a `SourceKey` or a `LocalSigner`
through public helpers. `ISigner.Algorithm` and Key Vault's own pairing check go, because the
self-test already proves both. The health check reports whether a successor is ready in time and
when a restart would rotate. Live rotation stays #527.

**Registration (#824).** A provider registers through `builder.AddSigningKeySource<T>()` on the
builder, with one "already registered" check; the factory overload and two exotic re-checks go.

**Development keys (#825, #826).** The environment gate fails closed when the environment is
unknown; one options type with `AllowedEnvironments`; names that match the other providers
(`AddInMemoryDevelopmentSigning()`). Key storage uses .NET's built-in permission APIs only; the
native ancestor-ownership walk is dropped for development keys and its interop moves to the
FileSystem provider, which protects production keys with it.

**Provider tests.** The builder and the ring become internal; our own provider test projects reach
them through `InternalsVisibleTo`. A TestKit helper for third-party provider authors waits until
after M1.

## What was rejected

- **A setting to pin the signing key for emergencies.** Removing the compromised key and restarting
  does it, and the fallback rule signs with the replacement at once.
- **A lead time of 0 as the emergency lever,** and a "first version" exemption: both are special
  cases the fallback rule makes unnecessary.
- **A fixed age cut-off for loading old versions.** It would drop a key that has signed for longer
  than the cut-off; the cut-off core derives cannot.
- **Keeping the full ancestor-ownership walk for development keys.** Neither Duende IdentityServer
  nor OpenIddict checks development-key permissions at all, or gates on environment; we keep the
  gate and the file checks, and drop the part only a shared multi-user machine needs.
