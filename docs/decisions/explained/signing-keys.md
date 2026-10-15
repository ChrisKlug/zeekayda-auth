# Signing keys, explained

Explains `signing-keys.md`: where signing keys come from, how the framework decides which key signs,
how tokens get signed without any caller holding a key, and how the public keys reach relying
parties. Principles that apply beyond this part are in `principles.md`.

## What it is for

Every ID token and access token is a JWS signed with a private key. Relying parties verify it with
the public key they fetch from our JWKS endpoint. So two things must hold: the key that signs should
be one relying parties already have, and the private key never leaks, not into a token header, a
log line, or the process when it isn't needed.

## The pieces

**`ISigningKeySource`** is what a provider implements. It declares one `Algorithm`, which every key
it lists signs under. `ReadAsync` lists public keys only, each with its dates, plus a failure for
each entry it could not list, so one broken entry cannot block a revocation. `CreateSignerAsync`
lends an `ISigner` for one key, and is where a private key is put to use. Listing touches one only to
check it: a password-protected PEM key is decrypted and paired once per file version. A source never names
a key publicly: it gives its own id (a file path, a vault version), and the framework derives the
`kid` from the public key (RFC 7638 thumbprint), so a vault URL or file path cannot leak into a token
or the JWKS. A provider registers with `builder.AddSigningKeySource<T>()`, one source per app.

**`ISigner`** signs bytes. Local providers (development, PEM, PFX, Windows) return the built-in
`LocalSigner`; only a remote signer (Key Vault remote signing) implements it.

**`SigningKeySetBuilder`** validates every listed key the same way: RSA of at least 2048 bits, NIST
curves only, the key fitting the source's algorithm, .NET's own import rejecting malformed material,
valid dates. A key that fails is dropped with a warning, and one key pair listed twice counts as one
key. Providers never repeat these checks.

**`SigningKeyRing`** reads the source at startup and again every `RefreshInterval` (default five
minutes), and decides from the keys' dates alone which key signs and which are published:

- every unexpired key is published;
- the newest key at least the lead time past its `NotBefore` signs (default one day, never shorter
  than `CacheMaxAge` plus `RefreshInterval`). A key added when it becomes valid has then been
  published that long, so relying parties already have it; a certificate listed long after its
  `NotBefore` (its CA issuance date) signs at the next read;
- if no key is that old, the oldest valid one signs, with a Warning. That one rule
  covers a first deployment, a normal rotation and an emergency, with no special cases;
- an old key stays published for `RetainRetiredKeysFor` after its successor takes over or it
  expires: two days, or the longest token lifetime plus clock skew if that is longer.

Each signer is **self-tested** before it signs: it signs a fixed non-JWS prefix plus a fresh nonce,
verified with the public key that will be published. At startup a bad signer fails the host. Later,
a key due to sign that cannot is skipped and the previous key signs on, Degraded. A failed read keeps
the last list; an empty list stops signing; a key removed at its source stops signing within one
refresh. The ring owns the source and every signer it opens, and closes a signer a refresh interval
after it stops signing. Token code asks the ring to sign through a callback told which key will sign,
so the header's `kid` and `alg` always name the key that actually signed. `Verify` checks a
signature against every listed key.

**The JWKS endpoint** publishes every published key as a JWK, anonymously, with `Cache-Control`
from `JwksEndpointOptions.CacheMaxAge`, or `no-store` when there is no key. Discovery advertises the
source's one algorithm.

**The health check** reports whether the ring can sign now and whether some key can still sign at
the end of a threshold, and reports failed reads and dropped or skipped keys as Degraded.

**Providers:** the development key (core; gated to `Development` by default through
`AllowedEnvironments`, `Production` always refused, an unknown environment refused, any other
opt-in and logged Critical), PEM and PFX files (`ZeeKayDa.Auth.FileSystem`; a PEM key may be
password-encrypted), the Windows certificate store (`ZeeKayDa.Auth.Windows`), and Azure Key Vault
with remote or cached signing (`ZeeKayDa.Auth.AzureKeyVault`). File and store providers take a plain
list; any listed key may sign. The PFX source parses the bundle itself so listing never decrypts its
key; the cached Key Vault source downloads a private key only for a version that signs.

**Provider tests** drive a real ring on a fake clock through the TestKit's `SigningKeyRingHarness`,
ours and third parties' alike; the ring's constructor stays internal.

## What it costs

- A source changing its algorithm is a new source and a restart.
- A key added at its `NotBefore` waits `RefreshInterval` plus the lead time before signing, by
  design. One whose `NotBefore` is already past the lead time skips that wait.

## What the walkthrough changed

The maintainer walked this part at code level. What it decided has landed in M1: the framework owns
the timing and sources only list keys (#823), registration on the builder (#824), the development
signing API and its fail-closed gate (#825, #826). The review that followed made rotation live
(#527) and added per-entry failures, one algorithm per source, skip-forward, signer disposal and the
TestKit harness (#905, #908, #916, #919, #929).

## What was rejected

- **A setting to pin the signing key for emergencies.** Removing the compromised key does it within
  one refresh interval, and the fallback rule signs with the replacement at once.
- **A lead time of 0 as the emergency lever,** and a "first version" exemption: both are special
  cases the fallback rule makes unnecessary.
- **A fixed age cut-off for loading old Key Vault versions.** It would drop a key that has signed for
  longer than the cut-off. A count (`MaxVersions`, minimum 3) is used instead.
- **Keeping the full ancestor-ownership walk for development keys.** Neither Duende IdentityServer
  nor OpenIddict checks development-key permissions at all, or gates on environment; we keep the
  gate and the file checks, and drop the part only a shared multi-user machine needs.
