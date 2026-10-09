# Signing keys

## Decisions in force

**One key ring, two source methods, and callers never hold a key.** `SigningKeyRing` lives in core; signing
is a protocol concern, not a web one. A provider implements `ISigningKeySource`: `ReadAsync` lists
public-only keys, `CreateSignerAsync` lends a signer for whichever listed key the ring chose. Since a provider
never holds a private-key object, aliasing one across reads is unrepresentable. `ISigner.Dispose` releases
only the handle that instance introduced, so a signer over a shared SDK client must not close it.
`SigningAlgorithm` has no `none` member.

**A source declares one algorithm, and every key it lists signs under it.** `ISigningKeySource.Algorithm`, never
per key and read once at startup, so a key change is never an algorithm change; discovery advertises that one.
Changing it is a new source and a restart; multi-algorithm support would be a ring per algorithm, never a mixed one.

**Sources only list keys; core owns all the timing, and the ring follows the clock.** A `SourceKey` carries
`NotBefore` and `ExpiresAt` (undated: accepted only as the sole key). `SigningKeySetBuilder.Build` validates every
key on public data, derives every `kid`, and returns a `SigningKeyTimeline` deciding from the dates alone. The
newest unexpired key at least `SigningKeys.LeadTime` (default one day) past its `NotBefore` signs, else the oldest
unexpired key, with a Warning. Every unexpired key is published, an older one until a newer key is
`LeadTime + RetainRetiredKeysFor` old, an expired one until `RetainRetiredKeysFor` after expiry, the signing key
always. `NotBefore` orders keys and starts the clock; no relying party sees it, so it is no validity gate. Retention
defaults to two days, or the longer token lifetime plus clock skew, so a replica whose handover is slow or failed
signs on safely; lower warns. Ties go to the greater source id. A key with bad material or dates is dropped (Warning,
Degraded) unless due to sign now; at startup that, an ambiguous list, or every key expired is fatal.

**The ring re-reads its source every `RefreshInterval` (default 5 min, min 1)**, so `LeadTime ≥ CacheMaxAge +
RefreshInterval`. A read that throws or exceeds a minute keeps the last list (Error, Degraded); no read starts while one
runs, so a source that never returns pins it. No keys revokes all; an ambiguous list or a bad key due now is refused
alike (one bad key cannot freeze the old set): signing stops (`SigningKey` null, `SignAsync` throws, JWKS `{"keys":[]}`
no-store, Unhealthy) until a good read; an unlisted signing key stops at once. Sources list a deleted file, key file,
certificate or vault object as nothing, so removing a key revokes it; an unmounted directory reads as deleted. A failed
successor is set aside until the next read, for good once its predecessor retires. Unlisted signers close a read later.

**File and store providers are plain lists, and any listed key may sign.** PEM, PFX and Windows list
`Files`/`Certificates` with the public `SourceKey.FromCertificate`; PEM and PFX sign via `LocalSigner.FromCertificate`.
A certificate's `NotBefore` is its CA issuance date, so one listed over a lead time later signs as soon as it is read.
Listing checks every entry can sign without importing a key: PFX key bags, PEM key files (permissions) and blocks,
Windows `HasPrivateKey`. No read lock or cache.

**The framework derives every `kid`; a provider cannot supply one.** The ring computes an RFC 7638 JWK thumbprint over
the public key. A provider supplies only its internal `SourceKeyId`, so it cannot leak a vault URI, certificate
thumbprint, or file path into every issued token. One key pair listed twice (a key-reusing renewal) is one key, dated
first `NotBefore` (older than keys listed between) to last expiry; its last to expire opens it, the earlier signs till then.

**The Key Vault sources list every enabled version, dated by vault metadata every replica agrees on.** A
version counts from the later of its `CreatedOn` and its own `nbf`, never first-seen time; its `exp` is its
expiry. Disabling a version unlists it. A version whose identifier is not pinned to it is rejected, since the SDK
resolves an unpinned URI to whatever version is newest at sign time. `MaxVersions` (default all, minimum 3: staged, signing, previous) lists only the
newest N, so only their public keys are fetched; too low drops a version whose tokens are still live.

**The cached Key Vault source downloads private material only for the version the ring asks to sign.** Reads
publish public `Cer` halves only (no `secrets/get`); that version's private key is downloaded once, in
`CreateSignerAsync`. The secret and the `Cer` are separate reads; the self-test catches a divergence.

**Listing a bundled format imports no private key.** PFX verifies the MAC against the password and takes the
certificate the key bag's `localKeyId` names — PKCS#12 has no bag ordering; only the chosen bundle's key is imported.

**Every signer handoff is self-tested before the signer is used.** `SigningKeyRing` signs a
non-JWS-shaped constant prefix plus a fresh 32-byte nonce and verifies it against that key's own published
public key, in the single choke point every handoff passes through; the nonce defeats a memoising signer or
caching proxy, and materialization alone proves nothing, since a signer can construct over material that
does not pair. It is unconditional with no HSM opt-out, and `SigningKeyRingActivator` forces the
first handoff eagerly, so a misconfigured key fails the host rather than the first request. Verifying under
the key's own algorithm also catches a signer signing under another one. A mismatch, a non-signature and a
signer that throws each fail closed under their own code, and the signer is disposed. A cancellation is the
caller's whenever the caller's token is cancelled, so a signer linking tokens is not reported as broken. Signed off in `security-sign-offs.md`.

**All load-time validation runs on public data, in one place.** Key/algorithm compatibility, EC curve pairing, RSA modulus
size (2048-bit minimum), NIST-curve-only EC keys and duplicate source ids are all checked before any private material is
loaded. A provider never repeats these locally — duplicated validation is how two layers drift.

**Development signing keys are one line, and hard-gated on environment.** Persistence is in the method
name, never a `null` argument. `AllowedEnvironments` is set in the registration callback and the
framework never binds it, so `appsettings.json` alone cannot widen it; `Production` is always rejected, a host
running in an allowed non-`Development` environment logs `Critical` on every start, and an unknown one fails closed.
Persisted keys are plain PEM, owner-only from creation (`0700`/`0600` POSIX, a non-inherited ACL on Windows)
via .NET's file APIs, created by one host at a time under a lock file and renamed into place (racers load the
winner's), and loading fails closed on a broader mode or a symlinked key file. Ancestor directories are not
walked: that matters only on a shared machine, and the environment gate keeps a development key out of production.

**Extension contracts are public in core; ZeeKayDa's own crypto and redaction stay internal.**
`InternalsVisibleTo` can only name first-party assemblies at build time, so it structurally cannot serve a
third-party provider package. `SanitizingLogger<T>` is nameable for that reason, and cannot be substituted:
its only constructor is internal. The two narrow grants that do exist — `ZeeKayDa.Auth.FileSystem` and `ZeeKayDa.Auth.Windows`, both for
the process-identity helper their access-denied messages share — are reviewed exceptions for assemblies
shipping in lockstep with core, not a pattern. Core has no native interop: the `lstat` owner check lives in
`ZeeKayDa.Auth.FileSystem`, the one package that protects production keys with it.

**No Microsoft.IdentityModel types on the public surface.** They would bake a large, fast-moving third-party
surface into the SemVer contract. The JWK mapping is hand-rolled over BCL types, held to RFC 7517/7518
known-answer vectors — a cost taken over the dependency.

**One signing provider per application, and nothing is registered for the source.**
`builder.AddSigningKeySource<TSource>()`, which every provider calls first from its own registration method,
enforces this with an internal marker: a second call on the same collection throws, whatever `TSource` — a
provider configures options beside its source, so a "harmless" duplicate would still apply a second callback.
`ISigningKeySource` itself is never registered: the ring constructs the source directly (unreachable from the
container) and owns its lifetime alongside the signer's. A source implementing `IAsyncDisposable` without
`IDisposable` is refused at registration.

**A client's allowed algorithms are an acceptance list, not a selector.** The ring owns one key set and
signs with one key; a client whose list excludes that key's algorithm fails closed (`token-contents.md`).
If selection ever comes it is an argument on the signing call, never a container-resolved ring strategy.

**Each production provider platform is its own package; the development provider is not.**
`ZeeKayDa.Auth.AzureKeyVault` (remote and cached together — same dependency and operational context, so the
choice is a method call, not a package swap), `ZeeKayDa.Auth.Windows` (Windows-only TFM, so a mismatched
restore fails at build time), `ZeeKayDa.Auth.FileSystem` (portable). Each references core only and exposes
nothing but its registration methods and options type — package identity is permanent once published. The
development provider stays in core.

## Tried, didn't work

- **`IJwtSigningService` / `JwtSigningService<TOptions>`: a provider base class owning selection, rotation, and
  signing.** Replaced by the key ring. A provider had to be a subclass, and the base carried a timeline engine,
  borrow/refcount machinery, and a producibility surface the slot model makes unnecessary rather than reimplements.
- **A two-tier options hierarchy: `KeySetOptions` for a fixed set, `KeySourceOptions` for a polled one.**
  The tiers duplicated slot shape and validation while differing only in who refreshes — now the source's
  own concern. One `ISigningKeySource` covers both.
- **A per-key `ActivateAt` with `PublishAt = ActivateAt − PublicationLead`.** The operator scheduled each
  activation by hand. Now a key's own `NotBefore` is its publication date and one `LeadTime` derives the rest.
- **A single rotating-source tier with one shared check interval.** Shipped, then reversed: file/store and Key
  Vault share only a *name*, covering both a clock tick over a fixed timeline and a real external poll.
- **An `ISigningKeyRetirementWindowProvider`.** Retention is one core setting over dates providers report.
- **A key set frozen at startup.** It forced a predecessor retention rule, a successor-predicting health check and a `NotBefore` grace.
- **A one-hour grace after a failed read, then stop.** An unreachable source is not a revocation; an empty list is.
- **Bootstrap exemptions — the single-key one, and Key Vault's "first version ever" one.** "No relying party
  could have cached anything" is false after any restart; a lone key signs at once through the ordinary
  oldest-valid-key fallback anyway. Deleted, not moved.
- **Timing owned by each provider: three operator-filled slots, and Key Vault's `KeyVaultVersionSelector`.** A
  provider author had to understand rotation, and the one real implementation of the rules sat in one provider.
- **Key Vault pruning by asking core which versions it keeps, or from a rotation period.** The first is custom
  handling of a first-party package; the second miscounts after an emergency rotation.
- **Per-key algorithms, an advertised set derived from them, and an `AdvertisedSigningAlgorithms` filter.**
  Any key change could change algorithm, so client checks had to forecast every future signer.
- **An `Enabled` flag, or a whole-set change-detection hook, on the provider contract.** The flag only
  ever meant "this Key Vault version is enabled"; the hook became the default once listings were public-only.
- **`InternalsVisibleTo` for the shared signing helpers.** The Azure Key Vault provider's first attempt. It can never
  serve a third party without a core release naming them. Public contracts with internal crypto is the fix.
- **The development-key environment gate on the shared server options root.** Shipped, then reverted: it conflated
  the gate's input (the host environment name) with its policy (inert unless a development-key method was called).
- **Hand-rolled key-pairing checks in the Windows and cached Key Vault providers.** Superseded — the same
  invariant is proven on every handoff.
- **`EphemeralKeySet` to keep a non-active PFX bundle's key off disk.** Platform-conditional (macOS throws)
  and it still materialises the key. Never decrypting the key bag beats it everywhere.
- **A macOS Keychain signing provider.** Implemented and reviewed, then descoped: the file-system provider
  already covers macOS and Linux without native interop.
- **A factory overload, and two more registration checks.** The overload was a second way to build a source;
  the resolve-time check against merged collections and the manual-ring refusal policed exotic mistakes.
