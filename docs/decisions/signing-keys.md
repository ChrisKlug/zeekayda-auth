# Signing keys

## Decisions in force

**One key ring, two source methods, and callers never hold a key.** `SigningKeyRing` lives in core; signing
is a protocol concern, not a web one. A provider implements `ISigningKeySource`: `ReadAsync` lists
public-only keys, `CreateSignerAsync` lends a signer for whichever listed key the ring chose. Since a provider
never holds a private-key object, aliasing one across reads is unrepresentable. `ISigner.Dispose` releases
only the handle that instance introduced, so a signer over a shared SDK client must not close it.
`SigningAlgorithm` has no `none` member.

**Sources only list keys; core owns all the timing.** A `SourceKey` carries `NotBefore` and `ExpiresAt`
(undated means `MinValue`/`MaxValue`; an undated key is accepted only as the sole key). The internal
`SigningKeySetBuilder.Build(keys, now, options, logger)` is the single choke point: it validates every key on
public data, derives every `kid` via `JwkThumbprint`, then decides from the dates alone. Every unexpired key
is published, oldest first. The newest key whose `NotBefore` is at least `SigningKeys.LeadTime` (default one
day, never below `JwksEndpoint.CacheMaxAge`) in the past signs; if none is, the oldest valid key signs and a
Warning says relying parties may reject its tokens until they refresh. A key stays published until a newer key
is `LeadTime + RetainRetiredKeysFor` old (retention defaults to the longer server-wide token lifetime; per-client
overrides are invisible at startup). Ties on `NotBefore` go to the ordinally greater source id. One rule covers a
first deployment, a normal rotation and an emergency (remove the key, restart), with no exemption.
`SigningKeyRing` reads once at startup, self-tests the signer, and owns it for the process lifetime;
`SigningKeySet.SigningKey` stays non-nullable, and live rotation is #527.

**A file or store provider's slot names carry no meaning to core.** PEM, PFX and Windows still configure
`Previous`/`Current`/`Next` and report the filled slots as a list; whichever key the dates choose signs. Each
still opens a signer only for `Current`, so a configuration in which the dates choose another slot fails
startup closed until those providers become plain lists.

**The framework derives every `kid`; a provider cannot supply one.** The ring computes an RFC 7638 JWK
thumbprint over the public key. A provider supplies only its internal `SourceKeyId`, so it cannot leak a
vault URI, certificate thumbprint, or file path into every issued token.

**The Key Vault sources list every enabled version, dated by vault metadata every replica agrees on.** A
version counts from the later of its `CreatedOn` and its own `nbf`, never first-seen time; its `exp` is its
expiry. Disabling a version removes it from the listing — the one revocation lever. A listed version whose
identifier is not pinned to that version is rejected, since the SDK resolves an unpinned URI to whatever
version is newest at sign time. Every enabled version's public key is fetched at startup; pruning fully
retired versions before fetching them is a Key Vault optimisation, not part of the contract.

**The cached Key Vault source downloads private material only for the version the ring asks to sign.** Reads
publish public `Cer` halves only (no `secrets/get`); that version's private key is downloaded once, in
`CreateSignerAsync`, and cross-checked against the public key the read published — separate vault reads that
could diverge, so a divergence is named rather than surfacing as a generic self-test failure. A
published-only version's key never enters the process.

**Bundled formats keep non-active private material out of reach by never importing it.** PFX verifies the
MAC against the password, takes the certificate the key bag's `localKeyId` names — PKCS#12 has no bag
ordering — and imports no key at all.

**Every signer handoff is self-tested before the signer is used.** `SigningKeyRing` signs a
non-JWS-shaped constant prefix plus a fresh 32-byte nonce and verifies it against that key's own published
public key, in the single choke point every handoff passes through; the nonce defeats a memoising signer or
caching proxy, and materialization alone proves nothing, since a signer can construct over material that
does not pair. It is unconditional with no HSM opt-out, and `SigningKeyRingActivator` forces the
first handoff eagerly, so a misconfigured key fails the host rather than the first request. Verifying under
the key's own algorithm also catches a signer signing under another one. A mismatch, a non-signature and a
signer that throws each fail closed under their own code, and the signer is disposed. A cancellation is the
caller's whenever the caller's token is cancelled, so a signer linking tokens is not reported as broken. Signed off in `security-sign-offs.md`.

**All load-time validation runs on public data, in one place.** Key/algorithm compatibility, EC curve
pairing, RSA modulus size (2048-bit minimum), NIST-curve-only EC keys, and rejection of duplicate source ids
and derived `kid`s all run before any private material is loaded, throwing `ZeeKayDaConfigurationException`.
A provider never repeats these locally — duplicated validation is how two layers drift.

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

- **`IJwtSigningService` / `JwtSigningService<TOptions>`: a provider base class owning selection, rotation,
  and signing.** Replaced by the key ring. A provider had to be a subclass rather than an
  implementation, and the base carried a timeline engine, borrow/refcount machinery, and a producibility
  surface the slot model makes unnecessary rather than reimplements.
- **A two-tier options hierarchy: `KeySetOptions` for a fixed set, `KeySourceOptions` for a polled one.**
  The tiers duplicated slot shape and validation while differing only in who refreshes — now the source's
  own concern. One `ISigningKeySource` covers both.
- **A per-key `ActivateAt` with `PublishAt = ActivateAt − PublicationLead`.** The operator scheduled each
  activation by hand. Now a key's own `NotBefore` is its publication date and one `LeadTime` derives the rest.
- **A single rotating-source tier with one shared check interval.** Ratified and shipped, reversed two weeks
  later. File/PFX/certificate-store and Key Vault share no model — only a *name*, covering both an internal
  clock tick over a fixed timeline and a real external poll cadence.
- **An `ISigningKeyRetirementWindowProvider` computing retirement per provider.** Retention is one core
  setting applied to dates every provider already reports.
- **Bootstrap exemptions — the single-key one, and Key Vault's "first version ever" one.** "No relying party
  could have cached anything" is false after any restart; a lone key signs at once through the ordinary
  oldest-valid-key fallback anyway. Deleted, not moved.
- **Timing owned by each provider: three operator-filled slots, and Key Vault's `KeyVaultVersionSelector`
  with `PreActivationDelay` and `PreviousVersionsToPublish`.** A provider author had to understand rotation
  to write a provider, and the one real implementation of the rules sat inside one provider package.
- **A startup cross-check between advertised and producible algorithms
  (`AdvertisedSigningAlgorithmVerifier`, `ISigningKeyProducibility`).** Detecting a disagreement the
  configuration should not express. #515 derives the advertised set from the published set instead, making
  it unrepresentable.
- **An `Enabled`/disabled flag on the provider contract.** It only ever meant "this Key Vault version is
  enabled", and forced every provider to carry a concept most had no equivalent for.
- **A whole-set change-detection hook alongside refresh.** Once listings became public-only data and signer
  creation was gated on the active key changing, it was the default behaviour.
- **`InternalsVisibleTo` for the shared signing helpers.** The Azure Key Vault provider's first attempt. It
  can serve exactly one first-party package and can never serve a third party without a new core release
  naming them. Public contracts with internal crypto is the fix.
- **The development-key environment gate on the shared server options root.** Shipped, then reverted: it
  conflated the gate's input (server-wide host environment name) with its policy (feature-scoped, inert
  unless a development-key method was called).
- **A hand-rolled key-pairing check inside the Windows Certificate Store provider.** Added after a
  security-review finding, then superseded — the same invariant is now proven on every handoff.
- **`EphemeralKeySet` to keep a non-active PFX bundle's key off disk.** Platform-conditional (macOS throws)
  and it still materialises the key. Never decrypting the key bag beats it everywhere.
- **A macOS Keychain signing provider.** Implemented and reviewed, then descoped: the file-system provider
  already covers macOS and Linux without native interop.
- **A factory overload, and two more registration checks.** The overload was a second way to build a source;
  the resolve-time check against merged collections and the manual-ring refusal policed exotic mistakes.
