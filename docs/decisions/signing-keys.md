# Signing keys

## Decisions in force

**One key ring, two source methods, and callers never hold a key.** `ISigningKeyRing` lives in core; signing
is a protocol concern, not a web one. A provider implements `ISigningKeySource`: `ReadAsync` returns
public-only slots, `CreateSignerAsync` lends a signer for the one key the ring selected. Since a provider
never holds a private-key object, aliasing one across reads is unrepresentable. `ISigner.Dispose` releases
only the handle that instance introduced, so a signer over a shared SDK client must not close it.
`SigningAlgorithm` has no `none` member.

**Keys are three named slots: `Previous`/`Current`/`Next`, `Current` required, the others independently
optional.** `SourceKeySet.Create` rejects a missing `Current`, so a provider cannot express "no signer".
`SigningKeySetBuilder.Build` is the single pure choke point `SourceKeySet` → `SigningKeySet`: no clock, no
policy, no I/O, always derives `kid` via `JwkThumbprint`, rejections throwing
`ZeeKayDaConfigurationException` before private material exists. `StaticSigningKeyRing` reads its source
once at startup, self-tests the signer, and owns it for the process lifetime. `SigningKeySet.SigningKey`
stays non-nullable: no reachable state lacks a signing key, and `ISigningKeyRing` being framework-sealed
lets a polling ring add `SigningKeyOrNull` later.

**Slots decide activation; there is no bootstrap exemption.** The operator names `Current`, so a lone
configured key is active through ordinary selection, and the ring rejects a `Current` whose validity window
has not opened (`NotBefore`) or has closed (`ExpiresAt`) — checked against the signing key alone, since
staging a key early is what `Next` is for. Rotation is restart-based (#527).

**The framework derives every `kid`; a provider cannot supply one.** The ring computes an RFC 7638 JWK
thumbprint over the public key. A provider supplies only its internal `SourceKeyId`, so it cannot leak a
vault URI, certificate thumbprint, or file path into every issued token.

**The Key Vault sources derive their slots from the vault's own version metadata; nothing is
slot-configured, and the derivation is one shared function.** One key (remote) or certificate (cached), its
versions, one selector (`KeyVaultVersionSelector.SelectVersions`): the newest enabled version inside its own
validity window that has existed for `PreActivationDelay` signs; every enabled version newer than it is
published as staged, so replicas restarting on either side of a version ripening still publish each other's
signing key; up to `PreviousVersionsToPublish` older enabled versions stay published. The delay derives from
Key Vault's durable per-version `CreatedOn`, never first-seen time, so every replica and restart agrees; the
chronologically-first version recorded is exempt, computed over the full history including disabled versions
so a stale partial listing cannot promote a young key early. An entry missing `Enabled` or `CreatedOn` is
rejected, never defaulted. Disabling a version excludes it everywhere — the one revocation lever — and no
eligible version fails startup closed (`PreActivationDelay = 0` is the escape hatch). The age gate is what
makes Key Vault rotation — which creates versions with no `nbf` — safe to promote.

**The cached Key Vault source downloads private material for exactly one version.** Reads publish public
`Cer` halves only (no `secrets/get`); the signing version's private key is downloaded once, in
`CreateSignerAsync`, and cross-checked against the public key the read published — separate vault reads that
could diverge, so a divergence is named rather than surfacing as a generic self-test failure. A
published-only version's key never enters the process.

**Bundled formats keep non-active private material out of reach by never importing it.** PFX verifies the
MAC against the password, takes the certificate the key bag's `localKeyId` names — PKCS#12 has no bag
ordering — and imports no key at all.

**Every signer handoff is self-tested before the signer is used.** The ring signs a fixed, non-JWS-shaped
constant and verifies it against that key's own published public key, in the single choke point every
handoff passes through. Materialization alone is not enough: a signer can construct successfully over
material that does not pair with the published key. It is unconditional with no HSM opt-out, and
`SigningKeyRingStartupVerifier` forces the first handoff eagerly, so a misconfigured key fails the host
rather than the first request. The ring also rejects a signer whose `Algorithm` disagrees with its key. Any
failure fails closed. No sign-off covers it.

**All load-time validation runs on public data, in one place.** Key/algorithm compatibility, EC curve
pairing, RSA modulus size (2048-bit minimum), NIST-curve-only EC keys, and rejection of duplicate source ids
and derived `kid`s all run before any private material is loaded, throwing `ZeeKayDaConfigurationException`.
A provider never repeats these locally — duplicated validation is how two layers drift.

**Development signing keys are one line, and hard-gated on environment.** The persistence choice lives in
the method name rather than a `null` argument. The allowed-environment list is reachable only through the
registration callback, never bindable configuration, so a committed `appsettings.json` cannot widen it;
`Production` is rejected unconditionally, and any non-`Development` entry logs `Critical` on every startup.
Persisted keys are plain PEM with permissions set atomically at creation (`0700`/`0600` POSIX, a restrictive
non-inherited ACL on Windows), and loading fails closed on a broader mode, a symlink, or a foreign-owned
directory.

**Extension contracts are public in core; ZeeKayDa's own crypto and redaction stay internal.**
`InternalsVisibleTo` can only name first-party assemblies at build time, so it structurally cannot serve a
third-party provider package. Making `ISanitizingLogger<T>` nameable creates a host-shadowing risk, closed
by a hard-failing startup gate that runs first and rejects an unexpected open-generic implementation or any
closed-generic override. The two narrow grants that do exist — `ZeeKayDa.Auth.FileSystem` for POSIX
`stat`/`lstat` interop, `ZeeKayDa.Auth.Windows` for process-identity diagnostics — are reviewed exceptions
for assemblies shipping in lockstep with core, not a pattern: forking security-critical, ABI-fragile interop
would risk a second, independently-drifting copy of code that already needed a security fix.

**No Microsoft.IdentityModel types on the public surface.** They would bake a large, fast-moving third-party
surface into the SemVer contract. The JWK mapping is hand-rolled over BCL types, held to RFC 7517/7518
known-answer vectors — a cost taken over the dependency.

**One signing provider per application, and nothing is registered for the source.**
`AddZeeKayDaSigningKeySource<TSource>()` (both overloads) enforces this with an internal marker: a second
call always throws, whichever overload either used and whether or not `TSource` matches. A same-type repeat
is deliberately not a no-op — a provider registers its source *and* configures options beside it, so a
"harmless" duplicate still applies a second configuration callback. A manual `ISigningKeyRing` also throws,
but only one already registered; one added afterwards wins under MS DI's last-wins resolution, undetectably.
`ISigningKeySource` itself is never registered: the ring factory re-validates the marker set, constructs the
source directly (unreachable from the container), owns its lifetime alongside the signer's, and rejects
`IAsyncDisposable` without `IDisposable`.

**Per-client algorithm selection is a parameter on the signing call, not a ring selector.** It is the
near-term pressure that looks like an `ISigningKeyRingSelector` and is not one: the ring owns one key set,
and choosing among the algorithms it publishes is a caller's argument, not a container-resolved strategy.

**Each production provider platform is its own package; the development provider is not.**
`ZeeKayDa.Auth.AzureKeyVault` (remote and cached together — same dependency and operational context, so the
choice is a method call, not a package swap), `ZeeKayDa.Auth.Windows` (Windows-only TFM, so a mismatched
restore fails at build time), `ZeeKayDa.Auth.FileSystem` (portable). Each references core only and exposes
nothing but its registration methods and options type — package identity is permanent once published. The
development provider stays in core.

## Tried, didn't work

- **`IJwtSigningService` / `JwtSigningService<TOptions>`: a provider base class owning selection, rotation,
  and signing.** Replaced by the three-slot key ring. A provider had to be a subclass rather than an
  implementation, and the base carried a timeline engine, borrow/refcount machinery, and a producibility
  surface the slot model makes unnecessary rather than reimplements.
- **A two-tier options hierarchy: `KeySetOptions` for a fixed set, `KeySourceOptions` for a polled one.**
  The tiers duplicated slot shape and validation while differing only in who refreshes — now the source's
  own concern. One `ISigningKeySource` with three slots covers both.
- **`PublicationLead` as a setting, with `PublishAt = ActivateAt − PublicationLead`.** A derived timeline
  needs a clock inside the pure builder. Publication is now structural: every configured slot is published,
  so staging a key *is* filling `Next`.
- **A single rotating-source tier with one shared check interval.** Ratified and shipped, reversed two weeks
  later. File/PFX/certificate-store and Key Vault share no model — only a *name*, covering both an internal
  clock tick over a fixed timeline and a real external poll cadence.
- **A derived `RetirementWindow` and an `ISigningKeyRetirementWindowProvider` to compute it.** Under the
  three-slot model nothing consumes it: the published set is every configured slot, so retirement is the
  operator emptying a slot, not a computed instant.
- **The single-key bootstrap exemption.** Its justification — "no prior published JWKS state any RP could
  have cached" — is false after any restart, and a key with no `ActivateAt` is active immediately through
  ordinary selection anyway. Deleted, not moved.
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
