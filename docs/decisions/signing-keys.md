# Signing keys

## Decisions in force

**One interface, two methods, and callers never hold a key.** `IJwtSigningService` lives in core; signing
is a protocol concern, not a web one. `SignAsync` selects the active key, builds the JWS header, and signs
in one call, so a token's `kid`/`alg` can never disagree with the key that signed it. No `VerifyAsync` —
verifying client-owned keys is a separate seam — and no `RotateAsync`, since whatever owns the keys owns
their schedule. `SigningAlgorithm` has no `none` member and never will.

**Providers return data, not key objects.** `JwtSigningService<TOptions>` is the base every provider
derives from. `ListKeysAsync` returns public-only listings; `CreateSignerAsync` lends a signer for
the one key the base has already selected as active, never for a future, retired, or non-active key.
Because a provider never holds a private-key object, aliasing or mis-ordering one across listings is
unrepresentable. `ISigner.Dispose` releases only the handle that instance introduced — the base disposes
it on active-key change, so a signer over a shared SDK client must not close that client.

**Bundled formats keep non-active private material out of reach by never importing it.** The framework
sees only public data and cannot enforce it. PFX verifies the MAC against the password, takes the
certificate the key bag's `localKeyId` names — PKCS#12 has no bag ordering — and imports no key at all.

**The framework derives every `kid`; a provider cannot supply one.** The base computes an RFC 7638 JWK
thumbprint over the public key. A provider supplies only its own internal `KeyId`, so it cannot express a
`kid` leaking a vault URI, certificate thumbprint, or file path into every issued token.

**A second, expand-only signing model sits beside `JwtSigningService<TOptions>` until the old model is
deleted, in two tiers: `KeySetOptions` for a fixed set an operator edits directly, `KeySourceOptions` for
a set a provider polls.** Keys are three named slots — `Previous`/`Current`/`Next`, `Current` required, the
others independently optional. `SourceKeySet.Create` rejects a missing `Current`, so a provider cannot
express "no signer." `SigningKeySetBuilder.Build` is the single pure choke point from `SourceKeySet` to
`SigningKeySet`: no clock, no policy, no I/O, always derives `kid` via `JwkThumbprint`, every rejection
throwing `ZeeKayDaConfigurationException` before private material exists. `StaticSigningKeyRing` reads its
`ISigningKeySource` once at startup, self-tests the signer with a fresh nonce, and owns it for the process
lifetime. `SigningKeySet.SigningKey` stays non-nullable: no reachable state here lacks a signing key, and
`ISigningKeyRing` being framework-sealed lets a polling ring add `SigningKeyOrNull` additively later.

**A slot-configured ported source has no bootstrap exemption; slots decide.** The operator names
`Current`, so a lone configured key is active through ordinary selection, and the ring rejects a
`Current` whose validity window has not opened (`NotBefore`) or has closed (`ExpiresAt`) — checked
against the signing key alone, since staging a key before its window opens is what `Next` is for. On
the un-ported tiers the exemption holds for `KeySetOptions` only: a `KeySourceOptions` listing shrunk
by revocation must not re-arm it.

**The Key Vault remote source derives its slots from the vault's own version metadata; nothing is
slot-configured.** One key, its versions: the newest enabled version inside its own validity window
that has existed for `PreActivationDelay` signs; the next version in line, still ripening or carrying
a future `nbf`, is published as staged; up to `PreviousVersionsToPublish` older enabled versions stay
published, expired-but-enabled included. The delay derives from Key Vault's durable per-version
`CreatedOn`, never first-seen time, so every replica and restart agrees; the chronologically-first
version ever recorded is exempt, computed over the full history including disabled versions so a stale
partial listing cannot promote a young key early. Disabling a version excludes it everywhere — the one
revocation lever — and no eligible version fails startup closed (`PreActivationDelay = 0` is the
operator escape hatch). Rotation is restart-based until #527, and the age gate is exactly what makes
Key Vault's automatic rotation policy — which creates versions with no `nbf` — safe to promote.

**One timeline engine, and the operator sets only `ActivateAt`.** `SigningKeyRotation` is a pure function
over immutable public data that both un-ported tiers call. Every other instant is derived —
`PublishAt = ActivateAt − PublicationLead`, and a key stays in the JWKS until its successor's activation
plus the retirement window — so there is no deactivation knob and a too-short overlap is unrepresentable.
A ported source has no timeline: it reports slots and the ring reads them once.

**`PublicationLead` is durable and `ActivateAt`-derived, never observed-first-seen.** A provider maps its
store's own durable timestamp onto `ActivateAt` so the lead survives restarts and replicas; in-memory
first-seen bookkeeping is banned. `KeySourceOptions` enforces `PublicationLead >= RefreshInterval`, so a
key cannot activate before the process would poll and notice it; on `KeySetOptions` the operator owns
activation timing and the lead only drives a warning.

**`RetirementWindow` is derived, never a user setting.** It is
`max(access-token lifetime, ID-token lifetime, 1-hour floor)` plus the configured clock-skew allowance,
measured from a successor becoming active; every off-default value is unsafe or useless. Refresh-token
lifetime is excluded — relying parties never validate refresh tokens against the JWKS. Security signed off.

**Omission is the kill switch; there is no `Enabled` flag.** A `KeySourceOptions` provider lists a key
for exactly as long as it should be trusted, so revoking or deleting it in the backing store drops it
from the JWKS on the next refresh, retirement window or not. Omission is a three-state signal: a vanish
after the retirement window closes is routine; a vanish *inside* it still drops the key but MUST emit a
`Warning`, never downgraded, as the only accidental-omission detector; and a provider that cannot read
its set completely MUST throw, so a store error never reads as revocation.

**Every active-signer handoff is self-tested before the signer is used.** The base signs a fixed,
non-JWS-shaped constant and verifies it against that key's own published public key, in the single choke
point every handoff passes through, so a key rotated days later is proven as thoroughly as the one active
at boot. Materialization alone is not enough: a signer can construct successfully over material that does
not pair with the published key. It is unconditional with no HSM opt-out, and a framework-owned startup
verifier forces the first handoff eagerly. Any failure fails the handoff closed. No sign-off covers it.

**All load-time validation runs on public data, in one place.** Key/algorithm compatibility, EC curve
pairing, RSA modulus size (2048-bit minimum), NIST-curve-only EC keys, and rejection of duplicate source
ids and derived `kid`s all run before any private material is loaded, throwing
`ZeeKayDaConfigurationException`. A provider never repeats these checks locally — duplicated validation
is how two layers drift, and the central failure is keyed on the provider's own source id anyway.

**Development signing keys are one line, and hard-gated on environment.** The persistence choice lives in
the method name rather than a `null` argument. The allowed-environment list is reachable only through the
registration callback, never bindable configuration, so a committed `appsettings.json` cannot widen it;
`Production` is rejected unconditionally, and any non-`Development` entry logs `Critical` on every startup.
Persisted keys are plain PEM with permissions set atomically at creation (`0700`/`0600` on POSIX, a
restrictive non-inherited ACL on Windows), and loading fails closed on a broader mode, a symlinked path,
or a directory not owned by the current user.

**Extension contracts are public in core; ZeeKayDa's own crypto and redaction stay internal.**
`InternalsVisibleTo` can only name first-party assemblies at build time, so it structurally cannot serve
a third-party provider package. Making `ISanitizingLogger<T>` nameable creates a host-shadowing risk,
closed by a hard-failing startup gate that runs before every other check and rejects an unexpected
open-generic implementation or any closed-generic override.

**No Microsoft.IdentityModel types on the public surface.** They would bake a large, fast-moving
third-party surface into the SemVer contract. The JWK mapping is hand-rolled over BCL types, fully
specified by RFC 7517/7518 and held to known-answer vectors — a cost taken deliberately over the dependency.

**One signing provider per application, and nothing is registered for the source.**
`AddZeeKayDaSigningKeySource<TSource>()` (both overloads) enforces this with an internal marker: a second
call always throws, whichever overload either used and whether or not `TSource` matches. A same-type
repeat is deliberately not a no-op — a provider registers its source *and* configures options beside it,
so a "harmless" duplicate still applies a second configuration callback. A manual `ISigningKeyRing` also
throws, but only one already registered; one added afterwards wins under MS DI's last-wins resolution,
undetectably. The ring factory re-validates the composed marker set. Providers still on the old contract
guard on `IJwtSigningService` until #511 deletes it; the mixed ordering it cannot see is accepted.
`ISigningKeySource` itself is never registered: the ring factory constructs it directly, unreachable from
the container, owns its lifetime alongside the signer's, disposing it once at shutdown normally after the
signer, and rejects `IAsyncDisposable` without `IDisposable` at registration and construction.

**Each production provider platform is its own package; the development provider is not.**
`ZeeKayDa.Auth.AzureKeyVault` (remote and cached variants together — same dependency, same operational
context, so the choice is a method call, not a package swap), `ZeeKayDa.Auth.Windows` (Windows-only TFM, so
a mismatched restore fails at build time), `ZeeKayDa.Auth.FileSystem` (portable; only Microsoft runtime
packages). Each references core only, never the ASP.NET Core adapter, and exposes nothing but its
registration methods and options type — package identity is permanent once published. The development
provider stays in core, with no platform to isolate.

**`ZeeKayDa.Auth.FileSystem` and `ZeeKayDa.Auth.Windows` hold narrow `InternalsVisibleTo` grants**
from core, for POSIX `stat`/`lstat` interop and process-identity diagnostics respectively — forking
security-critical, ABI-fragile interop would risk a second, independently-drifting copy of code that
already needed a security fix. Reviewed exceptions for assemblies shipping in lockstep with core,
not a pattern: anything expressible through core's public surface must use it.

## Tried, didn't work

- **A single rotating-source tier with one shared check interval.** Ratified and shipped, reversed
  two weeks later. File/PFX/certificate-store and Key Vault share no model — only a *name*, covering
  both an internal clock tick over a fixed timeline and a real external poll cadence and kill-switch
  reaction time. Every documentation fix had to read "X for Key Vault but Y for File". Anyone
  considering re-unifying the tiers should stop here.
- **An `Enabled`/disabled flag on the provider contract.** It only ever meant "this Key Vault version
  is enabled", and forced every provider to carry a concept most had no equivalent for. Kill-by-
  omission plus the within-window `Warning` and the completeness contract preserve its one real
  capability without the provider-conditional special case.
- **A whole-set change-detection hook alongside refresh.** It avoided re-downloading private material on a
  poll where nothing had rotated. Once listings became public-only data and signer creation was gated on
  the active key changing, that was the default behaviour, so the hook was deleted rather than ported.
- **`InternalsVisibleTo` for the shared signing helpers.** The Azure Key Vault provider's first
  attempt. It can serve exactly one first-party package and can never serve a third party without a
  new core release naming them. Public contracts with internal crypto is the fix.
- **The development-key environment gate on the shared server options root.** Shipped, then reverted:
  it conflated the gate's input (server-wide host environment name) with its policy (feature-scoped,
  inert unless a development-key method was called). Now lives on the provider's own options type.
- **A hand-rolled key-pairing check inside the Windows Certificate Store provider.** Added after a
  security-review finding, then superseded — the same invariant is now proven generically on every
  handoff, for every provider.
- **`EphemeralKeySet` to keep a non-active PFX bundle's key off disk.** Platform-conditional (macOS throws)
  and it still materialises the key. Never decrypting the key bag beats it everywhere.
- **A macOS Keychain signing provider.** Implemented and reviewed, then descoped: the file-system
  provider already covers macOS and Linux without native interop.
