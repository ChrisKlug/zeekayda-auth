# Signing keys

## Decisions in force

**One interface, two methods, and callers never hold a key.** `IJwtSigningService` lives in core;
signing is a protocol concern, not a web one. `SignAsync` selects the active key, builds the JWS
header, and signs in one call, so a token's `kid`/`alg` can never disagree with the key that signed
it. No `VerifyAsync` — verifying client-owned keys is a separate seam — and no `RotateAsync`, since
whatever owns the keys owns their schedule. `SigningAlgorithm` has no `none` member and never will.

**Providers return data, not key objects.** `JwtSigningService<TOptions>` is the base every provider
derives from. `ListKeysAsync` returns public-only listings; `CreateSignerAsync` lends a signer for
the one key the base has already selected as active, never for a future, retired, or non-active key.
Because a provider never holds a private-key object, aliasing or mis-ordering one across listings is
unrepresentable; keeping non-active private material out of memory stays a provider obligation for
bundled formats. `ISigner.Dispose` releases only the handle that instance introduced — the base
disposes it on active-key change, so a signer over a shared SDK client must not close that client.

**The framework derives every `kid`; a provider cannot supply one.** The base computes an RFC 7638
JWK thumbprint over the public key. A provider supplies only its own internal `KeyId`, so it cannot
express a `kid` that leaks a vault URI, certificate thumbprint, or file path into every issued token.

**A second, expand-only signing model sits beside `JwtSigningService<TOptions>` until the old model is
deleted, in two tiers: `KeySetOptions` for a fixed set an operator edits directly, `KeySourceOptions`
for a set a provider polls from an external store.** Keys are three named slots —
`Previous`/`Current`/`Next`, `Current` required, the other two independently optional. `SourceKeySet.Create`
rejects a missing `Current`, so a provider cannot express "no signer." `SigningKeySetBuilder.Build` is
the single pure choke point from `SourceKeySet` to `SigningKeySet`: no clock, no policy, no I/O,
always derives `kid` via `JwkThumbprint`, and every rejection throws `ZeeKayDaConfigurationException`
before any private material exists. `StaticSigningKeyRing` reads its `ISigningKeySource` once at
startup, self-tests the signer with a fresh per-invocation nonce, and owns that signer for the process
lifetime. `SigningKeySet.SigningKey` stays non-nullable: there is no reachable state here without a
signing key, and because `ISigningKeyRing` is framework-sealed, a future polling ring can add
`SigningKeyOrNull`/`IsSigning` additively instead of a breaking null check.

**The single-key bootstrap exemption belongs to the fixed tier only.** A lone eligible key is active
on `KeySetOptions`; on `KeySourceOptions` it is not, so a listing shrunk to one key by revocation
cannot re-arm the exemption on restart or scale-out. Dispatch is on the options type.

**One timeline engine, and the operator sets only `ActivateAt`.** `SigningKeyRotation` is a pure
function over immutable public data that both tiers call. Every other instant is derived —
`PublishAt = ActivateAt − PublicationLead`, and a key stays in the JWKS until its successor's
activation plus the retirement window — so there is no deactivation knob and a too-short overlap is
unrepresentable.

**`PublicationLead` is durable and `ActivateAt`-derived, never observed-first-seen.** A provider maps
its store's own durable timestamp onto `ActivateAt` so the lead survives restarts and replicas;
in-memory first-seen bookkeeping is banned. `KeySourceOptions` enforces
`PublicationLead >= RefreshInterval`, so a key cannot activate before the process would poll and
notice it; on `KeySetOptions` the operator owns activation timing and the lead only drives a warning.

**`RetirementWindow` is derived, never a user setting.** It is
`max(access-token lifetime, ID-token lifetime, 1-hour floor)` plus the configured clock-skew
allowance, measured from a successor becoming active; every off-default value is unsafe or useless.
Refresh-token lifetime is excluded — relying parties never validate refresh tokens against the JWKS.
The floor is the only live term until token lifetimes become configurable; the derivation then
changes in place, not into an option. Security signed off.

**Omission is the kill switch; there is no `Enabled` flag.** A `KeySourceOptions` provider lists a
key for exactly as long as it should be trusted, so revoking or deleting it in the backing store
drops it from the JWKS on the next refresh, retirement window or not. Omission is a three-state
signal: a vanish after the retirement window closes is routine; a vanish *inside* it still drops the
key but MUST emit a `Warning`, never downgraded, as the only accidental-omission detector; and a
provider that cannot read its set completely MUST throw, so a store error never reads as revocation.

**Every active-signer handoff is self-tested before the signer is used.** The base signs a fixed,
non-JWS-shaped constant and verifies it against that key's own published public key, in the single
choke point every handoff passes through, so a key rotated days later is proven as thoroughly as the
one active at boot. Materialization alone is not enough: a signer can construct successfully over
material that does not pair with the published key. It is unconditional with no HSM opt-out, and a
framework-owned startup verifier forces the first handoff eagerly rather than leaving it to the first
token request. Any failure, mismatch or transient, fails the handoff closed. No sign-off covers it.

**All load-time validation runs on public data.** Key/algorithm compatibility, RSA modulus size
(2048-bit minimum), NIST-curve-only EC keys, and rejection of duplicate provider key ids and
duplicate derived `kid`s all run when listings are read, before any private material is loaded,
throwing `ZeeKayDaConfigurationException`.

**Development signing keys are one line, and hard-gated on environment.** The persistence choice
lives in the method name rather than a `null` argument. The allowed-environment list is reachable
only through the registration callback, never bindable configuration, so a committed
`appsettings.json` cannot widen it; `Production` is rejected unconditionally, and any
non-`Development` entry logs `Critical` on every startup. Persisted keys are plain PEM with directory
and file permissions set atomically at creation (`0700`/`0600` on POSIX, a restrictive non-inherited
ACL on Windows), never create-then-chmod, and loading fails closed on a broader mode, a symlinked
path, or a directory not owned by the current user.

**Extension contracts are public in core; ZeeKayDa's own crypto and redaction stay internal.**
`InternalsVisibleTo` can only name first-party assemblies at build time, so it structurally cannot
serve a third-party provider package. Making `ISanitizingLogger<T>` nameable creates a host-shadowing
risk, closed by a hard-failing startup gate that runs before every other startup check and rejects
an unexpected open-generic implementation or any closed-generic override.

**No Microsoft.IdentityModel types on the public surface.** They would bake a large, fast-moving
third-party surface into the SemVer contract. The JWK mapping is hand-rolled over BCL types, fully
specified by RFC 7517/7518 and held to known-answer vectors — a maintenance cost taken deliberately
over the dependency.

**One signing provider per application, registered flatly.** The old model's
`Add<Provider>Signing()` extensions register `IJwtSigningService` as a singleton and call
`ThrowIfAlreadyRegistered` so a second provider fails loudly. The `KeySourceOptions` tier's
`AddZeeKayDaSigningKeySource<TSource>()` (type and factory overloads) enforces the same rule with an
internal `SigningKeySourceRegistration` marker, keyed under a private, unnameable object rather than
a string: the same `TSource` registered twice via the type overload is a no-op; a genuinely different
`TSource` throws; and a second registration of the same `TSource` throws whenever either call used
the factory overload, since a factory can close over configuration a silent no-op would discard.
Either way, environment-conditional provider selection stays an ordinary `if`/`else`.

**Each production provider platform is its own package; the development provider is not.**
`ZeeKayDa.Auth.AzureKeyVault` (remote and cached variants together — same dependency, same
operational context, so the choice is a method call, not a package swap), `ZeeKayDa.Auth.Windows`
(Windows-only TFM, so a mismatched restore fails at build time), `ZeeKayDa.Auth.FileSystem` (portable,
BCL-only). Each references core only, never the ASP.NET Core adapter, and exposes nothing but its
registration methods and options type — settled before any provider shipped, since package identity
is permanent once published. The development provider stays in core, with no platform to isolate.

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
- **A whole-set change-detection hook alongside refresh.** It avoided re-downloading private material
  on a poll where nothing had rotated. Once listings became public-only data and signer creation was
  gated on the active key changing, that became the default behaviour, so the hook and its comparison
  machinery were deleted rather than ported.
- **`InternalsVisibleTo` for the shared signing helpers.** The Azure Key Vault provider's first
  attempt. It can serve exactly one first-party package and can never serve a third party without a
  new core release naming them. Public contracts with internal crypto is the fix.
- **The development-key environment gate on the shared server options root.** Shipped, then reverted:
  it conflated the gate's input (the host environment name, genuinely server-wide) with its policy
  (feature-scoped, inert unless a development-key method was called). It now lives on the provider's
  own options type.
- **A hand-rolled key-pairing check inside the Windows Certificate Store provider.** Added after a
  security-review finding, then superseded — the same invariant is now proven generically on every
  handoff, for every provider.
- **A macOS Keychain signing provider.** Implemented and reviewed, then descoped: a production auth
  server is not a realistic macOS-hosted workload, and the file-system provider already covers
  macOS and Linux without native interop.
