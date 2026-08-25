# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`AddZeeKayDaSigningKeySource` now accepts a factory, for signing key sources that cannot be DI-activated, and nothing is registered in the container for the source itself** (#525, #530)

  `AddZeeKayDaSigningKeySource<TSource>(this IServiceCollection services, Func<IServiceProvider, TSource> implementationFactory)`
  constructs `TSource` via a factory instead of DI activation, for a source whose constructor needs a
  connection string, a slot name, or a pre-built client — for example an HSM or KMS integration owned
  by a third-party package. Both overloads funnel through the same one-source-per-application guard:
  a second registration throws `InvalidOperationException`, whichever overload either call used and
  whether or not `TSource` matches, naming both the rejected and the incumbent source with their full
  type and assembly names. A repeat registration of the same type is deliberately not a no-op — a
  provider's `Add<Provider>Signing()` method registers the source *and* configures its options beside
  it, so a second call treated as a no-op here would still have applied a second configuration
  callback. Passing an abstract type or interface (including `ISigningKeySource` itself) as
  `TSource` throws `ArgumentException`.

  The guard also covers composition: when two independently-built `IServiceCollection`s each
  registered a signing key source and are composed into one host, resolving `ISigningKeyRing` throws
  `ZeeKayDaConfigurationException` (`signing.source_registration_mismatch`) — whether the composed set
  names two different source types or the same one twice, since each collection also configured that
  source's options and only one of those configurations describes what the application actually signs
  with. The check runs before the source is constructed, so a failing composition never executes the
  winning registration's side effects.

  Nothing is registered in the container for `ISigningKeySource` at all — the `ISigningKeyRing`
  factory constructs and owns the source directly, by `ActivatorUtilities` or the caller's factory
  closure, so it is not reachable via `GetService`, `GetServices`, or any keyed lookup. **A
  third-party source author must act on one rule as a result: the ring, not the container, now owns
  the source's disposal.** It disposes the source once, at shutdown, after the `ISigner` it opened —
  via `IDisposable.Dispose` or `IAsyncDisposable.DisposeAsync`, whichever the host's own disposal path
  selects — except when `Dispose`/`DisposeAsync` races `InitializeAsync` before the signer is
  committed, in which case the source is disposed first and the signer once `InitializeAsync`
  completes and observes the disposed flag. A source implementing `IAsyncDisposable` without also
  implementing `IDisposable` is rejected with `ArgumentException`, both at registration on
  `typeof(TSource)` and by `StaticSigningKeyRing`'s own constructor on the actual constructed
  instance — so that shape can never reach a running ring, and nothing throws at shutdown.

  Registering an *unkeyed* `ISigningKeyRing` directly, ahead of `AddZeeKayDaSigningKeySource`, is
  rejected: it throws `InvalidOperationException` naming the offending descriptor's implementation type
  (or its factory/instance shape when there is no implementation type to name). A keyed
  `ISigningKeyRing` descriptor is ignored, since it can never win the unkeyed resolution the guard and
  the framework both use. This closes only the ordering the call can actually observe — an
  `ISigningKeyRing` already registered at the moment it runs. A manual `ISigningKeyRing` registered
  *after* `AddZeeKayDaSigningKeySource` wins outright under MS DI's last-registration-wins resolution
  and is not detectable from this method.

### Changed

- **BREAKING: PFX file signing is now an `ISigningKeySource` with three named key slots, and a published-only bundle's private key is never decrypted** (#517)

  `AddPfxFileSigning` no longer registers an `IJwtSigningService`. It registers a
  `PfxFileSigningKeySource` and a `StaticSigningKeyRing` over it, and gains a second overload for the
  three named slots, mirroring `AddPemFileSigning`:

  ```csharp
  // One signing key, no rotation staged — unchanged from before.
  .AddPfxFileSigning("/etc/zeekayda/signing/tls.pfx", SigningAlgorithm.RS256, ReadPassword);

  // The three slots, each with its own password.
  .AddPfxFileSigning(SigningAlgorithm.RS256, options =>
  {
      options.Previous = new PfxFile("/etc/zeekayda/signing/previous.pfx", ReadPreviousPassword);
      options.Current  = new PfxFile("/etc/zeekayda/signing/current.pfx", ReadCurrentPassword);
      options.Next     = new PfxFile("/etc/zeekayda/signing/next.pfx", ReadNextPassword);
  });
  ```

  `PfxFileSigningOptions` loses its `KeySetOptions` base (and with it `PublicationLead`), its `Path`,
  `PasswordSource`, `AddFile` and `AdditionalFiles` members, and carries `Previous`/`Current`/`Next`
  plus `Algorithm`, whose setter is now internal. `Current` is required; `Previous` and `Next` are
  independently optional. Every slot carries its own password source — a published-only bundle's
  certificate sits inside a password-protected safe — and two slots naming the same file is a startup
  failure. The path overload takes no `configure` callback.

  **A `Previous` or `Next` bundle's private key is never imported into a key object.** PKCS#12 bundles
  the certificate and key together, so keeping non-active private material out of reach is this
  provider's own obligation rather than something the framework can enforce. The read path now
  discharges it by walking the bundle with `Pkcs12Info`: the password authenticates the file and
  decrypts the authenticated safe, the certificate bag is read, and no key bag is ever decrypted or
  imported. `X509CertificateLoader.LoadPkcs12`, which would import one, is reached only when
  `Current`'s signer is opened. That holds on every platform, so the transient on-disk key-container
  residue this provider used to risk on Windows is now unreachable for the published-only slots rather
  than merely narrowed.

  **A bundle must now authenticate against its configured password, and must identify which
  certificate signs.** Two consequences follow, and both can reject a bundle that previously loaded:

  - The bundle's MAC is verified against the configured password, and a bundle carrying no password
    MAC is rejected outright. Without this the password is not a control on the read path at all: a
    bundle whose certificate sits in an unencrypted safe is never asked for one, so any password —
    and any substituted file — would be accepted. Because `Previous` and `Next` are published but
    never signed with, nothing downstream would have caught it; their public keys would simply appear
    in the JWKS as valid verification keys.
  - The certificate reported is the one paired with the bundle's private key by its `localKeyId`
    attribute, not the first certificate in the file. PKCS#12 imposes no bag ordering, so a bundle
    carrying a chain can store an issuer's certificate first. Publishing that instead would put a key
    nothing can sign with into the JWKS while the tokens the real key signed carry a `kid` that is no
    longer published. A bundle with several certificates and nothing identifying the signer is
    rejected rather than guessed at.

  Otherwise as for PEM: which key signs is decided entirely by which slot it is configured in, the
  single-key bootstrap exemption is gone, `NotBefore`/`ExpiresAt` come from the certificate, and the
  provider's own algorithm/key-type check is deleted in favour of `SigningKeySetBuilder`'s. File
  permission enforcement and symlink rejection are unchanged, and apply to every configured slot.

  `ZeeKayDa.Auth.FileSystem` picks up a `System.Security.Cryptography.Pkcs` package reference for the
  managed PKCS#12 parsing — already used by `ZeeKayDa.Auth.AzureKeyVault` for the same purpose, and
  internal to both, so no type from it reaches the public surface.

- **BREAKING: PEM file signing is now an `ISigningKeySource` with three named key slots** (#516)

  `AddPemFileSigning` no longer registers an `IJwtSigningService`. It registers a
  `PemFileSigningKeySource` and a `StaticSigningKeyRing` over it, and gains a second overload for
  configuring the three named slots the framework's rotation model uses:

  ```csharp
  // One signing key, no rotation staged — unchanged from before.
  .AddPemFileSigning("/etc/zeekayda/signing/tls.pem", SigningAlgorithm.RS256);

  // The three slots.
  .AddPemFileSigning(SigningAlgorithm.RS256, options =>
  {
      options.Previous = new PemCertificateFile("/etc/zeekayda/signing/previous.pem");
      options.Current  = new PemSigningFile("/etc/zeekayda/signing/current.pem");
      options.Next     = new PemCertificateFile("/etc/zeekayda/signing/next.pem");
  });
  ```

  **Only `Current` has a type that can name a private key.** `Current` is a
  `PemSigningFile(string Path, string? KeyPath = null)`; `Previous` and `Next` are a
  `PemCertificateFile(string Path)` with no `KeyPath` member at all. Since only `Current`'s private
  key is ever opened, naming one for a published-only slot could never do anything but leave a file
  the framework promises to permission-check and never opens — so it is unrepresentable rather than
  rejected. Promoting a staged key is consequently not an assignment: a slot that starts signing
  names its private key for the first time, and the key it succeeds stops naming one at the moment it
  stops signing.

  `PemFileSigningOptions` loses its `KeySetOptions` base (and with it `PublicationLead`), its `Path`,
  `KeyPath`, `AddFile` and `AdditionalFiles` members, and carries `Previous`/`Current`/`Next` plus
  `Algorithm`. `Current` is required; `Previous` and `Next` are independently optional. Two slots
  naming the same file is a startup failure. `PemFileRegistration` is renamed `PemSigningFile` and is
  now a slot value rather than an appended registration. `Algorithm`'s setter is internal, so the
  algorithm is said exactly once, in the registration argument. The path overload takes no
  `configure` callback, so the file it names is unambiguously the one that signs.

  **Nothing verifies that a key was staged as `Next` before it was promoted.** With a fixed,
  operator-edited list there is no observed history to check against, so staging a successor long
  enough ahead for relying parties to have re-fetched the JWKS is the operator's decision. Replacing
  `Current` in place and restarting is accepted silently. This is what the removed `PublicationLead`
  warning used to hint at, on a model that no longer applies.

  **Which key signs is now decided entirely by which slot it is configured in, never by the clock.**
  Certificate `NotBefore` no longer selects among registered files, and the single-key bootstrap
  exemption is deleted: a `Current`-only configuration is the active signer through ordinary slot
  selection, with no special case. A certificate whose validity window has not opened belongs in
  `Next`; configuring it as `Current` fails startup (`signing.signing_key_not_yet_valid`).

  The slots are read once, at startup, and never re-read. Replacing or deleting a configured file
  afterwards has no effect on what the process signs with or publishes until it restarts. Only
  `Current`'s private key is ever read: a `Previous` or `Next` private key is never loaded into the
  process at all.

  The provider no longer performs its own algorithm/key-type check, so
  `signing.file_signing.algorithm_key_type_mismatch` is gone. `SigningKeySetBuilder` rejects the same
  mismatch centrally as `signing.key_algorithm_mismatch`, plus EC curve pairing the provider's check
  did not cover, keyed on the configured file path so the failure still names the file. File
  permission enforcement, symlink rejection, and PEM parsing are unchanged.

- **A signing key source can report its keys' `NotBefore`, and the ring rejects a `Current` that is not valid yet** (#516)

  `SourceKey` gains an optional `NotBefore`, carried through to `SigningKey`. It is a fact about the
  credential, like the `ExpiresAt` already there — the two ends of one validity window — and neither
  decides which key signs. `StaticSigningKeyRing.InitializeAsync` now fails startup with
  `signing.signing_key_not_yet_valid` when the signing key's window has not opened, the mirror of the
  existing `signing.signing_key_expired` check. Both checks apply to the signing key alone and never
  to the published set: staging a key before its window opens is the entire point of the `Next` slot.
  A source whose keys carry no validity window reports `null` and is unaffected.

  The not-before end carries a fixed, non-configurable five-minute clock-skew grace; the expiry end
  carries none. Nothing outside the process can observe a key's `NotBefore` — it is not a JWK member
  and no certificate is published — so signing a few minutes early is undetectable, while a host clock
  trailing the machine that minted the credential would otherwise fail an entirely correct deployment.
  An expired key has a real observer in every relying party validating a token, so it stays exact.

- **BREAKING: the development signing key provider is now an `ISigningKeySource` served through the signing key ring** (#512)

  `AddInMemoryDevelopmentJwtSigningKeys()` and `AddPersistedDevelopmentJwtSigningKeys()` keep their
  names and their configuration surfaces, but now register a `DevelopmentSigningKeySource` and a
  `StaticSigningKeyRing` over it instead of an `IJwtSigningService`. An application that resolved
  `IJwtSigningService` to reach the development key must resolve `ISigningKeyRing` instead. The
  environment gate, the `0700`/`0600` file permissions, and the fail-closed checks on a broader mode,
  a symlinked path, or a directory owned by another user are all unchanged.

  `DevelopmentSigningKeyOptions` no longer derives from `KeySetOptions`, so its inherited
  `PublicationLead` property is gone — a single generated key under a read-once ring has no
  publication lead to configure. The development key is now reported with no expiry at all rather
  than an expiry of `DateTimeOffset.MaxValue`, so the signing key expiry health check reports it as
  a key that never expires instead of computing a remaining lifetime in millennia.

  The startup verifier that emits the development-key warning no longer pre-warms the key: the ring's
  own startup verifier already reads the source and self-tests its signer before the host accepts
  traffic, so file I/O and permission failures still surface at startup, not on the first token.

- **BREAKING (behavioral): the advertised-signing-algorithm startup check now also enforces that every currently-or-soon producible algorithm is advertised, and no longer treats a retirement-window key as producible** (#494)

  `AdvertisedSigningAlgorithmVerifier` previously derived the set of "algorithms the provider can
  produce" from the full result of `IJwtSigningService.GetSigningKeysAsync`, which includes
  retirement-window keys kept only so already-issued tokens can still be verified. A host that
  rotated its signing algorithm (e.g. RS256 -> ES256) but left `IdToken.SigningAlgValuesSupported`
  unchanged would pass startup as long as the old RS256 key was still inside its retirement window,
  even though every new token was actually signed ES256. That "producible" set is now derived from
  a new `ISigningKeyProducibility` interface — implemented by `JwtSigningService<TOptions>`, so
  every in-box provider gets it for free — which reports only the active key's algorithm plus any
  not-yet-active (staged) key's algorithm, explicitly excluding retirement-window-only keys.

  The check is also no longer one-directional: it now asserts full set equality between what is
  advertised and what is producible. Every algorithm the provider can currently or soon produce —
  the active key's algorithm, and the algorithm of any staged key — must itself be present in
  `IdToken.SigningAlgValuesSupported`, failing with a new `signing.producible_algorithm_not_advertised`
  code if it is not. This catches both a host that signs with an algorithm it does not advertise
  (the "signs with whatever it has, discovery lies" scenario), and an operator who stages a new
  key's algorithm before updating the advertised list — previously invisible until that key
  actually became the active signer, since startup verification is one-shot.

  **A previously-booting host may now fail startup** if its active or staged signer's algorithm was
  not advertised, or if an advertised algorithm has no key at all — active, staged, or retiring —
  able to sign or verify with it. An advertised algorithm backed *only* by a retirement-window key
  (normal for as long as a migration's retirement window stays open) is a `signing.advertised_algorithm_retirement_window_only`
  warning, not a failure — it becomes one once that key itself is gone. A custom, out-of-tree
  `IJwtSigningService` implementation that does not implement `ISigningKeyProducibility` is
  unaffected by any of this — the check is skipped for it, with a
  `signing.advertised_algorithm_check_skipped` warning logged instead.

- **BREAKING: `SigningKeyRotation.SelectActiveKey`'s bootstrap-exemption flag replaced by two entry points** (#449)

  The `bool supportsBootstrapExemption` parameter is removed. `SelectActiveKey(timeline, now)`
  now always applies `KeySourceOptions` (Tier B) semantics — never grants the single-key
  bootstrap exemption — and a new `SelectActiveKeyForFixedKeySet(timeline, now)` applies
  `KeySetOptions` (Tier A) semantics — always exempts a lone registered key. A caller
  previously passing `true`/`false` should call `SelectActiveKeyForFixedKeySet`/`SelectActiveKey`
  respectively; behavior for each tier is unchanged, only the call shape.

- **BREAKING: legacy signing-provider contract removed** (#428)

  `SigningKeySet`, `SigningKeyPair`, `RotatingKeySourceOptions`, and `StaticKeySourceOptions` are
  deleted, along with `JwtSigningService<TOptions>.LoadKeysAsync`, `HasKeySetChangedAsync`,
  `SignInputAsync`, `SigningKeyRotation.ToChangeDetectionSet`, and the two-argument
  `JwtSigningService(IOptions<TOptions>, TimeProvider)` constructor. `ListKeysAsync` and
  `CreateSignerAsync` are now `abstract` — every
  provider must implement the `KeySetOptions`/`KeySourceOptions` contract; there is no longer a
  throwing default for providers still on the old shape. All in-box providers (development,
  file/PEM, PFX, Windows Certificate Store, Azure Key Vault) already migrated in #421-#425 and are
  unaffected. A custom `IJwtSigningService` implementation still on the old contract will not
  compile against this version — see [Implement a custom signing
  provider](docs/how-to/implement-custom-signing-provider.md) for the current contract.

  `KeyRotationCheckInterval`, `SigningKeyActivationDelay`, and `AssumedJwksPropagationDelay` are
  also removed; use `KeySourceOptions.RefreshInterval` and `PublicationLead` instead (already the
  case for every in-box provider since #421-#425).

  A `KeySetOptions`/`KeySourceOptions` provider that registers two `KeyListing`s sharing the same
  `Id.Value` now fails fast with `signing.duplicate_key_id` at snapshot-build time, matching the
  existing duplicate-derived-`kid` rejection.

- **BREAKING (behavioral default change): Azure Key Vault signing providers migrated to the `KeySourceOptions`)** (#425)

  `AzureKeyVaultRemoteSigningOptions` and `AzureKeyVaultCachedSigningOptions` now derive from
  `KeySourceOptions` instead of the older `RotatingKeySourceOptions`. `KeyRotationCheckInterval`
  is replaced by `RefreshInterval`, and `SigningKeyActivationDelay` is replaced by
  `PublicationLead` (defaulting to `RefreshInterval` when left unset).

  **The default poll cadence changes from 5 minutes to 1 hour.** This is also the default
  cadence at which the provider notices an emergency revocation — disabling a compromised key
  version in Key Vault. If your incident-response plan assumes a revoked key stops signing
  within minutes, set `RefreshInterval` explicitly to a shorter value; do not rely on the new
  default. See [Configure Azure Key Vault signing](docs/how-to/configure-azure-key-vault-signing.md)
  and [Rotate signing keys](docs/how-to/rotate-signing-keys.md).

  The single-key bootstrap exemption (a lone registered key activates immediately, bypassing
  `PublicationLead`) no longer applies to this provider at all, on any refresh — including its
  very first one after a process restart. It remains scoped to Tier A (`KeySetOptions`) providers,
  whose key set is fixed for the process lifetime and so has no equivalent exposure. This closes a
  bypass where an operator disabling every other version as part of an emergency revocation (e.g.
  down to one surviving key still inside its `PublicationLead` window) could have that key
  promoted immediately regardless of `PublicationLead` — including if the process also restarted
  or a new instance scaled out while the revocation was still in effect, which a cold-start-only
  gate would not have caught. A genuinely first-ever-provisioned key on this provider does not
  need the exemption anyway: it is already eligible from startup via its own durable
  `ActivateAt = null` encoding for the chronologically-first version.

### Added

- **`ISigningKeyProducibility` and `SigningKeyProducibilitySnapshot`** (#494)

  New optional signing-provider interface reporting which algorithms an `IJwtSigningService` can
  sign a new token with right now or soon (the active key's algorithm, plus any staged key's
  algorithm). Backs the advertised-signing-algorithm startup check described above; every in-box
  provider implements it via `JwtSigningService<TOptions>`.

- **`SigningKeyRotation.SelectFutureSigners`** (#494)

  New method selecting every timeline entry that is not yet active but could still legitimately
  become the active signer once its own activation time arrives, excluding a staged key that would
  already be expired by the time it could take over. Used by `ISigningKeyProducibility`'s
  implementation to derive the staged-algorithm set.

- **`ZeeKayDa.Auth.AzureKeyVault` package — Azure Key Vault remote signing** (#287)

  New NuGet package, the first production `IJwtSigningService` provider.
  `AddAzureKeyVaultRemoteSigning(keyIdentifier, credential, configure?)` on `ZeeKayDaAuthBuilder`
  registers a signing provider where every JWT signature is produced by a live call to Key
  Vault's `CryptographyClient` — the private key never leaves the vault and is never held in
  process memory. Supports real multi-key rotation with overlapping validity windows, derived
  entirely from Key Vault's own durable per-version `CreatedOn`/`NotBefore` timestamps (restart-
  safe and consistent across load-balanced replicas). `kid` is the RFC 7638 JWK thumbprint of
  each key version's public key, not the raw Key Vault URI, so no vault/key name is disclosed via
  a token header or the JWKS.

- **`JwtSigningService<TOptions>.SignInputAsync` — overridable async signing hook** (#287)

  New `protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(SigningKeyPair activeKey,
  byte[] signingInput, CancellationToken cancellationToken)` on the core
  `JwtSigningService<TOptions>` base class. The default body reproduces the prior synchronous
  local-signing behaviour exactly, so this is additive and binary-compatible with
  `DevelopmentJwtSigningService` and any existing provider. Overriding it is what makes a genuine
  remote/network signer (such as Azure Key Vault) possible without blocking a thread for the
  round trip; header construction, active-key selection, and `kid`/`alg` fixation remain
  non-overridable.

- **`ISigningKeyRetirementWindowProvider`** (#287)

  New core service implementing the `RetirementWindow` derivation (`1 hour +
  ClockSkewTolerance`, until configurable per-token lifetimes exist), registered in
  `AddZeeKayDaAuthCore()`. First consumed by the Azure Key Vault remote signing provider.

- **`ZeeKayDa.Auth.Tokens.JwkThumbprint` — public RFC 7638 JWK thumbprint utility** (#287)

  New public static class computing RFC 7638 JSON Web Key SHA-256 thumbprints for RSA and EC
  public keys, extracted from logic previously private to the development signing provider. Lets
  any `JwtSigningService<TOptions>` author — first-party or third-party — derive a safe,
  non-leaking `kid` from a public key without hand-rolling RFC 7638 canonicalisation themselves.
  `DevelopmentJwtSigningService` now calls this shared helper with no change in the `kid` values
  it produces.

- **`ZeeKayDa.Auth.Logging.ISanitizingLogger<T>` is now public** (#287)

  Previously `internal`. Made public so that packages referencing only core `ZeeKayDa.Auth` —
  such as `ZeeKayDa.Auth.AzureKeyVault`, and genuine third-party signing/storage providers — can
  constructor-inject the framework's sanitizing-logger contract without `InternalsVisibleTo`,
  which can only ever name first-party assemblies at build time. `SecretSanitizingLogger<T>` (the
  concrete implementation) and its redaction-key allowlist stay `internal`. A new hosted service,
  `SanitizingLoggerRegistrationStartupValidator` — registered first among `AddZeeKayDaAuth()`'s
  hosted services — fails startup with a `ZeeKayDaConfigurationException` if a host registration
  has shadowed the framework's `ISanitizingLogger<>` at either the open-generic level (a
  replacement registered before or after `AddZeeKayDaAuth()`) or a closed-generic level (an
  override for one specific type), since either would silently disable credential
  redaction for the entire application.

- **`AuthorizationServerOptions.Logging.DisableExceptionSanitizing` config opt-out** (#173)

  New development opt-out. Set to `true` in `appsettings.Development.json` to have
  `SecretSanitizingLogger` pass exception objects to the underlying logger unchanged rather than
  wrapping them. A `LogLevel.Warning` is emitted at startup when this opt-out is active. Never
  enable in production. See [Configure host-level log hygiene](docs/how-to/configure-host-log-hygiene.md)
  for full guidance.

### Changed

- **BREAKING: `SecretSanitizingLogger` now unconditionally wraps all logged exceptions** (#173)

  All exceptions passed to `SecretSanitizingLogger` are wrapped in `RedactedExceptionWrapper`,
  replacing the exception `Message` with `[exception message redacted by SecretSanitizingLogger]`
  before the exception reaches any log sink. This is a **breaking behaviour change** for consumers
  who relied on exception messages appearing verbatim in their log sinks (for example, custom log
  enrichers that read `ex.Message` after the fact). Set `AuthorizationServerOptions.Logging.DisableExceptionSanitizing`
  to `true` in `appsettings.Development.json` to restore the previous behaviour.

### Removed

- **`ResponseMode.Fragment` enum member removed** (#160)

  Fragment response mode was configurable but permanently unsupported. Removing it prevents silent
  no-ops when operators configure it. Use `ResponseMode.Query` or `ResponseMode.FormPost`.

### Changed

- **`ScopeDefinition.IdTokenClaims` and `AccessTokenClaims` marked `[Experimental("ZKD001")]`** (#160)

  These properties are public but ahead of the claims ADR that will define their semantics. Mark
  with `[Experimental]` to signal instability. Suppress diagnostic `ZKD001` if you reference them.

- **`PromptValue` enum members now serialise to correct OIDC wire values** (#160)

  `JsonConverter` and `JsonStringEnumMemberName` attributes added so `PromptValue` round-trips
  correctly over JSON: `None` → `"none"`, `Login` → `"login"`, `Consent` → `"consent"`,
  `SelectAccount` → `"select_account"`.

- **`AuthorizationServerOptionsValidator` now reports all configuration errors at once** (#160)

  Previously the validator returned on the first failure. It now aggregates all errors and returns
  them together, so a misconfigured server surfaces every problem in a single startup failure.

### Changed

- **BREAKING: `TokenEndpoint.AuthMethodsSupported` is now `ICollection<string>`** (#115)

  `TokenEndpointOptions.AuthMethodsSupported` changes from `ICollection<TokenEndpointAuthMethod>` to
  `ICollection<string>`, and `OpenIdConfigurationDocument.TokenEndpointAuthMethodsSupported` changes
  from `IReadOnlyCollection<TokenEndpointAuthMethod>` to `IReadOnlyCollection<string>`.

  Use the `TokenEndpointAuthMethods` string constants (`ClientSecretBasic`, `ClientSecretPost`,
  `None`) in place of the enum values. Custom authentication methods (e.g. `"tls_client_auth"`) can
  now be included as plain strings alongside these constants.

  The `TokenEndpointAuthMethod` enum is removed entirely.

  Startup validation now enforces that every entry is a non-empty, non-whitespace string with no
  leading/trailing whitespace and no control characters.

- **Harden discovery/protocol endpoint responses with configurable CORS + defensive headers** (#73)

  Discovery responses now support an optional immutable CORS allowlist via
  `DiscoveryDocument.CorsOrigins` (wildcard when empty; strict allowlist matching when configured).
  Startup validation canonicalizes and deduplicates origins, rejects invalid entries, and enforces
  HTTPS by default (HTTP loopback only when `AllowInsecureIssuer = true`).

  ZeeKayDa.Auth protocol endpoints now emit defensive headers via `SecurityHeaders` options:
  `X-Content-Type-Options`, `Referrer-Policy`, and `Cross-Origin-Resource-Policy`, plus
  `X-ZeeKayDa-Insecure-Issuer: true` when insecure issuer mode is enabled for local development.

- **BREAKING: Remove hybrid response type `code id_token` from `ResponseType`** (#29)

  ZeeKayDa.Auth now exposes authorization code flow only. `ResponseType.CodeIdToken` has been
  removed from the public enum, related discovery test coverage has been updated, and the
  configuration docs now state that hybrid and implicit response types are unsupported.

- **BREAKING: Refactor `AuthorizationServerOptions` into grouped nested options** (#51)
  
  `AuthorizationServerOptions` is reshaped from a flat class into grouped nested options aligned with the OIDC Discovery 1.0 specification structure. Grouping mirrors the spec's naming conventions (e.g., `token_endpoint_*` fields group under `TokenEndpoint`, `id_token_*` fields group under `IdToken`). Get-only group properties prevent nulling and preserve framework invariants.

  **Migration table (old → new property paths):**

  | Old (flat) | New (grouped) | Notes |
  |---|---|---|
  | `Issuer` | `Issuer` | Unchanged (server-wide) |
  | `AllowInsecureIssuer` | `AllowInsecureIssuer` | Unchanged (server-wide) |
  | `AuthorizationEndpoint` | `AuthorizationEndpoint.Uri` | Moved into group |
  | `TokenEndpoint` | `TokenEndpoint.Uri` | Moved into group |
  | `JwksUri` | `JwksEndpoint.Uri` | Moved into group |
  | `ResponseTypesSupported` | `Response.TypesSupported` | Moved into new group |
  | `ResponseModesSupported` | `Response.ModesSupported` | Moved into new group |
  | `GrantTypesSupported` | `GrantTypesSupported` | Unchanged (server-wide) |
  | `TokenEndpointAuthMethodsSupported` | `TokenEndpoint.AuthMethodsSupported` | Moved into group |
  | `IdTokenSigningAlgValuesSupported` | `IdToken.SigningAlgValuesSupported` | Moved into new group |
  | `DiscoveryDocumentCacheMaxAgeSeconds` | `DiscoveryDocument.CacheMaxAgeSeconds` | Moved into new group |

  **Example migration:**

  Before:
  ```csharp
  services.AddZeeKayDaAuth(opts =>
  {
      opts.Issuer = "https://auth.example.com";
      opts.TokenEndpoint = "https://custom.example.com/token";
      opts.ResponseTypesSupported = [ResponseType.Code];
      opts.TokenEndpointAuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
  });
  ```

  After:
  ```csharp
  services.AddZeeKayDaAuth(opts =>
  {
      opts.Issuer = "https://auth.example.com";
      opts.TokenEndpoint.Uri = "https://custom.example.com/token";
      opts.Response.TypesSupported = [ResponseType.Code];
      opts.TokenEndpoint.AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic];
  });
  ```

- **Add new validation rules for token endpoint client authentication**
  - `TokenEndpoint.AuthMethodsSupported` must not be null or empty
  - `TokenEndpoint.AuthMethodsSupported` must contain at least one non-`None` method if `GrantTypesSupported` includes `ClientCredentials` (RFC 6749 §4.4 compliance)

### Documentation

- **Clarify `ZeeKayDaConfigurationException.Message` is diagnostic-only** (#159)

  `Message` is not a stable API contract and must not be parsed or asserted on. The stable surface
  for programmatic handling is `AggregatedFailures` and the `Code` field on each
  `ZeeKayDaConfigurationFailure`. `Message` may change in any release without notice.

- **Formalise `SecurityHeaders` as a framework-behavior group** (#159)

  A second option-group category is now formally recognised — **framework-behavior groups** —
  for settings that control the framework's own runtime behavior with no discovery-document
  analogue. `SecurityHeaders` is confirmed correct; no rename is needed. Future framework-behavior
  groups must use a plain descriptive name with no `Endpoint` suffix.

[unreleased]: https://github.com/ChrisKlug/zeekayda-auth/compare/HEAD...HEAD
