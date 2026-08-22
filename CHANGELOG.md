# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
