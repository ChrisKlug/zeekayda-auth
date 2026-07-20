# ADR 0011 — Signing Key Management

**Status:** Accepted
**Date:** 2026-06-23 (original) · rewritten 2026-07-11 (issue #337)

> **Format note.** This ADR was migrated to the three-part format defined in
> [`docs/decisions/README.md`](./README.md) (current state · considered and rejected
> alternatives · changelog appendix) as part of issue #337. Its earlier chronological
> amendment log (amendments 1–8) has been folded into the current-state description below and
> reduced to pointer entries in the changelog appendix. Nothing substantive was dropped in the
> migration; the security sign-off provenance that used to live in the amendment log is
> preserved in the changelog appendix, and the sign-off that still governs today's design is
> restated inline where it applies.

> **Security sign-off required on this ADR PR.** The current state below derives a
> `RetirementWindow` that directly governs how long a retired signing key's *public* half stays
> published in the JWKS, and therefore how long relying parties will continue to accept
> signatures made by that key. This is a token-validation trust-boundary decision. The security
> agent MUST review and approve the `RetirementWindow` derivation (§3.3) and the JWKS exposure
> behaviour (§4.3) before this ADR is merged. The environment-gate invariants that issue #337
> re-homes (Production always rejected, mandatory `Critical` startup log, never sourced from
> bindable configuration) are unchanged by this rewrite and are also in scope for the review.

---

## Context

ZeeKayDa.Auth issues signed artifacts — ID tokens today, JWT access tokens and other
JWS-protected objects in the near future — and must publish the corresponding public keys
at the JWKS endpoint so relying parties can validate them. The `connect/jwks` endpoint is
currently a `501 Not Implemented` placeholder, and `DiscoveryDocumentProvider` already
advertises a derived `jwks_uri` (`src/ZeeKayDa.Auth/Discovery/DiscoveryDocumentProvider.cs`)
that points at it. The signing-algorithm vocabulary exists
(`src/ZeeKayDa.Auth/Tokens/SigningAlgorithm.cs`) and `id_token_signing_alg_values_supported`
is advertised from static configuration (`IdTokenOptions.SigningAlgValuesSupported`).

This ADR (issue **#187**) settles signing key management end to end: the provider
abstraction consumers implement to supply keys, the developer-experience helpers for local
work, the rotation and caching machinery, the token-pipeline integration, the JWKS
endpoint, and the explicit exclusion of JWT encryption from v1.

The design serves the same two goals every ZeeKayDa.Auth decision serves: it must be
**easy to use** (the local-development path is one line; the production path has exactly
one correct way to implement it) and **secure by default** (private key material never
leaves the signing component; insecure development shortcuts hard-fail outside Development).

### Constraints and prior decisions that shape this ADR

- **No Microsoft.IdentityModel on the public surface.** `Microsoft.IdentityModel.Tokens` types
  (`SecurityKey`, `SigningCredentials`, `JsonWebKey`, …) are convenient but a large, churning
  surface we do not want to bake into our own public contract. The abstractions here are
  expressed entirely in BCL types and ZeeKayDa-owned types. Any use of Microsoft crypto types is
  an *internal implementation detail* of a concrete provider, never visible on an interface,
  descriptor, or options class.
- **ADR 0002** (options shape — grouped nested per-endpoint options) governs where new
  configuration lives. Per-provider knobs live on a provider-specific options type; the
  discovery-prefix grouping rule that hoists prefix-less settings to the root governs OIDC
  discovery-document configuration specifically and does **not** license hoisting
  feature-registration escape hatches onto the shared root (see ADR 0002's scope clarification,
  and §2 / §3.6 below).
- **ADR 0006** (exception hierarchy) governs the failure type: startup/configuration faults
  throw `ZeeKayDaConfigurationException`.
- **ADR 0008** (authorization-code and refresh-token store) establishes the
  `AddXxx()`-on-`ZeeKayDaAuthBuilder` registration idiom, the `ThrowIfAlreadyRegistered`
  double-registration guard, the in-memory-store escape-hatch pattern (mirrored here), the
  precedent against empty options classes purely to hold a flag, and — load-bearing for §3.3 —
  the fact that **refresh tokens are validated by the authorization server against the token
  store, never by relying parties against the JWKS**. Refresh-token family revocation (ADR 0008
  §4) is an AS-side store operation; a relying party never inspects a refresh token's signature.
- **ADR 0012** (signing-provider NuGet packaging model) governs which provider ships in which
  package, and why the shared rotation/descriptor helpers this ADR extracts must be *public* in
  core rather than `internal` + `InternalsVisibleTo` (§3.5, §4.4).

---

## Current State

### 1. Provider abstraction — a single non-generic `IJwtSigningService`

A single **non-generic** interface, `IJwtSigningService`, is defined in `ZeeKayDa.Auth` (the
core package — signing is a protocol concern, not an ASP.NET Core concern). It has exactly
two methods.

```csharp
namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Supplies the authorization server's currently trusted signing keys and performs
/// signatures over JWS input. The active signing key and algorithm are selected by the
/// implementation; callers never choose a key or algorithm and never hold private key
/// material.
/// </summary>
public interface IJwtSigningService
{
    /// <summary>
    /// Returns every currently trusted signing key — the active key plus any keys still
    /// inside their retirement/overlap window. Excludes fully retired keys and
    /// not-yet-activated keys. These are exactly the keys that must appear in the JWKS.
    /// </summary>
    ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs the supplied base64url-encoded payload segment. The service constructs the JWS
    /// header internally, forms the signing input, signs, and returns the pre-encoded header
    /// and signature segments. The caller assembles header + "." + payload + "." + signature.
    /// </summary>
    ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default);
}
```

**`SigningKeyDescriptor`** is a ZeeKayDa-owned type carrying only `(string Kid,
SigningAlgorithm Algorithm, public key material)`. The public key material is expressed in
BCL terms — the descriptor exposes the public-only parameters needed to build a JWK
(see §4.4), not a Microsoft.IdentityModel `SecurityKey`. The descriptor carries **no
rotation state** (no "is-active", no "retires-at"): the contract of `GetSigningKeysAsync`
is precisely "the set of keys a relying party should currently trust," and that set is the
only thing the JWKS needs. Rotation bookkeeping is the provider's private concern (§3).

**`SignAsync`** takes the **base64url-encoded payload segment** — the caller base64url-encodes
the raw claims bytes; the service does not encode the payload. The service constructs the
JWS header internally: it selects the active key and its algorithm, builds the header JSON
`{"alg":"…","kid":"…"}`, base64url-encodes it, forms the full signing input
`base64url(header) "." base64url(payload)`, and signs it — all in a single atomic call.
It returns **`SigningResult`** — `(ReadOnlyMemory<byte> HeaderSegment,
ReadOnlyMemory<byte> SignatureSegment, string Kid, SigningAlgorithm Algorithm)`, where
`HeaderSegment` and `SignatureSegment` are already base64url-encoded. `ITokenWriter` (§4.1)
assembles the compact JWS: `header "." payload "." signature`.

Because the service builds the header in the same operation that selects the key and produces
the signature, the header's `kid`/`alg` and the actual signing key are **always consistent by
construction** — there is no window in which a key rotation can cause the header to advertise a
different key than the one that signed. There is no API path through which a caller can supply a
mismatched algorithm, choose the wrong key, or produce a header that disagrees with the
signature.

**`alg:none` is not representable.** `SigningAlgorithm` has **no** `none` member and MUST
never gain one; `none` MUST never appear in a JWS `alg` header emitted by ZeeKayDa. This is
enforced structurally by the enum — there is no value through which an unsigned token could
be produced — and is stated here as a normative invariant so it is never relaxed.

**Key ↔ algorithm compatibility is validated at load time.** The base class (§3.2) MUST
validate that the algorithm claimed by each key descriptor is compatible with the key's type
and, for EC keys, its curve: `ES256` → P-256, `ES384` → P-384, `ES521` → P-521; `RS*`/`PS*`
→ RSA. A provider that returns a mismatched `(key, alg)` pair (e.g. claiming `ES256` while
supplying an RSA key) MUST fail with `ZeeKayDaConfigurationException` **at load time**, never
produce a malformed token at signing time.

**No `VerifyAsync`.** This interface is for *issuing* signatures. Verifying inbound
client signatures (`private_key_jwt` client assertions, signed request objects) is a
distinct concern with a distinct trust model — it consumes *client* keys, not the server's
own keys — and is deferred to a separate future seam.

**Async by deliberate design.** `SignAsync` and `GetSigningKeysAsync` are async even though
the local-key implementations are CPU-bound and synchronous under the hood. The async signature
is the seam that makes **remote signing (KMS / HSM / Azure Key Vault)** possible: a remote
signer performs network I/O on every `SignAsync` call. The companion invariant — **callers
never hold private key material** — is what makes remote signing actually possible: because
`SignAsync` returns a finished signature rather than a key, the private key can live in an HSM
that never exports it.

### 2. Developer experience — two named development-key registration methods

Local development is one line. There are **two distinct, named** builder extensions on
`ZeeKayDaAuthBuilder`, one per persistence mode:

```csharp
builder.Services.AddZeeKayDaAuth(/* … */)
       .AddInMemoryDevelopmentJwtSigningKeys();               // ephemeral, in-memory
// or
       .AddPersistedDevelopmentJwtSigningKeys();              // persist to the default path
// or
       .AddPersistedDevelopmentJwtSigningKeys(persistTo: "/some/path");
```

Signatures:

```csharp
AddInMemoryDevelopmentJwtSigningKeys(Action<InMemoryDevelopmentSigningKeyOptions>? configure = null);
AddPersistedDevelopmentJwtSigningKeys(string? persistTo = null, Action<DevelopmentSigningKeyOptions>? configure = null);
```

The persistence choice lives in the **method name**, not in an argument whose `null` value has
to be read against the grain. On `AddPersistedDevelopmentJwtSigningKeys`, `persistTo: null`
means exactly one thing — "persist to the default path" — with no second reading available.
Both methods take an optional `configure` callback, consistent with every production provider
registration method (`AddPemFileSigning`, `AddPfxFileSigning`, the Azure Key Vault and Windows
Certificate Store equivalents), which all already accept an `Action<TOptions>? configure = null`
— but the two development methods deliberately do **not** share the same `TOptions` for that
callback (see below).

`DevelopmentSigningKeyOptions` (`DevelopmentSigningKeyOptions : JwtSigningServiceOptions`) is the
**public**, provider-specific options type the signing pipeline actually consumes regardless of
which registration method was used, and is the `configure` callback type for
`AddPersistedDevelopmentJwtSigningKeys`. `AddInMemoryDevelopmentJwtSigningKeys` deliberately does
**not** reuse it as its own callback type — it exposes the smaller, separate
`InMemoryDevelopmentSigningKeyOptions`, which has no `PersistToDirectory` member at all. This is
intentional: if the in-memory method's callback exposed `PersistToDirectory`, a caller could set
it and silently turn an "ephemeral" registration into a persisted one. Values set through
`InMemoryDevelopmentSigningKeyOptions` are copied onto the real, internally-registered
`DevelopmentSigningKeyOptions` instance before it reaches the base class. Both options types are
reachable through their respective `configure` callback with no `InternalsVisibleTo` grant or
reflection required.

**Hard fail outside Development.** These methods register a development-only provider. If the
host environment is not in the allowed-environments list (below), startup fails with
`ZeeKayDaConfigurationException`, exactly mirroring the in-memory store behaviour from ADR 0008.

**The environment gate is a provider-scoped, code-only opt-in — `AllowedDevelopmentJwtSigningKeysEnvironments`.**

```csharp
public sealed class DevelopmentSigningKeyOptions : StaticKeySourceOptions // amended by issue #409; was JwtSigningServiceOptions
{
    // Defaults to ["Development"]. Widening it to a named non-production environment
    // (e.g. "Staging", "IntegrationTest") is an explicit, code-only opt-in.
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } = ["Development"];
    // … EnvironmentName (host-populated), PersistToDirectory …
    // No refresh-cadence property: StaticKeySourceOptions carries none (§3.4), replacing the
    // pre-#409 "inherited KeySourceRefreshInterval, always null" phrasing.
}
```

The allowed-environments list lives on each method's own provider-specific options type —
`DevelopmentSigningKeyOptions` for `AddPersistedDevelopmentJwtSigningKeys`,
`InMemoryDevelopmentSigningKeyOptions` for `AddInMemoryDevelopmentJwtSigningKeys` — both exposing
a property of the same name, configured through the registration method's own `configure`
callback:

```csharp
builder.AddInMemoryDevelopmentJwtSigningKeys(o =>
    o.AllowedDevelopmentJwtSigningKeysEnvironments = ["Development", "IntegrationTest"]);
```

It is deliberately **not** on the shared `AuthorizationServerOptions` root. It is inert unless
one of the two development-key methods was called, so it belongs on the feature that gives it
meaning — it appears in IntelliSense only when the development provider is actually being
configured. Placing it on the root would make it a setting that silently does nothing unless an
unrelated extension method was also called, which is the discoverability trap ADR 0008 already
names in the auto-registration context. See the considered-and-rejected section for the reversal
of PR #333, which had briefly hoisted this onto the root.

The following invariants hold regardless of list contents:

- The default list is exactly `["Development"]`.
- **`Production` is rejected unconditionally**, case-insensitively, regardless of the list's
  contents. This is enforced twice: `DevelopmentSigningKeyGate.Enforce` checks it before the
  allowed-list membership check (so adding `"Production"` to the list can never satisfy the gate),
  and `AllowedDevEnvironmentsValidator` — an `IValidateOptions<DevelopmentSigningKeyOptions>` —
  rejects a list containing `"Production"` (and any null/empty entry) at startup.
- When the current environment is in the allowed list but is not exactly `Development`, a
  `LogLevel.Critical` entry is emitted on **every** startup — not once, not only on first
  detection. This matches the severity the in-memory store gate uses in its own equivalent
  case (ADR 0008 §5): when the relevant in-memory registration method's `allowOutsideDevelopment`
  parameter is used outside `Development`, `InMemoryStoreWarningService` also escalates to
  `Critical`, not `Warning` — the
  plain `LogLevel.Warning` in-memory stores emit is scoped to the unremarkable case of using them
  *inside* `Development`, where no escape hatch is in play. Both gates treat "an explicit opt-in
  escape hatch for a Development-only feature is currently open outside Development" as
  maximal-severity, because a non-rotating, possibly-ephemeral signing key and a non-durable
  token store are each, in their own way, a correctness break for every relying party or client
  on restart.
- **The gate MUST NOT be sourced from bindable configuration.** `AllowedDevelopmentJwtSigningKeysEnvironments`
  MUST NOT be settable from `appsettings.json` or any other file that may be committed to source
  control. A code-only `configure` callback is intrinsically harder to accidentally wire to a
  config file than a bindable root property, which is part of why the gate lives on the
  provider options callback rather than the root. A committed environment name is exactly the
  silent escalation this gate exists to prevent.

Even with a widened list, the development provider still enforces **all** minimum-key-strength
and file-permission/ownership/symlink requirements below. The escape hatch relaxes **only** the
environment gate; it never relaxes any crypto or filesystem-hardening requirement.

**Ephemeral vs. persisted.** `AddInMemoryDevelopmentJwtSigningKeys` generates a fresh RSA key in
memory on each startup — nothing persists, nothing leaks to disk; correct for local development.
`AddPersistedDevelopmentJwtSigningKeys` opts into persistence so a developer's tokens survive an
app restart; with `persistTo: null` the default path is
`{IHostEnvironment.ContentRootPath}/.zeekayda/signing-keys/`.

**Minimum key strength.**

- The development helper MUST generate **RSA keys of at least 3072 bits** (NIST SP 800-57
  Part 1 Rev. 5 §5.6.1 Table 2's recommendation for new keys, not merely the 2048-bit floor).
- The base class (§3.2) MUST reject any RSA key smaller than **2048 bits** (the hard minimum)
  with `ZeeKayDaConfigurationException`, regardless of provider.
- Acceptable EC curves are exactly P-256, P-384, and P-521. Non-NIST curves (e.g. secp256k1)
  MUST be rejected with `ZeeKayDaConfigurationException`.

**Persistence is safe by construction.**

- The directory is created with `0700` and key files with `0600` — **atomically at
  open/create time**, not create-then-`chmod` (on .NET, `FileStreamOptions.UnixCreateMode =
  UserRead | UserWrite` when creating a key file, and the directory created `0700` in the same
  operation). Create-then-narrow is prohibited: it leaves a window in which the file exists with
  the process umask's default mode. The `umask` MUST NOT be relied upon for security.
- An existing key file with permissions **broader than `0600`** causes the provider to **fail
  loudly** (`ZeeKayDaConfigurationException`) rather than load it — treated as compromised, not
  as a warning.
- **No symlink following.** If the path (or any component of it) resolves through a symlink, the
  provider fails with `ZeeKayDaConfigurationException`, preventing a planted symlink from
  redirecting a freshly generated private key to an attacker-controlled location.
- **Parent-directory ownership.** Every component of the directory chain the provider creates or
  writes into MUST be owned by the current user; otherwise it fails closed.
- On Windows, the equivalent is a restrictive ACL granting the current user only (plus
  SYSTEM/Administrators at implementor discretion), with **inheritance disabled** and no
  `Everyone`/`Users` entries.
- On Linux there is no OS keystore integration: ephemeral or file-persisted are the only
  development options. Production keys come from a real provider (§3).

**Key format: plain PEM.** No password-based encryption, no PKCS#12. PEM is the least surprising,
most tool-compatible format for a file a developer may inspect, and the `0600` permission is the
access control.

The development provider derives from the §3 base class as
`JwtSigningService<DevelopmentSigningKeyOptions>`. **`IDevelopmentSigningKeyFileSystem`** exposes
async read/write operations (`ReadKeyFileAsync` / `WriteKeyFileAsync` / `EnsureDirectorySafe` /
`FileExists`) with a `CancellationToken`; `DevelopmentJwtSigningService` propagates the token
received from `LoadKeysAsync` to all file I/O. RSA key generation (`RSA.Create`) is CPU-bound
with no async variant, so that step cannot be cancelled. The interface is scoped to the
development provider by name — it is not a general-purpose signing file-system abstraction used
by production providers.

### 3. Rotation and the optional base class

#### 3.1 No third method on the interface

`IJwtSigningService` stays at the two methods in §1. Rotation is **not** part of the public
contract. A provider backed by a managed KMS rotates keys on the KMS's schedule; a provider
backed by a database rotates on its own job. ZeeKayDa is a **reader** of the trusted key set,
not the rotation authority.

#### 3.2 The optional base class `JwtSigningService<TOptions>`

Most implementors should not reimplement caching, single-flight refresh, or the crypto call. An
**optional** abstract base class carries all of it and ships in v1:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningService<TOptions> : IJwtSigningService
    where TOptions : JwtSigningServiceOptions
{
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider) { /* … */ }

    /// <summary>
    /// Loads the current set of trusted keys. For rotating-tier providers (`RotatingKeySourceOptions`,
    /// amended by issue #409 — historically `KeySourceRefreshInterval` on the base options type),
    /// called at most once per `KeyRotationCheckInterval`, with concurrent callers after the
    /// interval elapses coalesced into a single load; for static-tier providers
    /// (`StaticKeySourceOptions`) called exactly once, ever.
    /// </summary>
    protected abstract ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Produces the signature bytes for the already-selected active key. Default body performs
    /// the local BCL crypto operation; a remote (KMS/HSM) provider overrides this to make a
    /// network round trip. It can only change HOW the signature is produced, never WHICH key is
    /// selected or what the header says.
    /// </summary>
    protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
        SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken)
        => new(SigningAlgorithms.Sign(activeKey.Descriptor, signingInput, activeKey.PrivateKey));

    /// <summary>
    /// Asked once per refresh cycle, after the interval elapses and only when a previous set
    /// already exists, whether the trusted key set has actually changed since the last successful
    /// load. Returning false lets the base class keep serving the existing cached set for another
    /// interval WITHOUT calling LoadKeysAsync — skipping an expensive key-material reload when
    /// nothing has rotated. The default always returns true, so every provider that does not
    /// override it keeps the unconditional-rebuild behaviour unchanged. Never consulted for the
    /// first load.
    /// </summary>
    protected virtual ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken) => new(true);

    // IJwtSigningService implemented by the base class on top of LoadKeysAsync + SignInputAsync.
}
```

The base class owns:

- **Interval-throttled caching** driven by an injected **`TimeProvider`** — never
  `DateTime.Now` / `DateTimeOffset.UtcNow` — keeping the whole rotation/caching path
  unit-testable with a `FakeTimeProvider`.
- A **single-flight refresh gate**: when the refresh interval elapses, exactly one
  `LoadKeysAsync` runs and concurrent callers await its result. This matters on the signing hot
  path, where a thundering herd against a remote key source would be a self-inflicted outage.
- **A change-detection ("ask") step in front of the reload ("refresh").** When the refresh
  interval elapses and a previous set already exists, `BorrowSetAsync` first calls
  `HasKeySetChangedAsync`. If it returns `false`, the base class extends `_cacheExpiresAt` by
  another interval and keeps serving the existing cached set (re-borrowed) — `LoadKeysAsync` is
  not invoked, and nothing is swapped or disposed. Only when it returns `true` (or there is no
  previous set — the first load is never skippable) does the base class proceed exactly as before:
  `LoadKeysAsync` runs, its returned set replaces the cache, and the superseded set is disposed.
  The default `HasKeySetChangedAsync` returns `true`, so every provider that does not override it
  keeps today's unconditional-rebuild behaviour unchanged; the split exists so a provider whose
  backing store rotates rarely (a production certificate: months, not minutes) can skip
  re-downloading and re-materialising key material on every poll, while the **poll cadence itself
  is unchanged** — the ask still runs every interval. `LoadKeysAsync` MUST never return the same
  `SigningKeySet` instance twice to signal "unchanged": the refresh path unconditionally
  `Dispose()`s the previous reference after installing the new one, so a repeated instance would
  be disposed out from under the just-installed cache and the next `GetPrivateKey` would throw
  `ObjectDisposedException`. The ask/refresh split avoids that failure structurally by never
  calling `LoadKeysAsync` at all on an unchanged cycle, rather than by having it return a sentinel.
  Both the same-instance case and the subtler variant — a genuinely new `SigningKeySet` that
  nonetheless wraps one of the previous set's private-key objects under a shared `kid` — are
  enforced at runtime immediately after `LoadKeysAsync` returns, before the previous set is disposed
  or the new one installed, each with its own `InvalidOperationException`. Neither check is a full
  deep-equality comparison of the two sets; the second only compares private-key object identity for
  `kid`s common to both sets.
  `HasKeySetChangedAsync` throwing is **fail-closed by design**: the exception propagates straight
  out of `BorrowSetAsync` to the current caller (the in-flight `GetSigningKeysAsync`/`SignAsync`
  fails), and `_cachedSet`/`_cacheExpiresAt` are left untouched — no stale-cache fallback, nothing
  swallowed. This is deliberately the same failure shape `LoadKeysAsync` throwing already has, so
  adding the ask (a second network-capable operation) introduces no new failure mode — only the
  same existing "fail closed, no silent stale-key fallback" convention the base class has always had
  for `LoadKeysAsync`. Providers of this hook MUST NOT invent divergent fail-soft behaviour
  (swallow-and-treat-as-unchanged, or swallow-and-keep-serving-the-stale-set): a silent fallback
  would mask an operational check failing.
- **Header construction, active-key selection, `kid`/`alg` fixation, and the `SignAsync`
  crypto dispatch**, all inside a private, non-overridable `PerformSignAsync`. `SignInputAsync`
  is the only overridable seam and can affect only the signature-bytes production for the
  already-selected descriptor — it can never change which key is selected or what the header
  says, which is what preserves §1's "header and signature are always consistent by
  construction" invariant. Local-key providers (development, Windows Certificate Store,
  file-based) inherit the default body unchanged; only a genuinely remote/network signer
  overrides it.
- **Deterministic disposal of superseded private key material.** `SigningKeySet`, and any type
  holding private key material, MUST be `IDisposable`. When the base class replaces the cached
  set on refresh, it MUST `Dispose()` the previous set's private-key objects (the `RSA` /
  `ECDsa` / `AsymmetricAlgorithm` instances) rather than leaving them to the GC — those BCL types
  wrap unmanaged key handles that can retain key bytes in process memory until finalized. For a
  remote signer there is no local private key, so this disposes only the cached local handle/copy.
- **Ordered disposal after in-flight signs.** Disposal of the old set's private-key objects MUST
  be deferred until every in-flight `SignAsync` referencing the old set has completed; disposing
  an `RSA`/`ECDsa` mid-operation would raise `ObjectDisposedException`.

Implementors provide exactly one method: `LoadKeysAsync`, returning a **`SigningKeySet`** (the
current trusted set: active key plus in-window keys, with whatever private material the provider
holds). The development provider (§2) derives from this base.

**`SigningKeySet` construction names the active key explicitly (issue #355).** A `SigningKeySet`
is constructed from a **named active key plus a lifecycle-neutral collection of additional keys**,
not from a single positional list whose first element is the active key by convention:

```csharp
public SigningKeySet(SigningKeyPair activeKey, IEnumerable<SigningKeyPair>? additionalKeys = null);
```

The earlier `SigningKeySet(IReadOnlyList<SigningKeyPair> keys)` constructor made "the first entry
is the active signing key" a documented convention enforced nowhere. A provider whose
`LoadKeysAsync` assembled its list in any other order would silently sign every token with a
retired (or not-yet-active) key — code that compiles, still publishes a complete JWKS, and still
passes a happy-path test, because every published key continues to verify. That is exactly the
failure this project's design principles forbid treating as a documentation problem: an
invariant a naive implementation can violate while compiling and passing a happy-path test is an
open API-design problem, and the required fix is to reshape the extension point so the wrong
thing cannot be expressed — not a runtime guard and not a conformance test. Making the active key
a **distinct, mandatory constructor parameter** does exactly that: there is no ordering left to
get wrong. `ActiveKey` is now backed by that parameter, not by `Keys[0]`. Two properties that
were previously a runtime check or an unenforced convention become structural — there is always
exactly one active key (the old "at least one key required" `ArgumentException` on an empty list
is gone; emptiness is now unrepresentable), and which key is active is unambiguous.

The second parameter is named **`additionalKeys`**, deliberately lifecycle-neutral. Per §3.5's
publish-then-activate rule, at any instant the non-active bucket can hold both keys already
published but not yet activated (future) *and* keys no longer signing but still inside their
retirement window; the codebase already treats these two sub-cases identically as a single flat
"included but not active" list (`SelectIncludedKeys` / `SelectIncludedVersions`). Naming the
bucket `retired` (as the issue's own draft signature did) would mislabel the pre-published case.
`verificationOnlyKeys` was considered and rejected as subtly wrong in the other direction — the
active key's public half also verifies, and a not-yet-active key verifies nothing yet, so
"verification-only" is neither a clean partition of function nor accurate for the future case.
`additionalKeys` names the bucket purely by its relationship to the active key ("the active key,
plus these additional trusted keys"), which is exactly the distinction the constructor draws.
This is a **naming fix, not a new third bucket**: the model remains two buckets — active, and
everything-else.

**`Keys` ordering and JWKS output are unchanged.** The constructor still materialises `Keys` as a
single active-first descriptor array (active key first, then `additionalKeys` in their supplied
order), so `GetSigningKeysAsync` keeps returning the same pre-computed, allocation-free list on
the hot path (§4.3) and the JWKS is byte-for-byte identical to before. Active-first ordering is
retained purely as an implementation artifact — for zero-allocation reuse and stable output — but
it is **no longer load-bearing**: `ActiveKey` derives from the named parameter, not from position.
JWKS array order carries no protocol meaning anyway (RFC 7517 §5.1: a JWK Set is unordered by
default; relying parties match by `kid`, §4.5), so no independent JWKS reordering is introduced.

**Duplicate-`kid` validation stays at the load path, not the constructor.** The constructor does
not reject a `kid` that appears in both `activeKey` and `additionalKeys`. Duplicate-`kid`
rejection remains the base class's single load-time responsibility (§4.3 — reject a
`SigningKeySet` carrying duplicate `kid`s with `ZeeKayDaConfigurationException`), alongside the
key/algorithm-compatibility check (§1). Splitting that invariant into a second constructor-level
check would fragment it across two sites and two exception types (`ArgumentException` vs
`ZeeKayDaConfigurationException`) for no benefit; the base class load path is already the one
chokepoint every provider's returned set flows through.

#### 3.3 `RetirementWindow` is derived, not configurable

> **Security sign-off point.** The derivation and its safety argument below are the specific
> item the security agent must approve on this ADR PR.

`RetirementWindow` is the period for which a key that is no longer the active signer remains
published in the JWKS (and thus remains trusted by relying parties). It is **derived, not a user
setting**:

```
RetirementWindow = max(access-token lifetime, ID-token lifetime, <floor>) + clock-skew allowance
```

The window is measured from the moment the key **ceases to be the active signer** — the instant
a successor key becomes the active signer — **not** from key creation or initial activation.
Starting the clock at creation or first activation would retire the key before the last token it
signed has expired, causing valid tokens to be rejected.

Four properties of this derivation are normative:

- **(a) Sized to the longest-lived *signature-validated* token.** A key may only be retired from
  the JWKS once every token it could have signed has expired. The window is the longest lifetime
  among the artifacts a relying party validates by *signature* — today the ID token
  (`IdTokenOptions`), and the JWT access token once configurable access-token lifetime lands. Any
  future artifact validated by signature against the JWKS (logout tokens, JARM responses, SD-JWT)
  MUST be added to the `max(...)` set; introducing such an artifact without extending this
  derivation is a security regression.
- **(a′) A conservative floor bridges the missing lifetime configuration.** `IdTokenOptions`
  carries no ID-token lifetime property today (only `SigningAlgValuesSupported`), and there is no
  configurable JWT-access-token lifetime yet, so **both** terms of the `max(...)` are currently
  unconfigured. Until configurable per-token lifetimes exist, the implementation MUST apply a
  floor of at least **1 hour** to the `max(...)` term, so `RetirementWindow` is never shorter than
  1 hour + clock-skew. Without this floor the `max(...)` would resolve over zero configured terms
  and produce a near-zero window that would immediately invalidate every token in flight. 1 hour
  is a safe bridge, not a permanent default: once ID-token and JWT-access-token lifetime
  configuration exists, the derivation uses the configured values and the floor merely guards the
  degenerate case. The default implementation (`ISigningKeyRetirementWindowProvider`, §3.4)
  currently computes exactly `TimeSpan.FromHours(1) + AuthorizationServerOptions.ClockSkewTolerance`.
- **(b) Refresh-token lifetime is deliberately excluded.** `TokenEndpoint.RefreshTokenLifetime`
  (default 14 days) is *not* part of the `max(...)`. Refresh tokens are validated by the
  authorization server against the refresh-token store (ADR 0008), **never by a relying party
  against the JWKS**. Including the 14-day refresh lifetime would pin every retired public key in
  the JWKS for two weeks for no validation benefit.
- **(c) The retired key's *private* material is destroyed immediately on retirement.**
  `RetirementWindow` governs only how long the *public* key stays in the JWKS. Once a key stops
  being the active signer it signs nothing further, so its private half MUST be destroyed at once
  (via §3.2's deterministic disposal). For remote-signing providers (HSM/KMS) there is no local
  private key to destroy — the obligation there is to dispose whatever local *handle or copy* the
  base class or provider cached.

The clock-skew allowance always **widens** the window — it is added to the `max(...)` term and
never subtracts from it. `RetirementWindow` is **not** exposed on `JwtSigningServiceOptions` or
anywhere else (see rejected alternatives); it is computed inside ZeeKayDa from token-lifetime
configuration the server already owns.

#### 3.4 A three-tier options hierarchy (amended, issue #409)

> **Supersedes the single-property design below the historical description.** The original
> `KeySourceRefreshInterval`-on-`JwtSigningServiceOptions` design (kept further down for context)
> is replaced by a three-tier hierarchy that separates *load-once* sources, *rotating* sources,
> and the base type both derive from. This section records the ratified shape; it is a
> naming/regrouping fix, not a behaviour change — see "Backward compatibility" below.

```csharp
public abstract class JwtSigningServiceOptions
{
    // No rotation-shaped property at all. Every rotation-related knob lives on one of the
    // two tiers below, never on the shared base.
}

/// <summary>Options for a provider whose key source is immutable for the process lifetime.</summary>
public abstract class StaticKeySourceOptions : JwtSigningServiceOptions
{
    // No refresh-cadence property. The base class treats this tier as load-once-forever
    // structurally — LoadKeysAsync runs exactly once, never on a timer — replacing the old
    // "KeySourceRefreshInterval == null" sentinel with a real type distinction.
}

/// <summary>Options for a provider whose key source can change while the process runs.</summary>
public abstract class RotatingKeySourceOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// How often the base class re-evaluates whether the active/included key set has changed
    /// (poll cadence, coalesced via the single-flight gate and the HasKeySetChangedAsync ask,
    /// §3.2). Applies uniformly to all four rotating providers — File, PFX, Windows Certificate
    /// Store, and Azure Key Vault (cached and remote) — including cert-store, where most cycles
    /// do no I/O (§3.5).
    /// </summary>
    public TimeSpan KeyRotationCheckInterval { get; set; }
}
```

**Tier assignment.** `DevelopmentSigningKeyOptions` is the sole consumer of
`StaticKeySourceOptions` — a locally-generated or file-persisted development key set never
changes at runtime, so there is nothing to poll. `RotatingKeySourceOptions` is the shared parent
for the File, PFX, Windows Certificate Store, and Azure Key Vault (cached and remote) provider
options types — **not Key-Vault-only**, correcting the single-property design's implication that
only Key Vault rotates.

**Rename.** `KeySourceRefreshInterval` → **`KeyRotationCheckInterval`**, moved from the base type
onto `RotatingKeySourceOptions`. The meaning is unchanged from the historical description below:
how often the library re-evaluates whether the active/included key set has changed.

**Backward compatibility.** This is a naming and type-hierarchy fix, not a behaviour change. All
current defaults are preserved exactly: the development provider's load-once behaviour (now
structural via `StaticKeySourceOptions` rather than a `null` sentinel), the rotating providers'
poll cadence, expiry fail-closed detection, scheduled certificate promotion at `NotBefore`, and
the file provider's mtime-triggered reload (§3.5) all continue to work identically. Periodic
re-evaluation for File/PFX/cert-store providers remains load-bearing — there is still no sign-time
`NotAfter` guard elsewhere in `JwtSigningService.cs`.

**New properties introduced alongside the rename** — `SigningKeyActivationDelay`
(Key-Vault-only) and `AssumedJwksPropagationDelay` (File/cert-store-only) — are specified in
§3.5, since both replace roles the single `KeySourceRefreshInterval` property used to overload.

**Amendment (issue #407): default raised 5 minutes → 1 hour.** `KeyRotationCheckInterval`'s
default (carried over unchanged from `KeySourceRefreshInterval` by the #409 rename above) was
5 minutes, which — in its publish-then-activate lead-time role (§3.5) — sits well inside the
range the library's own Key Vault option validators already treat as near-certain
misconfiguration for a relying party's real-world JWKS-cache TTL. Architect and security review
converged on raising the default to **1 hour**: it clears ASP.NET Core's
`Microsoft.IdentityModel` `ConfigurationManager`'s 5-minute reactive refetch-on-unknown-`kid`
cooldown many times over (so the dominant managed relying-party stack self-heals well inside the
new interval), while keeping the poll-gated safety behaviors this same property also drives —
emergency key-disablement detection, the vanished-`kid` anomaly check, and certificate-expiry
warnings — reasonably responsive. A relying party with a longer fixed JWKS-cache TTL and no
retry-on-miss logic is still exposed regardless of the default chosen here; the recommended
mitigation is verifying that relying party's actual JWKS-cache TTL and setting
`SigningKeyActivationDelay`/`AssumedJwksPropagationDelay` explicitly to exceed it — there is no
mechanism (a pre-published "standby key" or otherwise) that lets an operator skip knowing that
number, since activation for every provider is driven solely by `NotBefore`/`ActivatesAt` versus
wall-clock time, with no separate enable/promote gate. The existing Key Vault validators'
1-minute floor and its "this is a floor, not a guarantee of safety" caveat are unchanged by this
amendment. The widened window between an operator disabling a compromised key in the store and
this library ceasing to sign with/publish it (bounded by `KeyRotationCheckInterval`,
traffic-gated) grows from 5 minutes to 1 hour, but the correct emergency runbook is provider-
specific, but both still rely on a restart forcing an immediate cold `LoadKeysAsync` to make the
change take effect right away rather than waiting out the poll cadence: File/PFX/Windows
Certificate Store have no enable/disable flag, so the runbook is remove-the-compromised-key,
redeploy, and restart; Azure Key Vault's `Enabled` flag is a genuine kill-switch (an unconditional
exclusion, independent of the retirement window) — no configuration file to edit, but disabling
the version still only takes effect on Key Vault's side until this library's next poll, so the
runbook there is disable-the-compromised-version-in-the-vault and restart. Both runbooks stop
the compromised key from being *newly* trusted, not its acceptance
by relying parties that already cached it (bounded by that relying party's own JWKS-cache TTL,
not by anything this library controls). This default's widening applies to all
`RotatingKeySourceOptions` consumers uniformly — File, PFX, Windows Certificate Store, and Azure
Key Vault (cached and remote) — not only Key Vault, so rotation pickup, the vanished-`kid` check,
and certificate-expiry warnings for the File/PFX/cert-store providers also now run on a 1-hour
cadence by default.

**Extensibility documentation requirement.** Every new/renamed property on these three tiers
requires XML doc coverage. A dedicated docs-site page is also required, walking a third-party
implementor through the three-tier model with Azure Key Vault as the worked example of "how to
build a rotating provider with its own enforced timing property, and where to enforce its
invariant" — see
[Implement a custom signing key provider](../how-to/implement-custom-signing-provider.md)
(outline stubbed alongside this amendment; content is follow-up implementation work).

---

<details>
<summary>Historical description (pre-#409): the single-property design this section replaces</summary>

```csharp
public abstract class JwtSigningServiceOptions
{
    /// <summary>
    /// How often the base class re-invokes LoadKeysAsync to refresh the cached trusted key set
    /// (poll cadence, coalesced via the single-flight gate) AND, for rotation-capable providers
    /// that publish-then-activate, the lead time a newly published key must be visible before it
    /// may become the active signer. These two roles are deliberately ONE property, not two — see
    /// the rejected "split into two knobs" alternative.
    ///
    /// null means "load once via LoadKeysAsync, never reload" — a real static-source mode for
    /// immutable key sources, not a sentinel value.
    /// </summary>
    public TimeSpan? KeySourceRefreshInterval { get; set; }
}
```

The base options type carried **`KeySourceRefreshInterval`** and nothing else. `RetirementWindow`
is *not* here (§3.3). Provider-specific options derived from this type.

`KeySourceRefreshInterval` was a **nullable `TimeSpan?`**: a non-null value was the finite poll
cadence; **`null` meant "load once, never reload,"** a named static-source mode for an immutable
key source. This replaced the earlier `TimeSpan.MaxValue`-as-sentinel design, in which a *mode*
("never poll") was expressed via a *cadence* value plus a magic-number special case in the base
class's refresh arithmetic. `DevelopmentSigningKeyOptions` defaulted this to `null`.

The single property deliberately conveyed **both** roles — poll cadence and, for Key Vault-style
providers, publish-then-activate lead time — because binding them to one value made it
structurally impossible to configure an activation delay shorter than the poll interval. Issue
#409 found this conflated a *third*, unrelated meaning (File/cert-store "too-soon" warning
threshold) into the same property, and that the "one property, two roles" argument only actually
held for Key Vault. §3.4/§3.5 above and below record the corrected design: the invariant is now
enforced by validation (§3.5) rather than by refusing to separate the properties.

</details>

#### 3.5 Rotation for external providers — read-only, durable-timestamp-derived, with anomaly surfacing

For provider-owned rotation (KMS, database, OS certificate store), ZeeKayDa reads the trusted set
via `LoadKeysAsync` and surfaces anomalies rather than driving rotation.

**Publish-then-activate.** If a key starts signing before its public half appears in the JWKS, a
relying party that fetches a fresh JWKS still will not find the new `kid` and will reject
otherwise-valid tokens. A key therefore MUST appear in `GetSigningKeysAsync()` results — and so
in the published JWKS — for at least one RP JWKS-cache-TTL period **before** it becomes the active
signer. Implementations MUST NOT promote a key to active signer until it has been published.

**Amendment (issue #409): the activation delay and the poll cadence are now separate,
per-provider-family properties, each with its own invariant enforcement — not one shared
property.**

- **Azure Key Vault (cached and remote)** gains **`SigningKeyActivationDelay`** on
  `AzureKeyVaultCachedSigningOptions`/`AzureKeyVaultRemoteSigningOptions`, defaulting to
  `KeyRotationCheckInterval` (§3.4) when unset. The invariant `ActivationDelay >=
  KeyRotationCheckInterval` — a newly-published key must not be able to activate before the
  process would even notice it exists — is enforced in exactly **two** places: (a) one shared
  validation helper used by both Key Vault option validators (not duplicated per-validator), and
  (b) inside `KeyVaultSigningKeyRotation.BuildActivationTimeline` itself, so a future custom
  KMS/HSM provider modeled on this pattern cannot silently reintroduce the activation race by
  forgetting a cross-field validator.
- **File (both PEM and PFX) and Windows Certificate Store** gain
  **`AssumedJwksPropagationDelay`**, feeding `SigningKeyRotation.HasTooSoonPendingActivation`,
  replacing the old reuse of the rotation-check interval as a proxy for RP-side JWKS cache
  staleness. Defaults to `KeyRotationCheckInterval` when unset, preserving today's behaviour
  exactly. This property lives on the shared `RotatingKeySourceOptions`-derived base that
  `PemFileSigningOptions` and `PfxFileSigningOptions` both inherit from (mirroring the shared
  `FileSigningJwtSigningService<TOptions>` base at the service level, whose `LoadKeysAsync`
  feeds the too-soon check for both PEM and PFX identically) — it is **not** PEM-only.
  `PfxFileSigningOptions` gains the same `HasTooSoonPendingActivation` XML-doc cross-reference
  as `PemFileSigningOptions` and `WindowsCertificateStoreSigningOptions` already carry, since PFX
  also supports pre-staged successor certificates via `AdditionalFiles` and the too-soon warning
  is equally live for it.

Both new properties default to the rotation-check interval specifically so that a consumer who
upgrades and sets nothing observes identical runtime behaviour to before the split.

**Anomaly surfacing (the "vanished kid" warning).** Rotation-capable providers keep a
restart-tolerant, purely-for-logging map of previously-published `(kid, raw provider version
string)` pairs. On each refresh, for a previously-published pair whose `kid` is no longer in the
newly-included (trusted/published) set, the provider consults **the key store's own complete
version list** (including disabled/expired versions) and logs a warning **only when that version
has disappeared from the store's version list entirely** — i.e. the store stopped returning it
(deleted/purged). A version that is still listed by the store but has simply aged out of its
`RetirementWindow`, or been disabled, is the expected, non-anomalous case and stays silent. The
trigger is "the key store no longer lists this version at all," anchored to the store's durable
version list, not to elapsed-retirement-window bookkeeping. ZeeKayDa cannot prevent a misbehaving
external provider from pulling a key prematurely, but it makes it loud.

**Durable, provider-side-timestamp-derived rotation is the required pattern.** A rotation-capable
provider MUST derive its entire activation/retirement timeline from the key store's own durable
per-key timestamps — never from local, in-memory "when did I first observe this kid" bookkeeping,
which breaks on process restart (a fresh replica has no history) and is inconsistent across
load-balanced replicas. An in-memory-only tracking of publish-then-activate or retirement state
is **non-compliant with this section** for any provider capable of holding more than one key at a
time. (The one piece of cross-call state a provider may keep in memory — the kid→version map used
purely for the "vanished kid" log line — is fine to lose on restart; losing it only risks missing
one log line, never a trust decision.)

The two shipped rotation models differ in which durable timestamp anchors the timeline, and the
shared, anchor-agnostic machinery accommodates both:

- **Azure Key Vault** anchors on Key Vault's own `CreatedOn`/`NotBefore`: `ActivatesAt(v)` is
  `v.CreatedOn` for the very first version ever recorded for the key name (a durable, shared fact
  determined across all versions ever created, including disabled/expired) and
  `v.CreatedOn + SigningKeyActivationDelay` for every subsequent version (the publish-then-activate
  delay term — **amended by issue #409**: `BuildActivationTimeline` derives this lead term from
  `SigningKeyActivationDelay`, defaulting to `KeyRotationCheckInterval` when unset, not from the
  poll cadence directly; the historical text below and the pre-#409 references to
  `KeySourceRefreshInterval` supplying this term are superseded — see §3.4/§3.5's amendment
  above); `NotBefore` folds into `ActivatesAt` as `max(rawActivatesAt, v.NotBefore)`;
  `Enabled = false` is an immediate, unconditional exclusion that bypasses `RetirementWindow`
  (an operator disabling a suspected-compromised version takes effect at once); `RetiredAt(v)` is
  the `ActivatesAt` of whichever *eligible* successor actually superseded `v`. This makes the whole
  timeline a stateless computation over `(the store's version list, now,
  SigningKeyActivationDelay, RetirementWindow)` — restart-safe, multi-replica-consistent, and
  fully `FakeTimeProvider`-testable. The Key Vault rotation model (`KeyVaultSigningKeyRotation`)
  stays internal to `ZeeKayDa.Auth.AzureKeyVault`.
- **Windows Certificate Store** (and, by the same pattern, the file-based provider) anchors on the
  certificate's immutable `NotBefore`/`NotAfter` (a Windows store certificate has no `CreatedOn`
  equivalent). `ActivatesAt(cert) = cert.NotBefore`, with **no** extra publish-then-activate delay
  term (every registered certificate is fully visible in the JWKS as of process start; there is no
  "has the store durably recorded this yet" question). The publish-then-activate safety property
  therefore becomes the **operator's** responsibility: a certificate generated for rotation must
  have its `NotBefore` set at least `AssumedJwksPropagationDelay` in the future (**amended by
  issue #409**: this family's lead-time input is `AssumedJwksPropagationDelay`, defaulting to
  `KeyRotationCheckInterval` when unset — see §3.4/§3.5's amendment above; pre-#409 references to
  `KeySourceRefreshInterval` supplying this figure are superseded).
  `SigningKeyRotation.HasTooSoonPendingActivation` surfaces a startup warning when it is not — the
  library's only defence, since a local store cannot prove when a certificate was actually
  deployed.

**Metadata-only change detection for cached-key providers.** The Azure Key Vault *cached-signing*
provider (`AzureKeyVaultCachedSigningJwtSigningService`) overrides `HasKeySetChangedAsync` (§3.2)
so a poll whose trusted set is unchanged skips the expensive key-material download entirely. The
override recomputes the *included version set* from the same cheap, metadata-only enumeration
`LoadKeysAsync` already performs (`GetCertificateVersionsAsync` — the durable version list, with
**no** secret/private-key download) via the existing `KeyVaultSigningKeyRotation.BuildActivationTimeline`
/ `SelectActiveVersion` / `SelectIncludedVersions` helpers, and compares it — by version identifier,
`Enabled` state, **and which entry is active** — against what was included as of the last successful
cycle. The comparison is over the **whole** included set, not merely "did the active version
change": a non-active version's `Enabled` flag flipping (the immediate-exclusion revocation case
above), or a version entering or leaving its retirement window purely from elapsed time, must still
trigger a rebuild even when the active-version identifier is unchanged.

Active-version identity has to be one of the compared fields in its own right, not merely
version-identifier-plus-`Enabled` membership, or a normal scheduled rotation silently stalls. The
poll cadence is `KeyRotationCheckInterval` and the publish-then-activate lead time is
`SigningKeyActivationDelay` (**amended by issue #409** — historically one shared property,
`KeySourceRefreshInterval`, serving both roles; see §3.4/§3.5's amendment above). With
`SigningKeyActivationDelay` at its default (equal to `KeyRotationCheckInterval`), a rotation
typically spans exactly two polls, as before: at poll *N*, the new version (v2)
is published but not yet active alongside the still-active v1 — a membership change from the prior
poll, so the comparison correctly detects it and `LoadKeysAsync` runs, downloading v2's public-only
handle. At poll *N+1*, v2 becomes active while v1 (still inside its retirement window) remains
included — the included set is still `{v1, v2}` with the same version identifiers and `Enabled`
states as poll *N*, only the active slot has swapped. A comparison keyed only on version identifier
and `Enabled` state cannot distinguish this from "nothing changed" and would skip the rebuild
indefinitely, leaving the service signing with v1's private key past the intended handoff — and
potentially past v1's own certificate expiry, since the reload that would have promoted v2 to
active never runs. Comparing active-version identity alongside membership and `Enabled` state
closes this gap: the poll-*N+1* activation swap is itself a difference in the compared tuple set,
so it is correctly detected as a change.

Only a genuine difference lets the base class call `LoadKeysAsync`, which is itself unchanged — it
still builds a brand-new `SigningKeySet` from scratch, including genuinely fresh private key
material for the active version. Two safety properties are preserved by construction: because the
metadata check still runs on **every** cycle at `KeyRotationCheckInterval` cadence, the immediate
`Enabled = false` exclusion and the "vanished kid" anomaly surfacing lose no reaction time — only
the key-material download is skipped, never the check; and because the "ask" reads only the same
per-version metadata already fetched today (comparable in kind to the existing
`_previouslyPublishedKidVersions` bookkeeping, not a new private-key-bearing cache), §3.3(c)'s
immediate destruction of retired private material is untouched — no key bytes ever live outside the
`SigningKeySet` disposal graph.

**Change-detection baseline is captured only on a successful load, never on the ask (guidance for
the follow-up cached providers).** The comparison baseline
(`AzureKeyVaultCachedSigningJwtSigningService._previouslyIncludedVersions`) is written **only inside
`LoadKeysAsync`**, never inside `HasKeySetChangedAsync` itself. Each ask therefore always diffs the
freshly computed set against the set captured by the last successful *load* — i.e. the set that was
actually materialised and served — not against whatever the previous *ask* happened to compute. The
follow-up cached providers (#347 / #348 / #349), which each implement their own version of this same
hook against their own backing store, MUST replicate this write-only-on-load pattern rather than
updating the baseline from the ask path. The reason is correctness-under-failure, not a subtle
steady-state drift: in normal operation, diffing against the last ask and diffing against the last
load coincide, because any ask that reports a change is immediately followed by a reload that would
rewrite the baseline anyway. The divergence appears when a reported change is *not* followed by a
successful load — the ask runs before, and separately from, `LoadKeysAsync`, and the reload can fail
(fail-closed, §3.2). If the baseline were written from the ask, that ask would have recorded a set
that was never actually served; every subsequent ask would then diff against that phantom baseline,
report "unchanged," and permanently mask the pending change, wedging the service on the stale key
set. Anchoring the baseline write to `LoadKeysAsync` keeps the baseline and the currently-served set
provably in lockstep: the baseline advances if and only if a new set was actually built and
installed.

**Issue #347 ships the same pattern for the remote-signing provider.**
`AzureKeyVaultRemoteSigningJwtSigningService` now overrides `HasKeySetChangedAsync` identically to
the cached-signing provider above — the same `ComputeIncludedVersionsAsync` extraction (shared with
`LoadKeysAsync`), the same three-field `(Version, Enabled, IsActive)` comparison tuple, and the same
write-only-on-load baseline discipline. It is simpler only in that `LoadKeysAsync` itself has no
active/non-active private-key branching to preserve (this provider is always public-key-only — see
§1's remote-signing description). Of the two safety properties described above, only the first
translates directly: the metadata check still runs every cycle, so the immediate `Enabled = false`
exclusion and "vanished kid" anomaly surfacing lose no reaction time here either. The second does
not — §3.3(c) is **moot**, not "preserved," for this provider: it never holds private key material
in the first place (every version, including the active one, is always a public-only handle; signing
happens remotely inside Key Vault), so there is no retired private material whose destruction this
change could ever have put at risk. The change-detection logic and its rationale are otherwise
unchanged from above.

**Issue #348 ships the same pattern for the Windows Certificate Store provider — with no store
access at all in the "ask."** `WindowsCertificateStoreSigningJwtSigningService` also overrides
`HasKeySetChangedAsync`, but its ask needs no live check against the backing store, unlike both
Key Vault providers above. The reason is structural, not an optimisation choice made for its own
sake: an X.509 thumbprint is a SHA-1 hash of the certificate's own DER encoding — content-addressed
— so for a *fixed* thumbprint, `NotBefore`/`NotAfter` cannot change without the thumbprint itself
changing, and the configured thumbprint set
(`WindowsCertificateStoreSigningOptions.Thumbprint`/`AdditionalThumbprints`) is bound once from
`IOptions<TOptions>` (not `IOptionsMonitor<TOptions>`) and is fixed for the lifetime of the
process — `AddWindowsCertificateStoreSigning`'s own remarks already document that adding, removing,
or replacing a registered certificate requires a host restart. A restart is a cold start, and a
cold start always calls `LoadKeysAsync` directly, never this hook (§3.2). So, for a thumbprint
that remains present and accessible in the store, the only input that can genuinely change between
two calls to this method, within a single process lifetime, is elapsed time moving a certificate in
or out of its active/included/retirement window. The override therefore recomputes
`SigningKeyRotation.BuildActivationTimeline` / `SelectActiveKey` /
`SelectIncludedKeys` purely from the `RotationKey` list (thumbprint + `NotBefore`/`NotAfter`)
recorded at the last successful `LoadKeysAsync` call, re-evaluated against the current time — zero
calls to `ICertificateStoreReader.GetCertificate`, which is cheaper even than the Key Vault
providers' still-necessary metadata-only network call (a Key Vault version's `Enabled` flag or
expiry can mutate independently of its identity between polls, so Key Vault must re-poll; none of a
certificate's thumbprint-keyed facts can). The comparison shape is otherwise identical in spirit —
`SigningKeyRotation.ToChangeDetectionSet` compares the whole included set keyed by thumbprint and
which entry is active, not just "did the active thumbprint change," for the same two-poll handoff
reason as above (a rotation between two overlapping certificates can leave the included thumbprint
set unchanged across a poll boundary while the active entry swaps). It carries no `Enabled`
counterpart — a certificate registration has no equivalent flag — and it writes its baseline
(`_previouslyIncludedKeys`) only inside `LoadKeysAsync`, following the same write-only-on-load
discipline as the Key Vault providers. If this method's own recomputation finds no certificate
currently eligible to sign (every registered certificate has expired since the last load), it
reports a change rather than failing itself; the subsequent `LoadKeysAsync` call is what fails
closed with its usual `signing.windows_certificate_store.no_active_certificate` error — this
method's contract is only ever "did the trusted set change," never "is the configuration currently
valid."

**Consequence: out-of-band store deletion is no longer detected within a refresh interval.**
Because the ask never touches the store, deleting a registered certificate from the Windows
Certificate Store out of band (outside the process that registered it) is not something
`HasKeySetChangedAsync` can ever notice — it only sees what it was told at the last successful
`LoadKeysAsync`. This is accepted, not an oversight: (a) `WindowsCertificateKeyExtractor` already
duplicates the certificate's CNG/CAPI private-key handle into memory when the certificate is
loaded, and that handle remains valid and usable for signing even after the underlying certificate
is deleted from the store — store-side deletion was never a reliable "kill this cert now" lever,
even before issue #348, since a process that already loaded the certificate keeps signing with it
regardless; and (b) any change to the *registered* thumbprint set (adding, removing, or replacing a
certificate in configuration) already requires a host restart (§3.2), and a restart is a cold start
that always runs a real `LoadKeysAsync` — the very set this hook is a shortcut for — regardless of
what this override does.

**Issue #349 ships the same pattern for the file-based provider — one override on the shared base
class covers both PEM and PFX.** `FileSigningJwtSigningService<TOptions>`, the shared base class
behind both `PemFileSigningJwtSigningService` and `PfxFileSigningJwtSigningService`, overrides
`HasKeySetChangedAsync` once, so both subclasses gain the skip-on-unchanged behaviour from a single
change. The comparison basis is a small superset of the Windows Certificate Store provider's: the
*registered path set* (a path added or removed from `GetRegisteredPaths` is checked first, before
touching the filesystem at all), each remaining path's **file mtime** (`File.GetLastWriteTimeUtc`
— a stat call, never a content read, compared against the timestamp recorded at the last successful
load), and — only once the path set and every mtime are unchanged — the recomputed *(active path,
included path set)* tuple, via the same generic `SigningKeyRotation.ToChangeDetectionSet` helper
#347/#348 already use, evaluated against the current time from the `NotBefore`/`NotAfter` recorded at
the last load rather than by re-parsing any file. The path-set check needs no filesystem access;
the mtime check is a stat per registered path; only the third trigger recomputes the rotation
timeline, and it does so purely from already-recorded metadata. A missing file's
`File.GetLastWriteTimeUtc` returns a sentinel rather than throwing, which will not match the
recorded real timestamp and so is itself correctly reported as a change (outright removal is also
independently caught by the path-set check).

Unlike the certificate-store provider, a file's mtime is *not* content-addressed the way a
thumbprint is — two different byte sequences can share an mtime after a filesystem-clock-resolution
coincidence, and mtime alone is not a strong integrity signal. That is deliberately not a problem
here: mtime is used only to decide whether to re-read the file, never as a substitute for the
key/algorithm-compatibility and minimum-key-strength validation the base class already performs at
every real `LoadKeysAsync` (§1, §2). A false "unchanged" verdict — an actual rotation whose new
file happens to collide on mtime with the old one — only delays that rotation being picked up by one
more refresh interval; it does not weaken any signature, trust, or validation guarantee, because the
worst case is identical in kind to any other cache-hit cycle: the previously-loaded (still valid,
still published) key keeps signing for one extra interval. The baseline
(`_previouslyLoadedFiles` / `_previouslyIncludedPaths`) is written only inside `LoadKeysAsync` on
success, never from the ask itself, following the same write-only-on-load discipline as the Key
Vault and Windows Certificate Store providers above. If this method's own recomputation finds no
registered file currently eligible to sign, it reports a change rather than failing itself; the
subsequent `LoadKeysAsync` call is what fails closed with its usual
`signing.file_signing.no_active_certificate` error.

This closes epic **#187**'s `HasKeySetChangedAsync` follow-up set opened by issue #334: all four
shipped providers (Azure Key Vault cached-signing and remote-signing, Windows Certificate Store,
and now file-based PEM/PFX) implement the change-detection hook.

**Issue #348 also relocated the near-expiry warning from `LoadKeysAsync` into
`HasKeySetChangedAsync`.** The 30-day active-certificate-expiry warning previously fired only
inside `LoadKeysAsync`; once an unchanged refresh cycle could skip `LoadKeysAsync` entirely, that
warning would stop re-firing in the common steady state (a single long-lived certificate, no
rotation in flight), letting a long-running process silently cross into its 30-day expiry window
with no signal until the certificate actually expired and signing failed closed. The check now
runs from `HasKeySetChangedAsync` itself — it only needs the cached active entry's `ExpiresAt`
compared against `TimeProvider.GetUtcNow()`, so it adds no store access — and fires on every ask
cycle (whether or not that cycle also triggers a reload) for as long as the condition holds.
`LoadKeysAsync` keeps a single call to the same check, guarded so it only runs for the cold-start
load (before any ask has ever run for this instance); every later call to `LoadKeysAsync` was
preceded, in the same cycle, by an ask that already performed the check, so the warning never
double-logs.

**Single-key bootstrap exemption.** With exactly one key registered, `SelectActiveKey` treats it
as active immediately regardless of its activation timing (there is no prior published JWKS state
any relying party could have cached), mirroring "the very first version ever used activates
immediately." The exemption covers activation *timing only*, never expiry: a sole registered key
whose expiry (`NotAfter`/`ExpiresOn`) has already passed still returns `null` (fail closed) —
signing with a credential relying parties and the issuing CA consider invalid is a regression the
exemption must never paper over.

#### 3.6 DI registration pattern

Every `.AddXxx()` signing extension on `ZeeKayDaAuthBuilder` is the consistent registration hook,
analogous to `AddAuthentication()` in ASP.NET Core and to the store registration methods in ADR
0008. Each such method:

1. registers `IJwtSigningService` as a **singleton**;
2. calls `builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService))` so a second signing
   provider fails loudly at registration time rather than silently winning or losing;
3. registers the per-provider `IValidateOptions<TOptions>` for startup validation (for the
   development provider, `AllowedDevEnvironmentsValidator` as
   `IValidateOptions<DevelopmentSigningKeyOptions>`, registered only inside the development-key
   methods since it is only meaningful when that provider is in use).

A shared **internal** helper standardises this plumbing so each public `AddXxx()` method is a
thin, uniform call.

**Environment-conditional provider selection composes with the flat methods.** All signing
registration methods return the same `ZeeKayDaAuthBuilder`, so choosing a provider by environment
is an ordinary `if`/`else` on the builder — no dedicated sub-builder is needed (see the rejected
alternative):

```csharp
var b = services.AddZeeKayDaAuth(opt => { /* … */ })
                .AddSecretsHasher<Foo>()
                .AddInMemoryStores();
if (env.IsDevelopment())
    b.AddInMemoryDevelopmentJwtSigningKeys();
else
    b.AddAzureKeyVaultRemoteSigning(/* … */);
```

### 4. Token-pipeline integration and JWKS

#### 4.1 `ITokenWriter` — the only caller of `SignAsync`

`ITokenWriter` (in `ZeeKayDa.Auth`) is the **single** component that calls
`IJwtSigningService.SignAsync`. It is **format-agnostic** — deliberately *not* `IJwtWriter`
(see rejected alternatives). Because the JWS header is part of the signed bytes, `kid`/`alg` are
determined and fixed in the header before the signing input is formed. The flow:

1. ID-token/access-token builders above `ITokenWriter` assemble claims and base64url-encode the
   payload segment.
2. `ITokenWriter` calls `SignAsync(payloadSegment)`.
3. Internally the service picks the active key, builds the header `{"alg":"…","kid":"…"}`,
   base64url-encodes it, forms `headerSegment "." payloadSegment`, and signs.
4. `SigningResult` returns `HeaderSegment`, `SignatureSegment`, `Kid`, `Algorithm` (all
   base64url-encoded).
5. `ITokenWriter` assembles the compact JWS: `HeaderSegment "." payloadSegment "." SignatureSegment`.

This eliminates the TOCTOU race that would exist if `ITokenWriter` queried the active key
separately and then passed the full signing input. The name is format-agnostic because a future
reference/opaque-token writer is simply a different `ITokenWriter` implementation.

#### 4.2 Implementors never touch signing or JWS formatting

Third-party key providers implement **only `LoadKeysAsync`** on the §3 base class (and, only for
genuinely remote signers, override `SignInputAsync`). They never implement JWS formatting, `kid`
selection, or base64url framing — all of that lives in code ZeeKayDa owns and tests. This is the
pit of success: the only thing a provider author writes is "here are my current keys."

#### 4.3 `IJwksDocumentProvider` and the JWKS endpoint

`IJwksDocumentProvider` (in `ZeeKayDa.Auth`) mirrors `IDiscoveryDocumentProvider`. It calls
`GetSigningKeysAsync()` and maps the owned `SigningKeyDescriptor`s to a stable JWK-set wire record
(`JsonWebKeySetDocument` or similar) whose fields are pinned with explicit `[JsonPropertyName]`
attributes — **no Microsoft.IdentityModel type leakage**. The `connect/jwks` endpoint becomes a
thin ASP.NET Core adapter over this provider, replacing the current `501` placeholder. Because
`GetSigningKeysAsync` returns exactly the trusted set (active + in-window keys), the JWKS
publishes exactly those keys — the relying-party trust boundary the security sign-off (§3.3)
covers.

**The JWKS read path shares the single-flight cache.** `connect/jwks` MUST serve from the same
single-flight-gated cache as the signing path (§3.2). A burst of anonymous JWKS requests against a
cold or expired cache MUST NOT become a thundering herd against a remote key source.

**`kid` uniqueness and stability.** A published JWKS MUST NOT contain duplicate `kid` values; the
base class MUST detect a `SigningKeySet` carrying duplicate `kid`s and reject it at load time
(`ZeeKayDaConfigurationException`). A `kid` MUST be stable for the entire life of a key so relying
parties can match a token's header `kid` to a JWKS entry deterministically.

#### 4.4 Descriptor → JWK parameter extraction, and the shared public helpers

Mapping a descriptor's public key to its JWK parameters is done with BCL primitives:
`RSA.ExportParameters(false)` / `ECDsa.ExportParameters(false)` (public parameters only — private
material is never exported into a JWK), plus .NET's built-in `Base64Url` encoding. **No new
dependency** — a small, fully-specified (RFC 7517/7518), test-covered transform, covered by
known-answer-vector unit tests drawn from RFC 7517 / RFC 7520. Each emitted JWK MUST include
`"use": "sig"` (plus `alg` and `kid`).

Two derivations are shared across provider packages and are therefore **public** core types in
`ZeeKayDa.Auth` (`src/ZeeKayDa.Auth/Tokens/`), alongside `SigningKeyDescriptor` /
`SigningKeyType` / `SigningAlgorithm`:

- **`JwkThumbprint`** — RFC 7638 JWK thumbprint computation (`Compute(RSAParameters)` /
  `Compute(ECParameters)`). A provider derives a safe, non-leaking `kid` from a public key with
  it. A `kid` is always public (every issued JWT header, and the JWKS), so it MUST NOT be a raw
  external identifier (a Key Vault/key URI, a certificate's X.509 thumbprint/subject/serial),
  which would leak reconnaissance value. All providers use `JwkThumbprint`, never a raw
  identifier.
- **`SigningKeyRotation`** (with `RotationKey`/`RotationEntry`) and **`SigningKeyDescriptorFactory`** —
  the stateless activation-timeline derivation (§3.5: `BuildActivationTimeline`, `SelectActiveKey`,
  `SelectIncludedKeys`, `HasTooSoonPendingActivation`) and the RSA/EC descriptor building +
  algorithm-family/key-type validation. `SigningKeyRotation` is **anchor-agnostic**: it consumes a
  precomputed `(ActivatesAt, ExpiresAt)` pair per key rather than any credential-specific type
  (no `X509Certificate2`, no raw `NotBefore`/`NotAfter`), so core `ZeeKayDa.Auth` depends on no
  credential representation; each provider maps its own durable timestamp onto that pair before
  calling in. Key Vault's structurally different model (`CreatedOn` anchor, delay term, `Enabled`
  flag, vanished-kid detection) stays internal to its package.

These are **public**, not `internal` + `InternalsVisibleTo`, because the consumers are separate,
non-friend NuGet packages (ADR 0012) and — decisively — because `InternalsVisibleTo` can only ever
name first-party assemblies at build time, so it structurally cannot serve a genuine third party
implementing this ADR's own §3.2/§4.2 extensibility contract. `SigningAlgorithms` (ZeeKayDa's
crypto dispatch and validation) correctly stays `internal`: only the contracts that must cross the
package boundary are public.

#### 4.5 `ISanitizingLogger<T>` is public; concrete redaction stays internal

Remote-signing providers (e.g. Azure Key Vault) constructor-inject `ISanitizingLogger<T>`
(`src/ZeeKayDa.Auth/Logging/ISanitizingLogger.cs`) for log hygiene. The interface is **public**
for the same reason as §4.4's helpers: a genuine third-party remote-signing provider (AWS KMS,
HashiCorp Vault, an on-prem HSM) needs the same log-hygiene guarantee, which `InternalsVisibleTo`
cannot grant. The concrete `SecretSanitizingLogger<T>` and its `SensitiveKeys` redaction allowlist
stay **internal**.

Making the interface nameable introduces a host-misconfiguration risk that internal visibility
structurally ruled out: a host that registers its own `ISanitizingLogger<>` (open-generic, or a
closed-generic `ISanitizingLogger<SomeType>`) can silently shadow the redaction wrapper, letting
credential material reach a log sink unredacted. This is a host-side misconfiguration, not
something an external caller can trigger, but the failure mode is silent. The mitigation is
`SanitizingLoggerRegistrationStartupValidator` (`src/ZeeKayDa.Auth.AspNetCore/`), registered
**first** among `AddZeeKayDaAuth()`'s hosted services (so no shadowed logger is used before the
check runs): it resolves `ISanitizingLogger<T>` and asserts the instance is
`SecretSanitizingLogger<T>` (open-generic case), and — via `SanitizingLoggerClosedOverrideScanner`,
which holds the live `IServiceCollection` — scans for any closed-generic `ISanitizingLogger<T>`
descriptor (closed-generic case, for any `T`). Both failures **fail hard** (a shadowed sanitizing
logger is a silent security regression, unlike ADR 0008's client-repository shadow warning, which
is only a functional footgun), aggregated into one `ZeeKayDaConfigurationException`. Replacing the
interface with a public sealed concrete type would remove substitution entirely but touches ~34
call sites across four packages plus both logging analyzers and three test doubles; it remains
available as a future hardening step but is not pursued.

The analyzer `ZEEKAYDA0002` (`InterpolatedStringLogAnalyzer`, requiring compile-time-constant
`Log*` templates in `ZeeKayDa.*` namespaces) gates its exemption on
`ContainingAssembly?.Name == "ZeeKayDa.Auth"` alone — the implemented interface's visibility plays
no part — so making `ISanitizingLogger<T>` public does not open a template-constness bypass. A
regression test
(`InterpolatedStringLogAnalyzerTests.Diagnostic_still_fires_inside_friend_assembly_class_implementing_a_PUBLIC_ISanitizingLogger`)
pins this.

### 5. JWT encryption (JWE) — absent end to end in v1

There is **no** encryption support in v1: no `IEncryptionService`, no `EncryptionOptions`, no
encryption discovery fields, no client-model encryption-preference fields — **not even an "off"
toggle**.

**Rationale.** v1 does not support dynamic client registration (RFC 7591). Clients are registered
statically (ADR 0007) with no encryption-preference fields, so no code path can request an
encrypted token and there is nothing to toggle. The encryption discovery fields
(`id_token_encryption_alg_values_supported`, etc.) are **OPTIONAL** in OIDC; their *absence* is
the spec-correct signal that the provider does not offer encryption. Shipping an empty
`EncryptionOptions` or an `Enabled = false` flag would be a SemVer commitment to a surface with no
behaviour behind it — the anti-pattern ADR 0008 rejected when it deleted the empty
`DistributedCacheTokenStoreOptions`.

**Forward-compat is preserved.** `ITokenWriter` is composable (§4.1). When encryption lands, a
sibling `IEncryptionService` / `EncryptionService<TOptions>` seam is introduced (mirroring the
signing seam), and `ITokenWriter` gains an optional JWE-wrap step — **sign first, then wrap as a
nested JWT** per RFC 7519 §3. The client model and discovery document are extended at that point.

### 6. `id_token_signing_alg_values_supported` stays static, cross-checked at startup

`id_token_signing_alg_values_supported` continues to be sourced from static configuration
(`IdTokenOptions.SigningAlgValuesSupported`), **not** derived from the live key set. A startup
`IValidateOptions` cross-check verifies that every advertised algorithm is one the registered
`IJwtSigningService` can actually produce — catching the misconfiguration where the discovery
document promises an algorithm no key can sign. (Why not dynamic derivation: see rejected
alternatives.)

---

## Considered and Rejected Alternatives

### Environment-gate and registration-shape alternatives (issue #337)

#### PR #333's placement of `AllowedDevelopmentJwtSigningKeysEnvironments` on `AuthorizationServerOptions`

**Tried, shipped (PR #333, commit `79379c8`, 2026-07-10), and reverted (issue #337).** PR #333
moved the allowed-environments list from the provider-specific options type onto the shared,
public `AuthorizationServerOptions` root. Its stated goal — public configurability without
`InternalsVisibleTo` or reflection — was sound and is kept; only the *placement* was wrong.

The justification cited "mirroring `AllowInMemoryStoresOutsideDevelopment`'s server-wide-gate
placement (ADR 0002/0008)," which conflated two different things. The gate's *input* (the host
environment name) is genuinely server-wide, but the gate's *policy* is entirely feature-scoped:
the list is an inert no-op unless a development-signing-key method was also registered. A setting
on the shared root that silently does nothing unless an unrelated extension method was called is
the exact discoverability trap ADR 0008 names for auto-registration. Placing it back on the
provider options means it appears in IntelliSense only when the feature it gates is actually being
configured, is more consistent with the requirement that the gate never be sourced from bindable
configuration (a code-only `configure` callback is harder to accidentally wire to `appsettings.json`
than a bindable root property), and is a small security-discoverability improvement rather than a
regression. The goal PR #333 was actually pursuing is achieved instead by making
`DevelopmentSigningKeyOptions` public and reaching it through the registration method's `configure`
callback (§2), which needs no `InternalsVisibleTo`. See ADR 0002's scope clarification and ADR
0008's equivalent store-side move (the flag becoming an `allowOutsideDevelopment` parameter on the
in-memory registration methods) — both are one decision made together.

#### A dedicated signing-provider-selection sub-builder (`AddJwtSigning(signing => …)`)

**Considered and rejected.** A sub-builder callback was floated to make environment-conditional
provider selection "cleaner." It is unnecessary: the flat `AddXxxSigning()` methods all return the
same `ZeeKayDaAuthBuilder`, so environment branching already composes fine with an ordinary
`if`/`else` on the builder (§3.6). A sub-builder would add a parallel API surface across four
provider packages (core, FileSystem, AzureKeyVault, Windows) for a problem the reordering already
solves, and would not generalise to store registration anyway — stores are "register up to two
independent interfaces you may mix" (ADR 0008), not "pick exactly one provider," so a sub-builder
would fight ADR 0008's deliberate mix-and-match design.

#### Splitting `KeySourceRefreshInterval` into two properties (poll cadence vs. activation delay)

**Originally rejected here; superseded by issue #409 (§3.4/§3.5 amendment).** The poll cadence and
the Key Vault publish-then-activate lead time *look* separable, and the original argument against
splitting them was that two independent knobs would allow configuring `activationDelay <
pollInterval` — i.e. promoting a key to active signer before the process would even poll and
notice it exists. Issue #409 found the single property was actually overloaded with a **third**,
unrelated meaning (a File/cert-store "too-soon" warning threshold, a proxy for RP-side JWKS cache
staleness, not Key-Vault activation timing at all), and that collapsing all three into one name
was becoming harder to reason about than the misconfiguration the single property prevented. The
amended design (§3.4/§3.5) splits the properties back out — `KeyRotationCheckInterval` (shared,
renamed from `KeySourceRefreshInterval`), `SigningKeyActivationDelay` (Key-Vault-only), and
`AssumedJwksPropagationDelay` (File/cert-store-only) — and preserves the original safety
argument by moving the `ActivationDelay >= KeyRotationCheckInterval` invariant into validation
(enforced in two places: a shared validator helper and inside
`KeyVaultSigningKeyRotation.BuildActivationTimeline` itself) rather than by refusing to let the
values vary independently.

#### Splitting `IJwtSigningService`/`JwtSigningService<TOptions>` into separate key-source and signing abstractions (issue #409)

**Considered and rejected.** Proposed as an alternative to the three-tier options split, by
analogy with the `Stores/` split for authorization codes/refresh tokens (ADR 0008). Rejected
because: both overloaded meanings that motivated #409 live entirely on the key-source side, and
signing code (`SignInputAsync`/`SignAsync`) never touches these properties at all — a source/signer
split would not address the naming problem it was proposed to solve. Source and signer never vary
independently in any current provider: only `AzureKeyVaultRemoteSigningJwtSigningService` overrides
`SignInputAsync`, and it is 1:1 coupled to its own `LoadKeysAsync`. The `Stores/` precedent doesn't
transfer — storage technology and protocol semantics genuinely vary independently there; that axis
doesn't exist here. A split would also add cross-boundary lease-handoff complexity for the
sign-time `SigningKeySet` borrow (§3.2) for no benefit. **One narrow future trigger to revisit:**
once the real JWKS endpoint (`connect/jwks`, currently `501`, §4.3) ships, reconsider whether
`GetSigningKeysAsync` vs. `SignAsync` should split against a concrete consumer.

#### The `AddDevelopmentJwtSigningKeys(persistTo:)` two-overload shape

**Replaced (issue #338).** The prior shape was `AddDevelopmentJwtSigningKeys()` (ephemeral) and
`AddDevelopmentJwtSigningKeys(string? persistTo)` where `persistTo: null` meant "persist, but use
the default path" — the opposite of what a `null` argument reads as, and the opposite of what the
parameter-less overload does. It was also the only signing-provider method without a `configure`
callback. Replaced by two named methods (§2) that put the persistence choice in the name and give
`persistTo: null` exactly one meaning.

### Provider-abstraction alternatives (original ADR)

#### A third method on `IJwtSigningService` for rotation

**Rejected.** Most real providers (KMS, managed databases) own rotation on their own schedule; a
`RotateAsync`/state method imposes a lifecycle model they do not have and would force them to fake
it. Rotation is provider-private; ZeeKayDa reads the trusted set and surfaces anomalies (§3.5).

#### Generic `IJwtSigningService<TOptions>` on the public surface

**Rejected.** The options type is an implementation detail of a *concrete provider*. Consumers of
signing (the token writer, the JWKS provider) depend only on "sign this" and "give me the keys,"
neither parameterised by provider options. Genericity belongs on the optional base class
(`JwtSigningService<TOptions>`), not the consumed interface; a non-generic interface also keeps DI
registration uniform.

#### `RetirementWindow` as a user-configurable option

**Rejected.** Like the tombstone-retention and family-revocation-marker TTLs ADR 0008 removed, the
only off-default values are unsafe or useless: shorter than the longest signature-validated token
lifetime causes relying parties to reject still-valid tokens (a silent outage); longer bloats the
published trust set. The correct value is fully derivable from token lifetimes the server already
configures (§3.3), so it is derived, not exposed.

#### `IJwtWriter` instead of `ITokenWriter`

**Rejected.** It would be a misnomer the moment a reference/opaque-token writer is added. The
format-agnostic name lets a future opaque-token writer be another `ITokenWriter` implementation
rather than forcing a second parallel interface.

#### `ISigningService` instead of `IJwtSigningService`

**Rejected.** Every outbound artifact an OIDC/OAuth2 authorization server signs is a JWT (ID
tokens, JWT access tokens, logout tokens, JARM, signed userinfo); non-JWT formats (opaque
reference tokens) are not signed at all. A generic name would imply flexibility that does not exist
in this domain; the honest name is `IJwtSigningService`.

#### A shared signing-and-encryption abstraction

**Rejected.** Signing and encryption use different keys, different trust directions, and different
lifecycles; v1 ships no encryption (§5). The forward-compatible shape is *sibling* seams
(`IJwtSigningService` / `IEncryptionService`) composed by `ITokenWriter`, introduced independently
when encryption actually lands.

#### Microsoft.IdentityModel types on the public surface

**Rejected.** Exposing `SigningCredentials` / `SecurityKey` / `JsonWebKey` would bake a large,
fast-moving third-party surface into our public contract and SemVer commitments. The hand-rolled
BCL JWK mapping (§4.4) is a small, fully-specified, test-covered transform — an acceptable amount
of owned code in exchange for keeping the dependency graph clean.

#### Dynamic derivation of advertised signing algorithms

**Rejected (§6).** Discovery is a stable published contract that relying parties cache. Deriving
the advertised algorithm list from whatever keys happen to be loaded makes the discovery document
flicker during rotation. Static config plus a startup consistency check gives a stable contract
*and* catches the inconsistency dynamic derivation was trying to prevent.

### Extensibility / packaging alternatives (surfaced during implementation)

#### `InternalsVisibleTo` for `JwkThumbprint` / `ISanitizingLogger<T>` (instead of making them public)

**Tried and rejected (PR #298 / #287).** The first attempt at reusing the RFC 7638 thumbprint
logic and the sanitizing logger from the Azure Key Vault provider granted it friend-assembly
access. `InternalsVisibleTo` only grants access to assemblies named explicitly at build time: it
can serve a single first-party provider package, but it **fundamentally cannot** serve a genuine
third party implementing this ADR's own §3.2/§4.2 extensibility contract without ZeeKayDa shipping
a new core release naming them specifically — which defeats the point of an open extension point.
The fix is to make the *contracts* public (`JwkThumbprint`, `SigningKeyRotation`,
`SigningKeyDescriptorFactory`, `ISanitizingLogger<T>`) while ZeeKayDa's own crypto/redaction logic
(`SigningAlgorithms`, `SecretSanitizingLogger<T>`) stays internal (§4.4, §4.5).

#### `AzureKeyVaultSigningException` as a shared core exception type

**Rejected as premature abstraction (PR #298).** It is a package-local transport exception for
transient Key Vault sign-time faults. Making it a shared core type "for future remote providers"
was rejected until a second real remote consumer exists — ADR 0006's "colocate with the feature"
rule reads honestly here as *the Azure Key Vault feature specifically*, not *signing in general*.

#### A public sealed concrete sanitizing-logger type (instead of a substitutable interface)

**Considered and deferred (PR #298).** Replacing `ISanitizingLogger<T>` with a public sealed
concrete type would structurally remove the host-shadowing risk (§4.5) but touches ~34 call sites
across four packages plus both logging analyzers and three test doubles. The startup-validator
mitigation is used instead; the sealed-type option remains available as a future hardening step.

#### In-memory-only rotation/publish-then-activate state

**Rejected as non-compliant (§3.5).** In-memory history breaks on restart and is inconsistent
across replicas. Rotation-capable providers MUST derive their timeline from the key store's own
durable timestamps.

#### A per-version raw-secret-byte cache to skip the download on a cache hit (issue #334)

**Considered and rejected.** #334's original body proposed caching the raw downloaded
certificate-secret bytes per Key Vault version so a cache hit could skip the network call inside
`LoadKeysAsync`. Rejected: it would place private-key-bearing bytes in a side-cache living
*outside* `SigningKeySet`'s disposal graph, forfeiting the "retired private material destroyed
immediately" property §3.3(c) currently gets for free. Such a cache would need its own eviction
logic tied to the rotation timeline, and getting it wrong risks retired private key material
lingering in process memory — the exact failure §3.3(c) exists to prevent. The chosen design
(the `HasKeySetChangedAsync` ask/refresh split, §3.2 / §3.5) reaches the same "skip the expensive
download when nothing rotated" goal by comparing only per-version *metadata*, which is never key
material, and so never introduces a private-key-bearing cache at all.

#### Simplifying `SigningKeyRotation`/`RotationKey` after the macOS provider was descoped

**Rejected (issue #290 descoped, 2026-07-10).** #290 (macOS Keychain) was the bare-key consumer
that motivated *articulating* `SigningKeyRotation`'s anchor-agnostic `(ActivatesAt, ExpiresAt)`
shape, but contributed no actual generality: that decoupling is required by #289 (Windows) and
#291 (file-based) regardless, there is no bare-key-specific code in core to remove (all of it lived
in #290's cancelled package), and the types are already-shipped *public* core surface (reshaping
them would re-couple core to `X509Certificate2`, break the file-based provider, and be a
SemVer-breaking change). Kept exactly as shipped.

---

## Consequences

### Positive

- **One correct production path.** A provider author implements a single method (`LoadKeysAsync`)
  and gets correct caching, single-flight refresh, header construction, `kid` selection, and
  signing for free; only a genuinely remote signer additionally overrides `SignInputAsync`.
- **Private key material never leaves the signing component.** `SignAsync` returns a finished
  signature; no caller ever holds a private key — the invariant that makes remote signing
  (KMS/HSM) possible.
- **Clean, minimal public surface.** No Microsoft.IdentityModel leakage; everything is BCL or
  ZeeKayDa-owned types. The extension contracts third parties need (`JwtSigningService<TOptions>`,
  `JwkThumbprint`, `SigningKeyRotation`, `SigningKeyDescriptorFactory`, `ISanitizingLogger<T>`)
  are public; ZeeKayDa's own crypto/redaction logic stays internal.
- **Safety gates live with the features they gate.** The development-key environment gate is on
  `DevelopmentSigningKeyOptions` (via `configure`) and the in-memory-store gate on the store
  registration methods (ADR 0008) — each surfaces in IntelliSense only when its feature is
  configured, and neither is reachable from bindable configuration.
- **Fully unit-testable rotation/caching** via injected `TimeProvider`.
- **Secure-by-default local DX**; **stable discovery contract** that does not flicker during
  rotation.

### Negative / Trade-offs

- **Hand-rolled JWK mapping is owned code** kept correct against RFC 7517/7518 via known-answer
  vectors — accepted deliberately vs. a Microsoft.IdentityModel dependency.
- **`RetirementWindow` depends on token-lifetime configuration not present yet.** The 1-hour floor
  (§3.3 a′) bridges the gap until per-token lifetimes land; when they do, the *derivation* is
  updated (not a new option) and the floor reverts to guarding the degenerate case.
- **External-provider rotation anomalies can only be surfaced, not prevented** (§3.5).
- **Windows Certificate Store: out-of-band store deletion is not detected within a refresh
  interval.** `HasKeySetChangedAsync`'s zero-store-access ask (§3.5) cannot notice a registered
  certificate being deleted from the store outside the process; accepted because the already
  in-memory-duplicated CNG/CAPI key handle keeps signing regardless, and any change to the
  registered thumbprint set already requires a host restart, which always runs a real
  `LoadKeysAsync`.
- **Public extension surface is a SemVer commitment.** Making the helper types public (rather than
  `internal` + `InternalsVisibleTo`) is what genuine third-party providers need, but it fixes those
  shapes as stable API. The `ISanitizingLogger<T>` host-shadowing risk is mitigated by a hard-failing
  startup validator (§4.5) rather than closed off structurally.
- **No encryption in v1** — acceptable given no dynamic client registration and OPTIONAL discovery
  fields, with the forward-compat path preserved (§5).

---

## Security Considerations

- **JWKS exposure is the relying-party trust boundary (security sign-off, §3.3 / §4.3).** A key
  remains published — and therefore trusted by verifiers — for exactly `RetirementWindow` after it
  stops being the active signer. Sizing this to `max(access-token, ID-token lifetime, floor) +
  clock-skew` (1-hour floor until per-token lifetimes are configurable) and *excluding*
  refresh-token lifetime is the core security claim of this ADR and the item requiring sign-off.
- **Environment gate invariants (in scope for issue #337's review, unchanged by the reversal).**
  `Production` is rejected unconditionally regardless of `AllowedDevelopmentJwtSigningKeysEnvironments`
  contents (enforced at validation time and again by the runtime gate); the `LogLevel.Critical`
  entry fires on every startup for any non-`Development` allowed entry; and the gate is never
  sourced from bindable configuration. Moving the list from the root back onto the provider options
  changes only *where the list lives*, not any of these invariants — the runtime gate
  (`DevelopmentSigningKeyGate.Enforce`) already takes the list as a plain parameter and is
  indifferent to which options type sourced it. The equivalent in-memory-store gate (the flag
  becoming an `allowOutsideDevelopment` parameter, moving onto the store registration methods per
  ADR 0008 / issue #339) preserves its own fail-closed-outside-Development behaviour and mandatory
  startup warning identically.
- **Private key destruction on retirement (§3.3c).** Enforced by `Dispose()`-ing the superseded
  `SigningKeySet`'s private-key objects on refresh, only after all in-flight `SignAsync` calls
  referencing the old set complete. For HSM/KMS providers only the cached local handle/copy is
  disposed.
- **Development keys must never reach production.** The development methods hard-fail outside the
  allowed environments; the widening escape hatch logs `LogLevel.Critical`.
- **File-permission enforcement is fail-closed.** A persisted key file broader than `0600` (or a
  non-restrictive Windows ACL) causes a hard failure, not a warning.
- **Header `kid`/`alg` are consistent with the signature by construction (§1, §4.1).** `none` is
  not a representable algorithm, so an unsigned token cannot be produced.
- **No private key material in logs or exceptions.** A permission-failure log records only the
  file path and observed mode — never key content. `ISanitizingLogger<T>` redaction cannot be
  silently shadowed by a host (§4.5).
- **Minimum key strength is enforced (§2).** RSA < 2048 bits and non-NIST EC curves are rejected at
  load time; the development helper generates RSA ≥ 3072 bits.
- **Single-flight refresh** prevents a thundering herd against a remote key source on the signing
  hot path — including via the anonymous `connect/jwks` read path (§4.3).

---

## Changelog

Pointer-only index (date · PR/issue · what changed). Full reasoning lives in the current-state and
alternatives sections above.

- **2026-06-23 — issue #187** — Initial ADR: `IJwtSigningService`, development helper, rotation/caching base class, derived `RetirementWindow`, JWKS endpoint, JWE exclusion. **Security sign-off:** the `RetirementWindow` derivation (§3.3) and JWKS exposure (§4.3) were reviewed and approved by the security agent as a token-validation trust-boundary decision before merge; this sign-off still governs today's derivation.
- **2026-07-02 — PR #286** — Escape hatch became environment-list-based: `bool AllowDevelopmentJwtSigningKeysOutsideDevelopment` → `IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments` (default `["Development"]`). `ISigningKeyFileSystem` renamed `IDevelopmentSigningKeyFileSystem`.
- **2026-07-03 — PR #298 (ships #287, Azure Key Vault remote signing — first production provider)** — Base-class `SignInputAsync` overridable async hook added (default body reproduces prior synchronous behaviour); `ISigningKeyRetirementWindowProvider` implements the §3.3 derivation; `JwkThumbprint` and `ISanitizingLogger<T>` made public (rejecting `InternalsVisibleTo`), with a hard-failing `SanitizingLoggerRegistrationStartupValidator` shadow guard; durable `CreatedOn`-derived rotation recorded as the normative pattern. **Security sign-off:** two full rounds of independent security + architect review (design, then the committed diff), both APPROVE with no blocking findings; the second round was against commit **`ea5c9b1`**, which closed the closed-generic sanitizing-logger shadow gap the first round flagged as a known accepted residual.
- **2026-07-04 — issue #300** — Key Vault list-key-versions read-consistency verified against Microsoft's documented reliability model rather than assumed; risk **accepted as-is, no mitigation** (the only affected case is a genuinely brand-new key during a rare Microsoft-initiated regional failover, self-healing and never a security regression). Security review of PR #298 had flagged this as the item to verify.
- **2026-07-04 — issue #288 / PR #312** — §3.5 "vanished kid" anomaly trigger prose corrected to match the implemented behaviour (trigger is "the key store no longer lists this version at all," not "no replacement active for `RetirementWindow`"); documentation-accuracy only, confirmed by security + architect review.
- **2026-07-06 — issue #289** — Windows Certificate Store provider: `NotBefore`-anchored rotation timeline (no publish-then-activate delay term; the safety property becomes the operator's responsibility, surfaced by `HasTooSoonPendingActivation`).
- **2026-07-07 — issue #319 / PR #320** — Rotation timeline and descriptor factory extracted to public core `SigningKeyRotation` (`RotationKey`/`RotationEntry`) and `SigningKeyDescriptorFactory`, anchor-agnostic; behaviour-preserving consolidation of already-reviewed trust-boundary logic (#287/#288/#289).
- **2026-07-10 — issue #290 descoped** — macOS Keychain provider closed "not planned" (thin production audience); #291 (file-based) becomes the sole macOS/Linux provider. Anchor-agnostic `SigningKeyRotation`/`RotationKey` generalization kept exactly as shipped.
- **2026-07-10 — PR #333 (commit `79379c8`, issue #332)** — `AllowedDevelopmentJwtSigningKeysEnvironments` moved from `DevelopmentSigningKeyOptions` (then `internal`) to the public `AuthorizationServerOptions` root. **Reverted by #337 below.**
- **2026-07-12 — issue #334 (this PR)** — Base class gains an overridable `HasKeySetChangedAsync` change-detection hook, defaulting to `true` (= today's unconditional rebuild, so every provider except the Azure Key Vault cached-signing one is behaviour-unchanged); `BorrowSetAsync` consults it on the expiry path when a previous set exists and, on `false`, extends the cache by another interval without calling `LoadKeysAsync`, swapping, or disposing (§3.2). The Azure Key Vault cached-signing provider overrides it with a metadata-only, whole-included-set comparison (version id + `Enabled` state) over the durable version list, skipping the key-material download when nothing has rotated while leaving the per-cycle revocation/anomaly check and §3.3(c) private-material destruction untouched (§3.5). A per-version raw-secret-byte cache recorded as rejected (it would move private-key-bearing bytes outside the `SigningKeySet` disposal graph). Follow-ups **#347** (remote KV signing), **#348** (Windows Certificate Store), **#349** (file-based PEM/PFX) — all sub-issues of epic **#187**, all blocked on this landing — opt the remaining providers in individually.
- **2026-07-12 — PR #350 security review** — the version-id + `Enabled` comparison above shipped with a gap: it did not compare which entry was *active*, so the publish-then-activate activation poll (the second of the two polls described in §3.5) produced the same compared tuple set as the immediately preceding publish poll and was incorrectly treated as "unchanged," stalling rotation indefinitely. Fixed by adding active-version identity (keyed by position — index 0 is always active, per `SelectIncludedVersions`) as a third field in the compared tuple; §3.5 above updated to describe the corrected three-field basis and the failure mode it closes.
- **2026-07-11 — issue #337** — ADR migrated to the three-part format ([README](./README.md)). PR #333's root-options placement **reverted**: the list lives on the now-**public** `DevelopmentSigningKeyOptions`, configured via the registration method's `configure` callback (impl #338). `AddDevelopmentJwtSigningKeys` overloads replaced by `AddInMemoryDevelopmentJwtSigningKeys` / `AddPersistedDevelopmentJwtSigningKeys` (impl #338). `RefreshInterval` renamed and reshaped to nullable `KeySourceRefreshInterval` (`null` = load once; replaces the `TimeSpan.MaxValue` sentinel; kept as one property serving both poll cadence and publish-then-activate lead time) (impl #340). Dedicated signing sub-builder (`AddJwtSigning(signing => …)`) and splitting `KeySourceRefreshInterval` in two both recorded as rejected. **Environment-gate invariants unchanged:** Production always rejected, mandatory `Critical` startup log, never sourced from bindable configuration.
- **2026-07-12 — issue #347** — `AzureKeyVaultRemoteSigningJwtSigningService` now overrides `HasKeySetChangedAsync` with the same metadata-only, three-field `(Version, Enabled, IsActive)` comparison as the cached-signing provider (§3.5), via a shared `ComputeIncludedVersionsAsync` extraction used by both `LoadKeysAsync` and the new override. Straight port, no new design decisions: this provider's `LoadKeysAsync` has no active/non-active private-key branching to preserve, so the port is proportionately simpler than the template. #348 (Windows Certificate Store) and #349 (file-based PEM/PFX) remain open follow-ups.
- **2026-07-13 — issue #348** — `WindowsCertificateStoreSigningJwtSigningService` overrides `HasKeySetChangedAsync` too, but — unlike both Key Vault providers above — with **no store access in the ask at all**: an X.509 thumbprint is content-addressed (a SHA-1 hash of the certificate's own DER encoding), so a fixed thumbprint's `NotBefore`/`NotAfter` cannot change without the thumbprint itself changing, and the configured thumbprint set is bound once from `IOptions<TOptions>` and fixed for the process lifetime (`AddWindowsCertificateStoreSigning` already documents that changing it requires a restart, i.e. a cold start, which never reaches this hook). The override therefore recomputes the rotation timeline purely from the `RotationKey` list cached at the last successful `LoadKeysAsync`, re-evaluated against the current time — cheaper than even the Key Vault providers' metadata-only network call. Comparison shape (whole included set, keyed by thumbprint and which entry is active, via the now-public `SigningKeyRotation.ToChangeDetectionSet`) and the write-only-on-load baseline discipline both carry over unchanged; there is no `Enabled` counterpart, since a certificate registration has none. Added a regression test proving the same "active identity must be part of the comparison" lesson as PR #350's finding, and confirmed by the same red/green process (temporarily dropping `IsActive` from the tuple, observing the test fail, then restoring it). #349 (file-based PEM/PFX) remains the last open follow-up.
- **2026-07-13 — issue #348 follow-up review** — architect and security review of the `HasKeySetChangedAsync` override above both converged on the same finding: the 30-day active-certificate-expiry warning lived only in `LoadKeysAsync`, so an unchanged ask cycle that now skips `LoadKeysAsync` entirely also silently skipped re-firing that warning, contradicting the method's own documented "repeats for as long as the condition holds" cadence. Fixed by relocating the check into `HasKeySetChangedAsync` itself (no store access added — it only needs the cached active entry's `ExpiresAt`), firing on every ask cycle; `LoadKeysAsync` keeps one guarded call for the cold-start case only, so the warning neither goes missing in the steady state nor double-logs on a cycle where a reload also runs. §3.5 above updated with the fix and with an explicit "consequences" note accepting that out-of-band store deletion is not detected within a refresh interval (§"Consequences" / Negative-Trade-offs). The "only elapsed time can change" phrasing (§3.5 and the code's own XML remarks) corrected to scope explicitly to "a thumbprint that remains present and accessible in the store."
- **2026-07-19 — issue #349** — `FileSigningJwtSigningService<TOptions>` (the shared base class
  behind `PemFileSigningJwtSigningService` and `PfxFileSigningJwtSigningService`) overrides
  `HasKeySetChangedAsync` once, covering both subclasses in a single change: registered-path-set
  membership, then per-path `File.GetLastWriteTimeUtc` (a stat, never a content read), then —
  only when both are unchanged — a recomputed `(active path, included path set)` tuple via the
  shared `SigningKeyRotation.ToChangeDetectionSet` helper #347/#348 also use, evaluated against
  the `NotBefore`/`NotAfter` metadata recorded at the last successful load rather than by
  re-parsing any file. mtime is not a strong integrity signal on its own, but is used only to
  decide whether to re-read — a mtime-collision false "unchanged" only delays picking up a
  rotation by one refresh interval, it does not weaken any validation guarantee. Same
  write-only-on-load baseline discipline as the other three providers. Closes epic #187's
  `HasKeySetChangedAsync` follow-up set opened by issue #334 (all four shipped providers now
  implement the hook).
- **2026-07-19 — issue #355** — `SigningKeySet` construction reshaped from a single positional `IReadOnlyList<SigningKeyPair>` (first entry = active by unenforced convention) to a named `SigningKeySet(SigningKeyPair activeKey, IEnumerable<SigningKeyPair>? additionalKeys = null)`, so the active signing key can no longer be selected by list order and an out-of-order custom provider can no longer silently sign with a retired/not-yet-active key (§3.2, structural tier-1 fix). `ActiveKey` now derives from the named parameter rather than `Keys[0]`; the empty-set `ArgumentException` disappears (emptiness is unrepresentable); `Keys`/JWKS ordering and the hot-path zero-alloc reuse are unchanged. Second bucket named `additionalKeys` — lifecycle-neutral (covers both pre-published/future and within-retirement-window keys), not `retired`; two buckets, no new third list. Duplicate-`kid` validation stays at the base-class load path (§4.3), not the constructor.
- **2026-07-20 — issue #409 (design only, no implementation in this PR)** — §3.4/§3.5 amended: the overloaded `KeySourceRefreshInterval` (`TimeSpan?` on `JwtSigningServiceOptions`) is replaced by a three-tier options hierarchy — `JwtSigningServiceOptions` (base, no rotation property), `StaticKeySourceOptions` (load-once-forever, used only by `DevelopmentSigningKeyOptions`, replacing the `null`-sentinel), and `RotatingKeySourceOptions` (used by File, PFX, Windows Certificate Store, *and* Azure Key Vault cached/remote — not Key-Vault-only as the old single-property design implied), carrying the renamed **`KeyRotationCheckInterval`**. Two new properties split out the roles the old property overloaded: **`SigningKeyActivationDelay`** (Key-Vault-only, on `AzureKeyVaultCachedSigningOptions`/`AzureKeyVaultRemoteSigningOptions`, invariant `>= KeyRotationCheckInterval` enforced in a shared validator helper *and* inside `KeyVaultSigningKeyRotation.BuildActivationTimeline`) and **`AssumedJwksPropagationDelay`** (File/cert-store-only, feeding `HasTooSoonPendingActivation`); both default to `KeyRotationCheckInterval` when unset, preserving today's runtime behaviour exactly. A source/signer abstraction split (analogous to ADR 0008's `Stores/`) was considered and rejected — see Rejected Alternatives. Naming/regrouping only; no behaviour change. Property renames, validators, and the docs-site extensibility page (three-tier model, Azure Key Vault worked example) are follow-up implementation work, tracked separately from this ADR amendment.
- **2026-07-20 — issue #407** — §3.4 amended: `RotatingKeySourceOptions.KeyRotationCheckInterval`'s default raised **5 minutes → 1 hour**, ratified by architect + security review (see §3.4's amendment prose for the full reasoning) and confirmed by @ChrisKlug. Applies uniformly to all four rotating providers, not Key-Vault-only. `SigningKeyActivationDelay` and `AssumedJwksPropagationDelay` are unaffected in mechanism — both still default to `KeyRotationCheckInterval` when unset — but now inherit the 1-hour value by that same default-propagation rule. The Key Vault validators' 1-minute floor is unchanged. Worked examples in the how-to docs updated to stop showing 5–10 minute values as copy-paste-safe production defaults.
- **2026-07-20 — issue #407 review correction** — §3.4's "operator-maintained published standby key" mitigation claim was factually wrong and has been corrected in place (not just amended below it): activation for every provider (File/PFX/cert-store/Key Vault) is driven solely by `NotBefore`/`ActivatesAt` versus wall-clock time, with no separate enable/promote gate, so a key cannot sit published-but-inactive past its own activation time and be promoted on demand — once eligible, it either already is the active signer or has already been superseded. There is no third, held-in-reserve state. The `rotate-signing-keys.md` "Emergency key rotation" section and its cross-references (including from `configure-azure-key-vault-signing.md`) are corrected to match: there is no stage-a-standby state for any provider, but the actual emergency procedure is provider-specific — File/PFX/Windows Certificate Store use remove-the-compromised-key-and-redeploy (no enable/disable flag exists), while Azure Key Vault uses disable-the-compromised-version-in-the-vault plus restart (its `Enabled` flag is a genuine kill-switch, but disabling only changes what the vault reports — a restart is still what forces the immediate cold `LoadKeysAsync` that drops the disabled version at once instead of on the next poll; a freshly created replacement version is not exempt from `SigningKeyActivationDelay`, since the bootstrap exemption is keyed on `firstEverVersion`, not "currently the only enabled version"). Both procedures stop the compromised key from being *newly* trusted but do not retroactively invalidate tokens already accepted by a relying party that cached the compromised key before rotation — that residual window is bounded by the relying party's own JWKS-cache TTL, not by anything this library controls. Found and confirmed by @ChrisKlug.
- **2026-07-20 — issue #407 second review correction** — architect and security review both
  found the prior correction incomplete on two fronts. First, the debunked standby-key claim
  still survived verbatim in `RotatingKeySourceOptions.KeyRotationCheckInterval`'s XML doc
  comment (a separate, consumer-facing spot the prior correction pass had not touched), and both
  this ADR's §3.4 body and its own 2026-07-20 changelog entry above still asserted
  "remove-and-redeploy" as the single, provider-agnostic correct emergency runbook — which is
  wrong for Azure Key Vault, whose `Enabled` flag is a genuine, unconditional kill-switch, and
  whose bootstrap exemption (keyed on `firstEverVersion`, not "sole enabled version") does not
  cover a freshly created emergency version. Second, the fixed-up Key Vault runbook then
  overcorrected into a self-contradiction: it described disabling a version as taking effect "on
  the next poll (within `KeyRotationCheckInterval`)" in one sentence and "immediately" in the
  next. Disabling only changes what Key Vault itself reports; ZeeKayDa.Auth does not observe it
  until its next poll or a restart — a restart forces the same immediate cold `LoadKeysAsync`
  that the File/PFX/cert-store runbook already relies on, so the Key Vault runbook needs it too.
  Fixed in place: the XML doc comment, §3.4's body, this changelog's prior entry,
  `rotate-signing-keys.md`'s "Emergency key rotation" section (split into a File/PFX/cert-store
  subsection and a Key-Vault-specific subsection, both now ending in restart), and the one
  cross-reference into it from `configure-azure-key-vault-signing.md`. Found and confirmed by
  @ChrisKlug.

---

## References

- Issue **#187** — signing key management design session.
- **ADR 0002** — options shape (grouping rule scope; per-provider knobs on provider options).
- **ADR 0006** — exception hierarchy (`ZeeKayDaConfigurationException`).
- **ADR 0007** — client registration model (static registration; no encryption-preference fields).
- **ADR 0008** — authorization-code/refresh-token store (registration idiom,
  `ThrowIfAlreadyRegistered`, escape-hatch pattern, refresh-token-via-store validation,
  empty-options-class SemVer lesson, and the equivalent `allowOutsideDevelopment` parameter
  placement change made together with this one).
- **ADR 0012** — signing-provider NuGet packaging model (why shared helpers are public in core,
  not `internal` + `InternalsVisibleTo`).
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT), RFC 7520 (JOSE examples),
  RFC 7591 (dynamic client registration), RFC 7638 (JWK thumbprint), RFC 9700 (OAuth security BCP).
