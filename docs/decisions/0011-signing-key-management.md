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
AddInMemoryDevelopmentJwtSigningKeys(Action<DevelopmentSigningKeyOptions>? configure = null);
AddPersistedDevelopmentJwtSigningKeys(string? persistTo = null, Action<DevelopmentSigningKeyOptions>? configure = null);
```

The persistence choice lives in the **method name**, not in an argument whose `null` value has
to be read against the grain. On `AddPersistedDevelopmentJwtSigningKeys`, `persistTo: null`
means exactly one thing — "persist to the default path" — with no second reading available.
Both methods take an optional `Action<DevelopmentSigningKeyOptions>? configure` callback,
consistent with every production provider registration method (`AddPemFileSigning`,
`AddPfxFileSigning`, the Azure Key Vault and Windows Certificate Store equivalents), which all
already accept an `Action<TOptions>? configure = null`.

`DevelopmentSigningKeyOptions` is a **public** provider-specific options type
(`DevelopmentSigningKeyOptions : JwtSigningServiceOptions`), reachable through the `configure`
callback with no `InternalsVisibleTo` grant or reflection required.

**Hard fail outside Development.** These methods register a development-only provider. If the
host environment is not in the allowed-environments list (below), startup fails with
`ZeeKayDaConfigurationException`, exactly mirroring the in-memory store behaviour from ADR 0008.

**The environment gate is a provider-scoped, code-only opt-in — `AllowedDevelopmentJwtSigningKeysEnvironments`.**

```csharp
public sealed class DevelopmentSigningKeyOptions : JwtSigningServiceOptions
{
    // Defaults to ["Development"]. Widening it to a named non-production environment
    // (e.g. "Staging", "IntegrationTest") is an explicit, code-only opt-in.
    public IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments { get; set; } = ["Development"];
    // … EnvironmentName (host-populated), PersistToDirectory, inherited KeySourceRefreshInterval …
}
```

The allowed-environments list lives on the **provider-specific `DevelopmentSigningKeyOptions`**,
configured through the registration method's `configure` callback:

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
  detection. Development signing keys log `Critical` (in-memory stores log `Warning`) because a
  non-rotating, possibly-ephemeral signing key in a non-development host breaks signature
  validation for every relying party on restart — a strictly more severe misconfiguration than a
  non-durable token store.
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
    /// Loads the current set of trusted keys. Called at most once per KeySourceRefreshInterval;
    /// concurrent callers after the interval elapses are coalesced into a single load.
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

#### 3.4 `JwtSigningServiceOptions` carries `KeySourceRefreshInterval` only

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

The base options type carries **`KeySourceRefreshInterval`** and nothing else. `RetirementWindow`
is *not* here (§3.3). Provider-specific options derive from this type.

`KeySourceRefreshInterval` is a **nullable `TimeSpan?`**: a non-null value is the finite poll
cadence; **`null` means "load once, never reload"**, a named static-source mode for an immutable
key source. This replaces the earlier `TimeSpan.MaxValue`-as-sentinel design, in which a *mode*
("never poll") was expressed via a *cadence* value plus a magic-number special case in the base
class's refresh arithmetic. `DevelopmentSigningKeyOptions` defaults this to `null` (a
locally-generated or file-persisted key set never changes at runtime, so there is nothing to
poll; static mode is also what lets the base class avoid disposing a still-referenced memoized
key set). `JwtSigningService<TOptions>.BorrowSetAsync` expresses the static case directly via a
null check — no `TimeSpan.MaxValue` comparison and no overflow guard.

The name conveys **both** roles the value serves — poll cadence and, for Key Vault-style
providers, publish-then-activate lead time (§3.5). They are one property on purpose: binding them
to a single value makes it structurally impossible to configure an activation delay shorter than
the poll interval, i.e. to activate a key before the process would even notice it exists — the
exact race the publish-then-activate/retirement-window model exists to prevent (see the rejected
"split into two knobs" alternative).

#### 3.5 Rotation for external providers — read-only, durable-timestamp-derived, with anomaly surfacing

For provider-owned rotation (KMS, database, OS certificate store), ZeeKayDa reads the trusted set
via `LoadKeysAsync` and surfaces anomalies rather than driving rotation.

**Publish-then-activate.** If a key starts signing before its public half appears in the JWKS, a
relying party that fetches a fresh JWKS still will not find the new `kid` and will reject
otherwise-valid tokens. A key therefore MUST appear in `GetSigningKeysAsync()` results — and so
in the published JWKS — for at least one RP JWKS-cache-TTL period **before** it becomes the active
signer. Implementations MUST NOT promote a key to active signer until it has been published. As a
safe default the activation delay SHOULD be ≥ `KeySourceRefreshInterval`, so an RP that polls the
JWKS at the interval will have observed the key before the first token signed with it.

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
  `v.CreatedOn + KeySourceRefreshInterval` for every subsequent version (the publish-then-activate
  delay); `NotBefore` folds into `ActivatesAt` as `max(rawActivatesAt, v.NotBefore)`;
  `Enabled = false` is an immediate, unconditional exclusion that bypasses `RetirementWindow`
  (an operator disabling a suspected-compromised version takes effect at once); `RetiredAt(v)` is
  the `ActivatesAt` of whichever *eligible* successor actually superseded `v`. This makes the whole
  timeline a stateless computation over `(the store's version list, now,
  KeySourceRefreshInterval, RetirementWindow)` — restart-safe, multi-replica-consistent, and
  fully `FakeTimeProvider`-testable. The Key Vault rotation model (`KeyVaultSigningKeyRotation`)
  stays internal to `ZeeKayDa.Auth.AzureKeyVault`.
- **Windows Certificate Store** (and, by the same pattern, the file-based provider) anchors on the
  certificate's immutable `NotBefore`/`NotAfter` (a Windows store certificate has no `CreatedOn`
  equivalent). `ActivatesAt(cert) = cert.NotBefore`, with **no** extra publish-then-activate delay
  term (every registered certificate is fully visible in the JWKS as of process start; there is no
  "has the store durably recorded this yet" question). The publish-then-activate safety property
  therefore becomes the **operator's** responsibility: a certificate generated for rotation must
  have its `NotBefore` set at least `KeySourceRefreshInterval` in the future.
  `SigningKeyRotation.HasTooSoonPendingActivation` surfaces a startup warning when it is not — the
  library's only defence, since a local store cannot prove when a certificate was actually
  deployed.

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
0008's equivalent store-side move (`AllowInMemoryStoresOutsideDevelopment` onto the in-memory
registration methods) — both are one decision made together.

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

**Considered and rejected.** The poll cadence and the Key Vault publish-then-activate lead time
*look* separable, and the temptation is to expose two knobs. Binding them to one value is
intentional: two independent knobs would allow configuring `activationDelay < pollInterval` — i.e.
promoting a key to active signer before the process would even poll and notice it exists — which is
exactly the race the publish-then-activate/retirement-window model (§3.5) exists to prevent. One
property makes that misconfiguration unrepresentable. (This is the same "the only off-default
values are unsafe" argument that keeps `RetirementWindow` derived rather than configurable.)

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
  indifferent to which options type sourced it. The equivalent in-memory-store gate
  (`AllowInMemoryStoresOutsideDevelopment`, moving onto the store registration methods per ADR
  0008 / issue #339) preserves its own fail-closed-outside-Development behaviour and mandatory
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
- **2026-07-11 — issue #337 (this PR)** — ADR migrated to the three-part format ([README](./README.md)). PR #333's root-options placement **reverted**: the list lives on the now-**public** `DevelopmentSigningKeyOptions`, configured via the registration method's `configure` callback (impl #338). `AddDevelopmentJwtSigningKeys` overloads replaced by `AddInMemoryDevelopmentJwtSigningKeys` / `AddPersistedDevelopmentJwtSigningKeys` (impl #338). `RefreshInterval` renamed and reshaped to nullable `KeySourceRefreshInterval` (`null` = load once; replaces the `TimeSpan.MaxValue` sentinel; kept as one property serving both poll cadence and publish-then-activate lead time) (impl #340). Dedicated signing sub-builder (`AddJwtSigning(signing => …)`) and splitting `KeySourceRefreshInterval` in two both recorded as rejected. **Environment-gate invariants unchanged:** Production always rejected, mandatory `Critical` startup log, never sourced from bindable configuration.

---

## References

- Issue **#187** — signing key management design session.
- **ADR 0002** — options shape (grouping rule scope; per-provider knobs on provider options).
- **ADR 0006** — exception hierarchy (`ZeeKayDaConfigurationException`).
- **ADR 0007** — client registration model (static registration; no encryption-preference fields).
- **ADR 0008** — authorization-code/refresh-token store (registration idiom,
  `ThrowIfAlreadyRegistered`, escape-hatch pattern, refresh-token-via-store validation,
  empty-options-class SemVer lesson, and the equivalent `AllowInMemoryStoresOutsideDevelopment`
  placement change made together with this one).
- **ADR 0012** — signing-provider NuGet packaging model (why shared helpers are public in core,
  not `internal` + `InternalsVisibleTo`).
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT), RFC 7520 (JOSE examples),
  RFC 7591 (dynamic client registration), RFC 7638 (JWK thumbprint), RFC 9700 (OAuth security BCP).
