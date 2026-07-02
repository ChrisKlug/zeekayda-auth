# ADR 0011 — Signing Key Management

**Status:** Accepted  
**Date:** 2026-06-23

> **Security sign-off required on the ADR PR.** §3 derives a `RetirementWindow` that
> directly governs how long a retired signing key's *public* half stays published in the
> JWKS, and therefore how long relying parties will continue to accept signatures made by
> that key. This is a token-validation trust-boundary decision. The security agent MUST
> review and approve the `RetirementWindow` derivation (§3.3) and the JWKS exposure
> behaviour (§4.3) before this ADR is merged. The flag is called out again inline at the
> relevant decision.

---

## Context

ZeeKayDa.Auth issues signed artifacts — ID tokens today, JWT access tokens and other
JWS-protected objects in the near future — and must publish the corresponding public keys
at the JWKS endpoint so relying parties can validate them. The `connect/jwks` endpoint is
currently a `501 Not Implemented` placeholder, and `DiscoveryDocumentProvider` already
advertises a derived `jwks_uri` (`src/ZeeKayDa.Auth/Discovery/DiscoveryDocumentProvider.cs`)
that points at it. Nothing yet sits behind it. The signing-algorithm vocabulary exists
(`src/ZeeKayDa.Auth/Tokens/SigningAlgorithm.cs`) and `id_token_signing_alg_values_supported`
is advertised from static configuration (`IdTokenOptions.SigningAlgValuesSupported`), but
there is no component that owns a private key, performs a signature, or maps a key to its
JWK wire representation.

This ADR (issue **#187**) settles signing key management end to end: the provider
abstraction consumers implement to supply keys, the developer-experience helper for local
work, the rotation and caching machinery, the token-pipeline integration, the JWKS
endpoint, and the explicit exclusion of JWT encryption from v1.

The design must serve the same two goals every ZeeKayDa.Auth decision serves: it must be
**easy to use** (the local-development path is one line; the production path has exactly
one correct way to implement it) and **secure by default** (private key material never
leaves the signing component; insecure development shortcuts hard-fail outside Development).

### Constraints and prior decisions that shape this ADR

- **No Microsoft.IdentityModel on the public surface.** ZeeKayDa.Auth keeps its dependency
  graph minimal and intentional. `Microsoft.IdentityModel.Tokens` types
  (`SecurityKey`, `SigningCredentials`, `JsonWebKey`, …) are convenient but they are a
  large, churning surface that we do not want to bake into our own public contract. The
  abstractions in this ADR are expressed entirely in BCL types and ZeeKayDa-owned types.
  Any use of Microsoft crypto types is an *internal implementation detail* of a concrete
  provider, never visible on an interface, descriptor, or options class.
- **ADR 0002** (options shape — grouped nested per-endpoint options) governs where new
  configuration lives. Server-wide safety gates live on the root `AuthorizationServerOptions`;
  per-provider knobs live on a provider-specific options type.
- **ADR 0006** (exception hierarchy) governs the failure type: startup/configuration faults
  throw `ZeeKayDaConfigurationException`.
- **ADR 0008** (authorization-code and refresh-token store) establishes the
  `AddXxx()`-on-`ZeeKayDaAuthBuilder` registration idiom, the `ThrowIfAlreadyRegistered`
  double-registration guard, the `AllowInMemoryStoresOutsideDevelopment` escape-hatch
  pattern (mirrored here), and — load-bearing for §3.3 — the fact that **refresh tokens are
  validated by the authorization server against the token store, never by relying parties
  against the JWKS**. Refresh-token family revocation (ADR 0008 §4) is an AS-side store
  operation; a relying party never inspects a refresh token's signature.

---

## Decision

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
`HeaderSegment` and `SignatureSegment` are already base64url-encoded. The caller (`ITokenWriter`,
§4.1) assembles the compact JWS: `header "." payload "." signature`.

This is the pit-of-success guarantee for the token pipeline. Because the service builds the
header in the same operation that selects the key and produces the signature, the header's
`kid`/`alg` and the actual signing key are **always consistent by construction** — there is no
window in which a key rotation can cause the header to advertise a different key than the one
that signed. There is no API path through which a caller can supply a mismatched algorithm,
choose the wrong key, or produce a header that disagrees with the signature.

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
own keys — and is deferred to a separate future seam. Putting verification here would
conflate "sign with my key" and "verify with someone else's key" on one interface.

**Async by deliberate design.** `SignAsync` and `GetSigningKeysAsync` are async even though
the v1 implementations are CPU-bound and synchronous under the hood. The async signature is
the seam that makes **remote signing (KMS / HSM / Azure Key Vault)** a non-breaking future
addition: a remote signer performs network I/O on every `SignAsync` call. The companion
invariant — **callers never hold private key material** — is what makes remote signing
actually possible later: because `SignAsync` returns a finished signature rather than a key,
the private key can live in an HSM that never exports it. Remote signing is **not
implemented in v1**; only the seam is reserved.

### 2. Developer experience — `AddDevelopmentJwtSigningKeys`

A single builder extension on `ZeeKayDaAuthBuilder` makes local development one line:

```csharp
builder.Services.AddZeeKayDaAuth(/* … */)
       .AddDevelopmentJwtSigningKeys();            // ephemeral, in-memory
// or
       .AddDevelopmentJwtSigningKeys(persistTo: null);   // persist to the default path
```

Signature: `AddDevelopmentJwtSigningKeys(string? persistTo = null)`.

**Hard fail outside Development.** This method registers a development-only provider. If the
host environment is not `Development`, startup fails with `ZeeKayDaConfigurationException`,
exactly mirroring the in-memory store behaviour from ADR 0008. The escape hatch is a single
server-wide flag on the root options class:

```csharp
public bool AllowDevelopmentJwtSigningKeysOutsideDevelopment { get; set; }   // default false
```

When set to `true`, the provider is permitted to run outside Development and a
`LogLevel.Critical` log entry is emitted (in-memory stores log `Warning`; development
signing keys log `Critical` because a non-rotating, possibly-ephemeral signing key in a
non-development host is a strictly more severe misconfiguration than a non-durable token
store — it breaks signature validation for every relying party on restart). The flag lives
on `AuthorizationServerOptions`, **not** on the provider options type, because it is a
server-wide safety gate, not a per-provider tuning knob (§3.5, ADR 0002).

`AllowDevelopmentJwtSigningKeysOutsideDevelopment` MUST NOT be settable from `appsettings.json`
or any other file that may be committed to source control. It SHOULD be sourced from an
environment variable or set explicitly in code, never bound from a config file — a committed
`true` is exactly the silent escalation this gate exists to prevent. The `LogLevel.Critical`
entry MUST fire on **every startup** while the flag is set — not once, not only on first
detection — so the misconfiguration is never silent on a long-running or restarted host.

Even with the flag set, the development provider still enforces **all** of the
minimum-key-strength (§2) and file-permission/ownership/symlink requirements above. The
escape hatch relaxes **only** the environment gate; it never relaxes any crypto or
filesystem-hardening requirement.

**Ephemeral by default.** With no argument, a fresh RSA key is generated in memory on each
startup. This is correct for local development: nothing persists, nothing leaks to disk.
Passing `persistTo` opts into persistence so a developer's tokens survive an app restart.

**Minimum key strength.** Generated keys are not arbitrarily sized:

- The development helper MUST generate **RSA keys of at least 3072 bits**. 3072 is the
  recommendation for new keys per NIST SP 800-57 Part 1 Rev. 5 §5.6.1 Table 2, not merely the
  2048-bit floor.
- The base class (§3.2) MUST reject any RSA key smaller than **2048 bits** (the hard minimum)
  with `ZeeKayDaConfigurationException`, regardless of provider.
- Acceptable EC curves are exactly P-256, P-384, and P-521 (the curves backing the
  `SigningAlgorithm` values). Non-NIST curves (e.g. secp256k1) MUST be rejected with
  `ZeeKayDaConfigurationException`.

**Persistence is safe by construction.** When persistence is opted into but no explicit
path is given, the default path is `{IHostEnvironment.ContentRootPath}/.zeekayda/signing-keys/`.

- The directory is created with `0700` and key files with `0600` — **atomically at
  open/create time**, not create-then-`chmod`. On .NET this means passing
  `FileStreamOptions.UnixCreateMode = UserRead | UserWrite` when creating a key file, and
  creating the directory with `0700` in the same operation. Creating with default permissions
  and then narrowing is **prohibited**: there is a window between creation and the permission
  change in which the file exists with the process umask's default mode, potentially readable
  by another local user. The `umask` MUST NOT be relied upon for security — it can only remove
  bits from a requested mode, so a permissive umask combined with create-then-`chmod` is
  precisely the bug being closed here.
- If an existing key file is found with permissions **broader than `0600`**, the provider
  **fails loudly** (`ZeeKayDaConfigurationException`) rather than loading it — a key file
  that other local users can read is treated as compromised, not as a warning.
- **No symlink following.** When opening or creating a key file the provider MUST refuse to
  follow symlinks: if the path (or any component of it) resolves through a symlink, the
  provider fails with `ZeeKayDaConfigurationException`. This prevents a planted symlink from
  redirecting a freshly generated private key to an attacker-controlled location.
- **Parent-directory ownership.** Every component of the directory chain the provider creates
  or writes into MUST be owned by the current user. If any component is owned by a different
  user, the provider fails closed (`ZeeKayDaConfigurationException`).
- On Windows, the equivalent is a restrictive ACL granting the current user only, with no
  `Everyone`/`Users` entries; the file's ACL MUST have **inheritance disabled**, so only the
  current user (plus SYSTEM/Administrators at implementor discretion) appears in the DACL.
- On Linux there is no OS keystore integration: ephemeral or file-persisted are the only
  development options. This is acceptable because the helper is development-only; production
  keys come from a real provider (§3).

**Key format: plain PEM.** No password-based encryption, no PKCS#12. PEM is the least
surprising, most tool-compatible format for a file a developer may inspect, and the `0600`
permission is the access control. Encrypting the PEM would require a passphrase-management
story that is out of scope for a development helper.

The development provider derives from the §3 base class as
`JwtSigningService<DevelopmentSigningKeyOptions>`, where
`DevelopmentSigningKeyOptions : JwtSigningServiceOptions`.

`ISigningKeyFileSystem` exposes async read/write operations (`ReadKeyFileAsync` /
`WriteKeyFileAsync`) with a `CancellationToken`; production implementations must propagate
the token to their underlying I/O. `DevelopmentJwtSigningService` propagates the token
received from `LoadKeysAsync` to all file I/O calls; however, RSA key generation
(`RSA.Create`) is CPU-bound and has no async variant, so that step cannot be cancelled.

### 3. Rotation and the optional base class

#### 3.1 No third method on the interface

`IJwtSigningService` stays at the two methods in §1. Rotation is **not** part of the public
contract. A provider backed by a managed KMS rotates keys on the KMS's schedule, entirely
outside ZeeKayDa's control; a provider backed by a database rotates on its own job. Forcing
a `RotateAsync` (or similar) onto every implementor would impose a lifecycle model that most
real providers do not own. ZeeKayDa is a **reader** of the trusted key set, not the rotation
authority.

#### 3.2 The optional base class `JwtSigningService<TOptions>`

Most implementors should not reimplement caching, single-flight refresh, or the crypto call.
An **optional** abstract base class carries all of it:

```csharp
namespace ZeeKayDa.Auth.Tokens;

public abstract class JwtSigningService<TOptions> : IJwtSigningService
    where TOptions : JwtSigningServiceOptions
{
    protected JwtSigningService(IOptions<TOptions> options, TimeProvider timeProvider) { /* … */ }

    /// <summary>
    /// Loads the current set of trusted keys. Called at most once per RefreshInterval;
    /// concurrent callers after the interval elapses are coalesced into a single load.
    /// </summary>
    protected abstract ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken);

    // IJwtSigningService implemented by the base class on top of LoadKeysAsync + the crypto call.
}
```

The base class owns:

- **Interval-throttled caching** driven by an injected **`TimeProvider`** — never
  `DateTime.Now` / `DateTimeOffset.UtcNow`. This keeps the whole rotation/caching path
  unit-testable with a `FakeTimeProvider`, satisfying the testability principle (no running
  server, no wall-clock dependency).
- A **single-flight refresh gate**: when the refresh interval elapses, concurrent
  first-requests do not all trigger `LoadKeysAsync` simultaneously; exactly one load runs
  and the rest await its result. This matters on the hot path — signing is per-token-issuance
  — where a thundering herd against a remote key source would be a self-inflicted outage.
- The **`SignAsync` crypto call** itself, selecting the active key from the loaded set.
- **Deterministic disposal of superseded private key material.** `SigningKeySet`, and any
  type holding private key material, MUST be `IDisposable`. When the base class replaces the
  cached set on refresh, it MUST `Dispose()` the previous set's private-key objects — the
  `RSA` / `ECDsa` / `AsymmetricAlgorithm` instances — rather than leaving them to the GC.
  These BCL types are `IDisposable` wrappers over unmanaged key handles that can retain key
  bytes in process memory indefinitely until finalized; relying on GC is not acceptable for
  key material. For a remote signer there is no local private key, so this disposes only the
  cached local handle/copy (see §3.3c).
- **Ordered disposal after in-flight signs.** Disposal of the old set's private-key objects
  MUST be deferred until every in-flight `SignAsync` call that references the old set has
  completed. Disposing an `RSA`/`ECDsa` while a concurrent `SignAsync` is mid-operation would
  raise `ObjectDisposedException` (or worse). The single-flight refresh gate already
  serialises the *loading* half; the same gate — or a reference count over the active set —
  MUST also ensure no caller is mid-sign with the old key objects when they are disposed.

Implementors provide exactly one method: `LoadKeysAsync`, returning a **`SigningKeySet`**
(the current trusted set: active key plus in-window keys, with whatever private material the
provider holds to perform signatures). The development provider (§2) derives from this base.
The base class ships in **v1**.

#### 3.3 `RetirementWindow` is derived, not configurable

> **Security sign-off point.** The derivation and its safety argument below are the specific
> item the security agent must approve on this ADR PR.

`RetirementWindow` is the period for which a key that is no longer the active signer remains
published in the JWKS (and thus remains trusted by relying parties). It is **derived, not a
user setting**:

```
RetirementWindow = max(access-token lifetime, ID-token lifetime, <floor>) + clock-skew allowance
```

The window is measured from the moment the key **ceases to be the active signer** — i.e. the
instant a successor key becomes the active signer — **not** from key creation or initial
activation. Starting the clock at creation or first activation would retire the key before
the last token it signed has expired, causing valid tokens to be rejected.

Four properties of this derivation are normative and must be stated explicitly:

- **(a) It is sized to the longest-lived *signature-validated* token.** A key may only be
  retired from the JWKS once every token it could have signed has expired. The window is the
  longest lifetime among the artifacts a relying party validates by *signature* — today the
  ID token (`IdTokenOptions`), and the JWT access token once configurable
  access-token lifetime lands. The clock-skew allowance covers relying parties whose clocks
  trail the issuer's, consistent with the `ClockSkewTolerance` rationale in ADR 0008. Any
  future artifact validated by signature against the JWKS (e.g. logout tokens, JARM
  responses, SD-JWT) MUST be added to the `max(...)` set; introducing such an artifact
  without extending this derivation is a security regression.
- **(a′) A conservative floor bridges the missing lifetime configuration.** `IdTokenOptions`
  carries no ID-token lifetime property today (only `SigningAlgValuesSupported`), and there
  is no configurable JWT-access-token lifetime yet, so **both** terms of the `max(...)` are
  currently unconfigured. Until configurable per-token lifetimes are introduced, the
  implementation MUST apply a floor of at least **1 hour** to the `max(...)` term, so that
  `RetirementWindow` is never shorter than 1 hour + clock-skew. Without this floor the
  `max(...)` would resolve over zero configured terms and produce a near-zero window that
  would immediately invalidate every token in flight. 1 hour is longer than any typical ID
  token yet far shorter than a refresh token — a safe bridge, **not** a permanent default.
  Once ID-token and JWT-access-token lifetime configuration exists, the derivation uses the
  configured values and the floor merely guards the degenerate case.
- **(b) Refresh-token lifetime is deliberately excluded.** `TokenEndpoint.RefreshTokenLifetime`
  (default 14 days) is *not* part of the `max(...)`. Refresh tokens are validated by the
  authorization server against the refresh-token store (ADR 0008), **never by a relying
  party against the JWKS**. Including the 14-day refresh lifetime would pin every retired
  public key in the JWKS for two weeks for no validation benefit, enlarging the published
  trust set far beyond what any verifier actually needs.
- **(c) The retired key's *private* material is destroyed immediately on retirement.**
  `RetirementWindow` governs only how long the *public* key stays in the JWKS so that
  already-issued tokens keep validating. Once a key stops being the active signer it signs
  nothing further, so its private half has no further use and MUST be destroyed at once.
  Keeping a retired private key alive is pure liability. For remote-signing providers
  (HSM/KMS) there is no local private key to destroy — it never left the HSM; the obligation
  there is to dispose whatever local *handle or copy* the base class or provider cached, not
  the key itself.

The clock-skew allowance always **widens** the window — it is added to the `max(...)` term
and never subtracts from it. Skew exists to keep accepting tokens for relying parties whose
clocks trail the issuer's; shortening the window for skew would do the opposite of its
purpose.

`RetirementWindow` is **not** exposed on `JwtSigningServiceOptions` or anywhere else (§3.4
rejected alternative). It is computed inside ZeeKayDa from the token-lifetime configuration
the server already owns.

#### 3.4 `JwtSigningServiceOptions` carries `RefreshInterval` only

```csharp
public abstract class JwtSigningServiceOptions
{
    public TimeSpan RefreshInterval { get; set; }   // base-class cache throttle
}
```

The base options type carries **`RefreshInterval`** and nothing else. `RetirementWindow` is
*not* here — see §3.3. Provider-specific options derive from this type
(`DevelopmentSigningKeyOptions : JwtSigningServiceOptions`).

#### 3.5 Rotation for external providers — read-only with anomaly surfacing

For provider-owned rotation (KMS, database), ZeeKayDa reads the trusted set via
`LoadKeysAsync` and surfaces anomalies rather than driving rotation. Specifically: if a
previously-seen `kid` **vanishes** from `LoadKeysAsync` results without a replacement key
having been active for at least `RetirementWindow`, the base class **logs a warning**. A key
that disappears too early means tokens it signed are still in circulation but their key is no
longer published — relying parties will start rejecting valid tokens. ZeeKayDa cannot prevent
a misbehaving external provider from doing this, but it can make it loud.

**Publish-then-activate.** There is a symmetric race on the *addition* side: if a key starts
signing before its public half appears in the JWKS, a relying party that fetches a fresh JWKS
still will not find the new `kid` and will reject otherwise-valid tokens. A key therefore MUST
appear in `GetSigningKeysAsync()` results — and so in the published JWKS — for at least one
RP JWKS-cache-TTL period **before** it becomes the active signer. Implementations MUST NOT
promote a key to active signer until it has been published. The exact TTL is RP-dependent; as
a safe default the activation delay SHOULD be ≥ `RefreshInterval`, so an RP that polls the
JWKS at the interval will have observed the key before the first token signed with it.

#### 3.6 DI registration pattern

Every `.AddXxx()` signing extension on `ZeeKayDaAuthBuilder` is the consistent registration
hook, analogous to `AddAuthentication()` in ASP.NET Core and to the store registration
methods in ADR 0008. Each such method:

1. registers `IJwtSigningService` as a **singleton**;
2. calls `builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService))` so a second signing
   provider fails loudly at registration time rather than silently winning or losing;
3. registers the per-provider `IValidateOptions<TOptions>` for startup validation.

A shared **internal** helper extension standardises this plumbing so each public `AddXxx()`
method is a thin, uniform call. `AllowDevelopmentJwtSigningKeysOutsideDevelopment` stays on
`AuthorizationServerOptions` (§2) — server-wide gate, not a per-provider knob.

### 4. Token-pipeline integration and JWKS

#### 4.1 `ITokenWriter` — the only caller of `SignAsync`

`ITokenWriter` (in `ZeeKayDa.Auth`) is the **single** component that calls
`IJwtSigningService.SignAsync`. It is **format-agnostic** — deliberately *not* `IJwtWriter`
(§ Rejected Alternatives).

Because the JWS header is part of the signed bytes, the `kid` and `alg` must be determined
and fixed in the header before the signing input is formed — they cannot be stamped in after
signing. The service handles this atomically: `ITokenWriter` passes only the base64url-encoded
payload, and the service constructs the header, forms the signing input, signs, and returns the
header and signature as pre-encoded segments. The flow is therefore:

1. Claim assembly: ID-token/access-token builders above `ITokenWriter` assemble the claims and
   base64url-encode the payload segment.
2. `ITokenWriter` calls `SignAsync(payloadSegment)`.
3. Internally, the service picks the active key, builds the header
   `{"alg":"…","kid":"…"}`, base64url-encodes it, forms
   `headerSegment "." payloadSegment`, and signs.
4. `SigningResult` is returned containing `HeaderSegment`, `SignatureSegment`, `Kid`,
   and `Algorithm` (all already base64url-encoded).
5. `ITokenWriter` assembles the compact JWS:
   `HeaderSegment "." payloadSegment "." SignatureSegment`.

This design eliminates the TOCTOU race that would exist if `ITokenWriter` queried the active
key separately and then passed the full signing input: there is no window between "learn which
key is active" and "sign with that key" in which a rotation could produce a header whose `kid`
disagrees with the actual signing key. The header and the signature are always consistent by
construction.

ID-token and JWT-access-token builders sit *above* `ITokenWriter` and own claim assembly;
`ITokenWriter` owns `kid` + header construction + signing. The name is format-agnostic
because a future reference/opaque-token writer is simply a different `ITokenWriter`
implementation — no misnomer, no interface proliferation, and the JWE forward-compat story
(§5) slots in cleanly.

#### 4.2 Implementors never touch signing or JWS formatting

Third-party key providers implement **only `LoadKeysAsync`** on the §3 base class. They never
implement `SignAsync` directly and never handle JWS formatting. This is the pit of success:
the only thing a provider author writes is "here are my current keys," and there is no wrong
way to do that. Header construction, `kid` selection, base64url framing, and the crypto call
all live in code ZeeKayDa owns and tests.

#### 4.3 `IJwksDocumentProvider` and the JWKS endpoint

`IJwksDocumentProvider` (in `ZeeKayDa.Auth`) mirrors `IDiscoveryDocumentProvider`. It calls
`IJwtSigningService.GetSigningKeysAsync()` and maps the owned `SigningKeyDescriptor`s to a
stable JWK-set wire record (`JsonWebKeySetDocument` or similar) whose fields are pinned with
explicit `[JsonPropertyName]` attributes — **no Microsoft.IdentityModel type leakage**, the
same discipline `OpenIdConfigurationDocument` already applies. The `connect/jwks` endpoint
becomes a thin ASP.NET Core adapter over this provider, replacing the current `501`
placeholder. Because `GetSigningKeysAsync` returns exactly the trusted set (active + in-window
keys; §1), the JWKS publishes exactly those keys — this is the relying-party trust boundary
the security sign-off (§3.3) covers.

**The JWKS read path shares the single-flight cache.** `connect/jwks` MUST serve from the
same single-flight-gated cache as the signing path (§3.2). An anonymous request to
`connect/jwks` MUST NOT be able to trigger an un-coalesced `LoadKeysAsync` against a remote
key source: if the cache is cold or expired, the single-flight gate applies equally to the
JWKS read path and the signing path, so a burst of unauthenticated JWKS requests cannot
become a thundering herd against the key source.

**`kid` uniqueness and stability.** A published JWKS MUST NOT contain duplicate `kid` values;
the base class MUST detect a `SigningKeySet` carrying duplicate `kid`s and reject it at load
time (`ZeeKayDaConfigurationException`). A `kid` MUST be stable for the entire life of a key
— it never changes once assigned — so relying parties can match a token's header `kid` to a
JWKS entry deterministically.

#### 4.4 Descriptor → JWK parameter extraction is hand-rolled over BCL crypto

Mapping a descriptor's public key to its JWK parameters is done with BCL primitives:
`RSA.ExportParameters(false)` for RSA keys, `ECDsa.ExportParameters(false)` for EC keys
(`false` = public parameters only — private material is never exported into a JWK), plus
.NET's built-in `Base64Url` encoding for the parameter values. **No new dependency** — this
is squarely within the "build it ourselves rather than take a dependency for a small,
well-specified transform" trade-off, and the transform is fully specified by RFC 7517/7518.
It is covered by **known-answer-vector unit tests** drawn from RFC 7517 / RFC 7520 so the
hand-rolled mapping is provably correct.

Each emitted JWK MUST include `"use": "sig"` so relying parties do not mistakenly treat a
signing key as an encryption key. (`alg` and `kid` are likewise emitted on every JWK.)

#### 4.5 `id_token_signing_alg_values_supported` stays static, cross-checked at startup

`id_token_signing_alg_values_supported` continues to be sourced from static configuration
(`IdTokenOptions.SigningAlgValuesSupported`), **not** derived from the live key set. A
startup `IValidateOptions` cross-check verifies that every advertised algorithm is one the
registered `IJwtSigningService` can actually produce — catching the misconfiguration where the
discovery document promises an algorithm no key can sign.

**Rejected alternative — derive the advertised algorithms dynamically from the live key set.**
Discovery is a *stable published contract*. Relying parties cache it. Deriving the advertised
algorithm list from whatever keys happen to be loaded means the discovery document
**flickers during rotation**: if a key of a different algorithm enters or leaves the trusted
set, the advertised list changes underneath cached consumers. Static config with a startup
consistency check gives a stable contract *and* catches the inconsistency that dynamic
derivation was trying to prevent.

### 5. JWT encryption (JWE) — absent end to end in v1

There is **no** encryption support in v1: no `IEncryptionService`, no `EncryptionOptions`, no
encryption discovery fields, no client-model encryption-preference fields — **not even an
"off" toggle**.

**Rationale.** v1 does not support dynamic client registration (RFC 7591). Clients are
registered statically (ADR 0007), and the client model simply has no encryption-preference
fields. No code path can request an encrypted token, so there is nothing to toggle. The
relevant encryption discovery fields (`id_token_encryption_alg_values_supported`, etc.) are
**OPTIONAL** in OIDC; their *absence* is the spec-correct signal that the provider does not
offer encryption. Shipping an empty `EncryptionOptions` or an `Enabled = false` flag would be
a SemVer commitment to a surface with no behaviour behind it — the same anti-pattern ADR 0008
rejected when it deleted the empty `DistributedCacheTokenStoreOptions`.

**Forward-compat is preserved.** `ITokenWriter` is composable (§4.1). When encryption lands,
a sibling `IEncryptionService` / `EncryptionService<TOptions>` seam is introduced (mirroring
the signing seam), and `ITokenWriter` gains an optional JWE-wrap step — **sign first, then
wrap as a nested JWT** per RFC 7519 §3. The client model and discovery document are extended
at that point. Nothing in this ADR forecloses that path.

---

## Rejected Alternatives

### A third method on `IJwtSigningService` for rotation

Considered: add `RotateAsync` (or a `CurrentKeyId`/state method) to the interface so ZeeKayDa
could drive or observe rotation directly. **Rejected:** most real providers (KMS, managed
databases) own rotation on their own schedule and lifecycle; a rotation method on the
interface imposes a model they do not have and would force them to fake it. Rotation is a
provider-private concern; ZeeKayDa reads the trusted set and surfaces anomalies (§3.5). The
two-method interface stays minimal and every method maps to a real consumer need.

### Generic `IJwtSigningService<TOptions>` on the public surface

Considered: make the interface itself generic over the options type. **Rejected:** the
options type is an implementation detail of a *concrete provider*. Consumers of signing — the
token writer, the JWKS provider — depend only on "sign this" and "give me the keys," neither
of which is parameterised by provider options. Genericity belongs on the optional base class
(`JwtSigningService<TOptions>`, §3.2), not on the consumed interface. A non-generic interface
also keeps DI registration (`IJwtSigningService` singleton) simple and uniform.

### `RetirementWindow` as a user-configurable option

Considered: expose `RetirementWindow` on `JwtSigningServiceOptions`. **Rejected:** like the
tombstone-retention and family-revocation-marker TTLs that ADR 0008 removed for the same
reason, the only off-default values are unsafe or useless. Set it *shorter* than the longest
signature-validated token lifetime and relying parties begin rejecting still-valid tokens
whose key was pulled from the JWKS too early — a silent outage. Set it *longer* and the
published trust set bloats with keys nothing needs. The correct value is fully *derivable*
from token lifetimes the server already configures (§3.3), so it is derived and not exposed.

### `IJwtWriter` instead of `ITokenWriter`

Considered: name the writer after the JWT format it produces in v1. **Rejected:** it would be
a misnomer the moment a reference/opaque-token writer is added — a non-JWT artifact emitted by
something called `IJwtWriter`. The format-agnostic name lets the future opaque-token writer be
another `ITokenWriter` implementation rather than forcing a second, parallel interface. The
seam is named for its *role* (writing tokens), not its current *format*.

### `ISigningService` instead of `IJwtSigningService`

**`ISigningService` instead of `IJwtSigningService`** — Considered: keep the name format-agnostic in case a future token format needs signing. Rejected: every outbound artifact signed by an OIDC/OAuth2 authorization server is a JWT (ID tokens, JWT access tokens, logout tokens, JARM, signed userinfo). Non-JWT formats (opaque reference tokens) are not signed at all. A generic name would imply flexibility that does not exist in this domain; the honest name is `IJwtSigningService`. If a genuinely different signing concern ever arises, it warrants its own purpose-named seam.

### A shared signing-and-encryption abstraction

Considered: one abstraction (or one interface with both sign and encrypt operations) to cover
JWS and JWE together. **Rejected:** signing and encryption use different keys, different trust
directions, and have different lifecycles; v1 ships no encryption at all (§5). Coupling them
now would either drag in encryption surface we deliberately exclude or produce a half-defined
interface. The forward-compatible shape is *sibling* seams (`IJwtSigningService` /
`IEncryptionService`) composed by `ITokenWriter`, introduced independently when encryption
actually lands.

### Microsoft.IdentityModel types on the public surface

Considered: expose `SigningCredentials` / `SecurityKey` / `JsonWebKey` directly on the
interface and descriptors to save the hand-rolled JWK mapping (§4.4). **Rejected:** it would
bake a large, fast-moving third-party surface into our own public contract and our SemVer
commitments, contradicting the minimal-dependency principle. The hand-rolled BCL mapping is a
small, fully-specified, test-covered transform — an acceptable amount of owned code in
exchange for keeping the dependency graph clean and the public surface ours.

### Dynamic derivation of advertised signing algorithms

Recorded in §4.5: rejected because it makes the published discovery contract flicker during
rotation. Static config plus a startup consistency check is the chosen approach.

---

## Consequences

### Positive

- **One correct production path.** A provider author implements a single method
  (`LoadKeysAsync`) and gets correct caching, single-flight refresh, header construction,
  `kid` selection, and signing for free. There is no wrong way to wire signing.
- **Private key material never leaves the signing component.** `SignAsync` returns a finished
  signature; no caller — including `ITokenWriter` — ever holds a private key. This is the
  invariant that makes future remote signing (KMS/HSM) a non-breaking addition.
- **Clean, minimal public surface.** No Microsoft.IdentityModel leakage anywhere; everything
  is BCL types or ZeeKayDa-owned types, all SemVer-stable.
- **Fully unit-testable rotation/caching** via injected `TimeProvider` — no running server,
  no wall clock.
- **Secure-by-default local DX.** One line for local development; hard-fail outside
  Development; `0600`/`0700` enforced; broader permissions fail loudly.
- **Stable discovery contract** that does not flicker during rotation.

### Negative / Trade-offs

- **Hand-rolled JWK mapping is owned code** we must keep correct against RFC 7517/7518. The
  known-answer-vector tests are the mitigation; the trade-off (vs. a Microsoft.IdentityModel
  dependency) is accepted deliberately.
- **`RetirementWindow` depends on token-lifetime configuration that is not present yet.**
  Today **neither** term of the `max(...)` is configurable: there is no ID-token lifetime
  property on `IdTokenOptions` (only `SigningAlgValuesSupported`) and no configurable
  JWT-access-token lifetime. The 1-hour floor (§3.3 a′) bridges this gap so the window can
  never collapse to near-zero. The access-token and ID-token lifetime terms become live when
  configurable per-token lifetimes land; until then the floor governs. This coupling must be
  honoured when those lifetimes are added — the derivation, not a new option, is updated, and
  the floor reverts to guarding only the degenerate case.
- **External-provider rotation anomalies can only be surfaced, not prevented.** ZeeKayDa logs
  a warning when a `kid` vanishes too early (§3.5); it cannot stop a misbehaving external
  provider from pulling a key prematurely.
- **No encryption in v1** — acceptable given no dynamic client registration and OPTIONAL
  discovery fields, with the forward-compat path preserved (§5).

---

## Security Considerations

- **JWKS exposure is the relying-party trust boundary (security sign-off, §3.3 / §4.3).** A
  key remains published — and therefore trusted by verifiers — for exactly `RetirementWindow`
  after it stops being the active signer. Sizing this to `max(access-token, ID-token lifetime,
  floor) + clock-skew` (with a 1-hour floor until per-token lifetimes are configurable, §3.3 a′)
  and *excluding* refresh-token lifetime is the core security claim of this ADR and the item
  requiring sign-off. Too short pulls keys before their tokens expire (valid tokens rejected);
  too long over-publishes trust. The clock-skew term only ever widens the window (§3.3).
- **Private key destruction on retirement (§3.3c).** A retired key's private half MUST be
  destroyed immediately; only the public half lingers in the JWKS for `RetirementWindow`.
  Keeping a retired private key is pure liability and is prohibited by the contract. The base
  class enforces this by `Dispose()`-ing the superseded `SigningKeySet`'s private-key objects
  on refresh (§3.2) rather than leaving them to the GC, and only after all in-flight
  `SignAsync` calls that reference the old set have completed. For HSM/KMS providers there is
  no local private key to destroy — only the cached local handle/copy is disposed.
- **Development keys must never reach production.** `AddDevelopmentJwtSigningKeys` hard-fails
  outside Development; the escape hatch logs `LogLevel.Critical` (more severe than the
  in-memory store's `Warning`) because an ephemeral or non-rotating signing key in production
  breaks signature validation for every relying party on restart.
- **File-permission enforcement is fail-closed.** A persisted key file with permissions
  broader than `0600` (or a non-restrictive ACL on Windows) is treated as compromised and
  causes a hard failure, not a warning.
- **Header `kid`/`alg` are determined from the active key before signing, and verified after.**
  The header `kid`/`alg` are resolved from the active key, fixed in the signed bytes, and the
  returned `SigningResult.Kid`/`Algorithm` MUST match them (§4.1). A header can therefore
  never advertise a different key than the one that produced the signature — closing the class
  of bugs where a token's header points relying parties at the wrong JWKS key. `none` is not a
  representable algorithm (§1), so an unsigned token cannot be produced.
- **No private key material in logs or exceptions.** No private key bytes, PEM contents, or
  any private key material MUST appear in any log message or exception. A permission-failure
  log records only the file path and the observed permission mode — never the key content.
- **Minimum key strength is enforced (§2).** RSA keys below 2048 bits and non-NIST EC curves
  are rejected at load time; the development helper generates RSA ≥ 3072 bits.
- **Single-flight refresh** prevents a thundering herd against a remote key source on the
  signing hot path — including via the anonymous `connect/jwks` read path (§4.3) — from
  becoming a self-inflicted availability incident.

---

## Amendments

### Amendment 1 — PR #286 (2026-07-02)

**`AllowDevelopmentJwtSigningKeysOutsideDevelopment` replaced by `AllowedDevelopmentJwtSigningKeysEnvironments`**

The original design specified a single `bool AllowDevelopmentJwtSigningKeysOutsideDevelopment` escape hatch (§2, §3.6). The implementation ships `IReadOnlyList<string> AllowedDevelopmentJwtSigningKeysEnvironments` on `AuthorizationServerOptions` instead. The list form is strictly more expressive: it allows development signing keys to be permitted in specific named non-production environments (e.g. `"Staging"`, `"IntegrationTest"`) without permitting them globally. The semantic invariant from §2 is unchanged — `Production` cannot be added to the list, the `LogLevel.Critical` entry still fires on every startup for any non-`Development` entry, and the feature flag remains on `AuthorizationServerOptions` (server-wide gate, not a per-provider knob). All §2 security requirements (key strength, file permissions, ownership, symlink protection) still apply regardless of the list contents.

**`ISigningKeyFileSystem` renamed to `IDevelopmentSigningKeyFileSystem`**

The §2 / §3.6 references to `ISigningKeyFileSystem` describe what shipped as `IDevelopmentSigningKeyFileSystem`. The rename scopes the interface to the development provider, clarifying that this is not a general-purpose signing file system abstraction used by production providers. The interface contract (async `ReadKeyFileAsync` / `WriteKeyFileAsync` / `EnsureDirectorySafe` / `FileExists` with `CancellationToken` propagation) is otherwise unchanged from the §2 description.

---

## References

- Issue **#187** — signing key management design session.
- **ADR 0002** — options shape (server-wide gate on root, per-provider knobs on provider
  options).
- **ADR 0006** — exception hierarchy (`ZeeKayDaConfigurationException`).
- **ADR 0007** — client registration model (static registration; no encryption-preference
  fields).
- **ADR 0008** — authorization-code/refresh-token store (registration idiom,
  `ThrowIfAlreadyRegistered`, escape-hatch pattern, refresh-token-via-store validation,
  empty-options-class SemVer lesson).
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7518 (JWA), RFC 7519 (JWT), RFC 7520 (JOSE examples),
  RFC 7591 (dynamic client registration), RFC 9700 (OAuth security BCP).
