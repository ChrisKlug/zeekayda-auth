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

### Amendment 2 — PR #298 (2026-07-03)

*(PR number is a placeholder pending final assignment at merge time — this is the PR that ships #287, Azure Key Vault remote signing, the first production `IJwtSigningService` provider and the first real consumer of rotation.)*

**(a) The base class's crypto step became an overridable async hook — `SignInputAsync`.**

§1 states the async design on `IJwtSigningService` exists specifically so "a remote signer performs network I/O on every `SignAsync` call." Despite that, the originally-shipped `JwtSigningService<TOptions>` (PR #286) actually performed the cryptographic operation via a private, non-overridable, **synchronous** method that called `SigningAlgorithms.Sign` (which bottoms out in `AsymmetricAlgorithm.SignData`/`SignHash`) directly. Since RSA/ECDsa have no async signing member anywhere in the BCL, this made genuine async remote signing (a live network round trip to a KMS/HSM) impossible without either blocking a thread for the round trip or changing the base class. PR #287 changes the base class. `src/ZeeKayDa.Auth/Tokens/JwtSigningService.cs` now exposes:

```csharp
protected virtual ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
    SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken)
    => new(SigningAlgorithms.Sign(activeKey.Descriptor, signingInput, activeKey.PrivateKey));
```

Header construction, active-key selection, and `kid`/`alg` fixation remain entirely inside the base class's private, non-overridable `PerformSignAsync`. An override of `SignInputAsync` can only change **how** the signature bytes for the already-selected descriptor are produced — it can never change **which** key is selected or what the header says. This is exactly what preserves §1's "header and signature are always consistent by construction" invariant: there is still no code path, overridden or not, through which the header could disagree with the key that actually signs.

This is a purely additive change — a new `protected virtual` method whose default body reproduces the prior synchronous behaviour exactly — so it is binary-compatible with the already-shipped `DevelopmentJwtSigningService` and does not require that provider (or any core release consumer) to be rebuilt or re-released.

`activeKey.PrivateKey` is deliberately unused by remote-signing overrides — the Azure Key Vault provider (`AzureKeyVaultRemoteSigningJwtSigningService.SignInputAsync`) ignores it entirely, since Key Vault never exports the private key into process memory. This is a considered trade-off, not an oversight: there is no clean way in C# to give the default local-crypto implementation access to the active key's `AsymmetricAlgorithm` without it being part of the shared method signature, and the alternative — threading a `Func<>` callback instead of the packaged `SigningKeyPair` — adds an allocation and an indirection layer for a purely cosmetic gain (the same shape as `Stream.Read(buffer, offset, count)`, where not every override needs every parameter). No provider is *required* to override `SignInputAsync`: Windows Certificate Store / macOS Keychain / Linux PEM (future issues #289–#291) and Azure Key Vault *cached* signing (#288) all sign with local key handles and get correct behaviour from the default body, exactly like the development provider today. Only a genuinely remote/network signer needs to override it.

**(b) `ISigningKeyRetirementWindowProvider` — the §3.3 derivation, implemented.**

§3.3 mandates the `RetirementWindow` derivation but nothing implemented it until now — the development provider never needed it (a single ephemeral or persisted key, no rotation, nothing ever retires). PR #287 is the first consumer of rotation (Azure Key Vault) and ships the derivation as a core service alongside it:

```csharp
// src/ZeeKayDa.Auth/Tokens/ISigningKeyRetirementWindowProvider.cs
public interface ISigningKeyRetirementWindowProvider
{
    TimeSpan GetRetirementWindow();
}
```

The internal default implementation (`src/ZeeKayDa.Auth/Tokens/SigningKeyRetirementWindowProvider.cs`) computes exactly the §3.3(a′) floor:

```
RetirementWindow = TimeSpan.FromHours(1) + AuthorizationServerOptions.ClockSkewTolerance
```

— the only real term today, since neither the ID-token lifetime nor a JWT-access-token lifetime is configurable on `AuthorizationServerOptions` yet. It is registered via `services.TryAddSingleton<ISigningKeyRetirementWindowProvider, SigningKeyRetirementWindowProvider>()` inside `AddZeeKayDaAuthCore()` (`src/ZeeKayDa.Auth/Extensions/ZeeKayDaAuthCoreServiceCollectionExtensions.cs`) — deliberately in core, not in `ZeeKayDa.Auth.AspNetCore`'s `AddZeeKayDaAuth()`, because provider packages such as `ZeeKayDa.Auth.AzureKeyVault` deliberately do not reference `ZeeKayDa.Auth.AspNetCore` (ADR 0012 §3) and must still be able to resolve it.

**This is the file to extend, not replace, once configurable per-token lifetimes exist.** When an ID-token lifetime and/or a configurable JWT-access-token lifetime are eventually added to `AuthorizationServerOptions`, `SigningKeyRetirementWindowProvider.GetRetirementWindow()` must take the `max(...)` of the 1-hour floor and those lifetimes per §3.3(a) — the floor is not deleted, it becomes the guard against the degenerate case §3.3(a′) already describes. The source carries a comment recording this obligation for whoever picks it up.

**(c) `JwkThumbprint` — a new public core utility, extracted for genuine third-party extensibility.**

Prior to PR #287, RFC 7638 JWK thumbprint computation existed only as a private `ComputeKid`-style method inline in the internal `SigningAlgorithms` class, used solely by `DevelopmentJwtSigningService` to derive a non-leaking `kid` from a locally-generated key's public parameters (rather than, say, the key's file path). PR #287 extracts this into a new **public** static class, `src/ZeeKayDa.Auth/Tokens/JwkThumbprint.cs`:

```csharp
public static class JwkThumbprint
{
    public static string Compute(RSAParameters rsaPublicParameters);
    public static string Compute(ECParameters ecPublicParameters);
}
```

This is documented as its own decision because of a real design flaw caught and fixed during PR #287's review, not merely a mechanical extraction. The Azure Key Vault provider needs the identical thumbprint derivation §4.2's kid discipline calls for — a Key Vault `kid` must not be the raw vault/key URI, since a `kid` is always public (every issued JWT header, and the JWKS) and embedding a real Azure resource identifier in it would leak reconnaissance value to anyone inspecting a token, with no functional benefit. The first attempt at reusing the existing (internal) thumbprint logic gave the Azure Key Vault provider `InternalsVisibleTo` friend-assembly access to `SigningAlgorithms`. That does not actually solve the general problem: `InternalsVisibleTo` only grants access to assemblies named explicitly at build time. It can serve a single first-party provider package ZeeKayDa itself controls, but it **fundamentally cannot** serve a genuine third party implementing this ADR's own §3.2/§4.2 extensibility contract ("any third party can subclass `JwtSigningService<TOptions>` and implement only `LoadKeysAsync`") — a third party's assembly can never be added to that friend list without ZeeKayDa shipping a new core release naming them specifically, which defeats the entire point of an open extension point.

The fix is to make the thumbprint computation itself **public**, while `SigningAlgorithms` correctly stays `internal` — it holds ZeeKayDa-owned crypto dispatch and validation logic (`Sign`, `ValidateKeyAlgorithmCompatibility`, `ValidateKeyStrength`) that §4.2 already establishes third parties never call directly; only the RFC 7638 canonicalisation needed extraction. Any `JwtSigningService<TOptions>` author — first-party or genuinely third-party — can now derive a safe, non-leaking `kid` from a public key without hand-rolling RFC 7638 canonicalisation themselves.

`DevelopmentJwtSigningService` was updated to call this same shared public helper (`src/ZeeKayDa.Auth/Tokens/DevelopmentJwtSigningService.cs`, `JwkThumbprint.Compute(rsaParams)`) in place of its own inline logic. This is a zero-behavioural-change refactor: the development provider produces byte-identical `kid` values before and after, confirmed by the existing `DevelopmentJwtSigningService` test suite passing unchanged and by the new `JwkThumbprintTests` known-answer-style coverage.

**(d) `ISanitizingLogger<T>` made public — the identical argument from (c) applied a second time in the same PR.**

The Azure Key Vault provider's `AzureKeyVaultRemoteSigningJwtSigningService` needs to constructor-inject `ISanitizingLogger<T>` (`src/ZeeKayDa.Auth/Logging/ISanitizingLogger.cs`) for one log call. `ISanitizingLogger<T>` was `internal`, so this initially required `[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AzureKeyVault")]` (+ `.Tests`) in `src/ZeeKayDa.Auth/ZeeKayDaAuth.cs` — exactly the pattern (c) already rejected for `JwkThumbprint`, for exactly the same reason: `InternalsVisibleTo` can only ever name first-party assemblies at build time, so it cannot serve a genuine third party writing their own remote-signing provider (AWS KMS, HashiCorp Vault, an on-prem HSM) that would want the same log-hygiene guarantee. A CHANGELOG-only entry would have broken the rationale trail (c) itself established, so this amendment records the fix the same way.

The interface was made public. `SecretSanitizingLogger<T>` — the concrete implementation, and its `SensitiveKeys` redaction allowlist — stays `internal`, exactly mirroring `SigningAlgorithms` staying `internal` while `JwkThumbprint` (extracted from it) went public: only the contract needs to cross the package boundary, not ZeeKayDa's own redaction logic.

A pre-existing test, `ISanitizingLoggerVisibilityTests.ISanitizingLogger_must_remain_non_public`, asserted the interface must stay non-public, citing a concern that analyzer `ZEEKAYDA0002` (`InterpolatedStringLogAnalyzer`, which requires `Log*` message templates in `ZeeKayDa.*` namespaces to be compile-time constants so `SecretSanitizingLogger` can inspect them) exempts logger-wrapper implementations *by visibility*, and that making the interface public would let any assembly implement it and opt out of the constant-template rule. Reading `IsInLoggerImplementation` (`InterpolatedStringLogAnalyzer.cs`) directly shows the exemption is gated on `typeSymbol.ContainingAssembly?.Name != "ZeeKayDa.Auth"` alone — visibility of the implemented interface plays no part in the check. No assembly other than the literal core `ZeeKayDa.Auth` assembly can ever satisfy that gate, regardless of whether `ISanitizingLogger<T>` is internal or public. This was verified two ways, not just by inspection: empirically, by building a throwaway internal type in `ZeeKayDa.Auth.AzureKeyVault` (a friend assembly under the then-still-internal interface) that implemented `ISanitizingLogger<T>` and forwarded a non-constant template — `ZEEKAYDA0002` fired anyway; and as a permanent regression test, `InterpolatedStringLogAnalyzerTests.Diagnostic_still_fires_inside_friend_assembly_class_implementing_a_PUBLIC_ISanitizingLogger`, which compiles a *public* `ISanitizingLogger<T>` in one assembly and a friend-assembly implementation in another and asserts `ZEEKAYDA0002` still fires. The old test's stated rationale was stale; it has been replaced with `ISanitizingLoggerVisibilityTests.ISanitizingLogger_is_public` / `SecretSanitizingLogger_remains_internal`, which assert and document the current, correct invariant.

Making the interface nameable does introduce new, real (if low-severity) risks that internal visibility structurally ruled out. `AddZeeKayDaAuthCore()` registers `ISanitizingLogger<>` as an open-generic singleton via `TryAddSingleton`, so a host that now registers its own `ISanitizingLogger<>` implementation — whether before `AddZeeKayDaAuth()` (wins the `TryAdd` race) or after via a plain `Add` (wins .NET DI's "last open-generic registration wins" resolution rule) — silently shadows the redaction wrapper for every ZeeKayDa service, not just ones the host intended to customize. A second, narrower variant of the same problem exists at the closed-generic level: a host registering `ISanitizingLogger<SomeSpecificType>` for one particular type shadows redaction only for that type, regardless of registration order, since .NET DI always prefers an exact closed-generic match over an open-generic fallback — the framework itself never registers a closed generic for this interface, so any closed registration found is unambiguous evidence of a shadow. Both are host misconfigurations inside the host's own trust boundary — not something a caller of the API or an external actor can trigger — but worth guarding against given how silent the failure mode is (no exception, no crash, just credential material reaching a log sink unredacted). Rather than closing this off structurally (e.g., replacing the interface with a public sealed concrete type, which would remove the possibility of substitution entirely but touches roughly 34 call sites across all four packages plus both logging analyzers plus three test doubles — a distinct, much larger change out of scope for this PR), the mitigation is a new hosted service, `SanitizingLoggerRegistrationStartupValidator` (`src/ZeeKayDa.Auth.AspNetCore/SanitizingLoggerRegistrationStartupValidator.cs`), registered by `AddZeeKayDaAuth()` first among its hosted services (before `InsecureIssuerWarningService`, `ClientRepositoryStartupActivator`, and the rest — hosted services start in registration order, and at least one of those siblings also logs through `ISanitizingLogger<T>`, so registering this check anywhere but first would leave a window where a shadowed logger gets used before the check has a chance to abort startup). It checks both failure modes and aggregates them into a single `ZeeKayDaConfigurationException` if both are present: it resolves `ISanitizingLogger<T>` for itself as `T` and checks the resolved instance is `SecretSanitizingLogger<T>` (catches the open-generic case), and it uses a companion `SanitizingLoggerClosedOverrideScanner` (`src/ZeeKayDa.Auth.AspNetCore/SanitizingLoggerClosedOverrideScanner.cs`) that holds a reference to the live `IServiceCollection` and scans it for any closed-generic `ISanitizingLogger<T>` descriptor (catches the closed-generic case, for any `T` — it does not need to know in advance which types exist, host or third-party). Both checks fail hard rather than warn — unlike `ClientRepositoryStartupActivator`'s analogous shadowing check (a warning, since a shadowed `IClientRepository` is a functional footgun), a shadowed sanitizing logger is a silent security regression, not a functional one. The sealed-concrete-type alternative remains available as a future hardening step if the ecosystem ever needs it, but is not pursued here.

This entire amendment — both the visibility change and the two-part shadow guard — went through two full rounds of independent security and architect review: once on the design before implementation, and once on the actual committed diff afterward (`ea5c9b1`), including the closed-generic gap the first round of review had explicitly flagged as a known, accepted residual risk before it was closed in a follow-up commit. Both rounds returned APPROVE with no blocking findings.

**Normative addition to §3.5 — durable, provider-side-timestamp-derived rotation is the expected pattern going forward.**

§3.5 already establishes that ZeeKayDa reads a provider's rotation on the provider's own schedule (no `RotateAsync`) and requires publish-then-activate. PR #287's Azure Key Vault provider is the first implementation of real multi-key rotation against that contract, and its design choice is recorded here as a normative refinement of §3.5 that future rotation-capable providers (Windows Certificate Store #289, macOS Keychain #290, Linux PEM #291, if any of them ever need multi-key rotation) are expected to follow:

The provider derives its entire activation/retirement timeline from **Key Vault's own durable per-version `CreatedOn`/`NotBefore` timestamps** — never from local, in-memory "when did I first observe this kid" bookkeeping. In-memory history breaks on every process restart (a freshly-started replica has no history, so publish-then-activate either throws on cold start or silently no-ops) and is inconsistent across load-balanced replicas (each independently seeded by whenever it started polling). Concretely (`AzureKeyVaultRemoteSigningJwtSigningService.BuildActivationTimeline`):

- `ActivatesAt(v)` is `v.CreatedOn` for the very first key version Key Vault has ever recorded for the key name (determined across **all** versions ever created, including disabled/expired ones — a durable, shared fact, not "oldest among currently-eligible," which could shift if an earlier version is later disabled), and `v.CreatedOn + RefreshInterval` for every subsequent version — the publish-then-activate delay §3.5 requires, since by the time a second version exists a relying party could plausibly have cached a JWKS containing only the first.
- `NotBefore` is folded directly into `ActivatesAt` as `max(rawActivatesAt, v.NotBefore)`, rather than being checked separately at "now" — so every downstream computation that orders by or reasons about `ActivatesAt` automatically accounts for an operator-scheduled later go-live with no separate special case.
- `Enabled = false` is an **immediate, unconditional exclusion** that bypasses `RetirementWindow` entirely: an operator disabling a suspected-compromised key version takes effect at once, not after the retirement window elapses.
- `RetiredAt(v)` is the `ActivatesAt` of whichever version actually superseded `v` as the active signer, computed over eligible successors only (a version that is disabled, or already past its own `ExpiresOn` by the time it would activate, can never win the active-signer selection and so is never anyone's real successor — treating it as one would gate a still-legitimately-active predecessor's retirement window too early).

This makes the whole timeline a stateless computation over `(the key store's version list, now, RefreshInterval, RetirementWindow)` — restart-safe, multi-replica-consistent, and fully testable with a `FakeTimeProvider` and fabricated timestamps, with no cross-call bookkeeping needed for anything that gates a trust decision. **An in-memory-only tracking of publish-then-activate or retirement state, going forward, should be considered non-compliant with §3.5** for any provider capable of holding more than one key at a time. (The one piece of cross-call state the Azure Key Vault provider does keep in memory — a plain kid-to-version map used purely to log §3.5's "kid vanished early" anomaly warning — is fine to lose on restart, since losing it only risks missing one log line, never a trust decision.)

**`AzureKeyVaultSigningException` is intentionally not documented here.** It is a package-local transport exception for transient sign-time faults (`src/ZeeKayDa.Auth.AzureKeyVault/AzureKeyVaultSigningException.cs`, namespace `ZeeKayDa.Auth.AzureKeyVault`), not a type this ADR defines or amends. Making it a shared core exception type "for future remote providers" was considered and deliberately rejected as premature abstraction — ADR 0006's "colocate with the feature" rule reads more honestly here as *the Azure Key Vault feature specifically*, not *signing in general*, until a second real consumer exists.

### Amendment 3 — issue #300 (2026-07-04)

**Key Vault's list-key-versions read consistency, verified rather than assumed — risk accepted as-is, no mitigation needed.**

PR #298's security review flagged, as an expected-not-buggy but unverified assumption, that `BuildActivationTimeline`'s `FirstEverVersion` bootstrap exemption (Amendment 2, above) relies on `IKeyVaultKeyReader.GetKeyVersionsAsync` returning a complete, consistent view of every version Key Vault has ever recorded for a key name. If that list read were only eventually consistent, two replicas — or the same replica across two refresh cycles immediately after a version is created — could disagree about which version is "first ever" and therefore which one gets the immediate-activation exemption instead of the normal publish-then-activate delay.

This is now confirmed against Microsoft's documented Key Vault reliability model (`https://learn.microsoft.com/azure/reliability/reliability-key-vault`), not left as an assumption:

- **Within a region — synchronously replicated, effectively strongly consistent.** Key Vault data is synchronously replicated across availability zones in regions that support them, and during normal operation *all* traffic — reads and writes alike — is served from a single active (primary) region. There is no load-balanced "read replica" that a list-versions call could observe mid-lag: a version committed via key creation or rotation is visible to the very next list call against the same, only, serving region.
- **Across the paired region — asynchronous, eventually consistent, but only during a Microsoft-triggered regional failover.** Key Vault replicates to its paired region asynchronously. If Microsoft fails a vault over — described as best-effort, likely delayed, and able to take hours to occur — the vault becomes read-only against that secondary, which *"might"* be missing the most recent writes. `List keys`/`Get (properties of) keys` are explicitly among the operations Microsoft states remain available in this read-only mode.
- Microsoft documents no per-request consistency knob (nothing analogous to Cosmos DB consistency levels) and no formal staleness-window SLA for list operations specifically; the consistency behavior is a direct, fully-documented consequence of the replication architecture above, not a gap in the documentation.

**Conclusion: the risk is accepted as-is, not mitigated.** The only condition under which `GetKeyVersionsAsync` could return an incomplete version list is a rare, Microsoft-initiated regional failover — not ordinary multi-replica load-balancing, and not a race a caller can trigger. Even then, the only version list operation ever affected is a **genuinely brand-new** key (created less than `RefreshInterval` ago, before a second version exists to make the bootstrap exemption moot); every other rotation decision in `BuildActivationTimeline` is unaffected because non-bootstrap versions activate on the normal `CreatedOn + RefreshInterval` delay regardless of list ordering. The failure mode is a transient, self-healing relying-party rejection (the new key briefly fails to activate) once the primary region recovers and the next refresh cycle re-lists — never a security regression, since a missing version can only cause a legitimate key to activate late, not cause an illegitimate one to be trusted. Building a mitigation (e.g. requiring an explicit operator-supplied `NotBefore` on every first version, or persisting a local "first version I've ever seen" fallback) would reintroduce exactly the process-local, restart-unsafe, multi-replica-inconsistent state that Amendment 2's `CreatedOn`-derived, stateless design was built to eliminate, to guard against an already-rare, already-self-healing, already non-security-relevant outage-recovery mode. `AzureKeyVaultRemoteSigningJwtSigningService.LoadKeysAsync` carries an updated code comment recording this same conclusion in place of the prior "assumes" phrasing.

### Amendment 4 — issue #288 / PR #312 (2026-07-04)

**§3.5's description of the "vanished kid" anomaly trigger corrected to match the implemented behaviour.**

This is a documentation-accuracy fix, not a design change. The implemented behaviour is correct as-is (confirmed by both security and architect review); §3.5's original prose simply describes a broader trigger condition than the code actually detects, and this amendment brings the prose into line.

§3.5 states the warning fires "if a previously-seen `kid` **vanishes** from `LoadKeysAsync` results without a replacement key having been active for at least `RetirementWindow`." That framing describes a more general condition than what is implemented. The actual anomaly detected — in both rotation-capable Azure Key Vault providers, whose logic is identical here (`AzureKeyVaultRemoteSigningJwtSigningService.WarnIfPreviouslyPublishedKidVanished` and `AzureKeyVaultCachedSigningJwtSigningService.WarnIfPreviouslyPublishedKidVanished`) — is narrower and simpler:

- The provider keeps a plain map of previously-published `(kid, raw Key Vault version string)` pairs (the same restart-tolerant, purely-for-logging map Amendment 2 describes).
- On each refresh, for a previously-published pair whose `kid` is no longer in the newly-included (trusted/published) set, the provider consults **Key Vault's own complete version list** — the full result of `GetKeyVersionsAsync` / `GetCertificateVersionsAsync`, including disabled and expired versions.
- It logs the warning **only when that pair's raw version string has disappeared from Key Vault's version list entirely** — i.e. Key Vault stopped returning the version at all (e.g. it was deleted or purged unexpectedly).
- A version that is **still returned by Key Vault** but has simply dropped out of the trusted/included set for a normal reason — it aged out of its `RetirementWindow`, or it was disabled — is treated as **expected** and does **not** trigger the warning.

In other words, the real trigger is "Key Vault no longer lists this version at all," **not** "no replacement key has been active for at least `RetirementWindow`." A version legitimately ageing out of its retirement window is the expected, non-anomalous case and stays silent; the retirement window is not part of the trigger condition at all. Anchoring the check to Key Vault's durable version list (rather than to elapsed-retirement-window bookkeeping) is consistent with Amendment 2's principle that rotation/anomaly reasoning is derived from the key store's own durable facts rather than from local wall-clock state.

The §3.5 goal is unchanged: surface loudly when a previously-published key disappears in a way that could make relying parties reject still-valid tokens whose signatures they can no longer verify against the JWKS. This amendment only corrects *how* that disappearance is defined. Nothing else in §3.5 (publish-then-activate, the read-only "surface, don't drive rotation" stance) is affected, and no requirement is added or removed.

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
