# ADR 0011 — Signing Key Management and the Provider Contract

Status: Accepted   ·   Date: 2026-06-23 / 2026-07-20   ·   Issues: #187, #418, #437, #478

> **Security sign-off — preserved provenance.** This ADR carries two formal security reviews. Both
> still govern; neither is superseded by the merge that produced this document.
>
> **Round 1 — signing-key design and the first production provider (originally ADR 0011).** The
> `RetirementWindow` derivation and the JWKS exposure behaviour were reviewed and approved by the
> security agent as a token-validation trust-boundary decision before the original ADR merged; that
> sign-off still governs today's derivation, which is unchanged. A second security + architect
> review — two rounds, both APPROVE with no blocking findings — covered the first production
> provider, Azure Key Vault remote signing, shipped in PR #298: round 1 reviewed that PR's design
> and diff directly, and round 2 was against commit `ea5c9b1`, which closed a closed-generic
> `ISanitizingLogger<T>` shadowing gap that round 1 had flagged as an accepted residual — that gap's
> fix is the `SanitizingLoggerRegistrationGate` startup control described below. Separately, a Key
> Vault list-key-versions read-consistency question raised in that review was investigated against
> Microsoft's documented reliability model and the residual risk was accepted as-is, with no
> mitigation — the only affected case, a brand-new key during a rare Microsoft-initiated regional
> failover, is self-healing and never a security regression.
>
> Round 1's sign-off was scoped to the `RetirementWindow` derivation and JWKS exposure specifically
> — it did not separately re-approve the dev-key environment gate, minimum key strength, or PEM
> hardening rules, which simply were not touched by anything reviewed in round 2 either and remain
> governed by ordinary code review.
>
> **Round 2 — the `KeySetOptions`/`KeySourceOptions` provider-contract reshape (originally ADR
> 0015).** Security reviewed the reshape on PR #419 and returned approve-with-conditions;
> @ChrisKlug adjudicated. Both must-fix conditions and the should-fix notes are folded into the
> decision text below rather than left outstanding:
> - Must-fix 1 — `PublicationLead` must be durable and `ActivateAt`-derived
>   (`PublishAt = ActivateAt − PublicationLead`), never derived from observed or first-seen time,
>   preserving the ban on in-memory, restart- and replica-inconsistent observed-time bookkeeping.
> - Must-fix 2 — kill-by-omission must be a disambiguated signal, not an overloaded one: post-window
>   vanish silent, within-window vanish dropped plus a `Warning` that **MUST NOT** be downgraded to
>   info/observability (it is the sole remaining detector for accidental early key omission,
>   replacing the old `Enabled` model's equivalent capability), failed or partial read MUST throw.
> - Accepted as-is, no mitigation required: the relaxation of retired-private-key destruction from
>   "immediately on retirement" to "bounded by request cadence, reclaimed on the next recompute or
>   at shutdown" — keeping non-active private material out of process memory is a provider
>   obligation for bundled formats (PFX, certificate store), not a structural guarantee.
> - Should-fix, folded in: duplicate-`kid` rejection restated as running on derived thumbprints at
>   `ListKeysAsync` time; `ISigner.Dispose` must-not-dispose-a-shared-client raised to a contract
>   MUST; an optional scavenge timer noted to bound the idle-app worst case.
> - Also reviewed and found sound (no fail-closed gap): during the `PublicationLead` window the
>   prior active key stays active until the successor's `ActivateAt` — a newly published key never
>   removes the incumbent, so `SelectActiveKey` returns null only when every configured key has
>   expired. A `KeySetOptions` deployment whose active key expires with no configured successor
>   drifts to that same null and fails closed at request time — the startup too-soon-activation
>   warning covers activation timing, not eventual expiry, so this is a real, if narrow, operational
>   gap operators should be aware of.
>
> The per-handoff signing self-test (issue #437) was added after both reviews above and is not
> covered by either sign-off. It generalises a pairing check that originated as a security-review
> finding on PR #436 against the Windows Certificate Store provider.

## Decision

**Provider abstraction.** A single non-generic interface, `IJwtSigningService`, defined in
`ZeeKayDa.Auth` (core, not the ASP.NET Core adapter — signing is a protocol concern):

```csharp
namespace ZeeKayDa.Auth.Tokens;

public interface IJwtSigningService
{
    // The active key plus any key still inside its retirement window. Exactly the set that
    // must appear in the JWKS.
    ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default);

    // Builds the JWS header internally (selecting the active key/algorithm), forms the signing
    // input, and signs, all in one call — so header and signature can never disagree about which
    // key produced them.
    ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default);
}
```

`SigningKeyDescriptor` carries only `(Kid, Algorithm, public key material)` — no rotation state.
`SignAsync` returns pre-encoded header/signature segments plus `Kid`/`Algorithm`; `ITokenWriter` is
the **only** caller and assembles the compact JWS, eliminating any TOCTOU window between choosing a
key and using it. `SigningAlgorithm` has no `none` member and must never gain one — an unsigned
token is structurally unrepresentable. The key/algorithm pairing (`ES256`→P-256, `ES384`→P-384,
`ES521`→P-521, `RS*`/`PS*`→RSA) is validated at load time, failing with
`ZeeKayDaConfigurationException` rather than producing a malformed token at sign time. There is no
`VerifyAsync` (verifying inbound client signatures is a distinct, deferred concern) and no rotation
method on the interface — rotation is provider-private, since most real providers (KMS, managed
databases) own it on their own schedule. Both methods are `async` even though local-key signing is
synchronous under the hood: this is the seam that makes remote signing (KMS/HSM/Key Vault) possible,
combined with the invariant that **callers never hold private key material** — `SignAsync` returns a
finished signature, so a remote signer's key can live in an HSM that never exports it.

**Provider contract — sources, not objects.** A provider never builds or returns a live bundle of
disposable private-key objects. The base class `JwtSigningService<TOptions>` — the only thing a
provider derives from — exposes two abstract methods that return data and lend a signer on demand:

```csharp
public abstract class JwtSigningService<TOptions> : IJwtSigningService
    where TOptions : JwtSigningServiceOptions
{
    /// <summary>Returns the current listing — pure public metadata, never private material.
    /// KeySetOptions: called exactly once, ever. KeySourceOptions: called each RefreshInterval.</summary>
    protected abstract ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken);

    /// <summary>Lends a signer for the key the base class has selected as active. The base class calls
    /// this ONLY for the currently-active key, owns the returned signer, and disposes it.</summary>
    protected abstract ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken);
}
```

```csharp
/// <summary>Pure public data describing one trusted key. No private material.</summary>
public sealed record KeyListing(
    KeyId Id,                       // the provider's own stable identifier (thumbprint, KV version id)
    SigningAlgorithm Algorithm,
    PublicKeyParameters PublicKey,  // public-only RSA/EC parameters
    DateTimeOffset? ActivateAt,     // null or past => active from startup (bootstrap)
    DateTimeOffset ExpiresAt);      // hard expiry (cert NotAfter); distinct from derived retirement

/// <summary>A lightweight wrapper over the provider's stable key identifier. NOT the JWKS `kid`.</summary>
public readonly record struct KeyId(string Value);

/// <summary>Public-only key parameters. Constructed from RSAParameters (public) or ECParameters
/// (public).</summary>
public sealed record PublicKeyParameters { /* SigningKeyType KeyType; RSAParameters?; ECParameters? */ }

/// <summary>Produces signature bytes over a formed signing input. One behavioural method; async so a
/// remote signer (KV/KMS/HSM) can make a network round trip.</summary>
public interface ISigner : IDisposable
{
    ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default);
}

/// <summary>Shipped BCL implementation over RSA/ECDsa. Local providers construct this and never
/// implement ISigner themselves. Only genuinely remote providers implement ISigner.</summary>
public sealed class LocalSigner : ISigner { /* wraps RSA/ECDsa; delegates to internal SigningAlgorithms.Sign */ }
```

`KeyListing` carries no `kid`. The base derives the public `kid` via `JwkThumbprint.Compute(PublicKey)`.
A `kid` MUST NOT be a raw external identifier (a Key Vault URI or certificate thumbprint would leak
reconnaissance value) — this is now **structurally enforced**: a provider supplies only its internal
`KeyId` and the public key, and cannot express a leaking `kid` because it never supplies the `kid` at
all. **The base requests private material only for the active key.** `CreateSignerAsync` is called
only for the selected active key; the base never asks for a non-active, future, or retired key's
private material. Whether that material is *actually* held out of process memory is then a
**provider obligation, not a structural guarantee** — a provider over a bundled format (PFX, a
Windows Certificate Store entry) reads the whole thing, private half included, when it reads the
file at all, so "non-active private material is never resident" holds only if that provider extracts
the public listing without retaining the private material until `CreateSignerAsync` asks for the
active key's. Local providers (development, File/PEM, PFX, Windows Certificate Store) build a
`LocalSigner` in `CreateSignerAsync`; a remote provider (Key Vault remote signing, KMS, HSM) returns
its own `ISigner` whose `SignAsync` is a network call — the private key never becomes local. Because
a provider never holds a private key object, it cannot alias, reuse, or mis-order one across two
listings — a class of bug the earlier object-returning contract needed dedicated reuse-guards to
police is now unrepresentable. `ISigner.Dispose` MUST release only its own per-activation handle: the
base disposes the `ISigner` each time the active key changes, and a remote `ISigner` (KV/KMS) that
references a shared, DI-owned SDK client MUST NOT tear that client down on `Dispose` — it disposes
only whatever local handle or copy it introduced. *This is a normative contract on `ISigner`.*
Duplicate-`kid` rejection still runs — now on the derived thumbprints: the base computes each
listing's `kid` via `JwkThumbprint.Compute(PublicKey)` at `ListKeysAsync` time and rejects a listing
set that yields duplicate `kid`s with `ZeeKayDaConfigurationException`, alongside the
key/algorithm-compatibility and key-strength checks described below.

**Two provider tiers, cut on acquisition and activation-driver.** The base type
`JwtSigningServiceOptions` (empty; never derived from directly) sits above two option types:

```csharp
namespace ZeeKayDa.Auth.Tokens;

/// <summary>Shared base. Empty. Never derived from directly.</summary>
public abstract class JwtSigningServiceOptions { }

/// <summary>
/// The complete, fixed set of keys is supplied at configuration time and never changes at runtime;
/// the only thing that advances is the wall clock crossing each key's ActivateAt.
/// </summary>
public abstract class KeySetOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// How long before a key's ActivateAt its public half must already be published in the JWKS.
    /// Advisory on this tier: the operator owns activation timing (via each key's ActivateAt), and
    /// the base class only surfaces a startup warning (HasTooSoonPendingActivation) when a key's
    /// ActivateAt is nearer than this.
    /// </summary>
    public TimeSpan PublicationLead { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// The provider re-supplies the current key list on a cadence; the list genuinely changes between
/// calls because something else owns the keys and the provider reads them.
/// </summary>
public abstract class KeySourceOptions : JwtSigningServiceOptions
{
    /// <summary>How often the base class re-asks the provider for the current key list.
    /// One meaning only: re-ask cadence.</summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long before a key's ActivateAt its public half must already have been published. Enforced
    /// entirely through durable, ActivateAt-derived timing: the base treats PublishAt = ActivateAt −
    /// PublicationLead as the instant the key's public half must already be in the JWKS, and the
    /// provider maps its store's durable timestamp onto ActivateAt so that lead is satisfied (e.g.
    /// Key Vault: ActivateAt = CreatedOn + PublicationLead). It is NEVER derived from observed/
    /// first-seen time. Defaults to RefreshInterval when left unset. Invariant:
    /// PublicationLead >= RefreshInterval — a config-level relationship (the lead is at least one
    /// poll cycle), not per-key state.
    /// </summary>
    public TimeSpan PublicationLead { get; set; } // unset => resolves to RefreshInterval
}
```

Durable and `ActivateAt`-derived only, never observed-first-seen — the resolution of a security
must-fix condition on PR #419.

**Tier assignment.** `KeySetOptions` covers File (PEM), PFX, Windows Certificate Store, and
development/in-memory (a trivial degenerate case: one key, no `ActivateAt`, active from startup).
`StaticKeySourceOptions` retired entirely; its sole consumer, `DevelopmentSigningKeyOptions`, is a
`KeySetOptions`. `KeySourceOptions` covers Azure Key Vault (cached and remote), a DB-backed table, a
file-glob that discovers new files at runtime, and remote signing (KMS/HSM). The cut is on **whether
the set is known up front**, not on whether it reloads: a single PEM file with a pre-staged successor
cert reloads on a schedule but its set is fixed at config time → `KeySetOptions`. A file-glob that
grows new members at runtime → `KeySourceOptions`, because the list genuinely changes. The
third-party litmus: *do you own the full list of keys up front? → `KeySetOptions`. Does something
else own the keys and you read them? → `KeySourceOptions`.*

**One shared timeline engine.** `SigningKeyRotation` (`RotationKey(Id, ActivatesAt, ExpiresAt)` →
`BuildActivationTimeline` / `SelectActiveKey` / `SelectIncludedKeys` / `HasTooSoonPendingActivation`)
is the single engine both tiers call, mapping `RotationKey.Id = KeyListing.Id.Value`,
`RotationKey.ActivatesAt = KeyListing.ActivateAt ?? DateTimeOffset.MinValue` (null/past => eligible
from startup), `RotationKey.ExpiresAt = KeyListing.ExpiresAt`. The operator sets only `ActivateAt`
per key; every other timing quantity is derived: `PublishAt = ActivateAt − PublicationLead` feeds the
too-soon check, and `DeactivateAt = successor.ActivateAt + RetirementWindow` is exactly the window
`SelectIncludedKeys` already computes. A too-short retirement window is therefore unrepresentable —
there is no operator deactivation-date knob to get wrong. The Key-Vault-specific bootstrap exemption
is encoded in the data (the provider sets `ActivateAt = null` or its `CreatedOn` for the
chronologically-first version), not as special engine logic; the single-key bootstrap exemption in
`SelectActiveKey` is otherwise unchanged.

**State model.** The base class holds an immutable snapshot of the public `KeyListing`s plus the
precomputed timeline, and exactly one live `ISigner` — the active key's. Active-key and JWKS
selection are computed lazily per request from the snapshot's timeline and `now` via
`SigningKeyRotation`, a pure function over immutable public data. On `KeySetOptions`, `ListKeysAsync`
runs once; the snapshot is built once and never swapped — no lock, no refcount, no single-flight, no
re-materialisation; `CreateSignerAsync` is called only when the computed active `KeyId` changes (the
wall clock crossing a successor's `ActivateAt`); all signers are disposed at process shutdown. On
`KeySourceOptions`, the snapshot is swapped on each refresh — the only tier that keeps swap/borrow
machinery, and only for safe disposal of a superseded active signer; because `ListKeysAsync` is a
cheap public-metadata call, the expensive step (`CreateSignerAsync`) is naturally gated on the active
`KeyId` changing, which the base computes directly from the cheap listings.

**Disposal.** Because `CreateSignerAsync` is called only for the active key, the base never requests
private material for a non-active/future/retired key. For the previously-active signer at a handoff,
`KeySetOptions`'s lazy recompute disposes it opportunistically when the computed active `KeyId`
changes on the next request — bounded by request cadence, falling back to shutdown if the process
goes idle at the handoff instant; the retiring signer's private material is reclaimed on the next
recompute or at shutdown. An optional `KeySetOptions` scavenge timer that recomputes active-key
selection and disposes a superseded signer on a low-frequency tick may be added to bound the
idle-app worst case; it is a noted possibility, not a requirement. `KeySourceOptions` disposes the
superseded signer after in-flight `SignAsync` calls complete. Security accepted this relaxation as-is
(PR #419) — the base requests private material only for the active key.

**No `Enabled` flag — omission is the kill switch.** There is no `Enabled`/disabled flag anywhere in
the options or the contract. A `KeySourceOptions` provider returns a key for exactly as long as it
should be trusted, including through its retirement window; a key that stops appearing in the
returned listing is dropped from the JWKS on the next refresh, immediately, retirement window or
not. Normal rotation (Key Vault / a DB naturally keeping old versions or rows) keeps a retiring key
appearing until its derived retirement window closes; an emergency kill (revoke/disable/delete in the
backing store) means the provider's next `ListKeysAsync` simply stops returning it. This three-state
disambiguation resolves a security must-fix condition on PR #419. The
within-window-vanish `Warning` **MUST NOT** be downgraded to info or observability; `ListKeysAsync`'s
completeness contract (MUST throw, never return a short list) is what stops a partial read being read
as a revocation. Concretely, omission disambiguates into three states: (1) **post-window vanish** — a
key that stops being listed after its derived retirement window has closed is the normal end of
life, no log beyond routine; (2) **within-window vanish** — a key that stops being listed while still
inside its derived retirement window is still dropped from the JWKS on the next refresh (the kill
switch still fires), but the base MUST emit a `Warning` — the accidental-omission / vanished-`kid`
detector, the one genuine capability the old `Enabled` model had that naive kill-by-omission would
otherwise lose; (3) **failed or partial read** — `ListKeysAsync` carries a completeness contract: a
provider that cannot produce a complete read of its current key set MUST throw (fail closed), never
return a short or partial list, so a transient store error can never be silently read as revoking
every key it failed to enumerate.

**Algorithm handling.** Algorithm is declared per-provider (applied across certs) or derived where
the key determines it (EC P-384 → ES384), and carried on `KeyListing.Algorithm`. The base runs
`SigningAlgorithms.ValidateKeyAlgorithmCompatibility` and `ValidateKeyStrength` over every listing at
`ListKeysAsync` time — key type, EC curve, and RSA modulus size are all readable from the public key,
so all load-time validation now runs on public data before any private material is loaded. The
development helper generates RSA keys of at least 3072 bits; the shared base validation rejects any
RSA key under 2048 bits or a non-NIST EC curve, for every provider. Mixed key types across a set are
allowed provided each key is internally consistent; the active signer's algorithm is the one written
to the JWS header.

**Local development is one line**, via two named builder extensions —
`AddInMemoryDevelopmentJwtSigningKeys()` (ephemeral) and
`AddPersistedDevelopmentJwtSigningKeys(persistTo: null)` (persists to a default path) — so the
persistence choice lives in the method name rather than in a `null` argument that would otherwise
read against the grain. Both hard-fail with `ZeeKayDaConfigurationException` outside an allowed
environment list (`AllowedDevelopmentJwtSigningKeysEnvironments`, default `["Development"]`),
configured only through the registration method's own `configure` callback — never through bindable
`IConfiguration` — so a committed `appsettings.json` cannot silently widen it. `Production` is
rejected unconditionally regardless of list contents, and any non-`Development` entry in the allowed
list logs `LogLevel.Critical` on **every** startup. Persisted keys are written as plain PEM with
directory/file permissions set atomically at create time (`0700`/`0600` on POSIX via
`UnixCreateMode`, a restrictive non-inherited ACL on Windows) — never create-then-`chmod` — and the
provider fails closed (`ZeeKayDaConfigurationException`) rather than loading a key file broader than
`0600`, a path that resolves through a symlink, or a directory not owned by the current user.

**`RetirementWindow`** — how long a key that has stopped being the active signer stays published in
the JWKS, and therefore trusted by relying parties — is **derived, never a user setting**:

```
RetirementWindow = max(access-token lifetime, ID-token lifetime, 1-hour floor) + clock-skew allowance
```

measured from the moment a successor key becomes active, not from the retired key's creation. This
derivation carries the original security sign-off recorded above and is never operator-configurable.
The 1-hour floor is a temporary bridge: `IdTokenOptions` and the access token
pipeline do not yet expose configurable lifetimes, so without a floor the `max(...)` would resolve
over zero terms and produce a near-zero window that invalidates tokens in flight. Refresh-token
lifetime is deliberately excluded — refresh tokens are validated by the authorization server against
the token store (ADR 0008), never by a relying party against the JWKS, so including its (unbounded,
sliding) lifetime would pin every retired key in the JWKS for no validation benefit. While a
newly-published key is inside its `PublicationLead` window, the prior active key stays active until
the successor's `ActivateAt` — a newly published key never removes the incumbent, so
`SelectActiveKey` returns `null` only when every configured key has expired; a `KeySetOptions`
deployment whose active key expires with no configured successor drifts to that same null and fails
closed at request time.

**JWKS and discovery.** `IJwksDocumentProvider` maps `GetSigningKeysAsync()`'s result to a JWK Set
using BCL-only types (`RSA.ExportParameters(false)`/`ECDsa.ExportParameters(false)`, no
Microsoft.IdentityModel leakage) and serves from the same single-flight-gated cache as the signing
path, so an anonymous request burst against a cold cache cannot become a thundering herd. The JWKS is
a trust boundary: what appears here is what relying parties will trust. Its exposure behaviour
carries the original security sign-off recorded above. `id_token_signing_alg_values_supported`
stays statically configured (not derived from the live key set, which would make the discovery
document flicker during rotation) with a startup cross-check that every advertised algorithm is one
the registered signing service can actually produce.

**Public extension surface.** `JwtSigningService<TOptions>` (the optional base class implementors
derive from), `JwkThumbprint`, `SigningKeyRotation`/`SigningKeyDescriptorFactory`, `KeySetOptions`,
`KeySourceOptions`, `KeyListing`, `KeyId`, `PublicKeyParameters`, `ISigner`, `LocalSigner`, and
`ISanitizingLogger<T>` are `public` in core rather than `internal` + `InternalsVisibleTo` — because
`InternalsVisibleTo` can only name first-party assemblies at build time and structurally cannot serve
a genuine third-party provider package (ADR 0012). ZeeKayDa's own crypto dispatch
(`SigningAlgorithms`) and concrete redaction logic (`SecretSanitizingLogger<T>`) stay `internal`.
Making `ISanitizingLogger<T>` nameable introduces a host-shadowing risk (a host registering its own
implementation could silently disable redaction), mitigated by a hard-failing startup gate
(`SanitizingLoggerRegistrationGate`, the sole `IStartupVerificationGate` — see ADR 0016). This gate is
the fix delivered by commit `ea5c9b1`, named in the sign-off above — it runs before every other
startup check and rejects both an unexpected open-generic implementation and any closed-generic
override, so a host cannot silently disable log redaction on the signing path.

**No JWT encryption (JWE) in v1** — not even an "off" toggle. v1 has no dynamic client registration,
so no client can request an encrypted token; the encryption discovery fields are OPTIONAL in OIDC
and their absence is the spec-correct signal. `ITokenWriter` is composable so a sibling
`IEncryptionService` seam can be added later without breaking this ADR's contract.

**Registration.** Every `Add<Provider>Signing()` extension on `ZeeKayDaAuthBuilder` registers
`IJwtSigningService` as a singleton, calls `ThrowIfAlreadyRegistered` so a second provider fails
loudly rather than silently winning, and registers its own `IValidateOptions<TOptions>`. All such
methods return the same builder, so environment-conditional provider selection is an ordinary
`if`/`else` — no dedicated sub-builder is needed.

**Startup self-test — pairing lazy `CreateSignerAsync` with materialize-and-verify.** Lazy
`CreateSignerAsync` — called only when the active `KeyId` changes, not eagerly at startup — leaves a
gap that an earlier, eager pre-warm used to close: a private-key acquisition or use failure that only
surfaces when the active key is actually used to sign, not when it is merely listed (a Key Vault
certificate policy marking the private key non-exportable; an inaccessible CNG key container; a
missing `sign` permission on a remote-signing key). None of these fail `ListKeysAsync`
(`GetSigningKeysAsync`'s pre-warm, which every provider's startup path already forces) — they only
fail once a signer is materialized and asked to sign, which otherwise would surface on the first
token-issuing request in production. The fix lives directly in `JwtSigningService<TOptions>`'s own
`EnsureActiveSignerAsync` — the single choke point every active-signer handoff already goes through,
whether that handoff is the very first materialization or a later rotation. Immediately after
`CreateSignerAsync` returns and its `Algorithm` is checked against the key's declared algorithm, the
new signer signs a fixed, non-JWS-shaped constant (`"zeekayda-auth signing self-test"` — contains a
space and no `.`, so it can never be mistaken for or lifted into a valid JWS) and the resulting
signature is verified against that same key's own listed public key before the signer is ever
installed as active or handed out for real signing. Verification (not just materialization) is what
structurally proves the signer `CreateSignerAsync` returned is the key the base class is publishing a
`kid` for — mere materialization is not enough, since a signer can be successfully constructed over
key material that does not actually pair with the published public key. Because this check runs
inside `EnsureActiveSignerAsync` itself, every handoff is self-tested, not just the one that happens
to occur first: a key rotated in hours or days after process start is proven exactly as thoroughly as
the key that was active at boot. The cost is one extra sign operation per handoff (for a remote
signer such as Azure Key Vault, one extra network call per rotation, not per token issued), which is
negligible next to rotation's own low-frequency cadence.

A small, explicitly-implemented `ISigningStartupSelfTest` interface on `JwtSigningService<TOptions>`
— deliberately not a member on `IJwtSigningService` itself, which would be a breaking change for an
external implementer, and non-virtual so no provider can weaken it — exists solely so a
framework-owned `IStartupVerifier` (`SigningStartupSelfTestVerifier`, an `internal sealed class :
IStartupVerifier` registered once by `AddZeeKayDaAuthCore()`) can force the *first* handoff to happen
eagerly, at host startup, rather than lazily on the first real token-issuing request: its one method
simply forces active-signer materialization, and the self-test above runs as a side effect of that
materialization exactly as it would for any other handoff. Every provider gets this
eager-at-startup behavior for free, and provider-specific startup services shrink to only genuinely
provider-specific behavior (the Azure Key Vault cached provider's memory-residency log line is the
one example; the Windows Certificate Store and File/PEM/PFX providers had no provider-specific
behavior left at all once their shared pre-warm moved here, so their startup services were deleted
outright). This also supersedes the Windows Certificate Store provider's own hand-rolled
`VerifySigningKeyMatchesListing` (added in response to PR #436 security review) — the same pairing
invariant, now proven on every handoff, generically, for every provider.

The self-test is **unconditional, with no HSM opt-out** — the secure-by-default choice. The cost (one
extra `CreateSignerAsync` and one sign operation per handoff; the active private key becoming
resident from the moment of handoff rather than from first use, which follows milliseconds later
regardless) is small and fixed, while a signer/public-key mismatch passing a handoff silently is
exactly the failure mode the lazy `CreateSignerAsync` model reopened. Since `AddZeeKayDaAuthCore()` is
also reachable from a host that has not (yet) configured any signing provider, `SigningStartupSelfTestVerifier`
resolves `IJwtSigningService` lazily and no-ops when nothing is registered, rather than taking it as a
hard constructor dependency — the self-test being unconditional for every *configured* signing
provider does not mean signing configuration itself becomes mandatory. It also logs a `Warning`
(naming the resolved type) when the registered `IJwtSigningService` does not implement
`ISigningStartupSelfTest` at all, so a decorator or wrapper that silently drops the interface does not
disable this control without a trace.

A *definitive* mismatch (`SigningAlgorithms.Verify` returning `false`) fails closed — that is the
entire point of the self-test. A transient failure to even run to completion (a network blip or
throttling response from a remote signer while signing the self-test payload) aborts the handoff —
and, at startup, the host's startup — exactly like the pre-existing `ListKeysAsync` pre-warm already
does; this is not a new failure class, since the base class cannot distinguish "the key is genuinely
gone" from "the remote signer is temporarily unavailable" at this layer, so both fail closed the same
way. No retry/backoff logic is implemented for the self-test call itself — a host that wants
resilience against transient throttling at startup or rotation time should apply it at the transport
layer (e.g. the Key Vault SDK's own retry policy), not by weakening this self-test.

## Why

- **A non-generic interface, not `IJwtSigningService<TOptions>`.** The options type is a concrete
  provider's implementation detail; consumers (the token writer, the JWKS provider) only need
  "sign this" / "give me the keys." Genericity belongs on the optional base class, not the
  interface every consumer depends on — a non-generic interface also keeps DI registration uniform.
- **No rotation method on the interface.** Forcing a `RotateAsync`/state method on every provider
  would impose a lifecycle model that KMS- or database-backed providers don't have.
- **`RetirementWindow` is derived, not configurable** — mirroring ADR 0008's rejection of
  user-configurable retention TTLs. The only off-default values are unsafe (too short, drops still-valid
  tokens; too long, bloats the trust set) or useless — the correct value is fully derivable from
  token lifetimes the server already configures.
- **`ITokenWriter`, not `IJwtWriter`** — a future opaque/reference-token writer would make `IJwtWriter`
  a misnomer; the format-agnostic name lets it be another `ITokenWriter` implementation.
- **`IJwtSigningService`, not `ISigningService`** — every artifact this server signs is a JWT; a
  generic name would imply a flexibility that doesn't exist in this domain.
- **No shared signing+encryption abstraction.** Different keys, different trust directions, different
  lifecycles; the forward-compatible shape is a sibling seam introduced when encryption actually lands.
- **No Microsoft.IdentityModel types on the public surface.** `SigningCredentials`/`SecurityKey`/
  `JsonWebKey` would bake a large, fast-moving third-party surface into the SemVer contract. The
  hand-rolled BCL JWK mapping is small, fully specified by RFC 7517/7518, and covered by known-answer
  vectors.
- **`InternalsVisibleTo` for the shared helpers was tried and rejected** (Azure Key Vault provider,
  first attempt) — it can serve exactly one first-party package, never a genuine third party
  implementing this ADR's own extensibility contract without a new core release naming them
  specifically. Making the contracts public, with ZeeKayDa's own crypto/redaction logic staying
  internal, is the fix.
- **Dynamic derivation of advertised signing algorithms was rejected** — discovery is a stable,
  cached contract; deriving it from whatever keys happen to be loaded would make it flicker during
  rotation. Static configuration plus a startup consistency check gives a stable contract and still
  catches the misconfiguration.
- **A dedicated signing-provider sub-builder (`AddJwtSigning(signing => …)`) was considered and
  rejected** — the flat `AddXxxSigning()` methods already compose with ordinary `if`/`else`
  branching, and a sub-builder would add a parallel surface across every provider package for a
  problem already solved.
- **Placing the development-key environment gate on the shared `AuthorizationServerOptions` root was
  tried, shipped, and reverted.** It mirrored the in-memory store's server-wide gate placement, but
  conflated the gate's *input* (genuinely server-wide: the host environment name) with its *policy*
  (feature-scoped: inert unless a development-signing-key method was also called) — exactly the
  discoverability trap ADR 0008 names for auto-registration. The gate now lives on the
  provider-specific, public options type, reached through the registration method's `configure`
  callback, with no `InternalsVisibleTo` or reflection required.
- **Keeping the earlier unified `RotatingKeySourceOptions` contract (the reversal this ADR records)
  was rejected — this is the decision being reversed, and it is the single highest-value rejected
  alternative in this ADR's history.** That earlier design (issue #409, PR #413/#414, ratified less
  than two weeks before it was reversed) cut the provider split on *"does the source reload?"* and
  gave every rotating provider one `KeyRotationCheckInterval`. It did not hold because File/PFX/
  cert-store and Key Vault do not share one underlying model — they shared a *name* for two different
  things: an internal clock-tick over a fixed, pre-configured timeline (`KeySetOptions`) versus a real
  external poll cadence and kill-switch reaction time (`KeySourceOptions`). The evidence was concrete
  and repeated: every documentation fix had to say "this means X for Key Vault but Y for File/PFX." A
  shared contract that can only be documented by per-provider caveats is describing two things, not
  one. The later splitting-out of separate activation-delay properties for Key Vault vs. File/cert was
  already a partial admission of this; the current `KeySetOptions`/`KeySourceOptions` split finishes
  the job by splitting the *tier itself* on the axis that genuinely differs (acquisition +
  activation-driver) rather than patching around a shared poll property. **A future reader
  considering re-unifying these tiers should stop here:** the unification was tried, ratified, and
  reversed for this reason.
- **"Active cert + optional next cert with a cutover date" for `KeySetOptions` was rejected** in
  favour of an ordered list of keys each with its own `ActivateAt`. The mandatory-active-plus-optional-
  next shape covers the common case but not a pre-staged chain of more than two certs, and it
  introduces a second way to express "which key is active" (positional/optional) that the
  ordered-listing-plus-`ActivateAt` model expresses once, uniformly, shared with `KeySourceOptions` via
  the same `SigningKeyRotation` engine. `KeySetOptions` needs no periodic-recheck knob: reacting to a
  file mtime change, or discovering new files, is either a restart concern (fixed set) or a
  `KeySourceOptions` concern (a genuinely changing set) — not a shared `KeySetOptions` property.
- **Keeping the whole-set change-detection ask/refresh split was rejected — subsumed structurally.**
  That split existed to avoid re-downloading *private key material* on a poll where nothing rotated.
  In the data-not-objects model, `ListKeysAsync` returns only public metadata and the expensive step
  (`CreateSignerAsync`) is called only when the active `KeyId` changes, which the base computes
  directly from the cheap listings. The optimisation the ask hand-rolled is now the default behaviour,
  so the hook and its comparison machinery are removed rather than ported.
- **An `Enabled`/disabled flag on the contract (instead of kill-by-omission) was rejected.** An
  `Enabled` flag only ever meant "Key Vault version is enabled," and it forced the shared abstraction
  to carry a concept most providers had no equivalent for (a File/cert registration has no enable
  bit). Collapsing it into "the provider lists trusted keys only" makes revocation uniform across
  every `KeySourceOptions` backing store (revoke/disable/delete → stops being listed → gone next poll)
  and removes a bespoke, provider-conditional kill-switch from the shared contract. The one capability
  the explicit flag had — telling an accidental early drop apart from a legitimate aging-out — is
  preserved by the within-window-vanish `Warning` and the `ListKeysAsync` completeness contract, so
  omission is a three-state disambiguated signal, not an overloaded one.
- **`PublicationLead` on the shared base instead of per-tier was rejected — and this is deliberately
  *not* a repeat of the earlier `RotatingKeySourceOptions` mistake.** `PublicationLead` lives on both
  `KeySetOptions` and `KeySourceOptions`, which superficially resembles the shared
  `KeyRotationCheckInterval` that was reversed. The difference is the reason the reversal was needed:
  `KeyRotationCheckInterval` fused *two genuinely different concepts* (internal clock-tick vs. external
  poll cadence) under one name. `PublicationLead` is *one* concept — the publish-then-activate lead —
  on both tiers; only its **enforcement** differs by the tier's activation driver (advisory startup
  warning on `KeySetOptions` where the operator owns `ActivateAt`; framework-derived `PublishAt` on
  `KeySourceOptions` where the framework owns activation). One concept, tier-appropriate enforcement,
  is a genuine shared abstraction; two concepts sharing a name was not. Putting it on the base anyway
  was rejected because `KeySourceOptions` needs the `PublicationLead >= RefreshInterval` invariant,
  which is meaningless on `KeySetOptions` (no interval), so a base-level property would carry a
  validation rule that applies to only one subtype.
- **A macOS Keychain signing provider was implemented, reviewed, and then descoped** — see ADR 0012
  for that packaging/product-scope decision.
- **Third parties choosing one of two tiers, rather than implementing one shared contract, was
  accepted.** The acquire-up-front-vs-read-from-a-source litmus makes the choice a one-liner in
  practice, and custom implementations are expected to be rare, so the two-tier choice is a minor,
  accepted cost over a single shared contract that would otherwise fuse two different models again.

## Consequences

- A provider author implements two methods (`ListKeysAsync`, `CreateSignerAsync`) to get correct
  caching, single-flight refresh, header construction, `kid` selection, and signing for free; only a
  genuinely remote signer additionally implements its own `ISigner`.
- Private key material never leaves the signing component, which is what makes remote signing
  (KMS/HSM) possible at all; the base requests private material only for the active key, and
  non-active/future/retired keys are only ever asked for in public form (keeping them out of memory
  entirely is then a provider obligation for bundled formats).
- The hand-rolled JWK mapping is owned code that must be kept correct against RFC 7517/7518 via
  known-answer vectors — an accepted, deliberate trade-off against a Microsoft.IdentityModel
  dependency.
- `RetirementWindow`'s 1-hour floor is a bridge: when per-token lifetime configuration lands, the
  derivation itself is updated in place (not a new option), and the floor reverts to guarding only
  the degenerate zero-terms case.
- Public extension types (`JwtSigningService<TOptions>`, `JwkThumbprint`, `SigningKeyRotation`,
  `SigningKeyDescriptorFactory`, `KeySetOptions`, `KeySourceOptions`, `KeyListing`, `KeyId`,
  `PublicKeyParameters`, `ISigner`, `LocalSigner`, `ISanitizingLogger<T>`) are a SemVer commitment —
  necessary for genuine third-party providers, but their shapes are now stable API. The
  `ISanitizingLogger<T>` host-shadowing risk is mitigated by a hard-failing startup gate rather than
  closed off structurally (a public sealed concrete type was considered, touches many call sites, and
  remains available as a future hardening step).
- No encryption in v1 is acceptable given no dynamic client registration and OPTIONAL discovery
  fields; the forward-compat path (a sibling `IEncryptionService` seam) is preserved.
- Kid-leak resistance is structural: a provider cannot supply a raw external identifier as `kid`,
  because it never supplies the `kid` at all.
- `KeySetOptions` has near-zero machinery (one snapshot, no locks/refcounts/single-flight);
  `KeySourceOptions` is correspondingly smaller than an object-returning contract would need (no ask,
  no re-materialisation, no reuse-guards).
- Revocation is uniform across every `KeySourceOptions` store via kill-by-omission; the within-window
  vanish `Warning` plus the `ListKeysAsync` completeness contract cover the one capability an explicit
  `Enabled` flag would otherwise be needed for.
- The per-handoff signing self-test costs one extra sign operation per handoff (one extra network call
  per rotation for a remote signer, not per token issued) — negligible next to rotation's own
  low-frequency cadence, and it is the only structural proof that a materialized signer actually pairs
  with the public key its `kid` publishes.
