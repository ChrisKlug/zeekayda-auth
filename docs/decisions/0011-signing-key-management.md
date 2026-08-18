# ADR 0011 — Signing Key Management

Status: Accepted   ·   Date: 2026-06-23   ·   Issue: #187

> **Security sign-off.** The `RetirementWindow` derivation and the JWKS exposure behaviour below
> were reviewed and approved by the security agent as a token-validation trust-boundary decision
> before this ADR merged; that sign-off still governs today's derivation. A second security +
> architect review (two rounds, both APPROVE with no blocking findings) covered the first
> production provider (Azure Key Vault remote signing); the second round was against commit
> `ea5c9b1`, which closed a closed-generic `ISanitizingLogger<T>` shadowing gap the first round had
> flagged as an accepted residual. Separately, a Key Vault list-key-versions read-consistency
> question raised in that review was investigated against Microsoft's documented reliability model
> and the residual risk was accepted as-is, with no mitigation (the only affected case — a
> brand-new key during a rare Microsoft-initiated regional failover — is self-healing and never a
> security regression).

> **Note.** [ADR 0015](./0015-signing-provider-set-source-tiers.md) supersedes this ADR's original
> rotation/caching provider contract (a provider returning a live `SigningKeySet` of disposable key
> objects, the `KeySourceRefreshInterval`/three-tier options split, and the timing of retired
> private-key destruction). Everything else below — the `IJwtSigningService` consumer contract,
> `RetirementWindow` and its sign-off, the development-key environment gate, minimum key strength
> and file-permission hardening, the JWKS endpoint, and the public helper types — is unchanged and
> still governs. Where the two disagree on provider mechanics, ADR 0015 governs; read it for the
> current provider contract.

## Decision

**Provider abstraction.** A single non-generic interface, `IJwtSigningService`, defined in
`ZeeKayDa.Auth` (core, not the ASP.NET Core adapter — signing is a protocol concern):

```csharp
namespace ZeeKayDa.Auth.Tokens;

public interface IJwtSigningService
{
    // The active key plus any key still inside its retirement window. Exactly the set that
    // must appear in the JWKS.
    ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken ct = default);

    // Builds the JWS header internally (selecting the active key/algorithm), forms the signing
    // input, and signs, all in one call — so header and signature can never disagree about which
    // key produced them.
    ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken ct = default);
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

**Local development is one line**, via two named builder extensions —
`AddInMemoryDevelopmentJwtSigningKeys()` (ephemeral) and
`AddPersistedDevelopmentJwtSigningKeys(persistTo: null)` (persists to a default path) — so the
persistence choice lives in the method name rather than in a `null` argument that would otherwise
read against the grain. Both hard-fail with `ZeeKayDaConfigurationException` outside an allowed
environment list (`AllowedDevelopmentJwtSigningKeysEnvironments`, default `["Development"]`),
configured only through the registration method's own `configure` callback — never through bindable
`IConfiguration` — so a committed `appsettings.json` cannot silently widen it. `Production` is
rejected unconditionally regardless of list contents, and any non-`Development` entry in the allowed
list logs `LogLevel.Critical` on **every** startup. The development helper generates RSA keys of at
least 3072 bits; the shared base validation rejects any RSA key under 2048 bits or a non-NIST EC
curve, for every provider. Persisted keys are written as plain PEM with directory/file permissions
set atomically at create time (`0700`/`0600` on POSIX via `UnixCreateMode`, a restrictive
non-inherited ACL on Windows) — never create-then-`chmod` — and the provider fails closed
(`ZeeKayDaConfigurationException`) rather than loading a key file broader than `0600`, a path that
resolves through a symlink, or a directory not owned by the current user.

**`RetirementWindow`** — how long a key that has stopped being the active signer stays published in
the JWKS, and therefore trusted by relying parties — is **derived, never a user setting**:

```
RetirementWindow = max(access-token lifetime, ID-token lifetime, 1-hour floor) + clock-skew allowance
```

measured from the moment a successor key becomes active, not from the retired key's creation. The
1-hour floor is a temporary bridge: `IdTokenOptions` and the access token pipeline do not yet expose
configurable lifetimes, so without a floor the `max(...)` would resolve over zero terms and produce
a near-zero window that invalidates tokens in flight. Refresh-token lifetime is deliberately
excluded — refresh tokens are validated by the authorization server against the token store (ADR
0008), never by a relying party against the JWKS, so including its (unbounded, sliding) lifetime
would pin every retired key in the JWKS for no validation benefit. The retired key's *private*
material is destroyed immediately on retirement regardless of `RetirementWindow` — only the public
half stays published.

**JWKS and discovery.** `IJwksDocumentProvider` maps `GetSigningKeysAsync()`'s result to a JWK Set
using BCL-only types (`RSA.ExportParameters(false)`/`ECDsa.ExportParameters(false)`, no
Microsoft.IdentityModel leakage) and serves from the same single-flight-gated cache as the signing
path, so an anonymous request burst against a cold cache cannot become a thundering herd. A `kid`
is derived via RFC 7638 JWK thumbprint (`JwkThumbprint`) — never a raw external identifier such as a
Key Vault URI or certificate thumbprint, which would leak reconnaissance value — and duplicate
`kid`s in a loaded key set are rejected at load time. `id_token_signing_alg_values_supported` stays
statically configured (not derived from the live key set, which would make the discovery document
flicker during rotation) with a startup cross-check that every advertised algorithm is one the
registered signing service can actually produce.

**Public extension surface.** `JwtSigningService<TOptions>` (the optional base class implementors
derive from), `JwkThumbprint`, `SigningKeyRotation`/`SigningKeyDescriptorFactory`, and
`ISanitizingLogger<T>` are `public` in core rather than `internal` + `InternalsVisibleTo` — because
`InternalsVisibleTo` can only name first-party assemblies at build time and structurally cannot
serve a genuine third-party provider package (ADR 0012). ZeeKayDa's own crypto dispatch
(`SigningAlgorithms`) and concrete redaction logic (`SecretSanitizingLogger<T>`) stay `internal`.
Making `ISanitizingLogger<T>` nameable introduces a host-shadowing risk (a host registering its own
implementation could silently disable redaction), mitigated by a hard-failing startup validator
(`SanitizingLoggerRegistrationStartupValidator`) that runs first among startup checks and rejects
both an unexpected open-generic implementation and any closed-generic override.

**No JWT encryption (JWE) in v1** — not even an "off" toggle. v1 has no dynamic client registration,
so no client can request an encrypted token; the encryption discovery fields are OPTIONAL in OIDC
and their absence is the spec-correct signal. `ITokenWriter` is composable so a sibling
`IEncryptionService` seam can be added later without breaking this ADR's contract.

**Registration.** Every `Add<Provider>Signing()` extension on `ZeeKayDaAuthBuilder` registers
`IJwtSigningService` as a singleton, calls `ThrowIfAlreadyRegistered` so a second provider fails
loudly rather than silently winning, and registers its own `IValidateOptions<TOptions>`. All such
methods return the same builder, so environment-conditional provider selection is an ordinary
`if`/`else` — no dedicated sub-builder is needed.

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

## Consequences

- A provider author implements one method to get correct caching, single-flight refresh, header
  construction, `kid` selection, and signing for free; only a genuinely remote signer additionally
  overrides the signature-production hook. See ADR 0015 for the current shape of that contract.
- Private key material never leaves the signing component, which is what makes remote signing
  (KMS/HSM) possible at all.
- The hand-rolled JWK mapping is owned code that must be kept correct against RFC 7517/7518 via
  known-answer vectors — an accepted, deliberate trade-off against a Microsoft.IdentityModel
  dependency.
- `RetirementWindow`'s 1-hour floor is a bridge: when per-token lifetime configuration lands, the
  derivation itself is updated in place (not a new option), and the floor reverts to guarding only
  the degenerate zero-terms case.
- Public extension types (`JwtSigningService<TOptions>`, `JwkThumbprint`, `SigningKeyRotation`,
  `SigningKeyDescriptorFactory`, `ISanitizingLogger<T>`) are a SemVer commitment — necessary for
  genuine third-party providers, but their shapes are now stable API. The `ISanitizingLogger<T>`
  host-shadowing risk is mitigated by a hard-failing startup validator rather than closed off
  structurally (a public sealed concrete type was considered, touches ~34 call sites, and remains
  available as a future hardening step).
- No encryption in v1 is acceptable given no dynamic client registration and OPTIONAL discovery
  fields; the forward-compat path (a sibling `IEncryptionService` seam) is preserved.
