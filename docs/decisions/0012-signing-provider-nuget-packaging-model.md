# ADR 0012 — Signing Provider NuGet Packaging Model

**Status:** Accepted  
**Date:** 2026-07-02

---

## Context

ADR 0011 settled the signing key abstraction (`IJwtSigningService`, `JwtSigningService<TOptions>`,
and `DevelopmentJwtSigningService`) and explicitly reserved the seam for production-grade signing
key providers without specifying how those providers would be delivered to consumers. Issues
#287–#291 (tracked under #282) define four distinct production provider surfaces:

- Azure Key Vault remote signing (#287)
- Azure Key Vault cached signing (#288)
- Windows Certificate Store (#289)
- macOS Keychain (#290)
- Linux OS-level signing, file-based PEM and optionally PKCS#11 (#291)

Two packaging questions must be resolved before any of these providers can be implemented:

1. **Does the development provider move to its own package, or stay in the existing packages?**
   `DevelopmentJwtSigningService` and its supporting types currently live in `ZeeKayDa.Auth` and
   `ZeeKayDa.Auth.AspNetCore`. Extracting them would be consistent with a "one provider, one
   package" rule; leaving them in is consistent with treating them as part of the core getting-
   started experience.

2. **Do all production providers ship in a single package, or does each get its own package?**
   A single consolidated `ZeeKayDa.Auth.Providers` package is simpler to publish; separate
   per-platform packages are leaner for consumers but add publishing and maintenance overhead.

The decision has lasting consequences. NuGet package identity is a SemVer commitment. Moving types
across packages later is a breaking change: existing consumers would need to update their package
references, and any transitive dependency that pins to the old package identity would be broken.
The shape decided here is effectively permanent for the v1 lifecycle.

### Constraints

- **ADR 0001 §3** establishes the strict core / AspNetCore boundary: `ZeeKayDa.Auth` contains no
  ASP.NET Core knowledge; `ZeeKayDa.Auth.AspNetCore` is the hosting adapter. Any new package must
  respect or extend this layering model.
- **ADR 0011 §3.6** establishes the `AddXxx()` on `ZeeKayDaAuthBuilder` registration idiom.
  Every signing provider must register as a singleton `IJwtSigningService` through this pattern.
- **ADR 0008** established the lesson that empty options classes and surface with no behaviour are
  an anti-pattern. A package that exists on NuGet but contains no meaningful type is the same
  mistake at the packaging level.
- Consumer deployments are typically single-platform: a Windows-only deployment has no need for
  the macOS Keychain; a Linux container has no need for Windows Certificate Store assemblies. A
  cloud deployment requiring Azure Key Vault has no architectural reason to carry platform-specific
  OS store libraries.
- Each provider has a distinct set of transitive dependencies: the Azure Key Vault providers depend
  on `Azure.Security.KeyVault.Keys` and `Azure.Identity`; the Windows provider depends on BCL
  Windows-only types; the macOS provider depends on Security framework interop; the Linux provider
  may depend on a PKCS#11 interop library. Shipping these in a single consolidated package would
  force every consumer to carry every cloud and platform SDK, regardless of which provider they
  actually use.

---

## Decision

### 1. Development provider stays in the existing packages, with internal type renames

`DevelopmentJwtSigningService` and its supporting public types (`DevelopmentSigningKeyOptions`,
`DevelopmentSigningKeyWarningService`) remain in `ZeeKayDa.Auth` and `ZeeKayDa.Auth.AspNetCore`.
They are not extracted to a separate package.

Two internal types were renamed in PR #286 to make their development-only scope explicit in code,
matching the "Development" prefix convention already established on the public types:

- `ISigningKeyFileSystem` → `IDevelopmentSigningKeyFileSystem`
- `OsSigningKeyFileSystem` → `LocalSigningKeyFileSystem`

These are `internal` types with no public surface impact. The renames are code-clarity changes, not
breaking changes.

**Rationale.** The development provider is deliberately part of the getting-started path — it is
the first signing registration a new adopter encounters ("one line to get started"). Extracting it
to a separate package would add a package reference to the minimal getting-started story, creating
friction precisely where the library should be frictionless. The development provider also carries
no platform-specific dependencies and no transitive cost for consumers who are already referencing
`ZeeKayDa.Auth.AspNetCore`. The reasons that motivate separate packages for production providers
(transitive dependency isolation, platform-specific assemblies, independent versioning) do not
apply here: the development provider is explicitly not a production key store, has no external
dependencies beyond the BCL, and is meant to be used universally in local development regardless of
the production platform the consumer ultimately targets.

### 2. Each production provider platform ships as its own NuGet package

| Package | Providers |
|---|---|
| `ZeeKayDa.Auth.AzureKeyVault` | `AddAzureKeyVaultRemoteSigning(...)` (#287) and `AddAzureKeyVaultCachedSigning(...)` (#288) |
| `ZeeKayDa.Auth.Windows` | `AddWindowsCertificateStoreSigning(...)` (#289) |
| ~~`ZeeKayDa.Auth.MacOS`~~ | ~~`AddMacOsKeychainSigning(...)` (#290)~~ — **cancelled, will not ship; see Amendment 1** |
| ~~`ZeeKayDa.Auth.Linux`~~ → `ZeeKayDa.Auth.FileSystem` | `AddPemFileSigning(...)` and `AddPfxFileSigning(...)` (#291) — ~~and optionally a PKCS#11 extension~~ (PKCS#11 descoped to its own future issue); **renamed and rescoped, see Amendment 2** |

Both Azure Key Vault variants live in a single package (`ZeeKayDa.Auth.AzureKeyVault`) because
they share the same external dependency (`Azure.Security.KeyVault.Keys`, `Azure.Identity`) and the
same operational context — consumers choosing between remote and cached signing are already
committed to Azure Key Vault as their key store. Splitting them into two packages would require a
consumer to swap package references rather than simply switch the extension method call, which is
the wrong unit of configuration at that decision point. The two variants do represent different
security postures: remote signing (#287) never exports private key material from Key Vault (every
sign operation is a network call), while cached signing (#288) fetches key material and holds it
in process memory for a configurable `RefreshInterval` in exchange for reduced latency. Consumers
should choose between them based on their threat model, not their package management.

The three OS-level providers are each in their own package because their dependencies,
assemblies, and applicable deployment targets are entirely disjoint. A Windows deployment does not
reference the macOS or Linux package; a Linux container does not reference the Windows or macOS
package. Platform-specific packages may also carry platform-specific CI requirements (Windows-only
runners for the Certificate Store tests, macOS runners for Keychain tests) that are isolated within
the relevant package project.

Each OS-level package targets the platform-specific TFM (`net10.0-windows`, `net10.0-macos`,
`net10.0-linux`). NuGet rejects the reference at restore time if the consuming project's TFM does
not match, producing a build-time failure rather than a runtime surprise. A portable project has
no business depending on a platform-specific signing store.

`ZeeKayDa.Auth.Linux` bundles two distinct signing approaches. The production PEM file provider
(`AddPemFileSigning`) keeps private key material on disk and inherits the full filesystem-hardening
requirements from ADR 0011 §2 (0600 permissions, ownership checks, symlink rejection, fail-closed
on broad permissions) — it is not a development shortcut. The optional PKCS#11 extension routes
signing through a hardware or software token via a native interop library, which is a separate
attack surface from the PEM provider. That surface and its dependencies will be specified in full
in issue #291.

### 3. Common structure for all provider packages

Every provider package follows the same pattern:

- **References:** `ZeeKayDa.Auth` (core) only. `ZeeKayDaAuthBuilder` — the entry point for all
  `Add<Provider>Signing()` extension methods — lives in `ZeeKayDa.Auth`. Provider packages do not
  need to depend on `ZeeKayDa.Auth.AspNetCore`. This preserves the ADR 0001 layering model and
  keeps non-web hosts viable as a future target. (`ZeeKayDaAuthBuilder` was moved to
  `ZeeKayDa.Auth` as a precondition for the first provider package; see PR #297.)
- **Public API:** one or more `ZeeKayDaAuthBuilder` extension methods — the provider's entire
  consumer-visible surface. The naming convention is `Add<Provider>Signing(...)`. Any options type
  passed to consumers via an `Action<TOptions>` configure callback is also `public` and forms part
  of the stable SemVer contract per ADR 0011 §3.4.
- **Internal implementation:** all concrete implementation types (the `JwtSigningService<TOptions>`
  subclass and any platform interop helpers) are `internal`. This prevents accidental construction
  outside of the intended DI wiring and keeps the SemVer surface minimal. It is not a security
  control: the actual key-strength, algorithm, and curve-pairing invariants are enforced by the
  public base class (`JwtSigningService<TOptions>`) and hold regardless of visibility modifiers.
- **Registration:** each extension method follows the ADR 0011 §3.6 pattern — registers
  `IJwtSigningService` as a singleton and calls `builder.ThrowIfAlreadyRegistered(...)`.

This keeps every provider package's public surface minimal and SemVer-stable: the only contract a
consumer takes on is the extension method signature and any options type it exposes.

---

## Consequences

### Positive

- **Consumers carry no transitive dependencies for platforms they don't use.** A Linux container
  referencing only `ZeeKayDa.Auth.Linux` does not pull in the Azure SDK or Windows Certificate
  Store bindings. A Windows-only deployment does not carry macOS Keychain interop assemblies.
- **Packages can version independently.** A bug fix in the Azure Key Vault provider does not force
  a new release of the Windows or Linux provider. A platform-specific security patch can ship as
  a point release of the affected package only.
- **Platform-specific CI is scoped to the relevant package.** The Windows Certificate Store
  integration tests run only on Windows CI agents, and that requirement is expressed in the project
  for `ZeeKayDa.Auth.Windows` only — it does not affect CI for the other packages.
- **Getting started stays frictionless.** A new adopter who references `ZeeKayDa.Auth.AspNetCore`
  gets `AddDevelopmentJwtSigningKeys()` with no additional package reference. The one-line getting-
  started experience is intact.
- **Minimal public surface per package.** Each package's public contract is one or two extension
  method signatures plus any options type. There is nothing for a consumer to misconfigure at the
  type level; all decision-making happens through the registration call.
- **Key-strength and algorithm enforcement survives the package split.** `JwtSigningService<TOptions>`
  calls `ValidateKeySet` on every `LoadKeysAsync` result, enforcing the RSA ≥ 2048-bit floor, the
  NIST-curve allowlist, and alg/curve pairing unconditionally. A provider package that implements
  only `LoadKeysAsync` inherits these checks with no additional effort and no code path to skip them.

### Negative / Trade-offs

- **More packages to publish and maintain.** Four production packages plus the two existing
  packages means six NuGet package identities to manage: CHANGELOG entries, SemVer decisions,
  NuGet publishing workflows, and package signing credentials for each. This is an ongoing
  operational cost for the project maintainer.
- **Integration tests that exercise the full stack must reference multiple packages.** An
  integration test suite that wants to verify end-to-end token issuance with, say, the Azure Key
  Vault provider and the AspNetCore hosting layer must reference `ZeeKayDa.Auth.AzureKeyVault`,
  `ZeeKayDa.Auth.AspNetCore`, and `ZeeKayDa.Auth`. This is the expected cost of separating
  concerns into independent packages and does not affect consumers' production references.
- **The development provider exception must be understood and maintained.** The rule "each provider
  in its own package" has a deliberate exception for the development provider. Future contributors
  must understand why — it is documented here — so the exception is not cargo-culted away in a
  future "tidying" refactor that breaks the getting-started experience.
- **Provider packages must be released when `JwtSigningService<TOptions>` has binary-incompatible
  changes.** Because provider packages subclass `JwtSigningService<TOptions>`, a change to the base
  class that adds an abstract member, alters a method signature, or removes a virtual member is a
  binary-breaking change for all provider packages compiled against the prior version. Additive
  changes (new non-abstract methods, new types, new extension methods) are safe. When a core release
  includes a binary-impacting change to the base class, all provider packages must be updated and
  re-released against the new version before consumers can upgrade core.
- **The development provider's environment gate requires a hosted service runner.** The fail-closed
  environment check (`DevelopmentSigningKeyWarningService`) is an `IHostedService` and only runs
  under a host that starts hosted services. In worker or console hosts the gate never fires.
  `DevelopmentJwtSigningService` mitigates this by enforcing the gate in `LoadKeysAsync` from
  `DevelopmentSigningKeyOptions.EnvironmentName`, which the AspNetCore registration layer populates
  from `IHostEnvironment` via `Configure<IHostEnvironment>`. The hosted service remains as the startup-warning UX layer; the hard fail-closed
  travels with the key material and is independent of host model.
- **Six package identities require NuGet signing and provenance attestations.** Six separately-
  published package identities create six typosquat targets. All packages must be published with
  NuGet repository signing and GitHub Actions provenance attestations so consumers can verify
  publisher identity and build origin. Package IDs should be reserved on NuGet.org before the
  project is publicly announced (see issue tracking NuGet publishing setup).

---

## Amendments

### Amendment 1 — issue #290 descoped (2026-07-10)

**The `ZeeKayDa.Auth.MacOS` package (#290, macOS Keychain provider) is cancelled and will not ship. The per-OS packaging *model* is otherwise unchanged.**

Issue #290 was closed as "not planned" — a fully-implemented, reviewed PR (#323) was closed unmerged and its branch deleted. This was a product-scope decision, not a technical one: the realistic audience for a production macOS-hosted authorization server is too thin to justify permanently carrying native Security.framework P/Invoke. (Recorded in parallel as ADR 0011 Amendment 7.)

Concretely for this ADR:

- **The `ZeeKayDa.Auth.MacOS` row in §2's table is cancelled.** `AddMacOsKeychainSigning(...)` and the `net10.0-macos` package do not exist and will not be published. The macOS-specific CI note in §2 (macOS runners for Keychain tests) and the macOS Keychain interop dependency mentioned in the Context and §2 are moot.
- **The macOS deployment target is now served by the file-based provider (#291).** With no native macOS store package, `ZeeKayDa.Auth` + `AddPemFileSigning`/`AddPfxFileSigning` (#291, cross-platform, in whatever package #291 ultimately publishes under) is the sole recommended signing provider for macOS-hosted deployments, in addition to its existing container/Linux/headless fallback role.
- **The packaging model itself stands unchanged.** The core decision — "each production provider platform ships as its own thin NuGet package, referencing only `ZeeKayDa.Auth` core, with a minimal `Add<Provider>Signing()` public surface" (§2, §3) — remains correct and is still exercised by `ZeeKayDa.Auth.AzureKeyVault` (#287/#288), `ZeeKayDa.Auth.Windows` (#289), and the file-based provider (#291). Only the macOS row is removed. The count of package identities in the Consequences section drops from six to five (the two existing packages, Azure Key Vault, Windows, and the file-based provider); the operational-cost, typosquat, and signing/provenance consequences all scale down accordingly but are otherwise unchanged.

The Context and §2 prose that enumerate #290 / macOS as one of the originally-planned provider surfaces are left intact by convention (they record what this ADR was written against); this amendment supersedes their forward-looking treatment of the macOS package as planned.

### Amendment 2 — issue #291 package identity resolved (2026-07-10)

**The file-based provider (#291) ships as `ZeeKayDa.Auth.FileSystem`, targeting portable `net10.0`. This resolves the open item Amendment 1 left as "in whatever package #291 ultimately publishes under."**

Amendment 1 established that the file-based provider (`AddPemFileSigning`/`AddPfxFileSigning`) is now the sole recommended signing provider for macOS deployments in addition to its original container/headless/Linux role, but deferred its package identity. Two facts are now decided:

- **Package name: `ZeeKayDa.Auth.FileSystem`** (superseding the originally-planned `ZeeKayDa.Auth.Linux`). Every other provider package is named after the mechanism or platform it binds to (`.Windows`, `.AzureKeyVault`), not after "signing" — so `.FileSigning` was rejected as the only candidate carrying that redundant word, and `.FileSystem` names the mechanism (files on disk) consistently with that convention. `.Linux` is wrong because the provider is cross-platform. `.Local` was considered and rejected: it would collide with the existing local-development signing provider (`AddDevelopmentJwtSigningKeys`, referred to throughout ADR 0011 as "the local-dev provider"), an unrelated dev-only feature already living in core.
- **TFM: portable `net10.0`**, not an OS-specific TFM. §2 requires each *OS-level* package to target a platform-specific TFM (`net10.0-windows`, etc.) precisely so NuGet rejects a portable reference to an interop-bound package at restore time. That rule exists to protect interop-bound packages; the file-based provider has no interop — `X509Certificate2.CreateFromPem` and `X509CertificateLoader` are portable BCL APIs. Gating it to one OS's TFM would be actively wrong: a portable consumer (a Linux container, a macOS host) must be able to reference it. `ZeeKayDa.Auth.FileSystem` is therefore the one production provider package that correctly targets portable `net10.0`.

Concretely for this ADR:

- **§2's `ZeeKayDa.Auth.Linux` table row is renamed to `ZeeKayDa.Auth.FileSystem` and rescoped.** Its public surface is `AddPemFileSigning(...)` and `AddPfxFileSigning(...)` (both #291).
- **PKCS#11 / HSM support is descoped from #291 and is not part of this package.** The Context enumeration ("file-based PEM and optionally PKCS#11", and the "Linux provider may depend on a PKCS#11 interop library" dependency note) and the §2 prose describing `ZeeKayDa.Auth.Linux` as bundling a PEM provider plus "an optional PKCS#11 extension" are superseded. PKCS#11 was explicitly moved out of #291's scope — it talks to a hardware- or network-backed token rather than reading a flat file, architecturally closer to Key Vault remote signing (#288) than to a file loader — and, if wanted, will be filed as its own future issue against the #282 provider list. `ZeeKayDa.Auth.FileSystem` ships only the PEM and PFX file loaders.
- **The platform-specific-TFM rule in §2 stands, but does not apply to this package.** It governs OS-level, interop-bound packages (`ZeeKayDa.Auth.Windows`); `ZeeKayDa.Auth.FileSystem` is portable by construction.
- **The five-package count from Amendment 1 is unchanged** — this amendment only names and scopes the fifth package (the two existing packages, Azure Key Vault, Windows, and now `ZeeKayDa.Auth.FileSystem`).

Amendment 1's forward-reference to "whatever package #291 ultimately publishes under" is resolved here: the package is `ZeeKayDa.Auth.FileSystem`. Per the convention Amendment 1 set for itself, its text is left intact as a record of what was known at the time.

### Amendment 3 — first-party internal-sharing exception via InternalsVisibleTo (2026-07-10)

**`ZeeKayDa.Auth` core grants `[assembly: InternalsVisibleTo("ZeeKayDa.Auth.FileSystem")]` so the file-based provider can reuse core's `internal` `stat()`/`lstat()` P/Invoke rather than duplicating it. This is the first time a provider package reaches into core internals via IVT instead of consuming only core's public surface — and it is a deliberately scoped exception, not a new general rule.**

§3 states that every provider package "References `ZeeKayDa.Auth` (core) only" and takes on nothing beyond core's public contract (`JwtSigningService<TOptions>`, and — since PR #319/#320 — `SigningKeyRotation` and `SigningKeyDescriptorFactory`). `ZeeKayDa.Auth.FileSystem` is the first provider to also depend on a core *internal*: `ZeeKayDa.Auth.Tokens.PosixInterop.GetLinkOwnerUid` (`lstat()`) and `GetOwnerUid` (`stat()`), declared `internal` in `src/ZeeKayDa.Auth/Tokens/LocalSigningKeyFileSystem.cs`. The provider uses `GetLinkOwnerUid` in `FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix` to apply the same root-owned-directory trust anchor to its own symlink-ancestor validation that core already applies to the development key file. The IVT grant in `src/ZeeKayDa.Auth/ZeeKayDaAuth.cs` is what makes that reuse possible.

Three options were considered:

- **(a) Promote `PosixInterop` to `public`.** Rejected. §3 already states that platform interop helpers are `internal` precisely to keep the SemVer surface minimal, and promoting it would commit ZeeKayDa to a SemVer-stable *public* interop contract — including the hand-computed, per-architecture `struct stat` layouts (macOS/BSD, Linux x64, Linux arm64) and their exact ABI-order fields and padding. That is a large, fragile, platform-coupled surface to freeze into the public contract for the benefit of exactly one first-party consumer, and it would invite third-party callers to bind to interop internals that were never designed as a consumer API.
- **(b) Duplicate the P/Invoke in `ZeeKayDa.Auth.FileSystem`.** Rejected. This is security-critical, ABI-fragile code: the `stat()`-vs-`lstat()` distinction (`GetOwnerUid` follows symlinks; `GetLinkOwnerUid` does not) was itself the subject of a security-review-driven fix *on this very PR (#326)*, because `stat()` on an attacker-planted symlink pointing at a root-owned directory would report the wrong owner and defeat the trust check. A second, independently-maintained copy of this code in the provider package would be free to drift out of sync with a future correction to the authoritative copy in core — reintroducing exactly the class of bug the review just closed. One authoritative, already-tested copy is safer than two.
- **(c) Share the one copy via `InternalsVisibleTo` (chosen).** The provider consumes the single, already-tested implementation in core without widening any consumer-visible or SemVer surface. `PosixInterop` stays `internal`; no public type, method, or `struct` layout is added to core's contract; third-party code still cannot see it.

**Why this is an exception and not a template.** This is implementation-detail sharing between core and a *specific first-party provider that ships in lockstep* with core — not a widening of any public/SemVer surface, and not a pattern third-party providers can follow (they cannot obtain an IVT grant into core and must build against the public surface only). The "each provider references core's public surface only" rule of §3 still governs every provider by default; `ZeeKayDa.Auth.FileSystem` is a narrow, reviewed carve-out justified by the specific need to avoid forking security-critical interop.

**Coupling introduced.** A signature change to `PosixInterop.GetLinkOwnerUid`/`GetOwnerUid` in core is now a binary-breaking change for `ZeeKayDa.Auth.FileSystem`, which must be recompiled and re-released against the new core version before consumers can upgrade. This is the *same kind* of binary coupling the Consequences section already accepts for `JwtSigningService<TOptions>` subclassing generally ("Provider packages must be released when `JwtSigningService<TOptions>` has binary-incompatible changes") — the only difference is that the coupled member is `internal` this time rather than public. It adds no new *category* of maintenance obligation, only one more member to the existing binary-compatibility watch-list; because both assemblies ship in lockstep, they are always rebuilt together in practice.

**Not to be cargo-culted.** Mirroring Amendment 1's own caution about the development-provider exception: this IVT grant must not become the default way future providers borrow behaviour from core. Each new `InternalsVisibleTo` into core internals is a deliberate, reviewed decision — justified here by security-critical, ABI-fragile interop that must not be forked — not a habit to be copied into the next provider package because it is convenient. A provider that can meet its needs through core's public surface must do so.

---

## References

- **ADR 0011** — Signing Key Management (establishes `IJwtSigningService`, `JwtSigningService<TOptions>`, `DevelopmentJwtSigningService`, and the `AddXxx()` registration pattern this ADR builds on).
- **ADR 0008** — Authorization Code and Refresh Token Store (establishes the registration idiom, `ThrowIfAlreadyRegistered`, and the empty-options SemVer lesson).
- **ADR 0001** — Endpoint Architecture Pattern (establishes the `ZeeKayDa.Auth` / `ZeeKayDa.Auth.AspNetCore` layering boundary that all provider packages must respect).
- Issue **#282** — Production signing key provider tracking issue.
- Issue **#287** — Azure Key Vault remote signing provider.
- Issue **#288** — Azure Key Vault cached signing provider.
- Issue **#289** — Windows Certificate Store provider.
- Issue **#290** — macOS Keychain provider *(descoped/closed "not planned" 2026-07-10; the `ZeeKayDa.Auth.MacOS` package will not ship — see Amendment 1)*.
- Issue **#291** — file-based PEM/PFX signing key provider (ships as `ZeeKayDa.Auth.FileSystem`, portable `net10.0`, cross-platform; now also the sole recommended provider for macOS deployments; PKCS#11 descoped to its own future issue — see Amendment 2; reuses core's `internal` `PosixInterop` `stat`/`lstat` P/Invoke via `InternalsVisibleTo` — see Amendment 3).
- **PR #326** — implementation of #291; carries the `InternalsVisibleTo("ZeeKayDa.Auth.FileSystem")` grant and the `stat`/`lstat` symlink-trust fix that motivated Amendment 3.
- **PR #319 / #320** — extracted `SigningKeyRotation` and `SigningKeyDescriptorFactory` into core's public surface, referenced by Amendment 3 when describing the public contract provider packages consume.
