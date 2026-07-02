# ADR 0012 — Signing Provider NuGet Packaging Model

**Status:** Proposed  
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
- **ADR 0011 §3.6** establishes the `AddXxx()` on `IZeeKayDaAuthBuilder` registration idiom.
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

Two internal types are renamed to make their development-only scope explicit in code, matching the
"Development" prefix convention already established on the public types:

- `ISigningKeyFileSystem` → `IDevelopmentSigningKeyFileSystem`
- `OsSigningKeyFileSystem` → `OsDevelopmentSigningKeyFileSystem`

These are `internal` types with no public surface impact. The rename is a code-clarity change, not
a breaking change.

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
| `ZeeKayDa.Auth.MacOS` | `AddMacOsKeychainSigning(...)` (#290) |
| `ZeeKayDa.Auth.Linux` | `AddPemFileSigning(...)` and optionally a PKCS#11 extension (#291) |

Both Azure Key Vault variants live in a single package (`ZeeKayDa.Auth.AzureKeyVault`) because
they share the same external dependency (`Azure.Security.KeyVault.Keys`, `Azure.Identity`) and the
same operational context — consumers choosing between remote and cached signing are already
committed to Azure Key Vault as their key store. Splitting them into two packages would require a
consumer to swap package references rather than simply switch the extension method call, which is
the wrong unit of configuration at that decision point.

The three OS-level providers are each in their own package because their dependencies,
assemblies, and applicable deployment targets are entirely disjoint. A Windows deployment does not
reference the macOS or Linux package; a Linux container does not reference the Windows or macOS
package. Platform-specific packages may also carry platform-specific CI requirements (Windows-only
runners for the Certificate Store tests, macOS runners for Keychain tests) that are isolated within
the relevant package project.

### 3. Common structure for all provider packages

Every provider package follows the same pattern:

- **References:** `ZeeKayDa.Auth` (core) and `ZeeKayDa.Auth.AspNetCore` as package dependencies.
- **Public API:** one or more `IZeeKayDaAuthBuilder` extension methods — the provider's entire
  public surface. The naming convention is `Add<Provider>Signing(...)`.
- **Internal implementation:** all concrete types (the `JwtSigningService<TOptions>` subclass,
  options validators, any platform interop helpers) are `internal`. No public types beyond the
  extension method(s).
- **Registration:** each extension method follows the ADR 0011 §3.6 pattern — registers
  `IJwtSigningService` as a singleton and calls `builder.ThrowIfAlreadyRegistered(...)`.

This keeps every provider package's public surface minimal and SemVer-stable: the only contract a
consumer takes on is the extension method signature.

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
  method signatures. There is nothing for a consumer to misconfigure at the type level; all
  decision-making happens through the registration call.

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

---

## References

- **ADR 0011** — Signing Key Management (establishes `IJwtSigningService`, `JwtSigningService<TOptions>`, `DevelopmentJwtSigningService`, and the `AddXxx()` registration pattern this ADR builds on).
- **ADR 0008** — Authorization Code and Refresh Token Store (establishes the registration idiom, `ThrowIfAlreadyRegistered`, and the empty-options SemVer lesson).
- **ADR 0001** — Endpoint Architecture Pattern (establishes the `ZeeKayDa.Auth` / `ZeeKayDa.Auth.AspNetCore` layering boundary that all provider packages must respect).
- Issue **#282** — Production signing key provider tracking issue.
- Issue **#287** — Azure Key Vault remote signing provider.
- Issue **#288** — Azure Key Vault cached signing provider.
- Issue **#289** — Windows Certificate Store provider.
- Issue **#290** — macOS Keychain provider.
- Issue **#291** — Linux OS-level signing key provider.
