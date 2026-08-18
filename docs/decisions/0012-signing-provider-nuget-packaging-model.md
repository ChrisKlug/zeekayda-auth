# ADR 0012 — Signing Provider NuGet Packaging Model

Status: Accepted   ·   Date: 2026-07-02   ·   Issue: #282

## Decision

The local development signing provider (`DevelopmentJwtSigningService` and its public types)
stays in `ZeeKayDa.Auth`/`ZeeKayDa.Auth.AspNetCore` — it is not extracted to its own package. Every
*production* signing provider platform ships as its own thin NuGet package:

| Package | Providers |
|---|---|
| `ZeeKayDa.Auth.AzureKeyVault` | `AddAzureKeyVaultRemoteSigning(...)`, `AddAzureKeyVaultCachedSigning(...)` |
| `ZeeKayDa.Auth.Windows` | `AddWindowsCertificateStoreSigning(...)` (Windows-only TFM) |
| `ZeeKayDa.Auth.FileSystem` | `AddPemFileSigning(...)`, `AddPfxFileSigning(...)` (portable `net10.0` — no OS-specific TFM, since it uses only portable BCL APIs) |

A planned macOS Keychain provider was implemented, reviewed, and then descoped as a product-scope
call — a production ASP.NET Core auth server is not a realistic macOS-hosted workload, and the file
system provider already covers macOS/Linux deployments without native interop. See ADR 0011's
history for the record of that decision.

Both Azure Key Vault variants ship in one package because they share the same dependency
(`Azure.Security.KeyVault.Keys`, `Azure.Identity`) and operational context — a consumer choosing
between remote signing (never exports key material; every sign is a network call) and cached
signing (holds key material in process memory for reduced latency) should switch by changing the
extension method call, not by swapping package references. The OS-level providers each get their
own package because their dependencies, assemblies, and deployment targets are disjoint — a Linux
container has no reason to reference Windows Certificate Store bindings — and an OS-specific TFM
makes NuGet reject a mismatched restore at build time rather than fail at runtime.

Every provider package references `ZeeKayDa.Auth` (core) only — never
`ZeeKayDa.Auth.AspNetCore` — keeping non-web hosts viable and respecting ADR 0001's core/AspNetCore
boundary. Its entire public surface is one or two `Add<Provider>Signing()` extension methods on
`ZeeKayDaAuthBuilder` plus any `configure` options type; the concrete `JwtSigningService<TOptions>`
subclass and any platform interop are `internal`.

```csharp
// Chosen: registration-shape convention every provider package follows.
public static ZeeKayDaAuthBuilder AddPemFileSigning(
    this ZeeKayDaAuthBuilder builder, Action<PemFileSigningOptions>? configure = null)
{
    builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));
    // register IJwtSigningService (singleton) + IValidateOptions<PemFileSigningOptions>
    return builder;
}
```

`ZeeKayDa.Auth.FileSystem` is granted `InternalsVisibleTo` from core so it can reuse core's
`internal` POSIX `stat`/`lstat` P/Invoke for symlink-ownership validation, rather than forking
security-critical, ABI-fragile interop code. This is a narrow, reviewed exception for a first-party
provider that ships in lockstep with core — not a pattern other providers (first- or third-party)
should reach for by default; a provider that can meet its needs through core's public surface must
do so.

## Why

- **Package identity is effectively permanent** once published (a SemVer commitment; moving a type
  across packages later breaks every consumer pinned to the old identity), so the packaging shape
  had to be settled before any production provider shipped.
- **The development provider stays in-package** because it is the first signing registration a new
  adopter hits — extracting it would add a package reference to the minimal getting-started path for
  no benefit, since it has no platform-specific dependency to isolate.
- **Consolidating all production providers into one package was rejected.** It would force every
  consumer to carry every cloud/platform SDK regardless of which provider they actually use — a
  Windows-only deployment would still pull in Azure and macOS/Linux interop assemblies.
- **Extracting the two Azure Key Vault variants into separate packages was rejected** — they share a
  dependency and an operational context; the two-package split would force a package-reference swap
  at the point where a consumer should just be choosing between two extension methods.
- **`InternalsVisibleTo` was tried for the file-system provider's dependency on core's shared
  thumbprint/logging helpers before this ADR, and rejected in favour of a public contract** —
  `InternalsVisibleTo` can only name assemblies known at build time, so it structurally cannot serve
  a genuine third-party provider implementing the same extensibility contract. The fix was making the
  contracts (`JwkThumbprint`, `SigningKeyRotation`, `SigningKeyDescriptorFactory`,
  `ISanitizingLogger<T>`) public in core (see ADR 0011), while keeping ZeeKayDa's own crypto/redaction
  logic internal. The POSIX interop IVT grant above is the one deliberate, reviewed exception to that
  rule, justified by the cost of forking security-critical, platform-ABI-dependent code — duplicating
  it would risk a second, independently-drifting copy of code that already needed a security-review
  fix for a symlink-following bug (`stat()` vs `lstat()`).

## Consequences

- Consumers carry no transitive dependency for a platform/cloud provider they don't use, and
  packages version and release independently — a provider-specific fix doesn't force a release of
  the others.
- Provider packages must be rebuilt and re-released whenever a core release makes a
  binary-incompatible change to `JwtSigningService<TOptions>` (or, for `ZeeKayDa.Auth.FileSystem`
  specifically, to the `internal` POSIX interop it consumes via `InternalsVisibleTo`) — both
  packages ship in lockstep with core in practice, so this is a watch-list item, not a process gap.
- Five separate package identities (two existing packages, Azure Key Vault, Windows, FileSystem) each
  need their own NuGet publishing, signing, and provenance-attestation setup, and each is an
  independent typosquat target — package IDs should be reserved before public announcement.
- The development-provider exception to "one provider, one package" must be understood, not
  cargo-culted away in a future refactor that would reintroduce getting-started friction.
