---
title: "Configure file-based signing"
description: "How to configure a PEM or PFX file as a JWT signing key provider in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 11
---

*Added in Unreleased.*

`AddPemFileSigning(...)` and `AddPfxFileSigning(...)` register a locally-stored PEM or PFX file as
the `IJwtSigningService` for your authorization server. Both are portable, OS-independent BCL
functionality — there is no platform interop, unlike the Windows Certificate Store provider — which
makes this **the recommended signing provider when the production host itself runs macOS** (there
is no native macOS Keychain provider), and the standard choice for containers, headless CI, and
Linux hosts generally.

> 💡 **Tip:** "The production host runs macOS" means the deployed server process itself runs on
> macOS — not "I'm writing code on a Mac." If you're developing locally on any OS, including macOS,
> use [Configure development signing keys](configure-development-signing-keys.md) instead; this
> guide is about production and other non-development hosts.

For the underlying `IJwtSigningService` abstraction and how signing keys reach the JWKS document,
see [Signing keys](../reference/signing-keys.md).

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- NuGet package: `ZeeKayDa.Auth.FileSystem`.
- Decide whether you need PEM or PFX — see [Choosing PEM or PFX](#choosing-pem-or-pfx) below.
- The key file must already exist on disk with the correct permissions before startup (see
  [Filesystem permission hardening](#filesystem-permission-hardening)); neither method creates,
  writes, or narrows permissions on a file for you.

---

## Choosing PEM or PFX

| Situation | Recommended option |
|---|---|
| You control the file's permissions directly (deployed via a config-management tool, mounted secret volume, etc.) and don't need a second layer of defense | PEM — `.AddPemFileSigning(...)` |
| The file might transit through a channel where a bare key would be riskier — for example, copied as part of a deployment artifact — and you want a password as defense in depth beyond filesystem permissions | PFX — `.AddPfxFileSigning(...)` |
| You already have a PKCS#12 bundle from a CA, HSM export, or existing certificate pipeline | PFX — `.AddPfxFileSigning(...)` |
| You only have (or want to manage) a combined cert+key PEM file | PEM — `.AddPemFileSigning(...)` |

Both options load the private key locally, in process, at startup — neither calls out to an
external service. For the JWK wire format the loaded key is exposed as, see
[RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517) and
[RFC 7518 (JSON Web Algorithms)](https://www.rfc-editor.org/rfc/rfc7518).

---

## Option 1 — PEM file

Call `.AddPemFileSigning(path)` with the path to a single file containing both the certificate and
its private key ([RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) PEM blocks):

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning("/etc/zeekayda/signing/tls.pem", algorithm: SigningAlgorithm.RS256);

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

There is no password — the file must contain the unencrypted private key alongside the certificate.

### The algorithm parameter

A certificate's key does not itself declare RS256 vs PS256, or RSA vs EC — so `algorithm` is a
required parameter, not something ZeeKayDa.Auth can infer from the file. Pass the value matching
the key type actually contained in the file:

```csharp
.AddPemFileSigning("/etc/zeekayda/signing/tls.pem", algorithm: SigningAlgorithm.ES256); // an EC key
```

If `algorithm` does not match the certificate's actual key type (for example, `ES256` passed for
an RSA certificate), startup fails validation.

### Separate certificate and private-key files

If your certificate and private key already live in two separate files — the convention used by
Let's Encrypt/certbot (`fullchain.pem` + `privkey.pem`), cert-manager in Kubernetes, and most
corporate PKI tooling — pass the private-key file's path as the `keyPath` parameter instead of
manually concatenating them into a single combined file:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        "/etc/zeekayda/signing/fullchain.pem",
        algorithm: SigningAlgorithm.RS256,
        keyPath: "/etc/zeekayda/signing/privkey.pem");
```

Both files are read independently and each is subject to exactly the same filesystem permission
hardening described in [Filesystem permission hardening](#filesystem-permission-hardening) below —
the private-key file is the one that actually carries sensitive key material, so it gets no less
scrutiny than a combined file would.

Rotation with split files works the same way as the combined-file case, via
`options.AddFile(certPath, keyPath)` — see
[Rotation and restart-to-reload semantics](#rotation-and-restart-to-reload-semantics) below.

---

## Option 2 — PFX file

Call `.AddPfxFileSigning(path, algorithm, passwordSource)` with the path to a PKCS#12 bundle, the
JWS algorithm matching the bundle's key, and a delegate that supplies its password:

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPfxFileSigning(
        "/etc/zeekayda/signing/tls.pfx",
        algorithm: SigningAlgorithm.RS256,
        passwordSource: static (cancellationToken) =>
            ValueTask.FromResult(Environment.GetEnvironmentVariable("ZEEKAYDA_PFX_PASSWORD")
                ?? throw new InvalidOperationException("ZEEKAYDA_PFX_PASSWORD is not set.")));

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

### Why `PasswordSource` is a delegate, not a string

`PasswordSource` is `Func<CancellationToken, ValueTask<string>>`, not a plain `string`, on purpose.
A raw string parameter would put the password inline in application configuration, which conflicts
with keeping key material and secrets out of plain sight. The delegate shape is async and
cancellable, so the password can be sourced from an environment variable, a mounted secret file, or
a remote secret store without blocking a thread — and it deliberately takes no `IServiceProvider`,
so callers are not forced into DI-resolution machinery for what is usually a simple lookup.

> ⚠️ **Warning:** Never hardcode the PFX password as a literal string inside the `configure`
> callback or anywhere else in source. A hardcoded password defeats the entire point of a
> password-protected bundle — anyone with read access to the source (or the compiled assembly, if
> the string ends up embedded) has the password. Source it from an environment variable, a mounted
> secret file, or a secret store at runtime instead.

`PasswordSource` is invoked at most twice per registered file, ever — not on a recurring interval.
The PFX provider reads its registered files exactly once, at startup (see
[Rotation and restart-to-reload semantics](#rotation-and-restart-to-reload-semantics) below): once
to open the bundle and read its public certificate for every registered file, and, only for
whichever file is currently the active signer, a second time to read the private key. If your
password source is slow or remote, cache the value yourself inside the delegate rather than
re-fetching it on every call.

#### Example: reading from an environment variable

```csharp
.AddPfxFileSigning(
    "/etc/zeekayda/signing/tls.pfx",
    algorithm: SigningAlgorithm.RS256,
    passwordSource: static (cancellationToken) =>
        ValueTask.FromResult(Environment.GetEnvironmentVariable("ZEEKAYDA_PFX_PASSWORD")
            ?? throw new InvalidOperationException("ZEEKAYDA_PFX_PASSWORD is not set.")));
```

#### Example: reading from a mounted secret file

A common pattern in Kubernetes or Docker deployments is to mount a secret as a file rather than an
environment variable:

```csharp
.AddPfxFileSigning(
    "/etc/zeekayda/signing/tls.pfx",
    algorithm: SigningAlgorithm.RS256,
    passwordSource: static async (cancellationToken) =>
    {
        var password = await File.ReadAllTextAsync(
            "/run/secrets/zeekayda-pfx-password", cancellationToken);
        return password.Trim();
    });
```

> 💡 **Tip:** The secret-mount path above is itself subject to the same filesystem trust model the
> host provides — mount it read-only and restrict it to the process identity, the same as the key
> file itself.

### The algorithm parameter

As with the PEM provider, `algorithm` is a required parameter and must match the bundle's actual
key type:

```csharp
.AddPfxFileSigning(path, algorithm: SigningAlgorithm.ES256, passwordSource); // an EC key
```

---

## Filesystem permission hardening

Both providers enforce filesystem permissions on every registered file as a real security control,
not a convenience default, applied fail-closed:

- **Unix:** the file must be no more permissive than `0600` (owner read/write only). Any bit
  granting group or other access — read, write, or execute — fails startup.
- **Windows:** the file's ACL must not grant access to `Everyone`, `Users`, or
  `Authenticated Users`.
- No path component — the file itself or any parent directory — may be a symlink. The provider
  walks the whole resolved path and fails startup if it finds one, to prevent an attacker from
  redirecting reads to a different location.

> ⚠️ **Warning:** A broader-than-expected permission is a **hard startup failure**, not a warning.
> ZeeKayDa.Auth throws a `ZeeKayDaConfigurationException` rather than silently loading a file that
> could have been tampered with by another local user.

A distinct, narrower-permission failure mode is the file being correctly locked down but owned by a
*different* identity than the one the application actually runs as (for example, a key file created
by an interactive deployment user but read by a service account). ZeeKayDa.Auth surfaces this too as
a `ZeeKayDaConfigurationException`, naming the resolved process identity when it can be determined,
rather than letting a raw `UnauthorizedAccessException` propagate — grant that identity read access
to the file (`chown`/`chmod` on Unix, `icacls` on Windows) and restart.

Fix a `0600`-violation on Unix with:

```bash
chmod 600 /etc/zeekayda/signing/tls.pem
```

On Windows, use `icacls` to strip inherited access and grant only the process identity:

```powershell
icacls "C:\zeekayda\signing\tls.pfx" /inheritance:r
icacls "C:\zeekayda\signing\tls.pfx" /grant:r "NT AUTHORITY\NETWORK SERVICE:(R)"
```

Replace `NT AUTHORITY\NETWORK SERVICE` with whichever identity actually runs your application pool
or service.

> 💡 **Tip:** These providers only *validate* an existing file's permissions — unlike
> [the development signing key provider](configure-development-signing-keys.md), they never create
> a file or narrow its permissions for you. Set the permissions correctly as part of whatever
> deploys the file (image build, config-management tool, secret-mount configuration), before the
> application ever starts.

Two additional checks are best-effort warnings, not hard failures, because neither the BCL nor
every OS exposes a fully reliable way to answer them: storing the file on a network volume, and a
world-writable parent directory. Treat either warning as a signal to tighten your deployment even
though startup will still succeed.

---

## Rotation and restart-to-reload semantics

Both providers implement ADR 0015's Tier A `KeySetOptions` contract: the complete set of
registered files is fixed at configuration time, and the only thing that ever advances afterward
is the wall clock crossing each certificate's `NotBefore`/`NotAfter`.

Concretely, that means:

- Every registered file is read **exactly once, ever**, at startup. A changed or newly-added file
  is **not** picked up live — adding, removing, or replacing a registered file always requires a
  configuration change and a restart, exactly as with the Windows Certificate Store provider.
  There is no background polling for new files, and no `KeyRotationCheckInterval`-style property
  to configure one.
- Rotation **between already-registered files** still switches the active signer purely from
  elapsed wall-clock time — each file's certificate `NotBefore`/`NotAfter` is compared against
  `now` on every request, with **zero further file I/O** once startup has completed.

Register additional files for rotation via `options.AddFile(...)`. With exactly one registered
file it is the active signer immediately; with two or more, the file whose certificate `NotBefore`
has arrived and is most recent becomes the active signer.

> 💡 **Tip:** Because reads happen only once, at startup, staging a rotated-in file ahead of its
> intended activation time means deploying and restarting *before* that time, not after. Register
> it via `options.AddFile(...)` well ahead of the `NotBefore` you set on it — see
> [Rotate signing keys](rotate-signing-keys.md) for exactly how much lead time that needs.

### `PublicationLead`

Both options types inherit `PublicationLead` (default: 1 hour) from `KeySetOptions`. On this
provider tier `PublicationLead` is **advisory only**, not enforced: you, the operator, own each
file's activation timing directly via its certificate's `NotBefore`, and `PublicationLead` is used
only to decide whether to log a startup warning that a registered file's `NotBefore` is nearer than
`PublicationLead` away — a signal that the file may not have had enough lead time in the JWKS
before it activates.

```csharp
.AddPemFileSigning(
    "/etc/zeekayda/signing/tls-current.pem",
    algorithm: SigningAlgorithm.RS256,
    configure: options =>
    {
        options.PublicationLead = TimeSpan.FromHours(2);
        options.AddFile("/etc/zeekayda/signing/tls-next.pem");
    });
```

> 💡 **Tip:** `PublicationLead` on this tier replaces what an earlier design called
> `AssumedJwksPropagationDelay`. Unlike that earlier design (and unlike Azure Key Vault's
> `SigningKeyActivationDelay`), there is no `KeyRotationCheckInterval`-style poll floor to enforce
> `PublicationLead` against on this tier — there is no poll at all, since every file is read once,
> at startup. See [Rotate signing keys](rotate-signing-keys.md) for the full activation/retirement
> timing model.

### PEM rotation

For combined cert+key files:

```csharp
.AddPemFileSigning(
    "/etc/zeekayda/signing/tls-current.pem",
    algorithm: SigningAlgorithm.RS256,
    configure: options =>
    {
        options.AddFile("/etc/zeekayda/signing/tls-next.pem");
    });
```

For separate certificate/private-key file pairs, `AddFile` accepts a matching `keyPath` parameter:

```csharp
.AddPemFileSigning(
    "/etc/zeekayda/signing/fullchain-current.pem",
    algorithm: SigningAlgorithm.RS256,
    keyPath: "/etc/zeekayda/signing/privkey-current.pem",
    configure: options =>
    {
        options.AddFile(
            "/etc/zeekayda/signing/fullchain-next.pem",
            "/etc/zeekayda/signing/privkey-next.pem");
    });
```

A rotated-in split file pair does not need to match the primary registration's shape — you can mix
a combined primary file with a split additional file (via `options.AddFile(certPath, keyPath)`), or
the reverse, since each registered file's shape is independent.

### PFX rotation

Each PFX file may have its own password, since real-world PFX bundles are frequently
password-per-file:

```csharp
.AddPfxFileSigning(
    "/etc/zeekayda/signing/tls-current.pfx",
    passwordSource: static (ct) => ValueTask.FromResult(
        Environment.GetEnvironmentVariable("ZEEKAYDA_PFX_PASSWORD_CURRENT")!),
    options =>
    {
        options.AddFile(
            "/etc/zeekayda/signing/tls-next.pfx",
            passwordSource: static (ct) => ValueTask.FromResult(
                Environment.GetEnvironmentVariable("ZEEKAYDA_PFX_PASSWORD_NEXT")!));
    });
```

For the full activation/retirement timing model — how `NotBefore` anchors when a rotated-in key
becomes active, why you need lead time before it does, and the operator's responsibility for
scheduling that lead time against relying parties' JWKS cache TTLs — see
[Rotate signing keys](rotate-signing-keys.md).

---

## Least-privilege reads: public metadata once, private keys only for the active file

Startup reads every registered file's *public* certificate to build the provider's key listing,
but reads a file's *private* key only for whichever file is currently the active signer — and only
once, at startup. A not-yet-active or retired file's private key material is never read at all
while it holds that status.

> ⚠️ **Warning:** This is a provider-level obligation, not a structural guarantee of the underlying
> contract — both PEM and PFX are bundled formats, so parsing a file at all necessarily has access
> to its private key. Both providers are written to defer extracting that private key until the
> file is actually selected as active, and to never retain it otherwise, but a hand-written custom
> provider over a bundled format must apply the same discipline itself; see
> [Implement a custom signing provider](implement-custom-signing-provider.md).

Because every registered file is read only once, there is no ongoing modification-time check, no
change-detection tuple, and no `PasswordSource` re-invocation on a timer — all of the machinery a
provider that re-reads on a cadence (Azure Key Vault) needs to avoid redundant reloads simply does
not apply here, because there is no reload to avoid. See
[Rotation and restart-to-reload semantics](#rotation-and-restart-to-reload-semantics) above for
what *does* still change at runtime (purely wall-clock-driven active-signer selection) versus what
requires a restart (anything about which files are registered).

---

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`, and how keys are exposed as a JWKS document
- [Rotate signing keys](rotate-signing-keys.md) — the activation/retirement timing model and lead-time responsibilities
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md) — the Windows-native alternative
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) — the cloud-managed alternative
- [Configure development signing keys](configure-development-signing-keys.md) — not for production use

For the JWK wire format the loaded key is exposed as, see
[RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517). For the JWS/JWA algorithm
identifiers `Algorithm` accepts, see
[RFC 7518 (JSON Web Algorithms)](https://www.rfc-editor.org/rfc/rfc7518).
