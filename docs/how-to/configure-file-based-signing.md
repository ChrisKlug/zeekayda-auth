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
corporate PKI tooling — call the `.AddPemFileSigning(certPath, keyPath, algorithm)` overload
instead of manually concatenating them into a single combined file:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        "/etc/zeekayda/signing/fullchain.pem",
        "/etc/zeekayda/signing/privkey.pem",
        algorithm: SigningAlgorithm.RS256);
```

Both files are read independently and each is subject to exactly the same filesystem permission
hardening described in [Filesystem permission hardening](#filesystem-permission-hardening) below —
the private-key file is the one that actually carries sensitive key material, so it gets no less
scrutiny than a combined file would.

Rotation with split files works the same way as the combined-file case, via
`options.AddFile(certPath, keyPath)` — see [Rotation](#rotation) below.

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

`PasswordSource` is invoked every time `LoadKeysAsync` actually runs: at startup, and again
whenever a later `KeySourceRefreshInterval` tick detects that something changed (see
[Unchanged files are never re-read on a refresh poll](#unchanged-files-are-never-re-read-on-a-refresh-poll)
below). An unchanged tick never invokes `LoadKeysAsync` at all, so `PasswordSource` is not called on
every refresh interval — only when a reload actually happens. If your password source is slow or
remote, cache the value yourself inside the delegate rather than re-fetching it every time it's
called.

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

## Rotation

Rotation is **config-fixed, not live**: adding a file to the provider requires a configuration
change and a restart, exactly as with the Windows Certificate Store provider. There is no
background polling for new files.

Register additional files for rotation via `options.AddFile(...)`. With exactly one registered
file it is the active signer immediately; with two or more, the file whose certificate `NotBefore`
has arrived and is most recent becomes the active signer.

### PEM rotation

For combined cert+key files:

```csharp
.AddPemFileSigning("/etc/zeekayda/signing/tls-current.pem", options =>
{
    options.AddFile("/etc/zeekayda/signing/tls-next.pem");
});
```

For separate certificate/private-key file pairs, `AddFile` has a matching two-path overload:

```csharp
.AddPemFileSigning(
    "/etc/zeekayda/signing/fullchain-current.pem",
    "/etc/zeekayda/signing/privkey-current.pem",
    algorithm: SigningAlgorithm.RS256,
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

## Unchanged files are never re-read on a refresh poll

Both providers check for a change on every `KeySourceRefreshInterval` tick, but that check never
re-reads or re-parses a registered file unless something has actually changed. Three things are
checked, cheapest first:

1. **The registered path set** — has a path been added to or removed from configuration since the
   last load? Checked first, with no filesystem access at all.
2. **Each remaining path's file modification time** (`File.GetLastWriteTimeUtc`) — a single stat
   call per registered file, never a content read, compared against the timestamp recorded the last
   time that file was actually loaded.
3. **Elapsed time alone** — even with zero file changes, a registered certificate can move into or
   out of its retirement window purely because time has passed. This is recomputed from the
   `NotBefore`/`NotAfter` metadata already recorded at the last load, not by re-parsing the file.

> 💡 **Tip:** For a split certificate/private-key registration, **either** file's modification time
> changing counts as that registered entry changing — not just the certificate file's. This matters
> for tools like cert-manager, which commonly rotate `privkey.pem` and `fullchain.pem` at slightly
> different moments (or, less commonly, only one of the two) rather than as a single atomic write.

Only when one of these three actually indicates a change does the provider re-read and re-parse the
file (and, for the PFX provider, re-invoke `PasswordSource`). This mirrors the same
skip-on-unchanged behavior already shipped for the Azure Key Vault and Windows Certificate Store
providers — see [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) and
[Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md).

> 💡 **Tip:** A file's modification time is not a strong integrity signal the way a certificate
> thumbprint is — two different files can coincidentally share an mtime after a filesystem
> clock-resolution collision. That's not a problem here: mtime is used only to decide whether to
> re-read a file, never as a substitute for the algorithm/key-type and minimum-key-strength
> validation the provider already performs on every real load. In the rare case of a false
> "unchanged" verdict, the worst outcome is that an actual rotation is picked up one refresh
> interval later than it otherwise would have been — not a weakened signature or trust guarantee.

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
