---
title: "Configure Windows Certificate Store signing"
description: "How to configure the Windows Certificate Store as a JWT signing key provider in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 10
---

*Added in Unreleased.*

The `ZeeKayDa.Auth.Windows` package lets ZeeKayDa.Auth sign ID tokens using a certificate's private key stored in a Windows Certificate Store, identified by thumbprint. The certificate is loaded at startup and signing happens locally, in process — no external round trip is made to sign a token.

For the full options and validation rules, see [Signing keys reference](../reference/signing-keys.md).

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- Your host runs on Windows, and the process identity that will run it (an IIS App Pool identity, a Windows Service account, etc.) is known ahead of time — you will need to grant it private key access.
- You have already imported a signing certificate (RSA or EC, with its private key) into a certificate store on the host, and you know its thumbprint.

> ⚠️ **Warning:** `AddWindowsCertificateStoreSigning(...)` throws `PlatformNotSupportedException` immediately when called on a non-Windows OS — before any argument validation runs. `ZeeKayDa.Auth.Windows` also targets a Windows-specific target framework, so a non-Windows project cannot even restore a project reference to it; this is enforced at build/NuGet-restore time, not just at runtime. If you need a signing provider that works across operating systems, use [Configure file-based signing](configure-file-based-signing.md) instead.

## Install the package

```bash
dotnet add package ZeeKayDa.Auth.Windows
```

## Locating your certificate's thumbprint

`AddWindowsCertificateStoreSigning` identifies the certificate to sign with by thumbprint, not by subject name or friendly name. You can find it two ways.

### Using the Certificates MMC snap-in (`certmgr.msc`)

1. Run `certmgr.msc` (for the `CurrentUser` store) or `certlm.msc` (for the `LocalMachine` store).
2. Expand **Personal > Certificates**.
3. If the **Thumbprint** column is not visible, right-click the column header and choose **Add/Remove Columns...**, then add **Thumbprint**.
4. Copy the thumbprint value for your signing certificate.

### Using PowerShell

```powershell
# CurrentUser store
Get-ChildItem -Path Cert:\CurrentUser\My | Select-Object Subject, Thumbprint

# LocalMachine store
Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint
```

> 💡 **Tip:** Whichever way you copy the thumbprint, ZeeKayDa.Auth normalizes it internally — embedded whitespace, casing, and the invisible left-to-right mark that some tools paste alongside a thumbprint are all stripped or normalized automatically. You don't need to clean it up by hand before passing it to `AddWindowsCertificateStoreSigning`.

## Choosing a store location and name

`AddWindowsCertificateStoreSigning` takes a `StoreLocation` and a `StoreName`:

- **`StoreLocation`** — `StoreLocation.CurrentUser` or `StoreLocation.LocalMachine`. For a service or IIS-hosted host, `LocalMachine` is the normal choice: the certificate lives in a store the machine manages, rather than one scoped to a specific user profile that may not exist, log on interactively, or persist consistently across deployments.
- **`StoreName`** — `StoreName.My` (the "Personal" store) is the typical choice for a signing certificate with its private key.

## Register the provider

```csharp
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddWindowsCertificateStoreSigning(
        thumbprint: "AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01",
        algorithm: SigningAlgorithm.RS256,
        storeLocation: StoreLocation.LocalMachine,
        storeName: StoreName.My);

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

> ⚠️ **Warning:** `Algorithm` must match the certificate's actual key type — RSA algorithms (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) for an RSA certificate, EC algorithms (`ES256`, `ES384`, `ES512`) for an EC certificate. The certificate itself does not declare which JWS algorithm to use ([RFC 7518, JWA](https://www.rfc-editor.org/rfc/rfc7518)), so a mismatch (for example, an EC certificate configured with `RS256`) is a configuration error, not something ZeeKayDa.Auth infers for you.

## Grant the process identity access to the private key

Loading the certificate itself only requires read access to the store, but **signing** requires the process identity to have permission to *use the private key*. This is the most common real-world gotcha with this provider: the certificate loads without error, but the first signing attempt fails with an access-denied-style error.

> ⚠️ **Warning:** Importing a certificate under your own interactive user account does not grant your App Pool identity, service account, or any other principal access to its private key. You must grant that access explicitly.

To grant access:

- **Using the Certificates MMC snap-in:** locate the certificate under **Personal > Certificates**, right-click it, choose **All Tasks > Manage Private Keys...**, and grant the service account or App Pool identity **Read** permission.
- **Scripted deployments:** grant access to the underlying CNG key container using `icacls` or PowerShell's `Set-Acl` against the key's file under `%ProgramData%\Microsoft\Crypto\Keys` (CNG) or the legacy CAPI key store, or use `certutil -repairstore` to repair key ACLs after an import.

If the private key exists but cannot be accessed by the current process identity, ZeeKayDa.Auth surfaces a configuration error identifying the certificate by thumbprint and pointing back at "Manage Private Keys" / `certutil -repairstore` — so if you see that error at startup, this permission step is the first thing to check.

## Rotation is fixed at startup, not live

Register additional certificates for a planned rotation with `AddCertificate`, from the *same* `StoreLocation`/`StoreName` as the primary:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddWindowsCertificateStoreSigning(
        thumbprint: "AB CD EF 01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF 01",
        algorithm: SigningAlgorithm.RS256,
        storeLocation: StoreLocation.LocalMachine,
        storeName: StoreName.My,
        configure: options =>
        {
            // The incoming certificate for a planned rotation. Its NotBefore should be set far
            // enough in the future that relying parties have had time to poll the updated JWKS
            // before it becomes the active signer.
            options.AddCertificate("11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 11 22 33 44");
        });
```

With exactly one registered certificate, it is the active signer immediately. With two or more registered, the certificate whose `NotBefore` has arrived and is most recent becomes the active signer — the operator's responsibility is to set the new certificate's `NotBefore` far enough in the future to give relying parties time to fetch the updated JWKS before it activates.

> ⚠️ **Warning:** The set of registered thumbprints is fixed at process start — it does not discover new certificates that were added to the store after startup, and it does not notice a certificate that was removed. Adding, removing, or replacing a registered thumbprint requires a host restart. Every `KeySourceRefreshInterval` tick re-evaluates which of those *already-registered* certificates is currently active, based on each one's `NotBefore` and the retirement window — this is pure timestamp comparison against the certificates read at startup, not a re-read of the store. The store itself is only re-read when that evaluation detects the active/included set has actually changed (i.e. around a rotation boundary), not on every tick.

For the full activation and retirement timing model — including how `NotBefore` anchors publish-then-activate rotation — see [Rotate signing keys](rotate-signing-keys.md).

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — full options and validation reference
- [Rotate signing keys](rotate-signing-keys.md) — activation/retirement timing model
- [Configure file-based signing](configure-file-based-signing.md) — a cross-platform alternative when Windows-only deployment is not an option
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) — a managed alternative that does not require local private key material or store ACL management
- [Configure development signing keys](configure-development-signing-keys.md) — for local development, not production
