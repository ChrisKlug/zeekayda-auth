---
title: "Configure Azure Key Vault signing"
description: "How to configure Azure Key Vault as a JWT signing key provider in ZeeKayDa.Auth, remote or cached."
parent: "How-to Guides"
nav_order: 8
---

*Added in Unreleased.*

The `ZeeKayDa.Auth.AzureKeyVault` package registers Azure Key Vault as a JWT signing key provider. It ships **two** distinct registration methods that solve the same problem with different threat models — they are alternatives you choose between, not steps you stack:

- `AddAzureKeyVaultRemoteSigning(...)` — every signature is produced by a live call into Key Vault. The private key never leaves the vault.
- `AddAzureKeyVaultCachedSigning(...)` — the private key is downloaded once at startup and cached in process memory for local, low-latency signing.

Only one `IJwtSigningService` may be registered per application; calling either method a second time, or calling both, throws `InvalidOperationException`.

For the underlying `IJwtSigningService` abstraction and how signing keys reach the JWKS document, see [Signing keys reference](../reference/signing-keys.md).

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- You have an Azure Key Vault (or Managed HSM) provisioned, and you know which registration method you need — see [Choosing between remote and cached signing](#choosing-between-remote-and-cached-signing) below.
- You have a `TokenCredential` your application can authenticate to Key Vault with — see [Credentials](#credentials) below.

## Install the package

```bash
dotnet add package ZeeKayDa.Auth.AzureKeyVault
```

`Azure.Security.KeyVault.Keys`, `Azure.Security.KeyVault.Certificates`, and `Azure.Security.KeyVault.Secrets` come along with this package as dependencies. `Azure.Identity` does **not** — if you want to authenticate with `DefaultAzureCredential` (the typical choice, shown below), add it separately:

```bash
dotnet add package Azure.Identity
```

## Choosing between remote and cached signing

| Priority | Recommended option |
|---|---|
| The private key must never leave the vault/HSM, even temporarily | [Remote signing](#option-1--remote-signing) |
| A compromised host must yield, at most, a temporary signing oracle — not a permanent copy of the key | [Remote signing](#option-1--remote-signing) |
| Your org's key-management policy does not allow an exportable key policy on this certificate | [Remote signing](#option-1--remote-signing) — cached signing is not possible without one |
| Key Vault latency, throughput, or throttling limits are a concern and local, in-process signing is required | [Cached signing](#option-2--cached-signing) |

> ⚠️ **Warning:** The two options have fundamentally different failure modes if the host is compromised. With **remote signing**, an attacker who compromises the host only gains a signing oracle for as long as the compromise persists — the private key itself is never present to steal. With **cached signing**, an attacker who achieves process memory read gets a permanent copy of the signing key, usable indefinitely and from anywhere, even after the compromise is remediated. See [Option 1](#option-1--remote-signing) and [Option 2](#option-2--cached-signing) below before choosing.

---

## Option 1 — Remote signing

`AddAzureKeyVaultRemoteSigning` takes a `KeyVaultKeyIdentifier` — a Key Vault **key**, not a certificate — plus a `TokenCredential`. Signing is performed remotely inside Key Vault; the private key never leaves the vault and is never held in process memory.

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

var keyIdentifier = new KeyVaultKeyIdentifier(
    new Uri("https://my-vault.vault.azure.net/keys/token-signing-key"));

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddAzureKeyVaultRemoteSigning(
        keyIdentifier,
        algorithm: SigningAlgorithm.RS256,
        credential: new DefaultAzureCredential());

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

> ⚠️ **Warning:** `Algorithm` must match the key's actual type — RSA algorithms (`RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`) for an RSA/RSA-HSM key, EC algorithms (`ES256`, `ES384`, `ES512`) for an EC/EC-HSM key. A Key Vault key does not itself declare which JWS algorithm to use ([RFC 7518, JWA](https://www.rfc-editor.org/rfc/rfc7518)), so a mismatch is a configuration error, not something ZeeKayDa.Auth infers for you.

If `keyIdentifier` includes a specific `Version` component, it is ignored — the provider always discovers and rotates through every live version of the key itself.

### Rotation

Rotation is automatic. The provider discovers Key Vault key versions on its own and rotates through them without a restart:

- The very first key version this deployment ever uses activates immediately — there is no prior published JWKS state any relying party could have cached.
- Every subsequent version requires the new Key Vault key version to exist for at least `KeySourceRefreshInterval` before it is expected to sign anything, so a relying party that cached the previous version's JWKS has had a chance to observe the new one. Create rotated-in key versions with at least that much lead time before they need to go live.
- `KeySourceRefreshInterval` (inherited from `JwtSigningServiceOptions`, default 5 minutes) doubles as this publish-then-activate delay, so it must exceed your relying parties' actual JWKS cache TTL. ZeeKayDa.Auth rejects values below a one-minute floor as an almost-certain misconfiguration, but cannot verify that a value above the floor is actually long enough for your specific relying parties.
- If the active (or most recently active) key version reaches its Key Vault `ExpiresOn` with no enabled successor version, key loading **fails closed** — a configuration error, not a silent continuation with an expired key or no key at all. Rotate in a new key version before the active one expires.

> 💡 **Tip:** For the full activation/retirement timing model shared across all signing providers, see [Rotate signing keys](rotate-signing-keys.md).

---

## Option 2 — Cached signing

`AddAzureKeyVaultCachedSigning` takes a `KeyVaultCertificateIdentifier` — a Key Vault **certificate**, not a bare key — plus a `TokenCredential`. The private key is downloaded once at startup and cached in process memory; signing happens locally, with no per-signature round trip to Key Vault.

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

var certificateIdentifier = new KeyVaultCertificateIdentifier(
    new Uri("https://my-vault.vault.azure.net/certificates/token-signing-cert"));

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddAzureKeyVaultCachedSigning(
        certificateIdentifier,
        algorithm: SigningAlgorithm.RS256,
        credential: new DefaultAzureCredential());

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

> ⚠️ **Warning:** `Algorithm` must match the certificate key's actual type — RSA algorithms for an RSA certificate, EC algorithms for an EC certificate ([RFC 7518, JWA](https://www.rfc-editor.org/rfc/rfc7518)). ZeeKayDa.Auth does not infer this from the certificate.

If `certificateIdentifier` includes a specific `Version` component, it is ignored — the provider always discovers and downloads every live certificate version itself.

### Why a certificate, and not a key

Azure Key Vault's `KeyClient.GetKeyAsync` never returns private key material, regardless of a key's exportable flag — key-only access to Key Vault has no path to bring the private key out of the vault. To cache the key locally, this provider instead downloads the **certificate's linked secret**, which only carries the full PFX (including the private key) when the certificate was created with an **exportable key policy**.

> ⚠️ **Warning:** If the certificate was created with a non-exportable key policy, startup fails with a `ZeeKayDaConfigurationException` telling you to either recreate the certificate with an exportable key policy or switch to [remote signing](#option-1--remote-signing) instead. Only mark a certificate's key policy exportable if you actually intend to use cached signing with it — an exportable policy is a real reduction in the guarantees Key Vault otherwise gives you, so apply it deliberately and not as a blanket default across every certificate in the vault.

### Rotation

The bootstrap behavior, publish-then-activate lead time, and fail-closed behavior on an expired active certificate with no enabled successor are identical to [remote signing](#option-1--remote-signing) — see that section for the full explanation.

> ⚠️ **Warning:** Every `KeySourceRefreshInterval` tick, the provider checks Key Vault's certificate-version metadata to see whether the included version set has actually changed; key material is only re-downloaded when it has. On a tick where nothing changed, no certificate content — public or private — is re-fetched. When a change is detected, the active certificate's re-download includes the actual **private** key (via the certificate's linked secret); every other in-window version (published-but-not-yet-active, or still inside its retirement window) only has its **public** key material fetched, never its private key, since it's exposed via the JWKS but never used to sign. Even so, an active-version rotation is more sensitive traffic than remote signing's refresh, which only ever fetches public key information for any version. Don't set `KeySourceRefreshInterval` too low purely out of habit; balance rotation responsiveness against how often the active certificate's private key material moves over the network and is re-materialized in process memory.

An informational log line, emitted once at startup (not on every refresh), records that the private key has been downloaded and is cached in process memory, including the configured certificate identifier. This is logged at `Information`, not `Warning` — it is a deliberate architectural consequence of choosing this provider, not a misconfiguration.

> 💡 **Tip:** For the full activation/retirement timing model shared across all signing providers, see [Rotate signing keys](rotate-signing-keys.md).

---

## Provisioning the Key Vault resource

The sections above cover the .NET side of the registration call. This section covers the other
half: creating the actual key or certificate in Key Vault, and configuring Key Vault's own
auto-rotation for it. Nothing here is ZeeKayDa.Auth-specific — it's standard Key Vault
provisioning — but the choice you make here does interact with how ZeeKayDa.Auth activates
rotated-in versions, so read [Rotation and Key Vault's rotation config](#rotation-and-key-vaults-rotation-config)
below once you've picked a path.

### Bare key or certificate?

The real decision here is not "which ZeeKayDa.Auth provider am I using" — it's what you actually
need out of Key Vault:

| | Bare key | Certificate |
|---|---|---|
| Works with `AddAzureKeyVaultRemoteSigning` | Yes | Yes — point at the certificate's auto-created key |
| Works with `AddAzureKeyVaultCachedSigning` | No | Yes — the only option |
| Setup overhead | Minimal — just a key | Higher — subject name, issuer, possibly a CA relationship |
| Auto-rotation trigger options | Duration only: `timeAfterCreate` / `timeBeforeExpiry` | Duration (`daysBeforeExpiry`) **or** percentage-of-lifetime |
| Exportable key policy | Should be `false` for signing-only use — no legitimate reason to export a key only ever used via the remote Sign API | Must be `true` for cached signing (required for the private-key download to succeed); should be `false` if the certificate is only ever used with remote signing |

A Key Vault **Certificate** always has an addressable **Key** (and Secret) auto-created alongside
it with the same name and version. `AddAzureKeyVaultRemoteSigning` can point at that auto-created
key instead of a standalone bare key, which is a reasonable way to get percentage-of-lifetime
rotation for remote signing too, at the cost of carrying certificate lifecycle overhead (subject
name, issuer) that a pure signing key has no real need for.

`AddAzureKeyVaultCachedSigning`, on the other hand, has no bare-key alternative: `KeyClient.GetKeyAsync`
never returns private key material, exportable or not, under any circumstances — a certificate's
linked secret is the only path Key Vault exposes for retrieving private key material at all, and
only when the certificate's key policy is exportable. See
[Why a certificate, and not a key](#why-a-certificate-and-not-a-key) above.

> ⚠️ **Warning:** Only set a key's or certificate's key policy to exportable if you actually
> intend to use cached signing with it. An exportable policy is a real reduction in the guarantees
> Key Vault otherwise gives you — don't apply it as a blanket default across every key or
> certificate in the vault.

### Setting up a bare key with auto-rotation (remote signing)

Create the key:

```bash
az keyvault key create \
  --vault-name my-vault \
  --name token-signing-key \
  --kty RSA \
  --size 2048
```

Then configure its rotation policy. A Key Vault key's rotation policy is a separate resource from
the key itself (`GET`/`PUT /keys/{key-name}/rotationpolicy`), and only supports duration-based
triggers — there is no percentage-of-lifetime option for a bare key:

```json
{
  "lifetimeActions": [
    {
      "trigger": { "timeAfterCreate": "P18M" },
      "action": { "type": "Rotate" }
    },
    {
      "trigger": { "timeBeforeExpiry": "P30D" },
      "action": { "type": "Notify" }
    }
  ],
  "attributes": { "expiryTime": "P2Y" }
}
```

Save that as `rotation-policy.json` and apply it:

```bash
az keyvault key rotation-policy update \
  --vault-name my-vault \
  --name token-signing-key \
  --value @rotation-policy.json
```

Durations are ISO 8601 (`P18M` = 18 months, `P30D` = 30 days, `P2Y` = 2 years). Each
`lifetimeActions` entry sets exactly one of `timeAfterCreate` or `timeBeforeExpiry` on its
trigger — `Rotate` creates a new key version automatically, `Notify` only emits an Event Grid
notification without rotating. `attributes.expiryTime` sets the expiry Key Vault stamps on the
*new* version each time it rotates. Key Vault enforces a minimum lead time between creation and
expiry for any rotation trigger — **7 days** for a standard Key Vault, **28 days** for Managed
HSM (a higher floor; don't reuse a vault's rotation policy JSON unmodified against an HSM).

The PowerShell equivalent:

```powershell
Set-AzKeyVaultKeyRotationPolicy -VaultName "my-vault" -KeyName "token-signing-key" `
  -ExpiresIn (New-TimeSpan -Days 730) `
  -KeyRotationLifetimeAction @{Action = "Rotate"; TimeAfterCreate = (New-TimeSpan -Days 540)}
```

> 💡 **Tip:** `Set-AzKeyVaultKeyRotationPolicy` only works against a vault; for Managed HSM, use
> the `az keyvault key rotation-policy update` CLI form shown above instead.

### Setting up a certificate with auto-rotation (cached signing, or remote signing against the cert's key)

Fetch and adapt the default policy, or write your own. The important fields for a signing-only
certificate are `key_props.exportable` (only `true` if you're using cached signing) and
`lifetime_actions` (the auto-rotation trigger):

```bash
az keyvault certificate get-default-policy > policy.json
```

Edit `policy.json` so it looks roughly like this — `exportable: true` only if this certificate
will back cached signing:

```json
{
  "issuer": { "name": "Self" },
  "key_props": {
    "exportable": true,
    "kty": "RSA",
    "key_size": 2048,
    "reuse_key": false
  },
  "secret_props": { "contentType": "application/x-pkcs12" },
  "x509_props": {
    "subject": "CN=token-signing-cert",
    "validity_months": 24
  },
  "lifetime_actions": [
    {
      "trigger": { "lifetime_percentage": 80 },
      "action": { "action_type": "AutoRenew" }
    },
    {
      "trigger": { "days_before_expiry": 30 },
      "action": { "action_type": "EmailContacts" }
    }
  ]
}
```

Then create the certificate:

```bash
az keyvault certificate create \
  --vault-name my-vault \
  --name token-signing-cert \
  --policy @policy.json
```

`lifetime_actions` on a certificate policy is where percentage-of-lifetime rotation actually
lives — `lifetime_percentage: 80` with `action_type: AutoRenew` reissues the certificate (new
certificate, secret, and key version, all together) once it's 80% of the way through its
validity period. The only two valid `action_type` values are `AutoRenew` and `EmailContacts` — do
not confuse this with the key rotation policy's `Rotate`/`Notify` action names above; the two
mechanisms are configured differently even though both call themselves "rotation."

> ⚠️ **Warning:** The certificate policy's wire format is **snake_case** throughout (`issuer`,
> `key_props`, `secret_props`, `x509_props`, `lifetime_actions`, `action_type`) — this is what
> `az keyvault certificate create --policy`, `get-default-policy`, and the raw REST API all
> actually expect. Don't confuse this with the key rotation policy above, which is a separate,
> newer, **camelCase** schema (`lifetimeActions`, `timeAfterCreate`, `action.type`). The two
> policies look superficially similar but use different casing conventions and different field
> names for the same concepts — copying one schema's shape into the other's command will fail.

The PowerShell equivalent, setting or updating percentage-of-lifetime auto-renew and an
email-notification trigger on an existing certificate:

```powershell
Set-AzKeyVaultCertificatePolicy -VaultName "my-vault" -Name "token-signing-cert" `
  -RenewAtPercentageLifetime 80 -EmailAtPercentageLifetime 90
```

Only set one of `-RenewAtPercentageLifetime` / `-RenewAtNumberOfDaysBeforeExpiry` (and similarly
for the `-EmailAt...` pair) at a time — they're alternative ways of expressing the same trigger,
not values that combine.

### Rotation and Key Vault's rotation config

Both mechanisms above are proactive: Key Vault runs rotation as a scheduled background job once
the configured trigger is reached, not lazily on next access. Either one works identically with
ZeeKayDa.Auth's own activation timing, because ZeeKayDa.Auth anchors on Key Vault's immutable
per-version `CreatedOn` timestamp regardless of what triggered the new version's creation — see the
"Why Key Vault gets an enforced overlap" tip in
[Rotate signing keys](rotate-signing-keys.md#windows-certificate-store-and-file-based-pempfx--manual-registration)
for the full explanation of `max(CreatedOn + KeySourceRefreshInterval, NotBefore)`.

In practice this means: whichever rotation trigger you configure here (`timeAfterCreate`/
`timeBeforeExpiry` for a bare key, or `lifetimePercentage`/`daysBeforeExpiry` for a certificate)
only decides *when Key Vault creates the new version*. From that point on, ZeeKayDa.Auth's own
publish-then-activate delay — see the "Rotation" section under each option above and
[The model, in plain language](rotate-signing-keys.md#the-model-in-plain-language) — still applies
on top: the new version won't actually become the active signer until it has been visible for at
least `KeySourceRefreshInterval`. Set Key Vault's own rotation trigger with enough lead time
before the certificate's or key's actual expiry that this additional delay never pushes activation
past `ExpiresOn`.

## Required Azure role assignments

Both variants need the application's identity to be able to authenticate to Key Vault, but they need different permissions once authenticated. Configure your vault to use the Azure RBAC permission model (not the legacy access-policy model) and assign one of these built-in roles, scoped as narrowly as possible — ideally to the specific key or certificate, not the whole vault:

- **Remote signing** needs permission to perform cryptographic sign operations against the key. The **Key Vault Crypto User** built-in role grants this (`sign`/`verify` and related crypto actions), or the equivalent access-policy `Sign`/`Get`/`List` permissions if you are still on the legacy model.
- **Cached signing** needs permission to read the certificate's linked secret, since that is how the exportable private key material is retrieved. The **Key Vault Certificate User** built-in role grants this — it includes reading certificate metadata and its linked secret in one role, which is the purpose-built option for this scenario. **Key Vault Secrets User** also works if assigned directly on the underlying secret, but it has no awareness of the certificate object and is a coarser fit.

Both roles only work against vaults using the Azure RBAC permission model. See Microsoft's [Azure Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide) and [Azure built-in roles for Security](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles/security) for the current list of built-in roles and how to assign them.

## Credentials

Both registration methods take a `TokenCredential` from `Azure.Core`. `DefaultAzureCredential` (from the `Azure.Identity` package) is the typical choice for both variants — it tries managed identity, environment variables, and developer credentials (Azure CLI, Visual Studio, etc.) in order, which lets the same code authenticate the same way in a local dev box and in an Azure-hosted production environment:

```csharp
credential: new DefaultAzureCredential()
```

> 💡 **Tip:** In production, prefer a user-assigned or system-assigned **managed identity** over a client secret or certificate credential. `DefaultAzureCredential` picks up a managed identity automatically when running in Azure, with no code change required between environments.

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`, and how keys are exposed as a JWKS document
- [Rotate signing keys](rotate-signing-keys.md) — the activation/retirement timing model shared across all signing providers
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md) — an alternative when you want no cloud dependency and already manage certificates on Windows hosts
- [Configure file-based signing](configure-file-based-signing.md) — a cross-platform PEM/PFX alternative when Key Vault isn't the right fit
- [Configure development signing keys](configure-development-signing-keys.md) — for local development, not production

For the JWK wire format signing keys are exposed as, see [RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517). For the JWS algorithm identifiers referenced above, see [RFC 7518 (JSON Web Algorithms)](https://www.rfc-editor.org/rfc/rfc7518).
