---
title: "Configure Data Protection for load-balanced deployments"
description: "How to configure shared ASP.NET Core Data Protection keys when running ZeeKayDa.Auth across multiple instances."
parent: "How-to Guides"
nav_order: 6
---

*Added in Unreleased.*

This guide shows how to configure shared ASP.NET Core Data Protection keys when running
ZeeKayDa.Auth on more than one instance — behind a load balancer, on Azure App Service with
scale-out, or in any other multi-instance topology.

For general setup of ZeeKayDa.Auth, see
[Configure ZeeKayDa.Auth](configure-zeekayda-auth.md). For the full options reference,
see [AuthorizationServerOptions reference](../reference/configuration.md).

---

## Why ZeeKayDa.Auth requires shared Data Protection keys

ZeeKayDa.Auth uses ASP.NET Core Data Protection in two distinct places. Both places require
every instance in a deployment to share the same key ring.

### Store entry encryption

The default authorization code and refresh token stores serialize each entry to JSON and
then encrypt the serialised bytes using `IDataProtectionProvider` before writing them to the
backing cache (see
[ADR 0008 §4b](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md#4b-encryption-at-rest)).
Purpose strings used:

- `ZeeKayDa.Auth:AuthorizationCodeStore`
- `ZeeKayDa.Auth:RefreshTokenStore`

If instance A encrypted an entry and instance B attempts to decrypt it, instance B must hold
the same Data Protection key. If it does not, the decrypt fails and the entry is treated as
`NotFound` — which means the refresh token silently stops working and the user is forced to
re-authenticate.

### Authentication-state cookies

ZeeKayDa.Auth registers four internal named cookie authentication schemes:

- `zkd.session` — SSO session cookie, shared across all authentication methods. This is the
  longest-lived of the four cookies: its lifetime is tied to the SSO session rather than to a
  single authorization flow, so a returning user may hold a `zkd.session` cookie that was
  written days or weeks before the current request. A key-ring gap is therefore most visible
  for returning users — their `zkd.session` cookie was encrypted by a key that the new
  instance does not yet hold, forcing a silent re-authentication even though the user
  successfully signed in previously.
- `zkd.interaction` — carries the authorization interaction context between redirects
- `zkd.pending` — carries the half-authenticated principal during multi-step sign-in
- `zkd.external` — carries the result of an external provider callback

These cookies are encrypted by ASP.NET Core's cookie authentication middleware using
`IDataProtectionProvider`. If a user's browser sends a cookie that was written by instance A
to instance B, instance B must be able to decrypt it. A decryption failure causes a silent
re-prompt: the user sees the login page again with no error message, even though their
browser held a valid cookie. This is documented in
[ADR 0005 §"Security Considerations"](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0005-authorization-endpoint-interaction-orchestration.md#security-considerations).

> ⚠️ **Warning:** ZeeKayDa.Auth does not solve distributed key management. It uses whatever
> key ring the host application configures. Failing to configure a shared key ring in a
> multi-instance deployment produces silent correctness failures — not startup errors — that
> are difficult to diagnose in production.

---

## Key retention requirement

> ⚠️ **Warning:** Data Protection keys must be retained for at least the configured
> `AuthorizationServerOptions.TokenEndpoint.RefreshTokenLifetime`. The default is
> **14 days**.
>
> A key that expires before the refresh tokens it protected become unreadable tokens, not a
> clean error. The store treats a failed decrypt as `NotFound` (per
> [ADR 0008 §7](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md#7-failure-modes-and-exception-contract)),
> which means users are silently logged out with no indication that the cause is an expired
> key. The consequence of underestimating retention is not a service error — it is invisible
> user disruption.

Set your key ring expiry and retention window to at least `RefreshTokenLifetime`. If you
raise `RefreshTokenLifetime` above the default, raise the key retention period to match.
The two values must stay in sync.

---

## Key rotation

ASP.NET Core Data Protection rotates keys automatically. Understanding how that rotation
interacts with refresh token lifetimes is important for safe key management.

### How rotation works

Data Protection generates a new default key automatically when the current key nears
expiry. The lead time is configurable via `SetDefaultKeyLifetime` (default is 90 days).
When a new default key is generated, old keys are never deleted — they stay in the ring
and can still decrypt any payload they originally protected. Rotation is therefore
overlapping by design: new encryptions use the new key while tokens encrypted with older
keys continue to decrypt successfully.

This means that at any point, your key ring will contain:

- The current default key — used for all new encryptions.
- One or more older keys — still present and usable for decryption.

### The safe deletion window

Because ASP.NET Core does not auto-delete keys, any cleanup (manual scripts, key store
retention policies) must respect the following constraint:

**An old key must not be removed from the key store until all refresh tokens it
protected have expired.**

The safe deletion window for a key is:

```
safe_to_delete_after = key_expiry_date + RefreshTokenLifetime
```

With defaults (90-day key lifetime, 14-day refresh token lifetime), a key is safe to
delete **104 days after it was created**. Removing a key before that window closes means
some in-flight refresh tokens can no longer be decrypted, which causes the silent
`invalid_grant` failure described in the [failure modes](#failure-modes) section below.

### Shortening the key lifetime

If you call `SetDefaultKeyLifetime(TimeSpan.FromDays(30))` to rotate keys more
frequently, you must ensure your key store retains expired keys for at least
`RefreshTokenLifetime` beyond their expiry date. With a 30-day key lifetime and the
default 14-day refresh token lifetime, the safe deletion window is 44 days from key
creation.

ASP.NET Core does not enforce this automatically. If your deployment uses a cleanup
script or a store with an automatic retention policy, configure that policy to use the
`key_expiry_date + RefreshTokenLifetime` formula, not just `key_expiry_date`.

> ⚠️ **Warning:** Never delete all keys and start fresh while active refresh tokens
> exist. This silently invalidates every in-flight session — all users holding a valid
> refresh token are logged out with no error message and no log entry to explain why.

### The migration gotcha

When migrating key storage — for example, moving from a shared file system to Azure Blob
Storage — you must copy **all** existing keys to the new store before cutover, including
keys that have already expired but whose safe deletion window has not yet closed.

If a key does not make it to the new store, any refresh token it protected will silently
return `NotFound` the first time a request is routed after the cutover. This is the most
dangerous operator error in key management, because the failure is invisible in logs and
only manifests as an elevated `invalid_grant` rate in your token endpoint metrics.

**Checklist before migrating key storage:**

1. Export the full key ring from the old store, including expired keys.
2. Import all exported keys to the new store.
3. Verify the key ring in the new store contains every key from the old store.
4. Cut over.
5. Keep the old store readable (but not writable) for `RefreshTokenLifetime` after
   cutover in case rollback is needed.

---

## Scenario A: Azure Blob Storage and Azure Key Vault (recommended)

Azure Blob Storage stores the key ring XML; Azure Key Vault wraps the key material. This is
the recommended configuration for Azure deployments because keys are encrypted at rest and
in transit without any custom key management.

### NuGet packages

```xml
<PackageReference Include="Azure.Extensions.AspNetCore.DataProtection.Blobs" Version="1.*" />
<PackageReference Include="Azure.Extensions.AspNetCore.DataProtection.Keys" Version="1.*" />
```

### Program.cs

```csharp
using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Shared Data Protection key ring — Azure Blob Storage + Azure Key Vault
var blobServiceClient = new BlobServiceClient(
    new Uri("https://<storage-account>.blob.core.windows.net"),
    new DefaultAzureCredential());

var containerClient = blobServiceClient.GetBlobContainerClient("data-protection-keys");
var blobClient = containerClient.GetBlobClient("keys.xml");

builder.Services
    .AddDataProtection()
    .SetApplicationName("zeekayda-auth")
    .PersistKeysToAzureBlobStorage(blobClient)
    .ProtectKeysWithAzureKeyVault(
        new Uri("https://<key-vault>.vault.azure.net/keys/<key-name>"),
        new DefaultAzureCredential());

// ZeeKayDa.Auth — uses the configured key ring automatically
builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

var app = builder.Build();

app.UseForwardedHeaders();   // required before UseAuthentication in reverse-proxy deployments
app.UseRouting();
app.UseAuthentication();
app.MapZeeKayDaAuth();

app.Run();
```

> 💡 **Tip:** `SetApplicationName` isolates the key ring from other applications sharing
> the same storage account. Use the same value on every instance of the same deployment.
> Different applications must use different names.

> ⚠️ **Warning:** `ProtectKeysWithAzureKeyVault` is the recommended option for encrypting
> keys at rest. Without it, the keys XML file in Blob Storage is written in plaintext.
> Anyone with read access to the container can read the key material and decrypt any
> protected payload — including all stored tokens and auth-state cookies.

For the full API reference, see:
- [`Microsoft.AspNetCore.DataProtection` — Key storage providers](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers)
- [`Azure.Extensions.AspNetCore.DataProtection.Blobs`](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers#azure-storage)

---

## Scenario B: Shared file system

Use `PersistKeysToFileSystem` when all instances share a common mount point — for example,
an NFS share, an Azure Files mount, or a network-attached file system in an on-premises
deployment.

### Program.cs

```csharp
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Shared Data Protection key ring — shared file system
builder.Services
    .AddDataProtection()
    .SetApplicationName("zeekayda-auth")
    .PersistKeysToFileSystem(new DirectoryInfo("/mnt/shared/data-protection-keys"));

// ZeeKayDa.Auth — uses the configured key ring automatically
builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseRouting();
app.UseAuthentication();
app.MapZeeKayDaAuth();

app.Run();
```

### Requirements for the shared path

- The path must be writable by every instance. If any instance cannot write to the directory
  at startup, key generation fails and Data Protection operations fail at runtime.
- The path must resolve to the same underlying storage on every instance. A path that is
  local on each host (e.g. `/var/data-protection-keys`) does not satisfy this requirement
  — it creates a separate key ring per instance.
- The directory should not be writable by other applications unless they are in the same
  application name group.

> ⚠️ **Warning:** `PersistKeysToFileSystem` stores keys in plaintext XML files on disk.
> Anyone with read access to the directory can read the key material. Add a
> `ProtectKeysWith*` call to encrypt key material at rest. For example, use
> `ProtectKeysWithCertificate` to wrap keys with an X.509 certificate stored in the
> certificate store, or use a custom `IXmlEncryptor`. Without this, key confidentiality
> depends entirely on file system permissions.

---

## Scenario C: SQL Server / EF Core

Use `PersistKeysToDbContext` when you already have a SQL Server database shared across
instances. The key ring is stored in a table managed by Entity Framework Core.

### NuGet package

```xml
<PackageReference Include="Microsoft.AspNetCore.DataProtection.EntityFrameworkCore" Version="9.*" />
```

### DbContext requirement

Your `DbContext` must implement `IDataProtectionKeyContext`:

```csharp
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class AppDbContext : DbContext, IDataProtectionKeyContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options) { }

    // Required by IDataProtectionKeyContext
    public DbSet<DataProtectionKey> DataProtectionKeys { get; set; } = null!;
}
```

Apply the EF Core migration to create the `DataProtectionKeys` table before running in
production:

```bash
dotnet ef migrations add AddDataProtectionKeys
dotnet ef database update
```

### Program.cs

```csharp
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// Shared Data Protection key ring — SQL Server via EF Core
builder.Services
    .AddDataProtection()
    .SetApplicationName("zeekayda-auth")
    .PersistKeysToDbContext<AppDbContext>();

// ZeeKayDa.Auth — uses the configured key ring automatically
builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseRouting();
app.UseAuthentication();
app.MapZeeKayDaAuth();

app.Run();
```

> ⚠️ **Warning:** `PersistKeysToDbContext` stores keys as plaintext XML in the database.
> Add `ProtectKeysWithCertificate` or another `IXmlEncryptor` to encrypt key material at
> rest. Without this, database read access is sufficient to read all protected token data
> and auth-state cookies.

> 💡 **Tip:** Keys stored in SQL Server are subject to the same retention requirement as
> other backends. Do not delete rows from the `DataProtectionKeys` table unless you have
> confirmed all tokens they protected have expired or been revoked.

---

## Failure modes

When Data Protection keys are not correctly shared, ZeeKayDa.Auth produces two distinct
symptoms depending on which path fails.

### Store failure: silent `invalid_grant`

If the default token stores cannot decrypt a stored entry, the `CryptographicException`
thrown by `IDataProtector.Unprotect` is **caught and silently discarded**. The store
returns `NotFound` (or `AlreadyRedeemed` for an unreadable authorization code tombstone).
No exception is thrown to the caller, and **no log entry is written**.

Per [ADR 0008 §7](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md#7-failure-modes-and-exception-contract),
a `NotFound` result causes the token endpoint to return `error=invalid_grant` to the
client. `ZeeKayDaStoreException` is reserved for transport-level failures — for example,
an `IDistributedCache` I/O error — not for decryption failures.

The operator-visible symptom is users experiencing silent logout and re-authentication
prompts, with no corresponding exception anywhere in the application logs.

**What to look for:**

- An elevated rate of `error=invalid_grant` responses at the token endpoint, **without**
  any `ZeeKayDaStoreException` in logs to explain them.
- Clients receiving `error=invalid_grant` on token refresh with no corresponding user
  activity that would explain the rejection.
- The pattern typically appears immediately after a key rotation event or a deployment that
  changed the key ring configuration.

> ⚠️ **Warning:** Because the failure is completely silent at the log level, a misconfigured
> or prematurely expired key ring will not produce any application error — only a rise in
> `invalid_grant` responses. Monitor your token endpoint error rate; do not rely on log
> alerts alone to detect this condition.

**Resolution:** Confirm that all instances share the same key ring and that keys are
retained for at least `RefreshTokenLifetime`. If you recently rotated keys, the old keys
must remain in the ring for the duration of the longest-lived refresh token they issued.

### Cookie failure: silent re-prompt

If a cookie written by one instance cannot be decrypted by another, ASP.NET Core's cookie
authentication middleware silently discards the cookie. The user sees the login page again
with no error message, even though their browser held a valid cookie. There is no exception
in logs — the middleware treats an unreadable cookie as absent.

**What to look for:**

- Users reporting unexpected re-authentication prompts, particularly after a deployment or
  scale-out event.
- No `ZeeKayDaStoreException` in logs — the failure is in the cookie layer, not the store.
- The pattern is reproducible when a user's request is routed to a different instance than
  the one that set the cookie (disable sticky sessions temporarily to confirm).

**Resolution:** Same root cause — instances do not share a key ring. Apply one of the
scenarios above. If you cannot confirm which instance wrote which cookie, enabling
temporary sticky sessions while you fix the key ring will stop the re-prompts.

### Startup log level for in-memory store override

If the host uses `AddInMemoryStores()` and is running outside a Development environment
with `AllowInMemoryStoresOutsideDevelopment = true`, ZeeKayDa.Auth emits a startup message
via `InMemoryStoreWarningService` to alert operators that in-memory stores are active. The
log level differs by environment:

| Environment | `AllowInMemoryStoresOutsideDevelopment` | Log level |
|---|---|---|
| Development | n/a | `LogLevel.Warning` |
| Non-Development | `true` | `LogLevel.Critical` |
| Non-Development | `false` (default) | Startup exception (`ZeeKayDaConfigurationException`) |

> ⚠️ **Warning:** When filtering application logs at `Warning` level to monitor for ZeeKayDa
> configuration issues, remember that the in-memory store override message outside Development
> is emitted at `LogLevel.Critical`. A log filter set to `Warning` and above will capture it;
> a filter set to exactly `Warning` (treating `Critical` as a separate category) will not.
> Configure your alerting to include `Critical` events from the `ZeeKayDa.Auth` log category.

---

## Further reading

- [ASP.NET Core Data Protection overview](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction)
- [Key storage providers in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers)
- [Key management in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-management)
- [Configure ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview)
- [ADR 0008 §4b and §10 — store encryption and key-sharing requirement](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md)
- [ADR 0005 — authorization-state cookie encryption](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0005-authorization-endpoint-interaction-orchestration.md)
