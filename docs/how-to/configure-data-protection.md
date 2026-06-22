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

ZeeKayDa.Auth registers several internal named cookie authentication schemes:

- `zkd.interaction` — carries the authorization interaction context between redirects
- `zkd.pending` — carries the half-authenticated principal during multi-step sign-in
- `zkd.external` — carries the result of an external provider callback
- The SSO session cookie

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

### Store failure: `ZeeKayDaStoreException`

If the default token stores cannot decrypt a stored entry, they treat it as `NotFound`.
Per [ADR 0008 §7](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md#7-failure-modes-and-exception-contract),
the token endpoint returns `error=invalid_grant` to the client. The `ZeeKayDaStoreException`
wraps the underlying Data Protection `CryptographicException` and is visible in logs.

**What to look for:**

- `ZeeKayDaStoreException` entries in your application logs, with an inner
  `CryptographicException` or `KeyNotFoundException` from the Data Protection stack.
- Clients receiving `error=invalid_grant` on token refresh, without any corresponding user
  activity that would explain the rejection.
- The pattern typically appears immediately after a key rotation event or a deployment that
  changed the key ring configuration.

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

---

## Further reading

- [ASP.NET Core Data Protection overview](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction)
- [Key storage providers in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-storage-providers)
- [Key management in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/key-management)
- [Configure ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview)
- [ADR 0008 §4b and §10 — store encryption and key-sharing requirement](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0008-authorization-code-and-refresh-token-store.md)
- [ADR 0005 — authorization-state cookie encryption](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0005-authorization-endpoint-interaction-orchestration.md)
