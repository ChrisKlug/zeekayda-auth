---
title: "Configure development signing keys"
description: "How to set up local-development JWT signing keys in ZeeKayDa.Auth."
parent: "How-to Guides"
nav_order: 7
---

*Added in Unreleased.*

ZeeKayDa.Auth requires an `IJwtSigningService` to be registered before the application starts.
There are two named registration methods that generate an RSA key locally, so you can run the
authorization server on your machine without provisioning a KMS, HSM, or certificate first:

- `AddInMemoryDevelopmentJwtSigningKeys()` — ephemeral, in-memory key.
- `AddPersistedDevelopmentJwtSigningKeys()` — key persisted to a local file.

For the underlying `IJwtSigningService` abstraction and how signing keys reach the JWKS document,
see [Signing keys](../reference/signing-keys.md).

> ⚠️ **Warning:** Both providers are for local development and testing only. Neither is ever
> suitable for production — see [Not for production](#not-for-production-use) below for what to
> use instead.

## Before you start

- You have a working `AddZeeKayDaAuth(...)` registration. If not, see [Configure ZeeKayDa.Auth](configure-zeekayda-auth.md).
- Decide whether you need tokens to survive a restart. If not, use the zero-config ephemeral
  option. If you do (for example, so a browser session created before lunch still validates after
  you restart the app in the afternoon), use the persisted option.

---

## Option 1 — Ephemeral in-memory key (zero configuration)

Call `.AddInMemoryDevelopmentJwtSigningKeys()` with no arguments to generate a fresh RSA key (at
least 3072 bits) in memory on every startup:

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://localhost:5001";
    })
    .AddInMemoryDevelopmentJwtSigningKeys();

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

The key is never written to disk. Restarting the application generates a brand-new key, so any
tokens issued by the previous process — including access tokens and ID tokens still cached in a
browser or a test client — stop validating immediately.

> 💡 **Tip:** If your local workflow keeps hitting "invalid token" errors after every restart
> (for example, a browser holding onto a JWT across an `dotnet watch` reload), switch to
> [Option 2](#option-2--persisted-key) so the key survives restarts.

---

## Option 2 — Persisted key

Call `.AddPersistedDevelopmentJwtSigningKeys()` to write the RSA key to a local file the first
time it is generated, and load it back on every subsequent startup:

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://localhost:5001";
    })
    .AddPersistedDevelopmentJwtSigningKeys();

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

With no `persistTo` argument (or `persistTo: null`), the key is stored at the default path,
`{ContentRootPath}/.zeekayda/signing-keys/dev-signing-key.pem`. Pass an explicit directory to use
a different location — unlike the in-memory method, `persistTo: null` on this method always means
"persist to the default path," never "don't persist":

```csharp
.AddPersistedDevelopmentJwtSigningKeys(persistTo: "/Users/me/.local/share/zeekayda-dev-keys")
```

The key file itself is always named `dev-signing-key.pem` inside that directory, and it is a
plain, unencrypted PEM — there is no passphrase.

> 💡 **Tip:** If you run more than one ZeeKayDa.Auth-based service locally, point each one at its
> own `persistTo` directory. Sharing a directory across services means they share a signing key,
> which is rarely what you want in a multi-service local setup.

### Permission hardening

> ⚠️ **Warning:** The persisted key file grants access to sign tokens as your authorization
> server. ZeeKayDa.Auth enforces filesystem permissions on it as a real security control, not a
> convenience default:
>
> - The key directory is created with `0700` permissions on Unix (owner read/write/execute only)
>   and a restrictive ACL on Windows (no `Everyone`/`Users` entries, inheritance disabled). The key
>   file is created with `0600` on Unix and the equivalent owner-only ACL on Windows.
> - The file is created with those permissions **atomically**, as part of the create call itself —
>   never by creating it first and then narrowing permissions afterwards, which would leave a
>   window where the key is briefly world-readable.
> - If ZeeKayDa.Auth finds an existing key file with broader permissions than `0600`, it does not
>   silently load it and does not just log a warning: startup fails hard with a
>   `ZeeKayDaConfigurationException`. A key file with loose permissions is treated as
>   potentially compromised.
> - No path component — the key file or any parent directory — is allowed to be a symlink.
>   ZeeKayDa.Auth checks the entire chain and fails startup if it finds one, to prevent an
>   attacker from redirecting reads or writes to a different location.
> - Every directory in the persistence path must be owned by the current user (root-owned system
>   directories are the only exception). If an ancestor directory is owned by someone else,
>   startup fails, because that user could otherwise replace or redirect the directory the key
>   lives in.
>
> If startup fails with one of these errors, delete the offending file or directory and let
> ZeeKayDa.Auth recreate it, or fix its ownership/permissions to match the rules above.

---

## The environment gate

Both methods enforce a hard environment gate at startup. If the host environment is not in the
provider's allowed-environments list — which defaults to `["Development"]` — startup throws a
`ZeeKayDaConfigurationException` and the application does not start. A `Production` environment
name always fails this gate, regardless of what the list contains.

This exists so that an accidental development-key registration can never be silently deployed: it
either runs in a genuinely `Development`-named environment or it refuses to start.

### If your host reports a non-Development environment name

The allowed-environments list is a **public, code-only opt-in** reached through each method's own
`configure` callback — it is a provider-scoped setting, not a property on the shared
`AuthorizationServerOptions` root, because it is inert unless one of the two development-key
methods is actually in use.

For `.AddInMemoryDevelopmentJwtSigningKeys(...)`, configure
`InMemoryDevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments`:

```csharp
using ZeeKayDa.Auth;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://localhost:5001";
    })
    .AddInMemoryDevelopmentJwtSigningKeys(options =>
        options.AllowedDevelopmentJwtSigningKeysEnvironments =
            ["Development", "IntegrationTesting", "CI"]);

var app = builder.Build();
app.MapZeeKayDaAuth();
app.Run();
```

For `.AddPersistedDevelopmentJwtSigningKeys(...)`, the same property lives on
`DevelopmentSigningKeyOptions`, reached through its own `configure` callback:

```csharp
.AddPersistedDevelopmentJwtSigningKeys(configure: options =>
    options.AllowedDevelopmentJwtSigningKeysEnvironments =
        ["Development", "IntegrationTesting", "CI"]);
```

*Added in Unreleased.* `Production` still cannot be added to this list — the gate rejects a
`Production` host environment unconditionally, regardless of what the list contains, and this is
enforced both by startup validation and by the gate itself. For why this property lives on the
provider-specific options type rather than a shared root, see
[ADR 0011 §2 and its "Considered and Rejected Alternatives" section](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0011-signing-key-management.md).

If you only need the host to report `Development` itself — for example, a local integration test
host that would otherwise pick up its own environment name — it can be simpler to leave the list
at its default and instead make that host report `Development`, by setting the standard ASP.NET
Core environment variable:

```bash
ASPNETCORE_ENVIRONMENT=Development
```

or, in a test host, by constructing `WebApplicationFactory` (or equivalent) with
`UseEnvironment("Development")`. Reach for widening the list instead when the host's environment
name itself is meaningful and you don't want to rename it — for example, a shared CI/QA host whose
name is also used by other environment-gated checks.

> ⚠️ **Warning:** Don't try to work around the gate by binding
> `AllowedDevelopmentJwtSigningKeysEnvironments` from `appsettings.json` or any other file that
> could end up committed to source control — this would silently defeat the whole point of the
> gate. Set it explicitly in code, as shown above, or source it from an environment variable read
> in code; never from a config file that could be committed.
>
> If a widened list is ever in effect, it does not fail quietly: every startup where the current
> environment is in the list but is not exactly `Development` logs a `LogLevel.Critical` entry, on
> every single boot, not just the first one. Treat a repeated Critical-level log line in a running
> environment as a strong signal that a development signing key configuration escaped somewhere it
> should not have.

---

## Not for production use

Neither `AddInMemoryDevelopmentJwtSigningKeys()` nor `AddPersistedDevelopmentJwtSigningKeys()` is
ever appropriate for a production deployment. The key is either regenerated on every restart
(in-memory) or stored as plaintext PEM with no HSM, KMS, or hardware-backed protection
(persisted) — neither survives a compromise of the host filesystem, and the in-memory option
invalidates every issued token on every restart.

For production, register one of the production signing key providers instead:

- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
- [Configure file-based signing](configure-file-based-signing.md) (PEM/PFX)

Once you have a production provider running, see [Rotate signing keys](rotate-signing-keys.md)
for how key rotation works across providers.

---

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`, and how keys are exposed as a JWKS document
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
- [Configure file-based signing](configure-file-based-signing.md) (PEM/PFX)
- [Rotate signing keys](rotate-signing-keys.md)

For the JWK wire format the generated key is exposed as, see
[RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517). For the signing-key
requirements OpenID Connect places on an authorization server, see
[OpenID Connect Core 1.0 Section 10.1](https://openid.net/specs/openid-connect-core-1_0.html#Signing).
