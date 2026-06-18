---
title: "Register clients"
description: "How to register OAuth 2.0 / OpenID Connect clients with the in-memory client repository."
parent: "How-to Guides"
nav_order: 4
---

*Added in Unreleased.*

ZeeKayDa.Auth requires at least one registered client before the server will start. This guide
shows you how to register public and confidential clients using the built-in in-memory repository.

## Quick start

Call `AddInMemoryClients` on the builder returned by `AddZeeKayDaAuth` and use the provided
builder callbacks to register your clients:

```csharp
var builder = services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    // Allow public clients (no client authentication)
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
});

builder.AddPbkdf2SecretsHasher();   // required for confidential clients

builder.AddInMemoryClients(clients =>
{
    // A public client (SPA or native app using PKCE)
    clients.AddPublic(
        clientId: "my-spa",
        redirectUris: ["https://app.example.com/callback"],
        postLogoutRedirectUris: ["https://app.example.com/logout"],
        allowedScopes: ["openid", "profile"]);

    // A confidential client (server-side app)
    clients.AddConfidential(
        clientId: "my-server-app",
        clientSecret: "replace-with-a-real-secret",
        redirectUris: ["https://server.example.com/callback"],
        postLogoutRedirectUris: [],
        allowedScopes: ["openid", "api"]);
});
```

> **Warning:** The `clientSecret` parameter in `AddConfidential` accepts a plaintext string that
> is hashed at repository construction time. **Never hardcode secrets in production code.** Load
> them from environment variables, a secrets manager (e.g. Azure Key Vault), or a secure
> configuration provider instead.

## Public clients

Public clients authenticate with no client credentials — they rely entirely on PKCE
(RFC 7636) for authorization code security. Use `AddPublic` for single-page applications and
native apps.

```csharp
clients.AddPublic(
    clientId: "my-spa",
    redirectUris: ["https://app.example.com/callback"],
    postLogoutRedirectUris: ["https://app.example.com/logout"],
    allowedScopes: ["openid", "profile", "email"]);
```

To allow public clients, the server must advertise `none` as a supported token endpoint
authentication method:

```csharp
services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethod.None);
});
```

## Confidential clients

Confidential clients authenticate at the token endpoint using a shared secret. Use `AddConfidential`
for server-side web applications, background services, and APIs.

```csharp
builder.AddPbkdf2SecretsHasher(); // must be registered before AddInMemoryClients

builder.AddInMemoryClients(clients =>
    clients.AddConfidential(
        clientId: "my-server-app",
        clientSecret: configuration["ClientSecrets:MyServerApp"],
        redirectUris: ["https://server.example.com/callback"],
        postLogoutRedirectUris: ["https://server.example.com/logout"],
        allowedScopes: ["openid"]));
```

The `clientSecret` value is hashed using the configured `IClientSecretHasher` (by default,
PBKDF2-HMAC-SHA256 at 600,000 iterations) when the repository is first resolved from DI. The
plaintext is not retained after hashing.

## Registering a pre-built client

If you need to set properties beyond what the builder methods expose (for example, custom
`AllowedGrantTypes` or a per-client signing algorithm allowlist), construct a
`ClientRegistration` directly and use `Add`:

```csharp
using ZeeKayDa.Auth.Clients;

var customClient = ClientRegistration.CreatePublic(
    clientId: "custom-client",
    redirectUris: ["https://app.example.com/callback"],
    postLogoutRedirectUris: [],
    allowedScopes: ["openid"])
    with
    {
        AllowedGrantTypes = new HashSet<GrantType> { GrantType.AuthorizationCode },
        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 },
    };

builder.AddInMemoryClients(clients => clients.Add(customClient));
```

`ClientRegistration` is a record, so `with` expressions work to override any property that was
not set by the factory method.

## Multiple `AddInMemoryClients` calls

Multiple calls to `AddInMemoryClients` accumulate registrations — they do not replace earlier
registrations. This is useful for separating concerns (for example, test clients from production
clients, or clients from different configuration sources):

```csharp
builder.AddInMemoryClients(clients =>
    clients.AddPublic("spa", ["https://app.example.com/cb"], [], ["openid"]));

// Called later in a different extension method or configuration source:
builder.AddInMemoryClients(clients =>
    clients.AddConfidential("api-gateway", secretValue, ["https://api.example.com/cb"], [], ["openid"]));
```

Both clients will be present in the repository.

## Hasher selection when multiple hashers are registered

When more than one `IClientSecretHasher` is registered, the framework must know which one to use
as the default — that is, which hasher creates new secrets and generates the timing-pad dummy
credential at startup. The `isDefault` parameter on `AddSecretsHasher<T>()` controls this. The
full selection matrix from ADR 0007 §3.5 is:

| Hashers registered | Explicit defaults (`isDefault: true`) | Outcome |
|---|---|---|
| 1 | 0 | That hasher is the default (auto-selected) |
| 2 or more | 0 | **Startup failure** — ambiguous, cannot select a default |
| 2 or more | 1 | The flagged hasher is the default |
| 2 or more | 2 or more | **Startup failure** — multiple defaults conflict |

> ⚠️ **Warning:** The "2 or more hashers, 0 defaults" case is easy to miss. If you register a
> second hasher during a credential rotation — for example to support both PBKDF2 and bcrypt —
> without marking one as `isDefault: true`, the host will fail to start. The error is caught by
> startup validation, not at runtime, so the failure is immediate and visible in the startup
> output.

```csharp
// ✓ Two hashers, one explicit default — startup succeeds
auth.AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true);   // creates new secrets
auth.AddSecretsHasher<BcryptClientSecretHasher>(isDefault: false);   // verifies old secrets

// ✗ Two hashers, no explicit default — startup failure ("ambiguous default")
auth.AddSecretsHasher<Pbkdf2ClientSecretHasher>();
auth.AddSecretsHasher<BcryptClientSecretHasher>();
```

For the full `isDefault` rules and startup validation behaviour, see
[Client secrets reference](../reference/client-secrets.md#isdefault-rules). To implement a
custom hasher, see [Implement a custom extension point](implement-custom-extension-points.md).

## Startup validation

All clients are validated when the `IClientRepository` singleton is first resolved. Validation
errors are aggregated into a single `ZeeKayDaConfigurationException` so you see all problems at
once rather than one at a time.

Common validation failures:

| Code | Cause |
|---|---|
| `client.redirect_uri.fragment` | Redirect URI contains a `#` fragment |
| `client.redirect_uri.scheme_http_non_loopback` | `http://` URI for a non-loopback host |
| `client.is_public.trinity_violation` | `IsPublic`, `Credentials`, and `AllowedTokenEndpointAuthMethods` are inconsistent |
| `client.token_endpoint_auth_methods.not_subset` | Client auth method not in server's `AuthMethodsSupported` |
| `client.client_id.duplicate` | Two clients with the same `ClientId` |

## See also

- [Implement a custom client repository](implement-custom-client-repository.md) — store clients
  in a database or other persistent store.
- [Implement a custom extension point](implement-custom-extension-points.md) — implement other
  custom extension points.
