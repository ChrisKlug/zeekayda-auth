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

Call `AddInMemoryClients` on the builder returned by `AddZeeKayDaAuth`. Each client is a client id
plus a callback that sets its redirect URIs, scopes and other settings:

```csharp
var builder = services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    // Allow public clients (no client authentication)
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
});

builder.AddInMemoryClients(clients =>
{
    // A public client (SPA or native app using PKCE)
    clients.AddPublic("my-spa", client =>
    {
        client.RedirectUris.Add("https://app.example.com/callback");
        client.PostLogoutRedirectUris.Add("https://app.example.com/logout");
        client.AllowedScopes.UnionWith(["openid", "profile"]);
    });

    // A confidential client (server-side app)
    clients.AddConfidential("my-server-app", client =>
    {
        client.SecretHash = configuration["ClientSecrets:MyServerApp"];
        client.RedirectUris.Add("https://server.example.com/callback");
        client.AllowedScopes.UnionWith(["openid", "api"]);
    });
});
```

## Clients from configuration

Most hosts keep a fixed client list in configuration. Pass the section instead of a callback:

```csharp
builder.AddInMemoryClients(configuration.GetSection("Clients"));
```

```json
"Clients": {
  "Confidential": {
    "my-server-app": {
      "SecretHash": "$pbkdf2-sha256$i=600000$...",
      "RedirectUris": [ "https://server.example.com/callback" ],
      "AllowedScopes": [ "openid", "api" ]
    }
  },
  "Public": {
    "my-spa": {
      "RedirectUris": [ "https://app.example.com/callback" ],
      "AllowedScopes": [ "openid", "profile" ]
    }
  }
}
```

Clients are keyed by client id, under `Confidential` or `Public`, and each client's keys are the
properties of `ConfidentialClientOptions` or `PublicClientOptions`. Keying by client id gives every
secret a stable path, so it can come from user secrets, environment variables or a vault rather than
the JSON file: `Clients:Confidential:my-server-app:Secret`. A child other than `Confidential` or
`Public`, or a key the options type does not have, fails at registration, so a misspelt setting is
never silently left on its default. The section is read once, when `AddInMemoryClients` is called.

## Secrets

A confidential client sets exactly one of two properties; startup fails if it sets neither or both:

- `SecretHash` — a hash in PHC string format, such as `$pbkdf2-sha256$...`, stored as given. A
  registered `IClientSecretHasher` must declare its algorithm id. Prefer this: the plaintext never
  reaches the host.
- `Secret` — a plaintext secret, hashed with the default `IClientSecretHasher` when the host starts.
  This is a convenience for development and bootstrapping. The framework releases its copy after
  hashing, but the configuration source it came from keeps its own for the life of the process.
  **Never hardcode a secret in code or commit one to a configuration file.**

## Public clients

Public clients authenticate with no client credentials — they rely entirely on PKCE
(RFC 7636) for authorization code security. Use `AddPublic` for single-page applications and
native apps.

```csharp
clients.AddPublic("my-spa", client =>
{
    client.RedirectUris.Add("https://app.example.com/callback");
    client.PostLogoutRedirectUris.Add("https://app.example.com/logout");
    client.AllowedScopes.UnionWith(["openid", "profile", "email"]);
});
```

To allow public clients, the server must advertise `none` as a supported token endpoint
authentication method:

```csharp
services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
});
```

## Confidential clients

Confidential clients authenticate at the token endpoint using a shared secret. Use `AddConfidential`
for server-side web applications, background services, and APIs.

```csharp
builder.AddInMemoryClients(clients =>
    clients.AddConfidential("my-server-app", client =>
    {
        client.Secret = configuration["ClientSecrets:MyServerApp"];
        client.RedirectUris.Add("https://server.example.com/callback");
        client.PostLogoutRedirectUris.Add("https://server.example.com/logout");
        client.AllowedScopes.Add("openid");
    }));
```

A `Secret` is hashed using the configured default `IClientSecretHasher` (by default,
PBKDF2-HMAC-SHA256 at 600,000 iterations) when the repository is first resolved from DI. The
framework does not keep the plaintext after hashing.

## Changing a client's other settings

The callback of `AddPublic` and `AddConfidential` receives the client's settings, already filled
with their defaults. Change only what you need:

```csharp
builder.AddInMemoryClients(clients =>
    clients.AddConfidential("first-party-web", options =>
    {
        options.SecretHash = secretHash;
        options.RedirectUris.Add("https://app.example.com/callback");
        options.AllowedScopes.UnionWith(["openid", "profile"]);
        options.RequireConsent = false;
        options.DisplayName = "Example Web";
        options.AccessTokenLifetime = TimeSpan.FromMinutes(2);
    }));
```

A public client's callback receives `PublicClientOptions`. A confidential client's receives
`ConfidentialClientOptions`, which adds `Secret`, `SecretHash`, `RequirePkce` and
`AllowedTokenEndpointAuthMethods` — settings a public client cannot have.

The collections that have a default — grant types, response types, response modes and a
confidential client's token endpoint authentication methods — start empty in the callback, and a
collection named in configuration replaces the default rather than adding to it. Add
the values you want and the client gets exactly those; add none and it gets the default:
`authorization_code`, `client_secret_basic`, and the `code` response type and `query` response mode
when the client may use `authorization_code`. A `client_credentials`-only client gets no response
types or modes:

```csharp
options.AllowedGrantTypes.Add(GrantType.ClientCredentials);
options.AllowedTokenEndpointAuthMethods.Add(TokenEndpointAuthMethods.ClientSecretPost); // only client_secret_post
```

> Turn `RequireConsent` off only for your own first-party applications. The consent page is what
> lets a user notice an authorization request they never started.

Set `InitiateLoginUri` to an `https` address in your application that starts a new sign-in. When a
login or consent page is submitted after its request is gone — a double click, or a page left open
too long — the server sends the user there, with the server's issuer as `iss`, instead of to its
error page. Start a sign-in there only when `iss` is the server your application trusts:

```csharp
options.InitiateLoginUri = "https://app.example.com/initiate-login";
```

The address must accept both `GET` and `POST`, and should not be frameable, so another site cannot
start a sign-in the user does not see:

```csharp
// In the application: an ASP.NET Core site using AddOpenIdConnect.
app.MapMethods("/initiate-login", [HttpMethods.Get, HttpMethods.Post], async (HttpRequest request) =>
{
    var iss = request.HasFormContentType
        ? (await request.ReadFormAsync())["iss"].ToString()
        : request.Query["iss"].ToString();

    return iss == "https://login.example.com"
        ? Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [OpenIdConnectDefaults.AuthenticationScheme])
        : Results.BadRequest();
});
```

## Registering a pre-built client

If you already have a registration built elsewhere, construct a `Client` directly and use `Add`:

```csharp
using ZeeKayDa.Auth.Clients;

var customClient = Client.CreatePublic(
    clientId: "custom-client",
    redirectUris: ["https://app.example.com/callback"],
    postLogoutRedirectUris: [],
    allowedScopes: ["openid"])
    with
    {
        AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.ES256 },
    };

builder.AddInMemoryClients(clients => clients.Add(customClient));
```

`Client` is a record, so `with` expressions work to override any property that was
not set by the factory method.

> `AllowedSigningAlgorithms` must be a subset of what the server advertises, and the server
> advertises only the algorithms its configured signing keys use. The `ES256` above therefore
> requires an ES256 signing key to be configured; without one, startup fails with
> `client.signing_algorithms.not_subset`.

## Multiple `AddInMemoryClients` calls

Multiple calls to `AddInMemoryClients` accumulate registrations — they do not replace earlier
registrations. This is useful for separating concerns (for example, test clients from production
clients, or clients from different configuration sources):

```csharp
builder.AddInMemoryClients(configuration.GetSection("Clients"));

// Called later in a different extension method:
builder.AddInMemoryClients(clients => clients.AddConfidential("api-gateway", client =>
{
    client.SecretHash = secretHash;
    client.RedirectUris.Add("https://api.example.com/cb");
    client.AllowedScopes.Add("openid");
}));
```

Both clients will be present in the repository.

## Hasher selection when multiple hashers are registered

When more than one `IClientSecretHasher` is registered, the framework must know which one to use
as the default — that is, which hasher creates new secrets. The `isDefault` parameter on `AddClientSecretHasher<T>()` controls this. The
full selection matrix is:

| Explicit defaults (`isDefault: true`) | Outcome |
|---|---|
| 0 | PBKDF2 is the default |
| 1 | The flagged hasher is the default |
| 2 or more | **Startup failure** — `configuration.hashers.multiple_defaults` |

The built-in PBKDF2 hasher is always registered and, unless you mark another hasher as the
default, creates every new secret. To keep verifying secrets hashed with another algorithm,
register that hasher alongside it; to make your own hasher create new secrets, mark it
`isDefault: true` — PBKDF2 stays registered, so existing PBKDF2 secrets keep verifying:

```csharp
auth.AddClientSecretHasher<BcryptClientSecretHasher>();                  // verifies old bcrypt secrets
auth.AddClientSecretHasher<Argon2ClientSecretHasher>(isDefault: true);   // creates new secrets
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
| `client.grant_types.client_credentials_on_public` | A public client allows `client_credentials`, which only a confidential client may use (RFC 6749 §4.4) |
| `client.token_endpoint_auth_methods.not_subset` | Client auth method not in server's `AuthMethodsSupported` |
| `client.client_id.duplicate` | Two clients with the same `ClientId` |
| `client.credentials.no_secret` | A confidential client sets neither `Secret` nor `SecretHash` |
| `client.credentials.secret_and_secret_hash` | A confidential client sets both `Secret` and `SecretHash` |
| `client.validator.malformed_result` | A host `IClientRegistrationValidator` returned null, or a list with a null entry |

## See also

- [Implement a custom client repository](implement-custom-client-repository.md) — store clients
  in a database or other persistent store.
- [Implement a custom extension point](implement-custom-extension-points.md) — implement other
  custom extension points.
