# Sample identity server

A complete identity server built on ZeeKayDa.Auth, written the way a host developer would write
one, and no more than that. The OpenID Foundation conformance suite runs against a separate host,
[`tests/ZeeKayDa.Auth.ConformanceHost`](../../tests/ZeeKayDa.Auth.ConformanceHost), which carries
the suite's clients and switches.

> **This is a sample, not a production template.** Users, clients and grants live in memory and
> vanish on restart; the signing key is a development key, generated on first run under
> `.zeekayda/`. The framework's in-memory stores and development signing key both refuse to start
> outside Development.

## Run it

```bash
dotnet run --project samples/IdentityServer
```

The server listens on `https://localhost:5443` using the ASP.NET Core development certificate
(`dotnet dev-certs https --trust` if you have not trusted it yet). Discovery is at
`https://localhost:5443/.well-known/openid-configuration`.

## What it shows

| Piece | Where |
|---|---|
| Registering the framework, clients, stores and signing | `Program.cs` |
| The user store the framework never reads | `Users/UserStore.cs` |
| Handing the framework a subject's claims | `Users/UserClaimsProvider.cs` |
| Completing a sign-in with `ILoginInteraction` | `Pages/Login.cshtml.cs` |
| Completing consent with `IConsentInteraction` | `Pages/Consent.cshtml.cs` |
| Confirming a sign-out with `ILogoutInteraction` | `Pages/Logout.cshtml.cs` |
| The page a user lands on once signed out, with no client to return to | `Pages/SignedOut.cshtml` |
| Rendering an error the client cannot be sent | `Pages/Error.cshtml.cs` |
| Verifying client secrets hashed by other libraries | `ClientSecrets/` |

`SignInAsync`, `DenyAsync`, `GrantAsync` and `SignOutAsync` are terminal: the framework writes the
response, so each page handler simply ends after the call and the framework skips rendering the page.
They are terminal even when the page is submitted after its request is gone — a double click, a
page left open too long, a bookmarked login page: the framework sends the user back to the client
to start again, or to the error page, which tells that case apart by
`AuthorizationErrorKind.NothingToContinue`. The consent and logout pages read their request with
`TryGetRequestAsync`, so they can say "nothing to confirm" themselves instead of failing.

To sign out, follow **Sign out** on the home page, or send the browser to the end-session endpoint
(`/connect/endsession`) from a client.

## Seeded data

| User | Password |
|---|---|
| `alice` | `alice-password` |

New users can be added through **Create an account** on the login page; they last until restart.

| Client | Type | Consent page |
|---|---|---|
| `sample-public-client` | public, PKCE | shown |
| `sample-bcrypt-client` | confidential, secret `bcrypt-client-secret` | shown |
| `sample-argon2-client` | confidential, secret `argon2-client-secret` | shown |
| `sample-pbkdf2-sha512-client` | confidential, secret `pbkdf2-sha512-client-secret` | shown |

`sample-public-client` is the [sample web client](../WebClient/README.md). It sends users back to
`https://localhost:5002/signout-callback-oidc` after a sign-out it asked for, and to
`https://localhost:5002/initiate-login` to start again when a login or consent page is submitted
after its request is gone.

## Client secrets from other hashing libraries

A stored client secret is one string that names its algorithm, such as `$2a$12$...` or
`$argon2id$v=19$...`, so a client store keeps any library's output without knowing the library. The
three confidential clients above are registered with secrets already hashed, the way they would
arrive from another system, each by a different library:

| Hasher | Library | How it gets its string |
|---|---|---|
| `BCryptClientSecretHasher` | BCrypt.Net-Next | the library writes and reads it |
| `Argon2ClientSecretHasher` | Isopoh.Cryptography.Argon2 | the library writes and reads a PHC string |
| `Pbkdf2Sha512ClientSecretHasher` | the .NET base class library | built and parsed with `PhcString` |

Each hasher declares the algorithm ids it owns, and the framework hands it only the secrets that
carry one of them. The built-in PBKDF2 hasher stays the default, so every secret hashed at startup
or through `IClientSecretFactory` is still `$pbkdf2-sha256$...`.
