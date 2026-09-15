# Sample identity server

A complete identity server built on ZeeKayDa.Auth, written the way a host developer would write
one. It is also the target the OpenID Foundation conformance suite runs against.

> **This is a sample, not a production template.** Users, clients and grants live in memory and
> vanish on restart; the signing key is generated on first run. The **Conformance** profile in
> particular is a test target: its client secrets are published in this file.

## Run it

```bash
dotnet run --project samples/IdentityServer
```

The server listens on `https://localhost:5443` using the ASP.NET Core development certificate
(`dotnet dev-certs https --trust` if you have not trusted it yet). Discovery is at
`https://localhost:5443/.well-known/openid-configuration`.

For the conformance suite's clients, run the **Conformance** profile:

```bash
dotnet run --project samples/IdentityServer --launch-profile Conformance
```

## What it shows

| Piece | Where |
|---|---|
| Registering the framework, clients, scopes, stores and signing | `Program.cs` |
| The user store the framework never reads | `Users/UserStore.cs` |
| Handing the framework a subject's claims | `Users/UserClaimsProvider.cs` |
| Completing a sign-in with `ILoginInteraction` | `Pages/Login.cshtml.cs` |
| Completing consent with `IConsentInteraction` | `Pages/Consent.cshtml.cs` |
| Rendering an error the client cannot be sent | `Pages/Error.cshtml.cs` |

`SignInAsync`, `DenyAsync` and `GrantAsync` are terminal: the framework writes the response, so
each page handler returns an `EmptyResult` afterwards instead of rendering.

## Seeded data

| User | Password |
|---|---|
| `alice` | `alice-password` |

New users can be added through **Create an account** on the login page; they last until restart.

| Client | Type | Secret | Profile |
|---|---|---|---|
| `sample-public-client` | public, PKCE | — | all |
| `conformance-client` | confidential, `client_secret_basic` | `conformance-client-secret` | Conformance |
| `conformance-client2` | confidential, `client_secret_basic` | `conformance-client2-secret` | Conformance |

The conformance clients register the suite's callback for the plan alias `zeekayda`:
`https://localhost.emobix.co.uk:8443/test/a/zeekayda/callback`.

## Not here yet

- **Logout** — the framework has no sign-out API yet (#671).
- **Clients that skip consent** — the in-memory builder cannot set `RequireConsent` (#670), so every
  client shows the consent page. The conformance suite's browser automation completes it.
