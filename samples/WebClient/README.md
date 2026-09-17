# Sample web client

An ordinary ASP.NET Core site that signs its users in against the
[sample identity server](../IdentityServer/README.md). It knows nothing about ZeeKayDa.Auth: it
uses Microsoft's `AddOpenIdConnect` handler, configured the way most .NET relying parties are, so
it is also a check that the server works with that handler.

> **This is a sample, not a production template.** It is a public client — the authorization code
> flow with PKCE and no secret — registered on the identity server as `sample-public-client`.

## Run it

Start the identity server, then the client, each in its own terminal:

```bash
dotnet run --project samples/IdentityServer
dotnet run --project samples/WebClient
```

The client listens on `https://localhost:5002` using the ASP.NET Core development certificate
(`dotnet dev-certs https --trust` if you have not trusted it yet).

1. Open `https://localhost:5002` and follow **Sign in**.
2. Sign in on the identity server as `alice` / `alice-password`, and allow access.
3. The profile page lists the claims from alice's ID token.
4. **Sign out** on the home page signs you out of both sites and brings you back.

## What it shows

| Piece | Where |
|---|---|
| Registering the cookie and OpenID Connect handlers | `Program.cs` |
| A page that requires a signed-in user | `Pages/Profile.cshtml`, authorized in `Program.cs` |
| Signing out of both the client and the identity server | `Pages/SignOut.cshtml.cs` |

Three settings differ from the handler's defaults, each commented in `Program.cs`:

- `ResponseMode` is `query`: the handler asks for `form_post` by default, and the server returns
  the code in the query string.
- `GetClaimsFromUserInfoEndpoint` is off: the server has no userinfo endpoint yet, so the claims
  come from the ID token.
- `MapInboundClaims` is off, so the claims keep the names the server gave them (`sub`, `name`).

The identity server's address and the client ID are in `appsettings.json`.
