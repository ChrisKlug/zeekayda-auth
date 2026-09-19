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
3. The profile page lists alice's claims, from her ID token and the userinfo endpoint.
4. **Sign out** on the home page signs you out of both sites and brings you back.

## What it shows

| Piece | Where |
|---|---|
| Registering the cookie and OpenID Connect handlers | `Program.cs` |
| A page that requires a signed-in user | `Pages/Profile.cshtml`, authorized in `Program.cs` |
| Signing out of both the client and the identity server | `Pages/SignOut.cshtml.cs` |
| Starting a new sign-in when the identity server asks for one | `/initiate-login` in `Program.cs` |

The identity server registers `https://localhost:5002/initiate-login` as this client's
`InitiateLoginUri`. When a sign-in page there is submitted after its request is gone — a double
click, or a page left open too long — the server sends the browser to that address with `iss`,
and the client starts a new sign-in if `iss` is the server it trusts.

Three settings differ from the handler's defaults, each commented in `Program.cs`:

- `ResponseMode` is `query`: the handler asks for `form_post` by default, and the server returns
  the code in the query string.
- `GetClaimsFromUserInfoEndpoint` is on, so the handler fetches the claims from the server's
  userinfo endpoint and merges them into the signed-in user.
- `MapInboundClaims` is off, so the claims keep the names the server gave them (`sub`, `name`).

The identity server's address and the client ID are in `appsettings.json`.
