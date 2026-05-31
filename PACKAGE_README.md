# ZeeKayDa.Auth

> Pre-alpha OpenID Connect identity provider framework for .NET.

ZeeKayDa.Auth is in **pre-alpha**. The current packages expose early discovery/configuration
building blocks and ASP.NET Core endpoint registration, but they are not a complete production
identity provider yet.

## Current status

- OpenID Connect discovery is available at `/.well-known/openid-configuration`.
- Discovery publishes authorization, token, and JWKS metadata.
- The advertised authorization, token, and JWKS endpoints currently return `501 Not Implemented`.
- APIs may change before the first stable release.

## ASP.NET Core setup

```csharp
using ZeeKayDa.Auth.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = "https://id.example.com";
});

var app = builder.Build();

app.UseRouting();
app.MapZeeKayDaAuth();

app.Run();
```

See the repository documentation for the full configuration and security guidance:
<https://github.com/ChrisKlug/zeekayda-auth>
