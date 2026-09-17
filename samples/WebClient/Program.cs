using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

var identityServer = builder.Configuration.GetSection("IdentityServer");

builder.Services.AddRazorPages(options => options.Conventions.AuthorizePage("/Profile"));

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddOpenIdConnect(options =>
    {
        options.Authority = identityServer["Authority"];
        options.ClientId = identityServer["ClientId"];

        // A public client: the authorization code flow with PKCE, and no secret to keep.
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.UsePkce = true;

        // The handler asks for form_post by default; the server returns the code in the query string.
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.Scope.Add("profile");
        options.Scope.Add("email");

        // The server has no userinfo endpoint yet (#708), so the claims come from the ID token.
        options.GetClaimsFromUserInfoEndpoint = false;

        // Keep the claim types the server sent ("sub", "name") instead of .NET's long URIs.
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "name";

        // Keeps the ID token, which sign-out sends back to the server as id_token_hint.
        options.SaveTokens = true;
    });

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();

/// <summary>The sample's entry point, public so the end-to-end tests can host it.</summary>
public partial class Program;
