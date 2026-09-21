using Microsoft.AspNetCore.Authentication;
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

        // The handler calls the server's userinfo endpoint after the code exchange and merges
        // what it returns into the signed-in user's claims. Required, not optional: the standard
        // scopes release their claims at userinfo (OpenID Connect Core 5.4), so the ID token
        // carries only "sub" and without this the signed-in user would have nothing else.
        options.GetClaimsFromUserInfoEndpoint = true;

        // Keep the claim types the server sent ("sub", "name") instead of .NET's long URIs.
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "name";

        // Keeps the ID token, which sign-out sends back to the server as id_token_hint.
        options.SaveTokens = true;
    });

var app = builder.Build();

app.UseHttpsRedirection();

// Nothing in this app is meant to be framed. Refusing it everywhere keeps another site from
// framing the sign-in pages, /initiate-login included, to start a sign-in the user did not see.
app.Use((context, next) =>
{
    context.Response.Headers.XFrameOptions = "DENY";
    context.Response.Headers.ContentSecurityPolicy = "frame-ancestors 'none'";
    return next(context);
});
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

// Third-party-initiated login (OpenID Connect Core §4): the identity server sends the browser here
// to start a new sign-in when one of its pages was submitted after its request was gone — a
// double click, a page left open too long. The endpoint must accept GET and POST (OpenID Connect
// Registration §2). Only a request naming the server this app trusts starts one; an app that wants
// to explain first could render a page here instead.
app.MapMethods("/initiate-login", [HttpMethods.Get, HttpMethods.Post], async (HttpRequest request) =>
{
    var iss = request.HasFormContentType
        ? (await request.ReadFormAsync(request.HttpContext.RequestAborted))["iss"].ToString()
        : request.Query["iss"].ToString();

    return string.Equals(iss, identityServer["Authority"], StringComparison.Ordinal)
        ? Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [OpenIdConnectDefaults.AuthenticationScheme])
        : Results.BadRequest();
});

app.Run();

/// <summary>The sample's entry point, public so the end-to-end tests can host it.</summary>
public partial class Program;
