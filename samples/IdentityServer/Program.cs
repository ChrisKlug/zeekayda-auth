using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Samples.IdentityServer;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;
using ZeeKayDa.Auth.Tokens;

var builder = WebApplication.CreateBuilder(args);

var settings = builder.Configuration.GetSection("IdentityServer").Get<IdentityServerSettings>()
    ?? throw new InvalidOperationException("The IdentityServer configuration section is missing.");

builder.Services.AddRazorPages();
builder.Services.AddSingleton<UserStore>();

var auth = builder.Services.AddZeeKayDaAuth(options =>
{
    options.Issuer = settings.Issuer;

    // The pages the framework hands the browser to. Each page completes its step through an
    // interaction service; none of them handles a return URL, a cookie or a scheme.
    options.AuthorizationEndpoint.Interaction.LoginPath = "/login";
    options.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
    options.AuthorizationEndpoint.Interaction.ErrorPath = "/error";
    options.EndSessionEndpoint.LogoutPath = "/logout";
    options.EndSessionEndpoint.SignedOutPath = "/signed-out";

    // Public clients authenticate with nothing at the token endpoint, so "none" must be advertised
    // for them to be registrable.
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
});

auth.AddInMemoryClients(clients =>
{
    foreach (var client in settings.Clients)
    {
        if (client.Secret is { } secret)
        {
            clients.AddConfidential(client.ClientId, secret, client.RedirectUris, client.PostLogoutRedirectUris, client.Scopes,
                options => Configure(options, client));
        }
        else
        {
            clients.AddPublic(client.ClientId, client.RedirectUris, client.PostLogoutRedirectUris, client.Scopes,
                options => Configure(options, client));
        }
    }

    static void Configure(ClientOptions options, ClientSettings client)
    {
        options.RequireConsent = client.RequireConsent;
        options.InitiateLoginUri = client.InitiateLoginUri;
    }
});

// In-memory stores and a development signing key keep the sample runnable with no setup. Both
// refuse to start outside Development: a deployment needs stores that survive restarts and span
// instances, and a signing key it provisions itself.
auth.AddInMemoryStores();
auth.AddPersistedDevelopmentSigning();

auth.AddClaimsProvider<UserClaimsProvider>();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();

app.MapZeeKayDaAuth();
app.MapRazorPages();

app.Run();

/// <summary>The sample's entry point, public so the smoke tests can host it.</summary>
public partial class Program;
