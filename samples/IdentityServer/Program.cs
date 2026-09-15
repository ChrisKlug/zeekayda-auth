using ZeeKayDa.Auth.Samples.IdentityServer;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;
using ZeeKayDa.Auth.Scopes;
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

    // Public clients authenticate with nothing at the token endpoint, so "none" must be advertised
    // for them to be registrable.
    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
});

auth.AddInMemoryScopes(StandardScopes.All);

auth.AddInMemoryClients(clients =>
{
    foreach (var client in settings.Clients)
    {
        if (client.Secret is { } secret)
            clients.AddConfidential(client.ClientId, secret, client.RedirectUris, [], client.Scopes);
        else
            clients.AddPublic(client.ClientId, client.RedirectUris, [], client.Scopes);
    }
});

// In-memory stores are deliberate: every restart starts from the same state, so there is nothing
// to reset between conformance runs. They refuse to run outside Development unless told otherwise.
auth.AddInMemoryStores(allowOutsideDevelopment: true);

auth.AddPemFileSigning(SigningKeyFile.Ensure(settings.SigningKeyPath), SigningAlgorithm.RS256);

auth.AddClaimsProvider<UserClaimsProvider>();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();

app.MapZeeKayDaAuth();
app.MapRazorPages();

app.Run();
