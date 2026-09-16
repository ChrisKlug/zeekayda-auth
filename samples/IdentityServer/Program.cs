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
    options.EndSessionEndpoint.LogoutPath = "/logout";
    options.EndSessionEndpoint.SignedOutPath = "/signed-out";

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
        {
            clients.AddConfidential(client.ClientId, secret, client.RedirectUris, client.PostLogoutRedirectUris, client.Scopes,
                options => options.RequireConsent = client.RequireConsent);
        }
        else
        {
            clients.AddPublic(client.ClientId, client.RedirectUris, client.PostLogoutRedirectUris, client.Scopes,
                options => options.RequireConsent = client.RequireConsent);
        }
    }
});

// In-memory stores are deliberate: every restart starts from the same state, so there is nothing
// to reset between conformance runs. They refuse to start outside Development — a production
// deployment needs stores that survive restarts and span instances — so only the Conformance test
// profile is let through, and a copy of this sample keeps the guard everywhere else.
auth.AddInMemoryStores(allowOutsideDevelopment: builder.Environment.IsEnvironment("Conformance"));

// A relative path resolves against the app's own folder rather than the working directory, so the
// default lands in the gitignored keys/ folder however the app is started. An absolute path — an
// operator placing the key elsewhere — is used as given.
var signingKeyPath = Path.IsPathFullyQualified(settings.SigningKeyPath)
    ? settings.SigningKeyPath
    : Path.Join(builder.Environment.ContentRootPath, settings.SigningKeyPath);
auth.AddPemFileSigning(SigningKeyFile.Ensure(signingKeyPath), SigningAlgorithm.RS256);

auth.AddClaimsProvider<UserClaimsProvider>();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseRouting();

app.MapZeeKayDaAuth();
app.MapRazorPages();

app.Run();

/// <summary>The sample's entry point, public so the smoke tests can host it.</summary>
public partial class Program;
