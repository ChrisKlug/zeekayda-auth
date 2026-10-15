using ZeeKayDa.Auth.ConformanceHost;
using ZeeKayDa.Auth.ConformanceHost.Users;
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
});

auth.AddInMemoryScopes(StandardScopes.All);

auth.AddInMemoryClients(builder.Configuration.GetSection("IdentityServer:Clients"));

// In-memory stores are deliberate: every restart starts from the same state, so there is nothing
// to reset between conformance runs. They refuse to start outside Development, so the Conformance
// environment the suite runs this host in is let through explicitly.
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
