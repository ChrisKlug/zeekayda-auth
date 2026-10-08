using ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;
using ZeeKayDa.Auth.Samples.IdentityServer.Users;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddSingleton<UserStore>();

// The Issuer key of the section is bound to the options; its Clients key is ignored by it.
var auth = builder.Services.AddZeeKayDaAuth(builder.Configuration.GetSection("IdentityServer"), options =>
{
    // The login and consent pages sit at the default /login and /consent. Each page completes its
    // step through an interaction service; none of them handles a return URL, a cookie or a scheme.
    options.AuthorizationEndpoint.Interaction.ErrorPath = "/error";
    options.EndSessionEndpoint.LogoutPath = "/logout";
    options.EndSessionEndpoint.SignedOutPath = "/signed-out";
});

// Hashers from other libraries, beside the built-in PBKDF2 one, which still hashes every new secret.
// Each verifies the stored secrets whose algorithm id it declares: "$2b$...", "$argon2id$..." and
// "$pbkdf2-sha512$...".
auth.AddClientSecretHasher<BCryptClientSecretHasher>()
    .AddClientSecretHasher<Argon2ClientSecretHasher>()
    .AddClientSecretHasher<Pbkdf2Sha512ClientSecretHasher>();

// The clients, keyed by client id under Confidential and Public. Each confidential client carries a
// hash in the format of one of the hashers above; a plaintext Secret, hashed at startup, could come
// from user secrets instead, under IdentityServer:Clients:Confidential:<client id>:Secret.
auth.AddInMemoryClients(builder.Configuration.GetSection("IdentityServer:Clients"));

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
