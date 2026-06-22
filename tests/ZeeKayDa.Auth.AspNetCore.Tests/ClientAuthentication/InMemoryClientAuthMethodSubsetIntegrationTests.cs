using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

/// <summary>
/// End-to-end host-startup integration tests for AC #3 of issue #146:
/// verifying that <c>InMemoryClientRepository</c> rejects client registrations whose
/// <c>AllowedTokenEndpointAuthMethods</c> are not a subset of the server's
/// <c>AuthMethodsSupported</c>, and that the failure aborts host startup.
/// </summary>
public sealed class InMemoryClientAuthMethodSubsetIntegrationTests
{
    // ── Failing path ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Host_startup_throws_when_client_AllowedTokenEndpointAuthMethods_is_not_subset_of_AuthMethodsSupported()
    {
        using var factory = new InvalidAuthMethodWebAppFactory();

        var act = () => factory.CreateClient();

        var ex = act.Should().Throw<Exception>().Which;
        var configEx = FindInChain<ZeeKayDaConfigurationException>(ex);

        configEx.Should().NotBeNull(
            because: "a ZeeKayDaConfigurationException must be somewhere in the exception chain " +
                     "when a client's AllowedTokenEndpointAuthMethods is not a subset of AuthMethodsSupported");

        configEx!.AggregatedFailures.Should().Contain(
            f => f.Code == "client.token_endpoint_auth_methods.not_subset",
            because: "the validator must produce a 'client.token_endpoint_auth_methods.not_subset' failure " +
                     "when the client's auth method is not in the server's AuthMethodsSupported list");
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Host_startup_succeeds_when_client_AllowedTokenEndpointAuthMethods_is_subset_of_AuthMethodsSupported()
    {
        using var factory = new ValidAuthMethodWebAppFactory();

        var act = () => factory.CreateClient();

        act.Should().NotThrow(
            because: "the client's auth method is present in AuthMethodsSupported so startup must succeed");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Walks the exception chain (via <see cref="Exception.InnerException"/> and
    /// <see cref="AggregateException.InnerExceptions"/>) looking for an exception of type
    /// <typeparamref name="T"/>.  Returns <see langword="null"/> if none is found.
    /// </summary>
    private static T? FindInChain<T>(Exception? ex) where T : Exception
    {
        while (ex is not null)
        {
            if (ex is T typed)
                return typed;

            if (ex is AggregateException aggregate)
            {
                foreach (var found in aggregate.InnerExceptions
                             .Select(FindInChain<T>)
                             .Where(found => found is not null))
                {
                    return found!;
                }
                return null;
            }

            ex = ex.InnerException;
        }

        return null;
    }

    // ── Inline factories ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Factory that registers a confidential client whose single auth method
    /// (<c>client_secret_post</c>) is NOT in <c>AuthMethodsSupported</c> (which only contains
    /// <c>client_secret_basic</c>).  Host startup must therefore throw.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A confidential client is used so the trinity check (IsPublic ⟺ Credentials.Count=0 ⟺
    /// AllowedTokenEndpointAuthMethods={"none"}) is satisfied and only the subset check fires.
    /// </para>
    /// <para>
    /// The <see cref="Pbkdf2ClientSecret"/> is constructed with fake-but-structurally-valid
    /// values (600,000 iterations so it passes the OWASP minimum check, 16-byte salt, 32-byte
    /// hash).  The bytes are all-zero on purpose: the credential will never be used for
    /// real authentication — the test aborts before the host accepts any requests.
    /// </para>
    /// </remarks>
    private sealed class InvalidAuthMethodWebAppFactory
        : WebApplicationFactory<InvalidAuthMethodWebAppFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder()
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            builder.ConfigureServices(services =>
            {
                services.AddRouting();

                // Server supports only client_secret_basic — intentionally omits client_secret_post.
                services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = "https://test.example.com";
                    // Only client_secret_basic is in AuthMethodsSupported.
                    // The ClientSecretAuthenticator covers it, satisfying AuthenticatorCoverageValidator.
                    // Integration test hosts run as "Production"; allow in-memory stores so only
                    // the intentional auth-method failure fires, not the environment guard.
                    options.AllowInMemoryStoresOutsideDevelopment = true;
                })
                .AddInMemoryClients(clients =>
                    clients.Add(
                        ClientRegistration.CreateConfidential(
                            "bad-method-client",
                            // Structurally valid pre-hashed credential (fake bytes, not used for auth).
                            new Pbkdf2ClientSecret(
                                Iterations: 600_000,
                                Salt: new byte[16],
                                Hash: new byte[32]),
                            ["https://test.example.com/callback"],
                            [],
                            ["openid"])
                        // Override the default AllowedTokenEndpointAuthMethods to client_secret_post,
                        // which is a valid method string but is NOT in AuthMethodsSupported.
                        with
                        {
                            AllowedTokenEndpointAuthMethods =
                                new HashSet<string>(StringComparer.Ordinal)
                                    { TokenEndpointAuthMethods.ClientSecretPost },
                        }))
                .AddInMemoryStores();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }

    /// <summary>
    /// Factory that registers a confidential client whose auth method
    /// (<c>client_secret_basic</c>) IS in <c>AuthMethodsSupported</c>.
    /// Host startup must succeed.
    /// </summary>
    private sealed class ValidAuthMethodWebAppFactory
        : WebApplicationFactory<ValidAuthMethodWebAppFactory>
    {
        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder()
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(AppContext.BaseDirectory);
            builder.ConfigureServices(services =>
            {
                services.AddRouting();

                // Server supports client_secret_basic. The client also uses client_secret_basic.
                services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = "https://test.example.com";
                    // Integration test hosts run as "Production" by default; allow in-memory stores.
                    options.AllowInMemoryStoresOutsideDevelopment = true;
                })
                .AddInMemoryClients(clients =>
                    clients.Add(
                        ClientRegistration.CreateConfidential(
                            "good-method-client",
                            new Pbkdf2ClientSecret(
                                Iterations: 600_000,
                                Salt: new byte[16],
                                Hash: new byte[32]),
                            ["https://test.example.com/callback"],
                            [],
                            ["openid"])
                    // AllowedTokenEndpointAuthMethods defaults to { "client_secret_basic" }
                    // which matches the server's AuthMethodsSupported — no override needed.
                    ))
                .AddInMemoryStores();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }
}
