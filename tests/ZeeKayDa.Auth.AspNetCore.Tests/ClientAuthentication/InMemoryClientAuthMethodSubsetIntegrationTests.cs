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
/// End-to-end host-startup tests: <c>InMemoryClientRepository</c> rejects a client registration
/// whose <c>AllowedTokenEndpointAuthMethods</c> are not all advertised by the server, and the
/// failure aborts host startup.
/// </summary>
public sealed class InMemoryClientAuthMethodSubsetIntegrationTests
{
    // ── Failing path ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Host_startup_throws_when_a_client_lists_a_method_no_authenticator_performs()
    {
        using var factory = new InvalidAuthMethodWebAppFactory();

        var act = () => factory.CreateClient();

        var ex = act.Should().Throw<Exception>().Which;
        var configEx = ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(ex);

        configEx.Should().NotBeNull(
            because: "a ZeeKayDaConfigurationException must be somewhere in the exception chain " +
                     "when a client lists a method the server does not advertise");

        configEx!.AggregatedFailures.Should().Contain(
            f => f.Code == "client.token_endpoint_auth_methods.not_subset",
            because: "the validator must produce a 'client.token_endpoint_auth_methods.not_subset' failure " +
                     "when the client's auth method is not advertised");
    }

    [Fact]
    public void Host_startup_failure_for_a_method_no_authenticator_performs_points_at_registering_one()
    {
        using var factory = new InvalidAuthMethodWebAppFactory();

        var act = () => factory.CreateClient();

        var configEx = ExceptionChain.FindInChain<ZeeKayDaConfigurationException>(
            act.Should().Throw<Exception>().Which);
        configEx!.AggregatedFailures
            .Single(f => f.Code == "client.token_endpoint_auth_methods.not_subset")
            .Message.Should().Contain("Register an IClientAuthenticator")
            .And.NotContain("Public clients", because: "that hint is for a public client the filter refuses");
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Host_startup_succeeds_when_client_AllowedTokenEndpointAuthMethods_are_all_advertised()
    {
        using var factory = new ValidAuthMethodWebAppFactory();

        var act = () => factory.CreateClient();

        act.Should().NotThrow(
            because: "the client's auth method is advertised so startup must succeed");
    }

    // ── Inline factories ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Factory that registers a confidential client whose single auth method
    /// (<c>private_key_jwt</c>) no registered authenticator performs, so the server does not
    /// advertise it. Host startup must therefore throw.
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

                services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com")
                .AddInMemoryClients(clients =>
                    clients.Add(
                        Client.CreateConfidential(
                            "bad-method-client",
                            // Structurally valid pre-hashed secret (fake bytes, not used for auth).
                            Pbkdf2ClientSecretHasher.Format(600_000, new byte[16], new byte[32]),
                            ["https://test.example.com/callback"],
                            [],
                            ["openid"])
                        with
                        {
                            AllowedTokenEndpointAuthMethods =
                                new HashSet<string>(StringComparer.Ordinal) { "private_key_jwt" },
                        }))
                // Integration test hosts run as "Production"; allow in-memory stores so only
                // the intentional auth-method failure fires, not the environment guard.
                .AddInMemoryStores(allowOutsideDevelopment: true)
                .AddTestSigningKeys().AddTestClaimsProvider();
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
    /// (<c>client_secret_basic</c>) the server advertises.
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

                services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = "https://test.example.com";
                })
                .AddInMemoryClients(clients =>
                    clients.Add(
                        Client.CreateConfidential(
                            "good-method-client",
                            Pbkdf2ClientSecretHasher.Format(600_000, new byte[16], new byte[32]),
                            ["https://test.example.com/callback"],
                            [],
                            ["openid"])
                    ))
                // Integration test hosts run as "Production" by default; allow in-memory stores.
                .AddInMemoryStores(allowOutsideDevelopment: true)
                .AddTestSigningKeys().AddTestClaimsProvider();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }
}
