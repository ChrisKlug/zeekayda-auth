using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class DevelopmentSigningKeyIntegrationTests
{
    /// <summary>
    /// A <see cref="WebApplicationFactory{TEntryPoint}"/> that stands up a minimal host with
    /// dev signing keys registered, used to verify the environment gate during host startup.
    /// </summary>
    private sealed class DevSigningKeyFactory : WebApplicationFactory<DevSigningKeyFactory>
    {
        private readonly string _environmentName;
        private readonly IReadOnlyList<string>? _allowedEnvironments;

        public DevSigningKeyFactory(string environmentName, IReadOnlyList<string>? allowedEnvironments = null)
        {
            _environmentName = environmentName;
            _allowedEnvironments = allowedEnvironments;
        }

        protected override IHostBuilder CreateHostBuilder()
            => Host.CreateDefaultBuilder()
                   .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(_environmentName);
            builder.UseContentRoot(AppContext.BaseDirectory);

            builder.ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddMemoryCache();
                services.AddDataProtection();
                var authBuilder = services.AddZeeKayDaAuth(options =>
                {
                    options.Issuer = "https://test.example.com";
                    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                    options.AllowInMemoryStoresOutsideDevelopment = true;
                    if (_allowedEnvironments is not null)
                        options.AllowedDevelopmentJwtSigningKeysEnvironments = _allowedEnvironments;
                });
                authBuilder
                    .AddInMemoryClients(clients =>
                        clients.AddPublic("test-client", ["https://test.example.com/callback"], [], ["openid"]))
                    .AddInMemoryStores()
                    .AddDevelopmentJwtSigningKeys();
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }

    [Fact]
    public void Host_starts_successfully_with_dev_signing_keys_in_Development()
    {
        using var factory = new DevSigningKeyFactory("Development");
        // CreateClient triggers host startup.
        var act = () => factory.CreateClient();
        act.Should().NotThrow();
    }

    [Fact]
    public void Host_fails_to_start_with_dev_signing_keys_in_Production()
    {
        using var factory = new DevSigningKeyFactory("Production");
        var act = () => factory.CreateClient();

        // The ZeeKayDaConfigurationException is thrown from DevelopmentSigningKeyWarningService.StartAsync
        // during host startup and propagates out of CreateClient.
        act.Should().Throw<Exception>()
            .Where(ex => ex is ZeeKayDaConfigurationException ||
                         (ex.InnerException is ZeeKayDaConfigurationException));
    }

    [Fact]
    public void Host_fails_to_start_with_dev_signing_keys_in_Staging_when_not_in_allowed_list()
    {
        using var factory = new DevSigningKeyFactory("Staging");
        var act = () => factory.CreateClient();

        act.Should().Throw<Exception>()
            .Where(ex => ex is ZeeKayDaConfigurationException ||
                         (ex.InnerException is ZeeKayDaConfigurationException));
    }

    [Fact]
    public void Host_starts_successfully_when_Staging_is_added_to_allowed_list()
    {
        using var factory = new DevSigningKeyFactory("Staging", allowedEnvironments: ["Development", "Staging"]);
        var act = () => factory.CreateClient();
        act.Should().NotThrow();
    }
}
