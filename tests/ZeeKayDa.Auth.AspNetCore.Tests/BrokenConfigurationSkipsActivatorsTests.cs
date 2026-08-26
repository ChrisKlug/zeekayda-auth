using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// #499's headline acceptance criterion, proven on a real host rather than through a fake activator:
/// a cheap configuration failure must stop the signing key source ever being read or a signer ever
/// being opened. On a Key Vault provider that read is a remote call, made on every startup of every
/// instance of a misconfigured deployment.
/// </summary>
public sealed class BrokenConfigurationSkipsActivatorsTests
{
    [Fact]
    public void A_failed_cheap_check_means_the_signing_key_source_is_never_touched()
    {
        RecordingSigningKeySource.Reset();
        using var factory = new MissingScopeWebAppFactory();

        var act = () => factory.CreateClient();

        act.Should().Throw<Exception>();
        RecordingSigningKeySource.ReadAsyncCallCount.Should().Be(0);
        RecordingSigningKeySource.CreateSignerAsyncCallCount.Should().Be(0);
        RecordingSigningKeySource.ConstructionCount.Should().Be(0,
            "constructing the source is itself the caller's code running");
    }

    /// <summary>Static counters: the ring owns its source, so a test cannot hold the instance.</summary>
    private sealed class RecordingSigningKeySource : ISigningKeySource
    {
        public static int ConstructionCount { get; private set; }

        public static int ReadAsyncCallCount { get; private set; }

        public static int CreateSignerAsyncCallCount { get; private set; }

        public RecordingSigningKeySource() => ConstructionCount++;

        public static void Reset()
        {
            ConstructionCount = 0;
            ReadAsyncCallCount = 0;
            CreateSignerAsyncCallCount = 0;
        }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            throw new NotSupportedException();
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            CreateSignerAsyncCallCount++;
            throw new NotSupportedException();
        }
    }

    private sealed class MissingScopeWebAppFactory : WebApplicationFactory<MissingScopeWebAppFactory>
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
                    options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                })
                .AddInMemoryClients(clients =>
                    clients.AddPublic("test-client", ["https://test.example.com/callback"], [], ["openid"]))
                .AddInMemoryStores(allowOutsideDevelopment: true);

                // Fails a cheap verifier: no IDistributedCache is registered for the distributed
                // store check to find. Nothing in the activator phase should run afterwards.
                services.AddZeeKayDaSigningKeySource<RecordingSigningKeySource>();
                services.AddSingleton<IStartupVerifier>(new AlwaysFailingVerifier());
            });

            builder.Configure(app =>
            {
                app.UseRouting();
                app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
            });
        }
    }

    private sealed class AlwaysFailingVerifier : IStartupVerifier
    {
        public string Name => "AlwaysFails";

        public ValueTask VerifyAsync(
            StartupVerificationContext context, IServiceProvider scopedServices, CancellationToken cancellationToken)
        {
            context.AddFailure("test.cheap_failure", "A cheap configuration check failed.");
            return ValueTask.CompletedTask;
        }
    }
}
