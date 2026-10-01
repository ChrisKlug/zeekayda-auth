using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Registers a ZeeKayDa.Auth server for a package's own tests, so they can run the real startup path
/// and observe only the feature the package adds.
/// </summary>
public static class ZeeKayDaAuthTestingServiceCollectionExtensions
{
    /// <summary>
    /// Calls <c>AddZeeKayDaAuthCore(configure)</c> with a valid issuer and registers everything its startup
    /// checks demand except a signing key source: an empty in-memory client set, a claims provider
    /// that returns no claims, the in-memory stores, and a <c>Development</c>
    /// <see cref="IHostEnvironment"/> when none is registered.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <returns>The <see cref="ZeeKayDaAuthBuilder"/>, for the package under test to register on.</returns>
    /// <remarks>
    /// Logging is not registered; add it the way the test wants it. Change the issuer or any other
    /// server option with <c>services.Configure&lt;AuthorizationServerOptions&gt;()</c>.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/>.</exception>
    public static ZeeKayDaAuthBuilder AddZeeKayDaAuthCoreForTesting(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IHostEnvironment>(new DevelopmentHostEnvironment());
        return services
            .AddZeeKayDaAuthCore(options => options.Issuer = "https://issuer.test")
            .AddInMemoryClients(_ => { })
            .AddClaimsProvider<NoClaimsProvider>()
            .AddInMemoryStores();
    }

    private sealed class DevelopmentHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "ZeeKayDa.Auth.TestKit";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class NoClaimsProvider : IClaimsProvider
    {
        public Task<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<ClaimsResolutionResult>(new ClaimsResolutionResult.Resolved { Claims = [] });
    }
}
