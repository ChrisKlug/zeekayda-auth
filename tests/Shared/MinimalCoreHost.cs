using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// A Core-only host with everything the framework's presence checks demand, so a test can run
/// the real startup path and observe only the feature it registers on top.
/// </summary>
/// <remarks>Linked into every test project that builds a host without ASP.NET Core.</remarks>
internal static class MinimalCoreHost
{
    internal const string Issuer = "https://issuer.test";

    internal static ZeeKayDaAuthBuilder AddMinimalZeeKayDaAuthCore(this IServiceCollection services)
    {
        services.AddSingleton<IHostEnvironment>(new DevelopmentHostEnvironment());
        return services
            .AddZeeKayDaAuthCore(options => options.Issuer = Issuer)
            .AddInMemoryClients(_ => { })
            .AddClaimsProvider<NoClaimsProvider>()
            .AddInMemoryStores();
    }

    private sealed class DevelopmentHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed class NoClaimsProvider : IClaimsProvider
    {
        public Task<ClaimsResolutionResult> GetClaimsAsync(ClaimsProviderContext context, CancellationToken cancellationToken = default) =>
            Task.FromResult<ClaimsResolutionResult>(new ClaimsResolutionResult.Resolved { Claims = [] });
    }
}
