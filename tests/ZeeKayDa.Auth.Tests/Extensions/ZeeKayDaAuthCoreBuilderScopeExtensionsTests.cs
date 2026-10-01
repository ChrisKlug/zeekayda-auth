using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class ZeeKayDaAuthCoreBuilderScopeExtensionsTests
{
    [Fact]
    public async Task AddInMemoryScopes_replaces_the_default_scope_repository()
    {
        var services = new ServiceCollection();
        var custom = new ScopeDefinition { Name = "orders.read" };

        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://test.example.com")
            .AddInMemoryScopes([StandardScopes.OpenId, custom]);

        services.Should().ContainSingle(descriptor => descriptor.ServiceType == typeof(IScopeRepository));
        using var provider = services.BuildServiceProvider();
        var scopes = await provider.GetRequiredService<IScopeRepository>()
            .GetScopesAsync(TestContext.Current.CancellationToken);

        scopes.Should().BeEquivalentTo([StandardScopes.OpenId, custom]);
    }
}
