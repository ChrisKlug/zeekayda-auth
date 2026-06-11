using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthServiceCollectionExtensionsTests
{
    [Fact]
    public void AddZeeKayDaAuth_AlwaysRegistersCompositeClientSecretHasher()
    {
        // Verify the descriptor is always present so users get a clear "missing hasher"
        // error on first use rather than a generic "service not registered" DI failure.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().Contain(sd => sd.ServiceType == typeof(CompositeClientSecretHasher));
    }

    [Fact]
    public void AddZeeKayDaAuth_NullServices_ThrowsArgumentNullException()
    {
        var act = () => ((IServiceCollection)null!).AddZeeKayDaAuth(_ => { });

        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void AddZeeKayDaAuth_NullConfigure_ThrowsArgumentNullException()
    {
        var act = () => new ServiceCollection().AddZeeKayDaAuth(null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public async Task AddZeeKayDaAuth_NoScopeRepositoryConfigured_RegistersInMemoryRepositorySeededWithStandardScopes()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var serviceProvider = services.BuildServiceProvider();

        var repository = serviceProvider.GetRequiredService<IScopeRepository>();
        var scopes = await repository.GetScopesAsync(TestContext.Current.CancellationToken);

        repository.Should().BeOfType<InMemoryScopeRepository>();
        scopes.Select(scope => scope.Name).Should().Equal(StandardScopes.All.Select(scope => scope.Name));
    }

    [Fact]
    public async Task AddZeeKayDaAuth_PreRegisteredScopeRepository_IsNotOverridden()
    {
        var services = new ServiceCollection();
        var preRegisteredRepository = new InMemoryScopeRepository([StandardScopes.OpenId]);

        services.AddSingleton<IScopeRepository>(preRegisteredRepository);
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        using var serviceProvider = services.BuildServiceProvider();

        var resolvedRepository = serviceProvider.GetRequiredService<IScopeRepository>();
        var scopes = await resolvedRepository.GetScopesAsync(TestContext.Current.CancellationToken);

        resolvedRepository.Should().BeSameAs(preRegisteredRepository);
        scopes.Select(scope => scope.Name).Should().Equal(StandardScopes.OpenId.Name);
    }
}
