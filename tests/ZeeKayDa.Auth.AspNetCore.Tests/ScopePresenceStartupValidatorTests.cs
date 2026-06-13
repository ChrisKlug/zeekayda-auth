using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ScopePresenceStartupValidatorTests
{
    private static ScopePresenceStartupValidator BuildSut(IScopeRepository repository)
    {
        var services = new ServiceCollection();
        services.AddSingleton(repository);
        return new ScopePresenceStartupValidator(
            services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>());
    }

    [Fact]
    public async Task StartAsync_completes_without_throwing_when_openid_scope_is_present()
    {
        var sut = BuildSut(new InMemoryScopeRepository([StandardScopes.OpenId]));

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_completes_when_openid_scope_is_among_several_scopes()
    {
        var sut = BuildSut(new InMemoryScopeRepository(StandardScopes.All));

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    [Fact]
    public async Task StartAsync_throws_ZeeKayDaConfigurationException_when_openid_scope_is_missing()
    {
        var sut = BuildSut(new InMemoryScopeRepository([StandardScopes.Profile]));

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task StartAsync_throws_with_code_scopes_openid_missing()
    {
        var sut = BuildSut(new InMemoryScopeRepository([]));

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("scopes.openid_missing");
    }

    [Fact]
    public async Task StartAsync_throws_with_message_containing_openid_scope_name()
    {
        var sut = BuildSut(new InMemoryScopeRepository([]));

        var ex = await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        ex.Which.AggregatedFailures.Single().Message.Should().Contain(StandardScopes.OpenId.Name);
    }

    [Fact]
    public async Task StartAsync_throws_for_custom_repository_without_openid_scope()
    {
        var sut = BuildSut(new CustomRepositoryWithoutOpenId());

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut(new InMemoryScopeRepository([StandardScopes.OpenId]));

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }

    private sealed class CustomRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }
}
