using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ScopePresenceStartupValidatorTests
{
    private static (ScopePresenceStartupValidator Sut, ServiceProvider Provider) BuildSut(IScopeRepository repository)
    {
        var services = new ServiceCollection();
        services.AddSingleton(repository);
        var provider = services.BuildServiceProvider();
        return (new ScopePresenceStartupValidator(), provider);
    }

    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_openid_scope_is_present()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([StandardScopes.OpenId]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_completes_when_openid_scope_is_among_several_scopes()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(StandardScopes.All));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_openid_scope_is_missing()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([StandardScopes.Profile]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_with_code_scopes_openid_missing()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("scopes.openid_missing");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_with_message_containing_openid_scope_name()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Single().Message.Should().Contain(StandardScopes.OpenId.Name);
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_for_custom_repository_without_openid_scope()
    {
        var (sut, provider) = BuildSut(new CustomRepositoryWithoutOpenId());
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
    }

    [Fact]
    public void Name_is_ScopePresence()
    {
        var sut = new ScopePresenceStartupValidator();

        sut.Name.Should().Be("ScopePresence");
    }

    private sealed class CustomRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }
}
