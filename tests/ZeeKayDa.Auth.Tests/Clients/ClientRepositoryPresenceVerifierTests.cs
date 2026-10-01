using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientRepositoryPresenceVerifierTests
{
    private sealed class FakeIsService(bool result) : IServiceProviderIsService
    {
        public bool IsService(Type serviceType) => result;
    }

    private sealed class FakeProvider(IServiceProviderIsService? isService) : IServiceProvider
    {
        public object? GetService(Type serviceType)
            => serviceType == typeof(IServiceProviderIsService) ? isService : null;
    }

    /// <summary>A container without <see cref="IServiceProviderIsService"/>, resolving only what it is given.</summary>
    private sealed class ResolvingOnlyProvider(Func<object?> repository) : IServiceProvider
    {
        public object? GetService(Type serviceType)
            => serviceType == typeof(IClientRepository) ? repository() : null;
    }

    private sealed class StubRepository : IClientRepository
    {
        public Task<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken cancellationToken = default)
            => Task.FromResult<IClientRegistration?>(null);
    }

    private static async Task<StartupVerificationContext> VerifyAsync(IServiceProvider services)
    {
        var context = new StartupVerificationContext();
        await new ClientRepositoryPresenceVerifier(services).VerifyAsync(
            context, TestContext.Current.CancellationToken);
        return context;
    }

    [Fact]
    public async Task VerifyAsync_adds_client_repository_missing_on_a_container_without_IServiceProviderIsService()
    {
        var context = await VerifyAsync(new ResolvingOnlyProvider(() => null));

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("client.repository.missing");
    }

    [Fact]
    public async Task VerifyAsync_finds_a_repository_by_resolving_on_a_container_without_IServiceProviderIsService()
    {
        var context = await VerifyAsync(new ResolvingOnlyProvider(() => new StubRepository()));

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_leaves_a_broken_repository_to_the_activator_on_a_container_without_IServiceProviderIsService()
    {
        var context = await VerifyAsync(new ResolvingOnlyProvider(
            () => throw new ZeeKayDaConfigurationException(new ZeeKayDaConfigurationFailure("x", "broken"))));

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_client_repository_missing_when_IClientRepository_is_not_registered()
    {
        var context = await VerifyAsync(new FakeProvider(new FakeIsService(false)));

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("client.repository.missing");
    }

    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_IClientRepository_is_registered()
    {
        var context = await VerifyAsync(new FakeProvider(new FakeIsService(true)));

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_does_not_construct_the_repository()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IClientRepository>(_ => throw new InvalidOperationException("must not be resolved"));
        using var provider = services.BuildServiceProvider();

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty();
    }
}
