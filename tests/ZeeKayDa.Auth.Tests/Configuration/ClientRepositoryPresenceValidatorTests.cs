using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class ClientRepositoryPresenceValidatorTests
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

    private static async Task<StartupVerificationContext> VerifyAsync(IServiceProvider services)
    {
        var context = new StartupVerificationContext();
        await new ClientRepositoryPresenceValidator().VerifyAsync(
            context, services, TestContext.Current.CancellationToken);
        return context;
    }

    [Fact]
    public async Task VerifyAsync_skips_the_check_when_IServiceProviderIsService_is_absent()
    {
        var context = await VerifyAsync(new FakeProvider(null));

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
