using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ClientRepositoryStartupActivatorTests
{
    [Fact]
    public async Task VerifyAsync_adds_a_warning_when_AddInMemoryClients_was_called_but_custom_repository_shadows_it()
    {
        var services = new ServiceCollection();
        // Simulate that AddInMemoryClients was called — this registers InMemoryClientRegistrationOptions.
        services.AddSingleton(new InMemoryClientRegistrationOptions());
        // Register a custom IClientRepository that is NOT InMemoryClientRepository.
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Args.Should().Contain(typeof(CustomClientRepository).FullName);
    }

    [Fact]
    public async Task VerifyAsync_adds_a_warning_with_code_clients_inmemory_shadowed()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new InMemoryClientRegistrationOptions());
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("clients.inmemory_shadowed");
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_a_warning_when_InMemoryClientRepository_is_the_resolved_repository()
    {
        // When AddInMemoryClients was NOT called, InMemoryClientRegistrationOptions is not
        // registered and GetService<InMemoryClientRegistrationOptions>() returns null.
        // The warning branch is therefore never entered, regardless of the IClientRepository type.
        var services = new ServiceCollection();
        services.AddSingleton<IClientRepository, CustomClientRepository>();

        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_propagates_the_exception_when_IClientRepository_resolution_fails()
    {
        var services = new ServiceCollection();
        // IClientRepository is not registered — GetRequiredService must throw and the exception
        // must flow out of VerifyAsync unmodified; nothing here catches it.
        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public void Name_is_ClientRepositoryActivation()
    {
        var sut = new ClientRepositoryStartupActivator();

        sut.Name.Should().Be("ClientRepositoryActivation");
    }

    private sealed class CustomClientRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IClientRegistration?>(null);
    }
}
