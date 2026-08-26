using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

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

    private sealed class CustomClientRepository : IClientRepository
    {
        public ValueTask<IClientRegistration?> FindByClientIdAsync(
            string clientId,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IClientRegistration?>(null);
    }

    // ── Asking the signing key ring for the key set (#499) ───────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_initializes_the_signing_key_ring_before_validating_clients()
    {
        // The client subset check validates against the advertised algorithms, so it asks for them
        // rather than assuming it runs after the ring's own activator.
        var ring = new RecordingSigningKeyRing(failure: null);
        var services = new ServiceCollection();
        services.AddSingleton<IClientRepository, CustomClientRepository>();
        services.AddSingleton<ISigningKeyRing>(ring);
        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        ring.EnsureInitializedCallCount.Should().Be(1);
    }

    [Fact]
    public async Task VerifyAsync_lets_a_ring_failure_propagate_rather_than_deciding_who_reports_it()
    {
        // The ring's own activator reports the same failure, and the runner collapses identical
        // failures within a phase. Catching it here would encode an assumption about what another
        // check reports — and would swallow it entirely if that check were ever absent.
        var ring = new RecordingSigningKeyRing(
            new ZeeKayDaConfigurationFailure("signing.source_unavailable", "Simulated."));
        var services = new ServiceCollection();
        services.AddSingleton<IClientRepository, CustomClientRepository>();
        services.AddSingleton<ISigningKeyRing>(ring);
        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*source_unavailable*");
    }

    [Fact]
    public async Task VerifyAsync_still_validates_clients_when_no_signing_key_ring_is_registered()
    {
        // A host that adds only the signing key health check has no ring at all.
        var services = new ServiceCollection();
        services.AddSingleton(new InMemoryClientRegistrationOptions());
        services.AddSingleton<IClientRepository, CustomClientRepository>();
        using var provider = services.BuildServiceProvider();
        var sut = new ClientRepositoryStartupActivator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle().Which.Code.Should().Be("clients.inmemory_shadowed");
    }

    private sealed class RecordingSigningKeyRing(ZeeKayDaConfigurationFailure? failure) : ISigningKeyRing
    {
        public int EnsureInitializedCallCount { get; private set; }

        public SigningKeySet Current => throw new NotSupportedException();

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state,
            Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken)
        {
            EnsureInitializedCallCount++;

            return failure is null
                ? ValueTask.CompletedTask
                : throw new ZeeKayDaConfigurationException(failure);
        }

        SigningKeySet? ISigningKeyRing.CurrentOrNull => null;
    }
}
