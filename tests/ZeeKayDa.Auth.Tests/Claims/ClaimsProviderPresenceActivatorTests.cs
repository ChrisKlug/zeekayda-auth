using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Tests.Claims;

/// <summary>
/// The claims seam is mandatory with no default. A real <see cref="ServiceProvider"/> answers
/// <see cref="IServiceProviderIsService"/> from its own engine, so the provider is registered or
/// omitted through the public builder method and the verifier reads the truth.
/// </summary>
public sealed class ClaimsProviderPresenceActivatorTests
{
    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_a_provider_is_registered()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthCoreBuilder(services).AddClaimsProvider<NoClaimsProvider>();
        using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new ClaimsProviderPresenceActivator(provider).VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_naming_the_registration_when_no_provider_is_registered()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new ClaimsProviderPresenceActivator(provider).VerifyAsync(context, TestContext.Current.CancellationToken);

        var failure = context.Failures.Should().ContainSingle().Subject;
        failure.Code.Should().Be("claims.provider.missing");
        failure.Message.Should().Contain("AddClaimsProvider");
    }

    [Fact]
    public async Task A_container_that_cannot_answer_IsService_is_asked_to_resolve_the_provider_and_still_fails_without_one()
    {
        // A third-party container without IServiceProviderIsService must not be the one place the
        // mandatory seam can be skipped.
        var context = new StartupVerificationContext();

        await new ClaimsProviderPresenceActivator(new ResolvingOnlyServiceProvider(provider: null)).VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("claims.provider.missing");
    }

    [Fact]
    public async Task A_container_that_cannot_answer_IsService_passes_when_it_resolves_a_provider()
    {
        var context = new StartupVerificationContext();

        await new ClaimsProviderPresenceActivator(new ResolvingOnlyServiceProvider(new NoClaimsProvider())).VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task A_container_that_cannot_answer_IsService_resolves_a_scoped_provider_from_the_phase_scope()
    {
        var services = new ServiceCollection();
        services.AddScoped<IClaimsProvider, NoClaimsProvider>();
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        await using var scope = provider.CreateAsyncScope();
        var context = new StartupVerificationContext();

        await new ClaimsProviderPresenceActivator(new WithholdingIsService(scope.ServiceProvider))
            .VerifyAsync(context, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    /// <summary>Forwards every resolution but withholds <see cref="IServiceProviderIsService"/>.</summary>
    private sealed class WithholdingIsService(IServiceProvider inner) : IServiceProvider
    {
        public object? GetService(Type serviceType) =>
            serviceType == typeof(IServiceProviderIsService) ? null : inner.GetService(serviceType);
    }

    /// <summary>A container with no <see cref="IServiceProviderIsService"/>, answering only a direct resolution of the provider.</summary>
    private sealed class ResolvingOnlyServiceProvider(NoClaimsProvider? provider) : IServiceProvider
    {
        public object? GetService(Type serviceType) =>
            serviceType == typeof(IClaimsProvider) ? provider : null;
    }
}
