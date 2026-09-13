using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The claims seam is mandatory with no default. A real <see cref="ServiceProvider"/> answers
/// <see cref="IServiceProviderIsService"/> from its own engine, so the provider is registered or
/// omitted through the public builder method and the verifier reads the truth.
/// </summary>
public sealed class ClaimsProviderPresenceValidatorTests
{
    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_a_provider_is_registered()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthBuilder(services).AddClaimsProvider<NoClaimsProvider>();
        using var provider = services.BuildServiceProvider();
        var sut = new ClaimsProviderPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_naming_the_registration_when_no_provider_is_registered()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        var sut = new ClaimsProviderPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        var failure = context.Failures.Should().ContainSingle().Subject;
        failure.Code.Should().Be("claims.provider.missing");
        failure.Message.Should().Contain("AddClaimsProvider");
    }

    [Fact]
    public async Task A_container_that_cannot_answer_IsService_is_asked_to_resolve_the_provider_and_still_fails_without_one()
    {
        // A third-party container without IServiceProviderIsService must not be the one place the
        // mandatory seam can be skipped.
        var sut = new ClaimsProviderPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ResolvingOnlyServiceProvider(provider: null), TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("claims.provider.missing");
    }

    [Fact]
    public async Task A_container_that_cannot_answer_IsService_passes_when_it_resolves_a_provider()
    {
        var sut = new ClaimsProviderPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new ResolvingOnlyServiceProvider(new NoClaimsProvider()), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    /// <summary>A container with no <see cref="IServiceProviderIsService"/>, answering only a direct resolution of the provider.</summary>
    private sealed class ResolvingOnlyServiceProvider(NoClaimsProvider? provider) : IServiceProvider
    {
        public object? GetService(Type serviceType) =>
            serviceType == typeof(Claims.IClaimsProvider) ? provider : null;
    }
}
