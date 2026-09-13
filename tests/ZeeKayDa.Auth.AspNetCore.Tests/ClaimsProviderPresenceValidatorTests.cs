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
    public async Task VerifyAsync_skips_the_check_when_the_container_cannot_answer_IsService()
    {
        var sut = new ClaimsProviderPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, new EmptyServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    private sealed class EmptyServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
