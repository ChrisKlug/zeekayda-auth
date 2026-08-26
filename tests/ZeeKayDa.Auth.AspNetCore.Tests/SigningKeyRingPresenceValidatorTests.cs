using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Exercises <see cref="SigningKeyRingPresenceValidator"/> — the check that makes a host with no
/// signing key source fail to start, rather than fail the first discovery request when the derived
/// <c>id_token_signing_alg_values_supported</c> has no key set to derive from.
/// </summary>
public sealed class SigningKeyRingPresenceValidatorTests
{
    private sealed class StubSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_a_signing_key_source_is_registered()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<StubSigningKeySource>();
        using var provider = services.BuildServiceProvider();
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_no_signing_key_source_is_registered()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.key_ring.missing");
    }

    [Fact]
    public async Task VerifyAsync_names_a_registration_the_operator_can_call()
    {
        var services = new ServiceCollection();
        using var provider = services.BuildServiceProvider();
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Single().Message.Should().Contain("AddInMemoryDevelopmentJwtSigningKeys");
        context.Failures.Single().Message.Should().Contain("AddZeeKayDaSigningKeySource");
    }

    [Fact]
    public async Task VerifyAsync_still_checks_on_a_container_without_IServiceProviderIsService()
    {
        // A third-party DI container replacing the default one. The check resolves the ring rather
        // than asking IServiceProviderIsService about it, so it reports truthfully here instead of
        // skipping itself.
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(
            context, new NoServiceProviderIsServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.key_ring.missing");
    }

    [Fact]
    public async Task VerifyAsync_reports_no_failure_when_the_ring_factory_itself_throws()
    {
        // "Registered but broken" is a different answer from "absent"; the ring's own activator
        // reports the failure in the next phase. Driven through a container with no
        // IServiceProviderIsService, because that is the only path that resolves the ring at all —
        // the default container answers without invoking the factory.
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<StubSigningKeySource>(_ => null!);
        using var inner = services.BuildServiceProvider();
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(
            context, new ResolvingOnlyServiceProvider(inner), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_SigningKeyRingPresence()
    {
        var sut = new SigningKeyRingPresenceValidator();

        sut.Name.Should().Be("SigningKeyRingPresence");
    }

    private sealed class NoServiceProviderIsServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    /// <summary>Forwards every resolution but withholds <see cref="IServiceProviderIsService"/>.</summary>
    private sealed class ResolvingOnlyServiceProvider(IServiceProvider inner) : IServiceProvider
    {
        public object? GetService(Type serviceType)
            => serviceType == typeof(IServiceProviderIsService) ? null : inner.GetService(serviceType);
    }
}

