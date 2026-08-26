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
    public async Task VerifyAsync_does_not_resolve_the_ring_when_one_is_registered()
    {
        // Resolving ISigningKeyRing constructs the signing key source. This check must inspect the
        // container instead — a source whose construction is expensive, or which opens a handle to
        // a key store, must not be built by a presence check.
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ThrowingOnConstructionSource>();
        using var provider = services.BuildServiceProvider();
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_does_not_add_failures_when_IServiceProviderIsService_is_absent()
    {
        // A third-party DI container replacing the default one — the check is skipped rather than
        // failing with a confusing resolution error.
        var sut = new SigningKeyRingPresenceValidator();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(
            context, new NoServiceProviderIsServiceProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_SigningKeyRingPresence()
    {
        var sut = new SigningKeyRingPresenceValidator();

        sut.Name.Should().Be("SigningKeyRingPresence");
    }

    private sealed class ThrowingOnConstructionSource : ISigningKeySource
    {
        public ThrowingOnConstructionSource()
            => throw new InvalidOperationException("The presence check must not construct the source.");

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private sealed class NoServiceProviderIsServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
