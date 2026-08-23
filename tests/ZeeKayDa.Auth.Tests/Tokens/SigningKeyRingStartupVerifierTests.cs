using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyRingStartupVerifier"/>: delegation to a registered
/// <see cref="ISigningKeyRing"/>, and the silent no-op when nothing is registered — the shape
/// <c>AddZeeKayDaSigningKeys()</c> (health check only, no ring) relies on to still start.
/// </summary>
public sealed class SigningKeyRingStartupVerifierTests
{
    private sealed class FakeSigningKeyRing(Func<CancellationToken, ValueTask> initialize) : ISigningKeyRing
    {
        public int InitializeAsyncCallCount { get; private set; }

        public SigningKeySet Current => throw new NotSupportedException();

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state, Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        async ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken)
        {
            InitializeAsyncCallCount++;
            await initialize(cancellationToken);
        }

        SigningKeySet? ISigningKeyRing.CurrentOrNull => null;
    }

    private static ServiceProvider BuildProvider(ISigningKeyRing? ring)
    {
        var services = new ServiceCollection();
        if (ring is not null)
            services.AddSingleton(ring);

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task VerifyAsync_delegates_to_the_registered_ISigningKeyRing()
    {
        var ring = new FakeSigningKeyRing(_ => ValueTask.CompletedTask);
        using var provider = BuildProvider(ring);
        var sut = new SigningKeyRingStartupVerifier();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        ring.InitializeAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task VerifyAsync_propagates_a_failure_from_InitializeAsync_unmodified()
    {
        var ring = new FakeSigningKeyRing(_ => throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure("signing.no_current_key", "Simulated failure.")));
        using var provider = BuildProvider(ring);
        var sut = new SigningKeyRingStartupVerifier();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_current_key*");
    }

    [Fact]
    public async Task VerifyAsync_is_a_no_op_when_no_ISigningKeyRing_is_registered()
    {
        using var provider = BuildProvider(ring: null);
        var sut = new SigningKeyRingStartupVerifier();
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_SigningKeyRing()
    {
        var sut = new SigningKeyRingStartupVerifier();

        sut.Name.Should().Be("SigningKeyRing");
    }
}
