using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyRingStartupVerifier"/>: delegation to a registered
/// <see cref="ISigningKeyRing"/>, the silent no-op when nothing is registered — the shape
/// <c>AddZeeKayDaSigningKeys()</c> (health check only, no ring) relies on to still start — and the
/// reconciliation of <see cref="IdTokenOptions.AdvertisedSigningAlgorithms"/> against the key set
/// the ring built.
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

    // ── AdvertisedSigningAlgorithms reconciliation ───────────────────────────────────────────────

    /// <summary>A ring already holding a key set, as one does the moment InitializeAsync returns.</summary>
    private sealed class InitializedRing(SigningKeySet keySet) : ISigningKeyRing
    {
        public SigningKeySet Current => keySet;

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state, Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;

        SigningKeySet? ISigningKeyRing.CurrentOrNull => keySet;
    }

    private static ServiceProvider BuildProvider(SigningKeySet keySet, params SigningAlgorithm[] filter)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.IdToken.AdvertisedSigningAlgorithms = filter.Length > 0 ? [.. filter] : null;

        var services = new ServiceCollection();
        services.AddSingleton<ISigningKeyRing>(new InitializedRing(keySet));
        services.AddSingleton<IOptions<AuthorizationServerOptions>>(Options.Create(options));

        return services.BuildServiceProvider();
    }

    private static async Task<StartupVerificationContext> VerifyAsync(ServiceProvider provider)
    {
        var context = new StartupVerificationContext();
        await new SigningKeyRingStartupVerifier()
            .VerifyAsync(context, provider, TestContext.Current.CancellationToken);
        return context;
    }

    [Fact]
    public async Task VerifyAsync_fails_when_the_filter_excludes_the_signing_keys_algorithm()
    {
        using var provider = BuildProvider(
            TestSigningKeys.KeySet(SigningAlgorithm.ES256, SigningAlgorithm.RS256),
            SigningAlgorithm.RS256);

        var context = await VerifyAsync(provider);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.advertised_algorithms.excludes_signing_key");
    }

    [Fact]
    public async Task VerifyAsync_names_the_signing_key_and_the_remedy_when_the_filter_excludes_it()
    {
        using var provider = BuildProvider(
            TestSigningKeys.KeySet(SigningAlgorithm.ES256, SigningAlgorithm.RS256),
            SigningAlgorithm.RS256);

        var context = await VerifyAsync(provider);

        var message = context.Failures.Single().Message;
        message.Should().Contain("ES256");
        message.Should().Contain("current", "the failure names the key's own source id");
        message.Should().Contain("null", "the operator is told how to opt out of narrowing entirely");
    }

    [Fact]
    public async Task VerifyAsync_fails_when_the_filter_is_empty()
    {
        using var provider = BuildProvider(TestSigningKeys.KeySet(SigningAlgorithm.RS256));
        provider.GetRequiredService<IOptions<AuthorizationServerOptions>>()
            .Value.IdToken.AdvertisedSigningAlgorithms = [];

        var context = await VerifyAsync(provider);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("signing.advertised_algorithms.excludes_signing_key");
    }

    [Fact]
    public async Task VerifyAsync_accepts_a_filter_that_keeps_the_signing_keys_algorithm()
    {
        using var provider = BuildProvider(
            TestSigningKeys.KeySet(SigningAlgorithm.RS256, SigningAlgorithm.ES256),
            SigningAlgorithm.RS256);

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_warns_when_the_filter_names_an_algorithm_no_key_uses()
    {
        using var provider = BuildProvider(
            TestSigningKeys.KeySet(SigningAlgorithm.RS256),
            SigningAlgorithm.RS256, SigningAlgorithm.ES512);

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty("an entry with no key behind it is a no-op, not a lie");
        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("signing.advertised_algorithms.absent_from_key_set");
    }

    [Fact]
    public async Task VerifyAsync_reconciles_nothing_when_no_filter_is_configured()
    {
        using var provider = BuildProvider(TestSigningKeys.KeySet(SigningAlgorithm.RS256));

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_SigningKeyRing()
    {
        var sut = new SigningKeyRingStartupVerifier();

        sut.Name.Should().Be("SigningKeyRing");
    }
}
