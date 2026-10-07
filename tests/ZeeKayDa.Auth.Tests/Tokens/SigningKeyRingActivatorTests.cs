using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyRingActivator"/>: delegation to a registered
/// <see cref="SigningKeyRing"/>, the silent no-op when nothing is registered — the shape
/// <c>AddZeeKayDaSigningKeys()</c> (health check only, no ring) relies on to still start — and the
/// RS256 warning OpenID Connect Discovery calls for.
/// </summary>
public sealed class SigningKeyRingActivatorTests
{
    private static ServiceProvider BuildProvider(SigningKeyRing? ring)
    {
        var services = new ServiceCollection();
        if (ring is not null)
            services.AddSingleton(ring);

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task VerifyAsync_delegates_to_the_registered_SigningKeyRing()
    {
        using var ring = TestSigningKeys.Uninitialized(SigningAlgorithm.RS256);
        using var provider = BuildProvider(ring);
        var context = new StartupVerificationContext();

        await ActivatorUtilities.CreateInstance<SigningKeyRingActivator>(provider).VerifyAsync(context, TestContext.Current.CancellationToken);

        ring.CurrentOrNull.Should().NotBeNull();
    }

    [Fact]
    public async Task VerifyAsync_propagates_a_failure_from_InitializeAsync_unmodified()
    {
        using var ring = TestSigningKeys.Failing(
            new ZeeKayDaConfigurationFailure("signing.no_current_key", "Simulated failure."));
        using var provider = BuildProvider(ring);
        var context = new StartupVerificationContext();

        var act = async () => await ActivatorUtilities.CreateInstance<SigningKeyRingActivator>(provider).VerifyAsync(context, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*no_current_key*");
    }

    [Fact]
    public async Task VerifyAsync_is_a_no_op_when_no_SigningKeyRing_is_registered()
    {
        using var provider = BuildProvider(ring: null);
        var context = new StartupVerificationContext();

        var act = async () => await ActivatorUtilities.CreateInstance<SigningKeyRingActivator>(provider).VerifyAsync(context, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        context.Failures.Should().BeEmpty();
    }

    // ── RS256 (OpenID Connect Discovery 1.0 §3) ─────────────────────────────────────────────────

    private static async Task<StartupVerificationContext> VerifyAsync(ServiceProvider provider)
    {
        var context = new StartupVerificationContext();
        await ActivatorUtilities.CreateInstance<SigningKeyRingActivator>(provider)
            .VerifyAsync(context, TestContext.Current.CancellationToken);
        return context;
    }

    [Fact]
    public async Task VerifyAsync_warns_when_the_advertised_set_omits_RS256()
    {
        // OpenID Connect Discovery 1.0 section 3 requires RS256 in
        // id_token_signing_alg_values_supported.
        using var provider = BuildProvider(TestSigningKeys.Ring(SigningAlgorithm.ES256));

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().ContainSingle()
            .Which.Code.Should().Be("signing.advertised_algorithms.rs256_absent");
    }

    [Fact]
    public async Task VerifyAsync_warns_nothing_when_the_source_signs_RS256()
    {
        using var provider = BuildProvider(TestSigningKeys.Ring(SigningAlgorithm.RS256, keyCount: 3));

        var context = await VerifyAsync(provider);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }
}
