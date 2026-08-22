using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="AdvertisedSigningAlgorithmVerifier"/> in isolation: the failure raised when
/// an advertised algorithm has no key at all, the warning raised when its only key is
/// retirement-window-only, the failure raised when a producible algorithm (active or staged) is not
/// advertised, the silent no-op when nothing is registered at all, and the deliberate exclusion of
/// retirement-window-only keys from the reverse direction.
/// </summary>
public sealed class AdvertisedSigningAlgorithmVerifierTests
{
    // Cached once and reused across every descriptor built below — key generation is slow and
    // these tests never inspect the key material itself, only each descriptor's Algorithm.
    private static readonly RSA SharedRsa = RSA.Create(2048);
    private static readonly ECDsa SharedEcP256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly ECDsa SharedEcP384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

    private static SigningKeyDescriptor DescriptorFor(SigningAlgorithm algorithm, string kid) => algorithm switch
    {
        SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512 =>
            new SigningKeyDescriptor(kid, algorithm, SharedRsa.ExportParameters(false)),
        SigningAlgorithm.ES256 => new SigningKeyDescriptor(kid, algorithm, SharedEcP256.ExportParameters(false)),
        SigningAlgorithm.ES384 => new SigningKeyDescriptor(kid, algorithm, SharedEcP384.ExportParameters(false)),
        _ => throw new NotSupportedException($"add a cached key pair for {algorithm} if a test needs it"),
    };

    /// <summary>
    /// A fake <see cref="IJwtSigningService"/> for verifier tests. <paramref name="snapshot"/> drives
    /// <see cref="ISigningKeyProducibility.GetProducibilityAsync"/> directly.
    /// <paramref name="allKeyAlgorithms"/> drives <see cref="IJwtSigningService.GetSigningKeysAsync"/> —
    /// the full active+staged+retirement-window listing — and defaults to exactly the snapshot's
    /// producible set (active plus staged) when omitted, i.e. "no separate retirement-window keys
    /// exist" unless a test says otherwise.
    /// </summary>
    private sealed class FakeSigningService(
        SigningKeyProducibilitySnapshot snapshot,
        IReadOnlyCollection<SigningAlgorithm>? allKeyAlgorithms = null)
        : IJwtSigningService, ISigningKeyProducibility
    {
        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
        {
            var algorithms = allKeyAlgorithms
                ?? new[] { snapshot.ActiveAlgorithm }.Concat(snapshot.StagedAlgorithms).Distinct();

            IReadOnlyList<SigningKeyDescriptor> descriptors = [.. algorithms.Select((a, i) => DescriptorFor(a, $"k{i}"))];
            return ValueTask.FromResult(descriptors);
        }

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningKeyProducibilitySnapshot> GetProducibilityAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(snapshot);
    }

    private sealed class FakeSigningServiceWithoutProducibility : IJwtSigningService
    {
        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => throw new NotImplementedException();

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    /// <summary>
    /// Builds a producibility snapshot for a fake provider: <paramref name="active"/> is the
    /// currently active signer's algorithm, and <paramref name="stagedAlgorithms"/> are the
    /// algorithms of any not-yet-active keys. A retirement-window-only key never appears here at
    /// all — it is simply omitted, exactly as the real <see cref="JwtSigningService{TOptions}"/>
    /// implementation excludes it.
    /// </summary>
    private static SigningKeyProducibilitySnapshot Producibility(
        SigningAlgorithm active, params SigningAlgorithm[] stagedAlgorithms)
        => new(active, new HashSet<SigningAlgorithm>(stagedAlgorithms));

    private static ServiceProvider BuildProvider(IJwtSigningService? signingService)
    {
        var services = new ServiceCollection();
        if (signingService is not null)
            services.AddSingleton(signingService);

        return services.BuildServiceProvider();
    }

    private static AdvertisedSigningAlgorithmVerifier BuildSut(params SigningAlgorithm[] advertised)
    {
        var options = new AuthorizationServerOptions { Issuer = "https://test.example.com" };
        options.IdToken.SigningAlgValuesSupported = advertised;

        return new AdvertisedSigningAlgorithmVerifier(Options.Create(options));
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_the_advertised_algorithm_has_no_matching_key()
    {
        using var provider = BuildProvider(new FakeSigningService(Producibility(SigningAlgorithm.ES256)));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            f.Message.Contains("RS256") &&
            f.Message.Contains("ES256"));
    }

    [Fact]
    public async Task VerifyAsync_is_a_no_op_when_no_IJwtSigningService_is_registered()
    {
        using var provider = BuildProvider(signingService: null);
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        var act = async () => await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        await act.Should().NotThrowAsync();
        context.Failures.Should().BeEmpty();
        context.Warnings.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_records_a_warning_and_skips_the_check_when_the_signing_service_does_not_implement_producibility()
    {
        using var provider = BuildProvider(new FakeSigningServiceWithoutProducibility());
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().ContainSingle(w => w.Code == "signing.advertised_algorithm_check_skipped");
    }

    [Fact]
    public async Task VerifyAsync_records_no_failure_when_the_advertised_algorithm_has_a_matching_key()
    {
        // Also the still-valid retirement-window case: a retiring key (a previously-advertised
        // algorithm now on its way out) never appears in the producibility snapshot at all, so its
        // absence from SigningAlgValuesSupported does not need to be modelled explicitly here.
        using var provider = BuildProvider(new FakeSigningService(Producibility(SigningAlgorithm.RS256)));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_records_a_single_failure_naming_the_unavailable_algorithm_and_the_covered_set()
    {
        using var provider = BuildProvider(new FakeSigningService(Producibility(SigningAlgorithm.RS256)));
        var sut = BuildSut(SigningAlgorithm.RS256, SigningAlgorithm.ES384);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            f.Message.Contains("ES384") &&
            f.Message.Contains("RS256"));
    }

    [Fact]
    public async Task VerifyAsync_names_the_active_algorithm_as_producible_even_with_no_staged_keys()
    {
        // A snapshot's producible set always contains at least ActiveAlgorithm by construction, so
        // the failure description can never degenerate to "no algorithms at all".
        using var provider = BuildProvider(
            new FakeSigningService(new SigningKeyProducibilitySnapshot(SigningAlgorithm.RS256, new HashSet<SigningAlgorithm>())));
        var sut = BuildSut(SigningAlgorithm.ES256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().Contain(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            f.Message.Contains("ES256") &&
            f.Message.Contains("RS256"));
    }

    [Fact]
    public async Task VerifyAsync_records_no_failure_but_a_warning_when_the_only_key_for_an_advertised_algorithm_is_retirement_window_only()
    {
        // Rotated RS256 -> ES256; the operator correctly widened SigningAlgValuesSupported to
        // [RS256, ES256] during the transition (satisfying the active-must-be-advertised direction)
        // but hasn't yet dropped RS256 now that it's retirement-window-only. That RS256 key cannot
        // sign a new token — yet a normal migration passes through exactly this state for as long as
        // the retirement window stays open, so it must not hard-fail startup. It still deserves a
        // warning: leaving RS256 advertised after the window closes becomes a hard failure once the
        // key itself is gone.
        using var provider = BuildProvider(new FakeSigningService(
            Producibility(SigningAlgorithm.ES256),
            allKeyAlgorithms: [SigningAlgorithm.RS256, SigningAlgorithm.ES256]));
        var sut = BuildSut(SigningAlgorithm.RS256, SigningAlgorithm.ES256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
        context.Warnings.Should().ContainSingle(w =>
            w.Code == "signing.advertised_algorithm_retirement_window_only" &&
            w.Args.Contains("RS256"));
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_an_advertised_algorithm_has_no_key_at_all_not_even_retiring()
    {
        // Distinguishes the true "no key at all" case (still a hard failure) from the
        // retirement-window-only case above (a warning): RS256 is advertised and absent from both
        // the producible set AND the full key listing (allKeyAlgorithms), so there has never been an
        // RS256 key of any kind, retiring or otherwise.
        using var provider = BuildProvider(new FakeSigningService(
            Producibility(SigningAlgorithm.ES256),
            allKeyAlgorithms: [SigningAlgorithm.ES256]));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Warnings.Should().BeEmpty();
        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            f.Message.Contains("RS256"));
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_the_active_key_signs_with_an_algorithm_that_is_not_advertised()
    {
        // The exact Fix 2 exploit: the active key signs RS256, but only ES256 (a staged key not
        // yet active) is advertised. The staged key being producible-soon satisfies the advertised
        // -> producible direction, so only the active-but-unadvertised failure should fire.
        using var provider = BuildProvider(
            new FakeSigningService(Producibility(SigningAlgorithm.RS256, SigningAlgorithm.ES256)));
        var sut = BuildSut(SigningAlgorithm.ES256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.producible_algorithm_not_advertised" &&
            f.Message.Contains("RS256") &&
            f.Message.Contains("(active)") &&
            f.Message.Contains("ES256"));
    }

    [Fact]
    public async Task VerifyAsync_records_a_failure_when_a_staged_algorithm_is_not_advertised()
    {
        // The full-equality contract added by Fix 2: the active key (RS256) is advertised, but a
        // staged key's algorithm (ES256) is not. Before this fix this passed — an operator could
        // stage a new algorithm without advertising it, and it would silently start signing once
        // the staged key activated tomorrow with no further check ever running.
        using var provider = BuildProvider(
            new FakeSigningService(Producibility(SigningAlgorithm.RS256, SigningAlgorithm.ES256)));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.producible_algorithm_not_advertised" &&
            f.Message.Contains("ES256") &&
            f.Message.Contains("(staged)"));
    }

    [Fact]
    public async Task VerifyAsync_records_no_failure_when_a_retiring_algorithm_is_no_longer_advertised()
    {
        // A retirement-window-only key never appears in the producibility snapshot at all (see
        // Producibility's doc comment), so its algorithm not being advertised any more is normal
        // migration state, unaffected by either direction of the check.
        using var provider = BuildProvider(new FakeSigningService(Producibility(SigningAlgorithm.ES256)));
        var sut = BuildSut(SigningAlgorithm.ES256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public void Name_is_AdvertisedSigningAlgorithms()
    {
        var sut = BuildSut(SigningAlgorithm.RS256);

        sut.Name.Should().Be("AdvertisedSigningAlgorithms");
    }
}
