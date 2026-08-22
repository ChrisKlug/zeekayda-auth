using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="AdvertisedSigningAlgorithmVerifier"/> in isolation: the failure raised when
/// an advertised algorithm has no matching key, the silent no-op when nothing is registered at all,
/// and the deliberate one-directional asymmetry that allows a key for a non-advertised algorithm
/// (a retirement-window key) to pass without complaint.
/// </summary>
public sealed class AdvertisedSigningAlgorithmVerifierTests
{
    private static readonly RSA Rsa = RSA.Create(2048);
    private static readonly ECDsa Ec256 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly ECDsa Ec384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

    private sealed class FakeSigningService(IReadOnlyList<SigningKeyDescriptor> keys) : IJwtSigningService
    {
        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(CancellationToken cancellationToken = default)
            => ValueTask.FromResult(keys);

        public ValueTask<SigningResult> SignAsync(ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private static SigningKeyDescriptor RsaKey(SigningAlgorithm algorithm, string kid = "rsa-1")
        => new(kid, algorithm, Rsa.ExportParameters(false));

    private static SigningKeyDescriptor EcKey(SigningAlgorithm algorithm, string kid = "ec-1")
        => new(kid, algorithm, algorithm == SigningAlgorithm.ES384 ? Ec384.ExportParameters(false) : Ec256.ExportParameters(false));

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
        using var provider = BuildProvider(new FakeSigningService([EcKey(SigningAlgorithm.ES256)]));
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
    public async Task VerifyAsync_records_no_failure_when_the_advertised_algorithm_has_a_matching_key()
    {
        using var provider = BuildProvider(new FakeSigningService([RsaKey(SigningAlgorithm.RS256)]));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_ignores_a_key_whose_algorithm_is_not_advertised()
    {
        using var provider = BuildProvider(new FakeSigningService(
        [
            RsaKey(SigningAlgorithm.RS256),
            EcKey(SigningAlgorithm.ES256),
        ]));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty(
            "a key for an algorithm that is no longer advertised is normal retirement-window state, " +
            "not a misconfiguration — the check only runs advertised -> producible, never the reverse");
    }

    [Fact]
    public async Task VerifyAsync_records_a_single_failure_naming_the_unavailable_algorithm_and_the_covered_set()
    {
        using var provider = BuildProvider(new FakeSigningService([RsaKey(SigningAlgorithm.RS256)]));
        var sut = BuildSut(SigningAlgorithm.RS256, SigningAlgorithm.ES384);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            f.Message.Contains("ES384") &&
            f.Message.Contains("RS256"));
    }

    [Fact]
    public async Task VerifyAsync_describes_an_empty_key_set_without_empty_brackets()
    {
        using var provider = BuildProvider(new FakeSigningService([]));
        var sut = BuildSut(SigningAlgorithm.RS256);
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle(f =>
            f.Code == "signing.advertised_algorithm_unavailable" &&
            !f.Message.Contains("[]") &&
            f.Message.Contains("no algorithms at all"));
    }

    [Fact]
    public void Name_is_AdvertisedSigningAlgorithms()
    {
        var sut = BuildSut(SigningAlgorithm.RS256);

        sut.Name.Should().Be("AdvertisedSigningAlgorithms");
    }
}
