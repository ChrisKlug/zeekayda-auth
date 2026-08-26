using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The client-registration subset check is only as good as the order the startup verifiers run in:
/// the ring must have read its source before client registrations are validated against the
/// advertised set. That order is registration order, and nothing but these tests holds it in place.
/// </summary>
public sealed class StartupVerifierOrderingTests
{
    [Fact]
    public void SigningKeyRingStartupVerifier_is_registered_before_ClientRepositoryStartupActivator()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com");
        services.AddZeeKayDaSigningKeySource<StubSigningKeySource>();

        AssertRingIsVerifiedFirst(services);
    }

    [Fact]
    public void SigningKeyRingStartupVerifier_is_registered_first_when_the_source_is_registered_first()
    {
        // What a provider package's sample looks like: the signing registration comes before
        // AddZeeKayDaAuth(). TryAddEnumerable keeps the verifier at its first registration
        // position, so the order must hold either way round.
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<StubSigningKeySource>();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com");

        AssertRingIsVerifiedFirst(services);
    }

    private static void AssertRingIsVerifiedFirst(IServiceCollection services)
    {
        var verifiers = services
            .Where(d => d.ServiceType == typeof(IStartupVerifier))
            .Select(d => d.ImplementationType)
            .ToList();

        var ringIndex = verifiers.IndexOf(typeof(SigningKeyRingStartupVerifier));
        var clientIndex = verifiers.IndexOf(typeof(ClientRepositoryStartupActivator));

        ringIndex.Should().BeGreaterThanOrEqualTo(0);
        clientIndex.Should().BeGreaterThanOrEqualTo(0);
        ringIndex.Should().BeLessThan(clientIndex,
            "client registrations are validated against the advertised algorithms, which do not " +
            "exist until the ring has read its source");
    }

    private sealed class StubSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
