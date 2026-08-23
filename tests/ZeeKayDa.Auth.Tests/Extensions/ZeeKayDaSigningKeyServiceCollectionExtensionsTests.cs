using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

/// <summary>
/// Exercises <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource{TSource}"/>:
/// registration idempotency with respect to the ring, and that a source type defined entirely
/// outside this framework's own assemblies — using only <see cref="ISigningKeySource"/>'s public
/// members, no <c>InternalsVisibleTo</c> grant relied on — registers through the same public call.
/// </summary>
public sealed class ZeeKayDaSigningKeyServiceCollectionExtensionsTests
{
    /// <summary>
    /// Models a signing key source defined by a third party from its own package: it implements
    /// only the public members of <see cref="ISigningKeySource"/>.
    /// </summary>
    private sealed class ExternalSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            using var rsa = RSA.Create(2048);
            var current = new SourceKey(
                new KeyId("current"), SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));

            return new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_registers_an_ISigningKeyRing()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_registers_the_source()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeySource>().Should().BeOfType<ExternalSigningKeySource>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_called_twice_registers_the_ring_exactly_once()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        services.Should().ContainSingle(d => d.ServiceType == typeof(ISigningKeyRing));
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_registers_the_startup_verifier()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupVerifier>().Should().ContainSingle(v => v is SigningKeyRingStartupVerifier);
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_throws_ArgumentNullException_when_services_is_null()
    {
        IServiceCollection services = null!;

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<ArgumentNullException>();
    }
}
