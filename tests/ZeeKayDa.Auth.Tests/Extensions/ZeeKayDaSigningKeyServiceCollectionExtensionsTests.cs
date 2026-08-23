using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

/// <summary>
/// Exercises <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource{TSource}"/>:
/// registration idempotency, the loud failure on registering a second, different source, and that
/// <see cref="ISigningKeySource"/> is not ambiently resolvable. This assembly carries an
/// <c>InternalsVisibleTo</c> grant from core, so it cannot prove a source needs no such grant —
/// <c>ZeeKayDa.Auth.FileSystem.Tests</c>' <c>ThirdPartySigningKeySourceRegistrationTests</c> proves
/// that from an assembly with no grant at all.
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

    /// <summary>A second, distinct <see cref="ISigningKeySource"/> implementation, for proving that
    /// registering a different source than one already registered fails loudly.</summary>
    private sealed class OtherExternalSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

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
    public void AddZeeKayDaSigningKeySource_does_not_register_ISigningKeySource_for_ambient_resolution()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetService<ISigningKeySource>().Should().BeNull();
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
    public void AddZeeKayDaSigningKeySource_called_twice_with_the_same_source_registers_it_exactly_once()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        services.Should().ContainSingle(d => d.ServiceType == typeof(ISigningKeySource));
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_called_with_a_different_source_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
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
