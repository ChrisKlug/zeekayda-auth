using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Extensions;

/// <summary>
/// Proves both <c>AddZeeKayDaSigningKeySource</c> overloads work for a source type defined entirely
/// outside this framework's own assemblies. Unlike <c>ZeeKayDa.Auth.Tests</c>, this assembly carries
/// no <c>InternalsVisibleTo</c> grant from core, so this test compiling and passing is the actual
/// proof that only <see cref="ISigningKeySource"/>'s public members are needed — including for the
/// factory overload, whose one-source-per-application guard depends on the internal
/// <c>SigningKeySourceRegistration</c> type, which must therefore work with no such grant.
/// </summary>
public sealed class ThirdPartySigningKeySourceRegistrationTests
{
    private sealed class ExternalSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            using var rsa = RSA.Create(2048);
            var current = new SourceKey(
                new SourceKeyId("current"), SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));

            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_registers_an_ISigningKeyRing_for_a_third_party_source()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().NotBeNull();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_registers_an_ISigningKeyRing_for_a_third_party_source()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().NotBeNull();
    }
}
