using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Extensions;

/// <summary>
/// Proves <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource{TSource}"/>
/// works for a source type defined entirely outside this framework's own assemblies. Unlike
/// <c>ZeeKayDa.Auth.Tests</c>, this assembly carries no <c>InternalsVisibleTo</c> grant from core, so
/// this test compiling and passing is the actual proof that only <see cref="ISigningKeySource"/>'s
/// public members are needed — a grant this project does not have could not silently be relied on.
/// </summary>
public sealed class ThirdPartySigningKeySourceRegistrationTests
{
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
    public void AddZeeKayDaSigningKeySource_registers_an_ISigningKeyRing_for_a_third_party_source()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().NotBeNull();
    }
}
