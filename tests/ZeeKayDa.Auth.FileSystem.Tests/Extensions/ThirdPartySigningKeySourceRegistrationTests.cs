using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem.Tests.Extensions;

/// <summary>
/// Proves <c>AddSigningKeySource</c>, including the one-source-per-application
/// guard's different-source failure, work for source types defined entirely outside this framework's
/// own assemblies. Unlike <c>ZeeKayDa.Auth.Tests</c>, this assembly carries no
/// <c>InternalsVisibleTo</c> grant from core, so this test compiling and passing is the actual proof
/// that only <see cref="ISigningKeySource"/>'s public members are needed — including for the guard,
/// which depends on the internal <c>SigningKeySourceRegistration</c> type and must therefore work
/// with no such grant.
/// </summary>
public sealed class ThirdPartySigningKeySourceRegistrationTests
{
    private sealed class ExternalSigningKeySource : ISigningKeySource
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            using var rsa = RSA.Create(2048);
            var current = new SourceKey(
                new SourceKeyId("current"), SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: DateTimeOffset.UtcNow.AddDays(90));

            return Task.FromResult<IReadOnlyList<SourceKey>>([current]);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>A second, distinct <see cref="ISigningKeySource"/> implementation, for proving that
    /// registering a different source than one already registered fails loudly.</summary>
    private sealed class OtherExternalSigningKeySource : ISigningKeySource
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public void AddSigningKeySource_registers_an_SigningKeyRing_for_a_third_party_source()
    {
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddZeeKayDaAuthCoreForTesting().AddSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<SigningKeyRing>().Should().NotBeNull();
    }

    [Fact]
    public void AddSigningKeySource_called_with_a_different_source_throws_InvalidOperationException()
    {
        var builder = new ServiceCollection().AddZeeKayDaAuthCoreForTesting();
        builder.AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => builder.AddSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
    }
}
