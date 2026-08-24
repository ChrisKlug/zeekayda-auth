using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

/// <summary>
/// Exercises both <c>AddZeeKayDaSigningKeySource</c> overloads: registration idempotency (including
/// across the type and factory overloads), the loud failure on registering a second, different
/// source or a second factory for the same source, rejection of an abstract <c>TSource</c>, and that
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
                new SourceKeyId("current"), SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));

            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>A second, distinct <see cref="ISigningKeySource"/> implementation, for proving that
    /// registering a different source than one already registered fails loudly.</summary>
    private sealed class OtherExternalSigningKeySource : ISigningKeySource
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// A working <see cref="ISigningKeySource"/> that reuses the same key pair on every call and
    /// counts its own invocations, so a test can prove that a specific instance — not merely some
    /// instance of its type — is the one the ring reads from and opens a signer against.
    /// </summary>
    private sealed class CountingSigningKeySource(SourceKey current, string privateKeyPem) : ISigningKeySource
    {
        public int ReadAsyncCallCount { get; private set; }

        public int CreateSignerAsyncCallCount { get; private set; }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return new ValueTask<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            CreateSignerAsyncCallCount++;
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
        }
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

    [Fact]
    public void AddZeeKayDaSigningKeySource_throws_ArgumentException_when_TSource_is_the_interface_itself()
    {
        var services = new ServiceCollection();
        Func<IServiceProvider, ISigningKeySource> implementationFactory = _ => new ExternalSigningKeySource();

        var act = () => services.AddZeeKayDaSigningKeySource(implementationFactory);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_type_overload_throws_ArgumentException_when_TSource_is_abstract()
    {
        var services = new ServiceCollection();

        var act = () => services.AddZeeKayDaSigningKeySource<AbstractSigningKeySource>();

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_registers_a_working_ISigningKeyRing()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public async Task AddZeeKayDaSigningKeySource_with_factory_uses_the_exact_instance_the_factory_returns()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));
        var instance = new CountingSigningKeySource(current, rsa.ExportRSAPrivateKeyPem());
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => instance);

        using var provider = services.BuildServiceProvider();
        var ring = (ISigningKeyRing)provider.GetRequiredService<ISigningKeyRing>();
        await ring.InitializeAsync(TestContext.Current.CancellationToken);

        // Both counters live on the one instance the test holds a reference to, so this can only
        // pass if that exact instance — not a separately DI-activated one — is what the ring reads
        // from and opens a signer against.
        instance.ReadAsyncCallCount.Should().Be(1);
        instance.CreateSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_called_twice_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        var act = () => services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_type_then_factory_of_the_same_source_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_then_type_of_the_same_source_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_of_a_different_source_throws_naming_both_sources()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource(_ => new OtherExternalSigningKeySource());

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(ExternalSigningKeySource).FullName}*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_of_a_different_source_after_a_factory_throws_naming_both_sources()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        var act = () => services.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(ExternalSigningKeySource).FullName}*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_different_source_message_names_the_registering_assembly()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).Assembly.GetName().Name}*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_throws_ArgumentNullException_when_services_is_null()
    {
        IServiceCollection services = null!;

        var act = () => services.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_throws_ArgumentNullException_when_implementationFactory_is_null()
    {
        var services = new ServiceCollection();
        Func<IServiceProvider, ExternalSigningKeySource> implementationFactory = null!;

        var act = () => services.AddZeeKayDaSigningKeySource(implementationFactory);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_throws_ArgumentNullException_for_paramName_services_when_both_arguments_are_null()
    {
        IServiceCollection services = null!;
        Func<IServiceProvider, ExternalSigningKeySource> implementationFactory = null!;

        var act = () => services.AddZeeKayDaSigningKeySource(implementationFactory);

        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void Resolving_ISigningKeyRing_throws_when_composed_descriptors_disagree_about_the_registered_source_type()
    {
        // Models a service collection composed from two independently-built collections, each of
        // which registered its own signing key source. Interleaved so that DI's own "last
        // registration wins" resolution picks the marker from one and the source from the other —
        // exactly the divergence a naive keyed lookup would miss.
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        var combined = new ServiceCollection();
        combined.Add(firstServices.Single(d => d.ServiceType == typeof(SigningKeySourceRegistration)));
        combined.Add(secondServices.Single(d => d.ServiceType == typeof(SigningKeySourceRegistration)));
        combined.Add(secondServices.Single(d => d.ServiceType == typeof(ISigningKeySource)));
        combined.Add(firstServices.Single(d => d.ServiceType == typeof(ISigningKeySource)));
        combined.TryAddSingleton<TimeProvider>(TimeProvider.System);
        combined.Add(firstServices.Single(d => d.ServiceType == typeof(ISigningKeyRing)));

        using var provider = combined.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.source_registration_mismatch");
    }

    private abstract class AbstractSigningKeySource : ISigningKeySource
    {
        public abstract ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default);

        public abstract ValueTask<ISigner> CreateSignerAsync(
            SourceKeyId id, CancellationToken cancellationToken = default);
    }
}
