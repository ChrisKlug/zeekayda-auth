using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tests.Tokens;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

/// <summary>
/// Exercises <c>AddSigningKeySource</c>: the loud failure on registering a second source of any
/// type, rejection of an abstract <c>TSource</c>, that
/// <see cref="ISigningKeySource"/> is not resolvable or reachable by any means, and the ring's
/// ownership of the source's disposal. This assembly carries an <c>InternalsVisibleTo</c> grant from
/// core, so it cannot prove a source needs no such grant —
/// <c>ZeeKayDa.Auth.FileSystem.Tests</c>' <c>ThirdPartySigningKeySourceRegistrationTests</c> proves
/// that from an assembly with no grant at all.
/// </summary>
public sealed class ZeeKayDaAuthCoreBuilderSigningKeySourceExtensionsTests
{
    /// <summary>
    /// Models a signing key source defined by a third party from its own package: it implements
    /// only the public members of <see cref="ISigningKeySource"/>.
    /// </summary>
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

    /// <summary>
    /// A working <see cref="ISigningKeySource"/> that reuses the same key pair on every call and
    /// counts its own invocations, so a test can prove that a specific instance — not merely some
    /// instance of its type — is the one the ring reads from and opens a signer against.
    /// </summary>
    private sealed class CountingSigningKeySource(SourceKey current, string privateKeyPem) : ISigningKeySource
    {
        public int ReadAsyncCallCount { get; private set; }

        public int CreateSignerAsyncCallCount { get; private set; }

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return Task.FromResult<IReadOnlyList<SourceKey>>([current]);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            CreateSignerAsyncCallCount++;
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
        }
    }

    /// <summary>A concrete <see cref="ISigningKeySource"/> that implements only
    /// <see cref="IAsyncDisposable"/>, modelling the shape registration must reject.</summary>
    private sealed class AsyncOnlySigningKeySource : ISigningKeySource, IAsyncDisposable
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>
    /// A working <see cref="ISigningKeySource"/> and a matching signer that both append to a shared
    /// list on disposal, so a test can assert the order the ring disposes them in.
    /// </summary>
    private sealed record TestKey(SourceKey Current, string PrivateKeyPem);

    private sealed class DisposalLog
    {
        public List<string> Order { get; } = [];

        public bool SyncDisposed { get; set; }

        public bool AsyncDisposed { get; set; }
    }

    private sealed class OrderRecordingSigningKeySource(TestKey key, DisposalLog log)
        : ISigningKeySource, IDisposable
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<SourceKey>>([key.Current]);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKeyPem);
            return Task.FromResult<ISigner>(new OrderRecordingSigner(new LocalSigner(SigningAlgorithm.RS256, rsa), log.Order));
        }

        public void Dispose() => log.Order.Add("source");
    }

    private sealed class OrderRecordingSigner(ISigner inner, List<string> disposalOrder) : ISigner
    {
        public Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => inner.SignAsync(signingInput, cancellationToken);

        public void Dispose()
        {
            inner.Dispose();
            disposalOrder.Add("signer");
        }
    }

    /// <summary>A working <see cref="ISigningKeySource"/> implementing both <see cref="IDisposable"/>
    /// and <see cref="IAsyncDisposable"/>, recording which disposal path was used.</summary>
    private sealed class DualDisposableSigningKeySource(TestKey key, DisposalLog log)
        : ISigningKeySource, IDisposable, IAsyncDisposable
    {
        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<SourceKey>>([key.Current]);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(key.PrivateKeyPem);
            return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
        }

        public void Dispose() => log.SyncDisposed = true;

        public ValueTask DisposeAsync()
        {
            log.AsyncDisposed = true;
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public void AddSigningKeySource_registers_an_SigningKeyRing()
    {
        var services = new ServiceCollection().AddRingDependencies();

        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<SigningKeyRing>().Should().BeOfType<SigningKeyRing>();
    }

    [Fact]
    public void AddSigningKeySource_does_not_register_ISigningKeySource_in_the_container()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        services.Should().NotContain(d => d.ServiceType == typeof(ISigningKeySource));
    }

    [Fact]
    public void AddSigningKeySource_leaves_ISigningKeySource_unreachable_by_any_resolution_means()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();
        using var provider = services.BuildServiceProvider();

        provider.GetService<ISigningKeySource>().Should().BeNull();
        provider.GetServices<ISigningKeySource>().Should().BeEmpty();
        provider.GetKeyedServices<ISigningKeySource>(KeyedService.AnyKey).Should().BeEmpty();
    }

    [Fact]
    public void AddSigningKeySource_called_twice_with_the_same_source_throws_InvalidOperationException()
    {
        // Not idempotent even though the source type matches: a provider's own registration method
        // registers the source and configures its options beside it, so a second call that looked
        // like a no-op here would still have applied a second configuration callback.
        var services = new ServiceCollection();
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
    }

    [Fact]
    public void AddSigningKeySource_called_twice_leaves_the_first_registration_intact()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
        services.Should().ContainSingle(d => d.ServiceType == typeof(SigningKeyRing));
        services.Should().ContainSingle(d => d.ServiceType == typeof(SigningKeySourceRegistration));
    }

    [Fact]
    public void AddSigningKeySource_called_with_a_different_source_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddSigningKeySource_registers_the_startup_verifier()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        services.Should().ContainSingle(descriptor => descriptor.ServiceType == typeof(IStartupActivator)
            && descriptor.ImplementationType == typeof(SigningKeyRingActivator));
        services.Should().NotContain(descriptor => descriptor.ServiceType == typeof(IStartupVerifier),
            "reading the source is real work and belongs in the activator phase");
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthCoreBuilder builder = null!;

        var act = () => builder.AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_is_the_interface_itself()
    {
        var services = new ServiceCollection();
        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ISigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_is_abstract()
    {
        var services = new ServiceCollection();

        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<AbstractSigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_implements_IAsyncDisposable_only()
    {
        var services = new ServiceCollection();

        var act = () => new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<AsyncOnlySigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public async Task Disposing_the_provider_disposes_the_signer_before_the_source()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<OrderRecordingSigningKeySource>();
        using (var provider = services.BuildServiceProvider())
        {
            await provider.GetRequiredService<SigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
        }

        log.Order.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task Disposing_the_provider_synchronously_calls_Dispose_on_a_source_implementing_both_disposal_interfaces()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<DualDisposableSigningKeySource>();
        using (var provider = services.BuildServiceProvider())
        {
            await provider.GetRequiredService<SigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
        }

        log.SyncDisposed.Should().BeTrue();
        log.AsyncDisposed.Should().BeFalse();
    }

    [Fact]
    public async Task Disposing_the_provider_asynchronously_calls_DisposeAsync_on_a_source_implementing_both_disposal_interfaces()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<DualDisposableSigningKeySource>();
        var provider = services.BuildServiceProvider();
        try
        {
            await provider.GetRequiredService<SigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
        }
        finally
        {
            await provider.DisposeAsync();
        }

        log.AsyncDisposed.Should().BeTrue();
        log.SyncDisposed.Should().BeFalse();
    }

    [Fact]
    public void AddSigningKeySource_of_a_different_source_throws_naming_both_sources_and_the_registering_assembly()
    {
        var builder = new ZeeKayDaAuthCoreBuilder(new ServiceCollection());
        builder.AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => builder.AddSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(ExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).Assembly.GetName().Name}*");
    }

    [Fact]
    public void A_clock_that_fails_to_resolve_leaves_no_source_constructed()
    {
        // Once the source exists only the ring may own it, so the clock is resolved first; a
        // failure there must not leave a constructed source with nobody to dispose it.
        var log = new ConstructionLog();
        var services = new ServiceCollection();
        services.AddSingleton(log);
        services.AddSingleton<TimeProvider>(_ => throw new InvalidOperationException("No clock."));
        new ZeeKayDaAuthCoreBuilder(services).AddSigningKeySource<ConstructionRecordingSigningKeySource>();
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<SigningKeyRing>();

        act.Should().Throw<InvalidOperationException>();
        log.Constructed.Should().BeFalse();
    }

    private sealed class ConstructionLog
    {
        public bool Constructed { get; set; }
    }

    private sealed class ConstructionRecordingSigningKeySource : ISigningKeySource
    {
        public ConstructionRecordingSigningKeySource(ConstructionLog log) => log.Constructed = true;

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    private static ServiceCollection ServicesWithTestKey(DisposalLog log)
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: DateTimeOffset.UtcNow.AddDays(90));
        var services = new ServiceCollection();
        services.AddRingDependencies();
        services.AddSingleton(new TestKey(current, rsa.ExportRSAPrivateKeyPem()));
        services.AddSingleton(log);
        return services;
    }

    private abstract class AbstractSigningKeySource : ISigningKeySource
    {
        public abstract Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default);

        public abstract Task<ISigner> CreateSignerAsync(
            SourceKeyId id, CancellationToken cancellationToken = default);
    }
}
