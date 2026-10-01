using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
public sealed class ZeeKayDaAuthBuilderSigningKeySourceExtensionsTests
{
    /// <summary>
    /// Models a signing key source defined by a third party from its own package: it implements
    /// only the public members of <see cref="ISigningKeySource"/>.
    /// </summary>
    private sealed class ExternalSigningKeySource : ISigningKeySource
    {
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            using var rsa = RSA.Create(2048);
            var current = new SourceKey(
                new SourceKeyId("current"), SigningAlgorithm.RS256,
                PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));

            return Task.FromResult<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>A minimal <see cref="ISigningKeyRing"/> standing in for a manual registration, so a
    /// test can prove which registered instance a resolution actually returns.</summary>
    private sealed class FakeSigningKeyRing : ISigningKeyRing
    {
        public SigningKeySet Current => throw new NotSupportedException();

        public Task<SigningOutcome> SignAsync<TState>(
            TState state, Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        Task ISigningKeyRing.EnsureInitializedAsync(CancellationToken cancellationToken) => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => null;
    }

    /// <summary>A second, distinct <see cref="ISigningKeySource"/> implementation, for proving that
    /// registering a different source than one already registered fails loudly.</summary>
    private sealed class OtherExternalSigningKeySource : ISigningKeySource
    {
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
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

        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return Task.FromResult<SourceKeySet>(SourceKeySet.Create(previous: null, current, next: null));
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
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
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
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<SourceKeySet>(SourceKeySet.Create(previous: null, key.Current, next: null));

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
        public SigningAlgorithm Algorithm => inner.Algorithm;

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
        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<SourceKeySet>(SourceKeySet.Create(previous: null, key.Current, next: null));

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
    public void AddSigningKeySource_registers_an_ISigningKeyRing()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public void AddSigningKeySource_does_not_register_ISigningKeySource_in_the_container()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        services.Should().NotContain(d => d.ServiceType == typeof(ISigningKeySource));
    }

    [Fact]
    public void AddSigningKeySource_leaves_ISigningKeySource_unreachable_by_any_resolution_means()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();
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
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
    }

    [Fact]
    public void AddSigningKeySource_called_twice_leaves_the_first_registration_intact()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
        services.Should().ContainSingle(d => d.ServiceType == typeof(ISigningKeyRing));
        services.Should().ContainSingle(d => d.ServiceType == typeof(SigningKeySourceRegistration));
    }

    [Fact]
    public void AddSigningKeySource_called_with_a_different_source_throws_InvalidOperationException()
    {
        var services = new ServiceCollection();
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void AddSigningKeySource_registers_the_startup_verifier()
    {
        var services = new ServiceCollection();

        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IStartupActivator>().Should().ContainSingle(v => v is SigningKeyRingStartupVerifier);
        provider.GetServices<IStartupVerifier>().Should().BeEmpty(
            "reading the source is real work and belongs in the activator phase");
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentNullException_when_builder_is_null()
    {
        ZeeKayDaAuthBuilder builder = null!;

        var act = () => builder.AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_is_the_interface_itself()
    {
        var services = new ServiceCollection();
        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ISigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_is_abstract()
    {
        var services = new ServiceCollection();

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<AbstractSigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddSigningKeySource_throws_ArgumentException_when_TSource_implements_IAsyncDisposable_only()
    {
        var services = new ServiceCollection();

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<AsyncOnlySigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public async Task Disposing_the_provider_disposes_the_signer_before_the_source()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<OrderRecordingSigningKeySource>();
        using (var provider = services.BuildServiceProvider())
        {
            await provider.GetRequiredService<ISigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
        }

        log.Order.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task Disposing_the_provider_synchronously_calls_Dispose_on_a_source_implementing_both_disposal_interfaces()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<DualDisposableSigningKeySource>();
        using (var provider = services.BuildServiceProvider())
        {
            await provider.GetRequiredService<ISigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
        }

        log.SyncDisposed.Should().BeTrue();
        log.AsyncDisposed.Should().BeFalse();
    }

    [Fact]
    public async Task Disposing_the_provider_asynchronously_calls_DisposeAsync_on_a_source_implementing_both_disposal_interfaces()
    {
        var log = new DisposalLog();
        var services = ServicesWithTestKey(log);
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<DualDisposableSigningKeySource>();
        var provider = services.BuildServiceProvider();
        try
        {
            await provider.GetRequiredService<ISigningKeyRing>().EnsureInitializedAsync(TestContext.Current.CancellationToken);
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
        var builder = new ZeeKayDaAuthBuilder(new ServiceCollection());
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
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ConstructionRecordingSigningKeySource>();
        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

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

        public Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    [Fact]
    public void AddSigningKeySource_overrides_a_manual_ISigningKeyRing_registered_before_it()
    {
        // The framework's ring is added with AddSingleton, so under MS DI's last-wins resolution it
        // replaces a hand-registered ring that came first; the call does not reject it.
        var services = new ServiceCollection();
        services.AddSingleton<ISigningKeyRing>(new FakeSigningKeyRing());

        var act = () => new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        act.Should().NotThrow();
        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public void A_manual_ISigningKeyRing_registration_added_after_AddSigningKeySource_wins_and_is_not_rejected()
    {
        // MS DI resolves ISigningKeyRing last-wins, so a ring registered after AddSigningKeySource
        // replaces the framework's; nothing detects it.
        var manualRing = new FakeSigningKeyRing();
        var services = new ServiceCollection();
        new ZeeKayDaAuthBuilder(services).AddSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddSingleton<ISigningKeyRing>(manualRing);

        act.Should().NotThrow();
        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeSameAs(manualRing);
    }

    private static ServiceCollection ServicesWithTestKey(DisposalLog log)
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));
        var services = new ServiceCollection();
        services.AddSingleton(new TestKey(current, rsa.ExportRSAPrivateKeyPem()));
        services.AddSingleton(log);
        return services;
    }

    private abstract class AbstractSigningKeySource : ISigningKeySource
    {
        public abstract Task<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default);

        public abstract Task<ISigner> CreateSignerAsync(
            SourceKeyId id, CancellationToken cancellationToken = default);
    }

    [Fact]
    public void AddZeeKayDaAuthCore_registers_the_ring_activator_for_a_manually_registered_ring()
    {
        // StaticSigningKeyRing has a public constructor, so a host can register an ISigningKeyRing
        // without AddSigningKeySource. Without this registration that ring would never be
        // initialized or self-tested, and the host would start with an uninitialized ring.
        var services = new ServiceCollection();

        services.AddZeeKayDaAuthCore(options => options.Issuer = "https://issuer.test");

        services.Should().Contain(
            d => d.ServiceType == typeof(IStartupActivator)
                 && d.ImplementationType == typeof(SigningKeyRingStartupVerifier));
    }
}
