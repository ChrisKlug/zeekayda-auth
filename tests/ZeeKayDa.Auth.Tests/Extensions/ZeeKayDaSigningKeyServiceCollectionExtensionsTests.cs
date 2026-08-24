using System.Collections.Generic;
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
/// source or a second factory for the same source, rejection of an abstract <c>TSource</c>, that
/// <see cref="ISigningKeySource"/> is not resolvable or reachable by any means, and the ring's
/// ownership of the source's disposal. This assembly carries an <c>InternalsVisibleTo</c> grant from
/// core, so it cannot prove a source needs no such grant —
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

    /// <summary>A minimal <see cref="ISigningKeyRing"/> standing in for a manual registration, so a
    /// test can prove which registered instance a resolution actually returns.</summary>
    private sealed class FakeSigningKeyRing : ISigningKeyRing
    {
        public SigningKeySet Current => throw new NotSupportedException();

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state, Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken) => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => null;
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

    /// <summary>A concrete <see cref="ISigningKeySource"/> that implements only
    /// <see cref="IAsyncDisposable"/>, modelling the shape registration must reject.</summary>
    private sealed class AsyncOnlySigningKeySource : ISigningKeySource, IAsyncDisposable
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>A base <see cref="ISigningKeySource"/> that a factory can be declared over, modelling
    /// a provider package whose public factory signature names a base type.</summary>
    private class BaseSigningKeySource : ISigningKeySource
    {
        public virtual ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public virtual ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }

    /// <summary>A derived source, implementing only <see cref="IAsyncDisposable"/>, that a base-typed
    /// factory can return without the registration-time check on <c>typeof(TSource)</c> ever seeing
    /// it.</summary>
    private sealed class AsyncOnlyDerivedSigningKeySource : BaseSigningKeySource, IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>
    /// A working <see cref="ISigningKeySource"/> and a matching signer that both append to a shared
    /// list on disposal, so a test can assert the order the ring disposes them in.
    /// </summary>
    private sealed class OrderRecordingSigningKeySource(SourceKey current, string privateKeyPem, List<string> disposalOrder)
        : ISigningKeySource, IDisposable
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => new(SourceKeySet.Create(previous: null, current, next: null));

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            return new ValueTask<ISigner>(new OrderRecordingSigner(new LocalSigner(SigningAlgorithm.RS256, rsa), disposalOrder));
        }

        public void Dispose() => disposalOrder.Add("source");
    }

    private sealed class OrderRecordingSigner(ISigner inner, List<string> disposalOrder) : ISigner
    {
        public SigningAlgorithm Algorithm => inner.Algorithm;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
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
    private sealed class DualDisposableSigningKeySource(SourceKey current, string privateKeyPem)
        : ISigningKeySource, IDisposable, IAsyncDisposable
    {
        public bool SyncDisposed { get; private set; }

        public bool AsyncDisposed { get; private set; }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
            => new(SourceKeySet.Create(previous: null, current, next: null));

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, rsa));
        }

        public void Dispose() => SyncDisposed = true;

        public ValueTask DisposeAsync()
        {
            AsyncDisposed = true;
            return ValueTask.CompletedTask;
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
    public void AddZeeKayDaSigningKeySource_does_not_register_ISigningKeySource_in_the_container()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        services.Should().NotContain(d => d.ServiceType == typeof(ISigningKeySource));
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_leaves_ISigningKeySource_unreachable_by_any_resolution_means()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();
        using var provider = services.BuildServiceProvider();

        provider.GetService<ISigningKeySource>().Should().BeNull();
        provider.GetServices<ISigningKeySource>().Should().BeEmpty();
        provider.GetKeyedServices<ISigningKeySource>(KeyedService.AnyKey).Should().BeEmpty();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_called_twice_with_the_same_source_throws_InvalidOperationException()
    {
        // Not idempotent even though the source type matches: a provider's own registration method
        // registers the source and configures its options beside it, so a second call that looked
        // like a no-op here would still have applied a second configuration callback.
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*already registered as the signing key source*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_called_twice_leaves_the_first_registration_intact()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>();
        services.Should().ContainSingle(d => d.ServiceType == typeof(ISigningKeyRing));
        services.Should().ContainSingle(d => d.ServiceType == typeof(SigningKeySourceRegistration));
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

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_type_overload_throws_ArgumentException_when_TSource_is_abstract()
    {
        var services = new ServiceCollection();

        var act = () => services.AddZeeKayDaSigningKeySource<AbstractSigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_type_overload_throws_ArgumentException_when_TSource_implements_IAsyncDisposable_only()
    {
        var services = new ServiceCollection();

        var act = () => services.AddZeeKayDaSigningKeySource<AsyncOnlySigningKeySource>();

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_with_factory_throws_ArgumentException_when_TSource_implements_IAsyncDisposable_only()
    {
        var services = new ServiceCollection();
        Func<IServiceProvider, AsyncOnlySigningKeySource> implementationFactory = _ => new AsyncOnlySigningKeySource();

        var act = () => services.AddZeeKayDaSigningKeySource(implementationFactory);

        act.Should().Throw<ArgumentException>().WithParameterName("TSource");
        services.Should().BeEmpty();
    }

    [Fact]
    public void Resolving_ISigningKeyRing_throws_ArgumentException_when_a_base_typed_factory_returns_an_async_only_derived_source()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<BaseSigningKeySource>(_ => new AsyncOnlyDerivedSigningKeySource());

        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ArgumentException>().WithParameterName("source");
    }

    [Fact]
    public async Task Disposing_the_provider_disposes_the_signer_before_the_source()
    {
        var (source, disposalOrder) = CreateOrderRecordingSource();
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => source);
        var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<ISigningKeyRing>();
        await ring.InitializeAsync(TestContext.Current.CancellationToken);

        provider.Dispose();

        disposalOrder.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task Disposing_the_provider_synchronously_calls_Dispose_on_a_source_implementing_both_disposal_interfaces()
    {
        var source = CreateDualDisposableSource();
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => source);
        var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<ISigningKeyRing>();
        await ring.InitializeAsync(TestContext.Current.CancellationToken);

        provider.Dispose();

        source.SyncDisposed.Should().BeTrue();
        source.AsyncDisposed.Should().BeFalse();
    }

    [Fact]
    public async Task Disposing_the_provider_asynchronously_calls_DisposeAsync_on_a_source_implementing_both_disposal_interfaces()
    {
        var source = CreateDualDisposableSource();
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => source);
        var provider = services.BuildServiceProvider();
        var ring = provider.GetRequiredService<ISigningKeyRing>();
        await ring.InitializeAsync(TestContext.Current.CancellationToken);

        await provider.DisposeAsync();

        source.AsyncDisposed.Should().BeTrue();
        source.SyncDisposed.Should().BeFalse();
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
        var ring = provider.GetRequiredService<ISigningKeyRing>();
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

    public enum SecondRegistrationKind
    {
        TypeOverload,
        FactoryOverload,
    }

    [Theory]
    [InlineData(SecondRegistrationKind.TypeOverload, SecondRegistrationKind.FactoryOverload)]
    [InlineData(SecondRegistrationKind.FactoryOverload, SecondRegistrationKind.TypeOverload)]
    [InlineData(SecondRegistrationKind.TypeOverload, SecondRegistrationKind.TypeOverload)]
    [InlineData(SecondRegistrationKind.FactoryOverload, SecondRegistrationKind.FactoryOverload)]
    public void AddZeeKayDaSigningKeySource_of_a_different_source_throws_naming_both_sources_and_the_registering_assembly(
        SecondRegistrationKind first, SecondRegistrationKind second)
    {
        var services = new ServiceCollection();
        Register<ExternalSigningKeySource>(services, first);

        var act = () => Register<OtherExternalSigningKeySource>(services, second);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(ExternalSigningKeySource).FullName}*")
            .WithMessage($"*{typeof(OtherExternalSigningKeySource).Assembly.GetName().Name}*");

        static void Register<TSource>(IServiceCollection services, SecondRegistrationKind kind)
            where TSource : class, ISigningKeySource
        {
            if (kind == SecondRegistrationKind.TypeOverload)
                services.AddZeeKayDaSigningKeySource<TSource>();
            else
                services.AddZeeKayDaSigningKeySource(_ => Activator.CreateInstance<TSource>());
        }
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
    public void Resolving_ISigningKeyRing_throws_when_composed_from_two_libraries_that_each_registered_their_own_source()
    {
        // Models the composition a modular host or shared bootstrap library actually produces: two
        // independently-built service collections, each of which called AddZeeKayDaSigningKeySource
        // for its own, distinct source, appended into one host collection in the natural order (all
        // of the first collection's descriptors, then all of the second's) — not hand-interleaved.
        // With nothing registered under a container key at all, only counting the recorded markers
        // can catch this.
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        var combined = new ServiceCollection();
        foreach (var descriptor in firstServices)
            combined.Add(descriptor);
        foreach (var descriptor in secondServices)
            combined.Add(descriptor);

        using var provider = combined.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.source_registration_mismatch");
    }

    [Fact]
    public void Resolving_ISigningKeyRing_throws_when_composed_from_two_libraries_that_each_used_the_factory_overload()
    {
        // Same composition shape, but both collections registered the *same* source type via the
        // factory overload. The distinct-type check alone would wave this through, but each factory
        // can close over its own configuration, so the composition is still ambiguous and must throw.
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource(_ => new ExternalSigningKeySource());

        var combined = new ServiceCollection();
        foreach (var descriptor in firstServices)
            combined.Add(descriptor);
        foreach (var descriptor in secondServices)
            combined.Add(descriptor);

        using var provider = combined.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.source_registration_mismatch");
    }

    [Fact]
    public void Resolving_ISigningKeyRing_for_a_failing_composed_registration_never_constructs_or_invokes_any_source()
    {
        var firstConstructions = 0;
        var secondConstructions = 0;
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource(_ =>
        {
            firstConstructions++;
            return new ExternalSigningKeySource();
        });

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource(_ =>
        {
            secondConstructions++;
            return new OtherExternalSigningKeySource();
        });

        var combined = new ServiceCollection();
        foreach (var descriptor in firstServices)
            combined.Add(descriptor);
        foreach (var descriptor in secondServices)
            combined.Add(descriptor);

        using var provider = combined.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>();
        firstConstructions.Should().Be(0);
        secondConstructions.Should().Be(0);
    }

    [Fact]
    public void Resolving_ISigningKeyRing_throws_when_composed_from_two_libraries_that_registered_the_same_source()
    {
        // Two collections that each registered the same source type each also configured that
        // source's options, and only one of those configurations describes what the application
        // actually signs with — so composing them is ambiguous, not a harmless duplicate.
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var combined = new ServiceCollection();
        foreach (var descriptor in firstServices)
            combined.Add(descriptor);
        foreach (var descriptor in secondServices)
            combined.Add(descriptor);

        using var provider = combined.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>();
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_after_composed_registrations_names_the_most_recently_registered_source()
    {
        // Every further call throws, so what this pins is which incumbent the operator is told
        // about: the one DI will actually resolve, not a stale first entry.
        var firstServices = new ServiceCollection();
        firstServices.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var secondServices = new ServiceCollection();
        secondServices.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        var combined = new ServiceCollection();
        foreach (var descriptor in firstServices)
            combined.Add(descriptor);
        foreach (var descriptor in secondServices)
            combined.Add(descriptor);

        var act = () => combined.AddZeeKayDaSigningKeySource<OtherExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{nameof(OtherExternalSigningKeySource)}*already registered as the signing key source*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_throws_when_an_unkeyed_ISigningKeyRing_is_already_registered_manually()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISigningKeyRing>(_ => throw new NotSupportedException("must not be constructed"));

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{nameof(ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource)}*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_is_not_rejected_by_a_keyed_ISigningKeyRing_registration()
    {
        // A keyed descriptor can never win GetRequiredService<ISigningKeyRing>()'s unkeyed
        // resolution, so it is not the manual registration this guard exists to catch.
        var services = new ServiceCollection();
        services.AddKeyedSingleton<ISigningKeyRing>(
            "some-key", (_, _) => throw new NotSupportedException("must not be constructed"));

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().NotThrow();
        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeOfType<StaticSigningKeyRing>();
    }

    [Fact]
    public void A_manual_ISigningKeyRing_registration_added_after_AddZeeKayDaSigningKeySource_wins_and_is_not_rejected()
    {
        // AddZeeKayDaSigningKeySource has no hook into a manual registration made after it returns:
        // that call goes straight to the IServiceCollection, not through this extension. The guard
        // above only closes the ordering it can actually observe — a manual registration already
        // present when this method runs. MS DI's ISigningKeyRing resolution is last-wins, so a
        // manual registration added afterwards wins outright: the framework's own ring is never
        // constructed, and nothing here detects or rejects it.
        var manualRing = new FakeSigningKeyRing();
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        var act = () => services.AddSingleton<ISigningKeyRing>(manualRing);

        act.Should().NotThrow();
        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISigningKeyRing>().Should().BeSameAs(manualRing);
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_names_the_offending_ISigningKeyRing_registration_in_its_message()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ISigningKeyRing, FakeSigningKeyRing>();

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>().WithMessage($"*{nameof(FakeSigningKeyRing)}*");
    }

    [Fact]
    public void AddZeeKayDaSigningKeySource_message_distinguishes_its_own_removed_marker_from_a_foreign_registration()
    {
        // IServiceCollection is IList<ServiceDescriptor>, so removing this method's own marker after
        // it ran needs no reflection. Once removed, the guard can no longer tell "our own descriptor,
        // marker gone" apart from "a foreign descriptor" structurally — the message must say so
        // honestly rather than accusing a caller of a manual registration that never happened.
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();
        var marker = services.Single(d => d.ServiceType == typeof(SigningKeySourceRegistration));
        services.Remove(marker);

        var act = () => services.AddZeeKayDaSigningKeySource<ExternalSigningKeySource>();

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*or this collection's own marker for it was removed*");
    }

    [Fact]
    public void Resolving_ISigningKeyRing_throws_a_coded_failure_when_the_factory_returns_null()
    {
        var services = new ServiceCollection();
        services.AddZeeKayDaSigningKeySource(_ => (ExternalSigningKeySource)null!);

        using var provider = services.BuildServiceProvider();

        var act = () => provider.GetRequiredService<ISigningKeyRing>();

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_source");
    }

    private static (OrderRecordingSigningKeySource Source, List<string> DisposalOrder) CreateOrderRecordingSource()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));
        var disposalOrder = new List<string>();
        return (new OrderRecordingSigningKeySource(current, rsa.ExportRSAPrivateKeyPem(), disposalOrder), disposalOrder);
    }

    private static DualDisposableSigningKeySource CreateDualDisposableSource()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256,
            PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), DateTimeOffset.UtcNow.AddDays(90));
        return new DualDisposableSigningKeySource(current, rsa.ExportRSAPrivateKeyPem());
    }

    private abstract class AbstractSigningKeySource : ISigningKeySource
    {
        public abstract ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default);

        public abstract ValueTask<ISigner> CreateSignerAsync(
            SourceKeyId id, CancellationToken cancellationToken = default);
    }
}
