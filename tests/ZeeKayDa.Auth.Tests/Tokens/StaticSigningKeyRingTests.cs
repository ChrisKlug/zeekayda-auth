using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="StaticSigningKeyRing"/>: the one-time startup read, the signing key's
/// expiry and signer-open/self-test checks that fail startup, <see cref="ISigningKeyRing.SignAsync{TState}"/>,
/// and ownership of the one <see cref="ISigner"/> it opens for the process lifetime.
/// </summary>
public sealed class StaticSigningKeyRingTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeSigningKeySource(
        Func<CancellationToken, ValueTask<SourceKeySet>> read,
        Func<SourceKeyId, CancellationToken, ValueTask<ISigner>> createSigner) : ISigningKeySource
    {
        public int ReadAsyncCallCount { get; private set; }

        public int CreateSignerAsyncCallCount { get; private set; }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return read(cancellationToken);
        }

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            CreateSignerAsyncCallCount++;
            return createSigner(id, cancellationToken);
        }
    }

    /// <summary>
    /// Wraps a real <see cref="ISigner"/> but signs only the first input it is ever asked to sign,
    /// then returns that same cached signature for every later call regardless of what is actually
    /// asked — modelling a memoizing remote signer or caching signing proxy shared across two
    /// separate self-tests. Primed on whatever the first real input turns out to be, never on a
    /// value the test itself knows in advance, so this stays a valid probe even if the self-test's
    /// own payload shape changes: it depends only on two self-tests asking for different bytes, not
    /// on knowing what either of them is.
    /// </summary>
    private sealed class MemoizingSigner(ISigner inner) : ISigner
    {
        private ReadOnlyMemory<byte>? _cachedSignature;

        public SigningAlgorithm Algorithm => inner.Algorithm;

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            _cachedSignature ??= await inner.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
            return _cachedSignature.Value;
        }

        public void Dispose() => inner.Dispose();
    }

    private sealed class WrongAlgorithmSigner(ISigner inner, SigningAlgorithm algorithm) : ISigner
    {
        public SigningAlgorithm Algorithm => algorithm;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => inner.SignAsync(signingInput, cancellationToken);

        public void Dispose() => inner.Dispose();
    }

    /// <summary>
    /// Signs for real, then hands back a signature buffer it goes on to mutate in place afterwards —
    /// modelling a provider that reuses or pools its return buffer.
    /// </summary>
    private sealed class BufferReusingSigner(ISigner inner) : ISigner
    {
        private byte[]? _lastReturnedBuffer;

        public SigningAlgorithm Algorithm => inner.Algorithm;

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            var signature = (await inner.SignAsync(signingInput, cancellationToken).ConfigureAwait(false)).ToArray();
            _lastReturnedBuffer = signature;
            return signature;
        }

        /// <summary>Corrupts the buffer most recently returned from <see cref="SignAsync"/>, as if the
        /// provider reused it for its next operation.</summary>
        public void CorruptLastReturnedBuffer() => _lastReturnedBuffer![0] ^= 0xFF;

        public void Dispose() => inner.Dispose();
    }

    private sealed class TrackingSigner(ISigner inner, Action onDispose) : ISigner
    {
        public SigningAlgorithm Algorithm => inner.Algorithm;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => inner.SignAsync(signingInput, cancellationToken);

        public void Dispose()
        {
            inner.Dispose();
            onDispose();
        }
    }

    /// <summary>An <see cref="ISigner"/> whose <c>Dispose</c> always throws, modelling a third-party
    /// signer whose cleanup fails — used to prove the ring still disposes its source.</summary>
    private sealed class ThrowingDisposeSigner(ISigner inner) : ISigner
    {
        public SigningAlgorithm Algorithm => inner.Algorithm;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => inner.SignAsync(signingInput, cancellationToken);

        public void Dispose() => throw new InvalidOperationException("simulated: signer Dispose failure");
    }

    /// <summary>A working <see cref="ISigningKeySource"/> that also implements <see cref="IDisposable"/>,
    /// recording disposal via a caller-supplied callback.</summary>
    private sealed class DisposableSigningKeySource(
        Func<CancellationToken, ValueTask<SourceKeySet>> read,
        Func<SourceKeyId, CancellationToken, ValueTask<ISigner>> createSigner,
        Action onDispose) : ISigningKeySource, IDisposable
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public void Dispose() => onDispose();
    }

    /// <summary>A working <see cref="ISigningKeySource"/> that implements only
    /// <see cref="IAsyncDisposable"/>, modelling the shape the ring's synchronous <c>Dispose</c>
    /// rejects as a last line of defence.</summary>
    private sealed class AsyncOnlySigningKeySource(
        Func<CancellationToken, ValueTask<SourceKeySet>> read,
        Func<SourceKeyId, CancellationToken, ValueTask<ISigner>> createSigner,
        Func<ValueTask> onDisposeAsync) : ISigningKeySource, IAsyncDisposable
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public ValueTask DisposeAsync() => onDisposeAsync();
    }

    /// <summary>A working <see cref="ISigningKeySource"/> implementing both disposal interfaces,
    /// recording which one was invoked via caller-supplied callbacks.</summary>
    private sealed class DualDisposableSigningKeySource(
        Func<CancellationToken, ValueTask<SourceKeySet>> read,
        Func<SourceKeyId, CancellationToken, ValueTask<ISigner>> createSigner,
        Action onDispose,
        Func<ValueTask> onDisposeAsync) : ISigningKeySource, IDisposable, IAsyncDisposable
    {
        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public ValueTask<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public void Dispose() => onDispose();

        public ValueTask DisposeAsync() => onDisposeAsync();
    }

    // ── Current / CurrentOrNull before initialization ───────────────────────────────────────────

    [Fact]
    public void Current_throws_InvalidOperationException_before_initialization()
    {
        using var ring = new StaticSigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch));

        var act = () => ring.Current;

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void CurrentOrNull_is_null_before_initialization()
    {
        ISigningKeyRing ring = new StaticSigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch));

        ring.CurrentOrNull.Should().BeNull();
    }

    // ── InitializeAsync — success ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InitializeAsync_builds_the_key_set_and_opens_the_signer_exactly_once()
    {
        using var rsa = RSA.Create(2048);
        var (source, current) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        await ring.InitializeAsync(TestContext.Current.CancellationToken);

        ring.Current.SigningKey.SourceId.Should().Be(current.Id);
        source.ReadAsyncCallCount.Should().Be(1);
        source.CreateSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task SignAsync_signs_with_the_current_signing_key_and_returns_a_verifiable_outcome()
    {
        using var rsa = RSA.Create(2048);
        var (source, current) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        var outcome = await ring.SignAsync(
            "payload"u8.ToArray(),
            static (_, state) => state,
            TestContext.Current.CancellationToken);

        outcome.Key.SourceId.Should().Be(current.Id);
        SigningAlgorithms.Verify(outcome.Key.Algorithm, outcome.Key.PublicKey, outcome.SigningInput.Span, outcome.Signature.Span)
            .Should().BeTrue();
    }

    [Fact]
    public async Task SignAsync_throws_ObjectDisposedException_after_Dispose()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);
        ((IDisposable)ring).Dispose();

        var act = async () => await ring.SignAsync(
            "payload"u8.ToArray(), static (_, state) => state, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Dispose_disposes_the_owned_signer_exactly_once()
    {
        using var rsa = RSA.Create(2048);
        var disposeCount = 0;
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return new ValueTask<ISigner>(
                    new TrackingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa), () => disposeCount++));
            });

        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        ((IDisposable)ring).Dispose();
        ((IDisposable)ring).Dispose();

        disposeCount.Should().Be(1);
    }

    [Fact]
    public async Task Dispose_disposes_the_source_after_the_signer()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder, (read, createSigner) => new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")));

        ((IDisposable)ring).Dispose();

        disposalOrder.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task DisposeAsync_disposes_the_source_after_the_signer()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder, (read, createSigner) => new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")));

        await ((IAsyncDisposable)ring).DisposeAsync();

        disposalOrder.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task DisposeAsync_prefers_DisposeAsync_over_Dispose_on_a_source_implementing_both()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder,
            (read, createSigner) => new DualDisposableSigningKeySource(
                read, createSigner,
                onDispose: () => disposalOrder.Add("sync"),
                onDisposeAsync: () =>
                {
                    disposalOrder.Add("async");
                    return ValueTask.CompletedTask;
                }));

        await ((IAsyncDisposable)ring).DisposeAsync();

        disposalOrder.Should().Equal("signer", "async");
    }

    [Fact]
    public async Task Dispose_calls_Dispose_not_DisposeAsync_on_a_source_implementing_both()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder,
            (read, createSigner) => new DualDisposableSigningKeySource(
                read, createSigner,
                onDispose: () => disposalOrder.Add("sync"),
                onDisposeAsync: () =>
                {
                    disposalOrder.Add("async");
                    return ValueTask.CompletedTask;
                }));

        ((IDisposable)ring).Dispose();

        disposalOrder.Should().Equal("signer", "sync");
    }

    [Fact]
    public async Task Dispose_and_then_DisposeAsync_only_run_the_first_call_s_disposal()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder, (read, createSigner) => new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")));

        ((IDisposable)ring).Dispose();
        await ((IAsyncDisposable)ring).DisposeAsync();

        disposalOrder.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task Dispose_disposes_the_source_even_when_the_signer_s_Dispose_throws()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder,
            (read, createSigner) => new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")),
            signerThrowsOnDispose: true);

        var act = () => ((IDisposable)ring).Dispose();

        act.Should().NotThrow();
        disposalOrder.Should().Equal("source");
    }

    [Fact]
    public async Task DisposeAsync_disposes_the_source_even_when_the_signer_s_Dispose_throws()
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder,
            (read, createSigner) => new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")),
            signerThrowsOnDispose: true);

        var act = async () => await ((IAsyncDisposable)ring).DisposeAsync();

        await act.Should().NotThrowAsync();
        disposalOrder.Should().Equal("source");
    }

    [Fact]
    public void Constructor_throws_ArgumentException_when_the_source_implements_IAsyncDisposable_only()
    {
        var source = new AsyncOnlySigningKeySource(
            _ => throw new InvalidOperationException("must not be called"),
            (_, _) => throw new InvalidOperationException("must not be called"),
            onDisposeAsync: () => ValueTask.CompletedTask);

        var act = () => new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        act.Should().Throw<ArgumentException>().WithParameterName("source");
    }

    // ── InitializeAsync — startup failures ───────────────────────────────────────────────────────

    [Fact]
    public async Task InitializeAsync_throws_when_the_Current_key_is_already_expired()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(-1));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signing_key_expired");
    }

    [Fact]
    public async Task InitializeAsync_propagates_a_builder_validation_failure_from_ReadAsync()
    {
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, null, null)), // no Current
            (_, _) => throw new NotSupportedException("must not be reached"));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_current_key");
    }

    [Fact]
    public async Task InitializeAsync_throws_signer_unavailable_when_CreateSignerAsync_throws()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => throw new InvalidOperationException("simulated: key vault unreachable"));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signer_unavailable");
    }

    [Fact]
    public async Task InitializeAsync_throws_signer_algorithm_mismatch_when_the_signer_disagrees_with_the_key()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => new ValueTask<ISigner>(
                new WrongAlgorithmSigner(new LocalSigner(SigningAlgorithm.RS256, RSA.Create(2048)), SigningAlgorithm.RS384)));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signer_algorithm_mismatch");
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_the_signer_does_not_pair_with_the_public_key()
    {
        using var publicRsa = RSA.Create(2048); // published public key
        using var otherRsa = RSA.Create(2048); // signer's actual (mismatched) private key
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(publicRsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, otherRsa)));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_a_shared_signer_returns_a_signature_memoized_from_an_earlier_self_test()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var signerRsa = RSA.Create();
        signerRsa.ImportFromPem(privateKeyPem);
        var sharedSigner = new MemoizingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa));

        SourceKeySet ReadCurrent(CancellationToken _) => SourceKeySet.Create(null, current, null);
        ValueTask<ISigner> LendSharedSigner(SourceKeyId _, CancellationToken __) => new(sharedSigner);

        var firstSource = new FakeSigningKeySource(t => new ValueTask<SourceKeySet>(ReadCurrent(t)), LendSharedSigner);
        ISigningKeyRing firstRing = new StaticSigningKeyRing(firstSource, new FakeTimeProvider(Epoch));

        // Succeeds: the shared signer's very first call is a genuine sign over this self-test's own
        // random nonce, so it verifies and the cache is primed with a correct-for-that-nonce signature.
        await firstRing.InitializeAsync(TestContext.Current.CancellationToken);

        var secondSource = new FakeSigningKeySource(t => new ValueTask<SourceKeySet>(ReadCurrent(t)), LendSharedSigner);
        ISigningKeyRing secondRing = new StaticSigningKeyRing(secondSource, new FakeTimeProvider(Epoch));

        // A second, independent self-test generates a different random nonce, but the shared signer
        // returns the signature it cached for the first ring's nonce — this must fail verification.
        var act = async () => await secondRing.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task InitializeAsync_disposes_the_signer_when_the_self_test_fails()
    {
        using var publicRsa = RSA.Create(2048);
        using var otherRsa = RSA.Create(2048); // mismatched private key: the self-test must fail
        var disposeCount = 0;
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(publicRsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => new ValueTask<ISigner>(
                new TrackingSigner(new LocalSigner(SigningAlgorithm.RS256, otherRsa), () => disposeCount++)));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        disposeCount.Should().Be(1);
    }

    [Fact]
    public async Task InitializeAsync_disposes_the_signer_when_the_algorithm_mismatches()
    {
        using var rsa = RSA.Create(2048);
        var disposeCount = 0;
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => new ValueTask<ISigner>(
                new TrackingSigner(
                    new WrongAlgorithmSigner(new LocalSigner(SigningAlgorithm.RS256, RSA.Create(2048)), SigningAlgorithm.RS384),
                    () => disposeCount++)));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        disposeCount.Should().Be(1);
    }

    [Fact]
    public async Task InitializeAsync_throws_ZeeKayDaConfigurationException_when_ReadAsync_returns_null()
    {
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>((SourceKeySet)null!),
            (_, _) => throw new NotSupportedException("must not be reached"));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_source_key_set");
    }

    [Fact]
    public async Task InitializeAsync_throws_ZeeKayDaConfigurationException_when_CreateSignerAsync_returns_null()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => new ValueTask<ISigner>((ISigner)null!));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_signer");
    }

    [Fact]
    public async Task InitializeAsync_message_does_not_contain_the_underlying_exception_s_message()
    {
        const string secret = "Authorization: Bearer eyJsecret-token-value";
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => throw new InvalidOperationException($"GET https://contoso-prod.vault.azure.net/keys/signing 401; {secret}"));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        var exception = (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>()).Which;
        exception.AggregatedFailures.Should().OnlyContain(f => !f.Message.Contains(secret));
        exception.InnerException.Should().NotBeNull();
        exception.InnerException!.Message.Should().Contain(secret);
    }

    [Fact]
    public async Task InitializeAsync_does_not_flatten_a_source_s_own_ZeeKayDaConfigurationException()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) => throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("provider.custom_failure", "a provider-specific failure")));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "provider.custom_failure");
    }

    [Fact]
    public async Task InitializeAsync_called_twice_throws_on_the_second_call_and_leaves_the_first_signer_open()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);
        var firstCurrent = ring.Current;

        var act = async () => await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
        ring.Current.Should().BeSameAs(firstCurrent);
    }

    [Fact]
    public async Task SignAsync_throws_ArgumentNullException_when_buildSigningInput_is_null()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        var act = async () => await ring.SignAsync<byte[]>(
            [], null!, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task SignAsync_mutating_the_callback_s_returned_buffer_afterwards_does_not_change_the_reported_SigningInput()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);
        var mutableBuffer = "payload"u8.ToArray();

        var outcome = await ring.SignAsync(
            mutableBuffer, static (_, state) => state, TestContext.Current.CancellationToken);
        var reportedBeforeMutation = outcome.SigningInput.ToArray();
        mutableBuffer[0] ^= 0xFF; // mutate the caller's own buffer after SignAsync returns

        outcome.SigningInput.ToArray().Should().Equal(reportedBeforeMutation);
    }

    [Fact]
    public async Task SignAsync_the_signer_reusing_its_returned_buffer_afterwards_does_not_change_the_reported_Signature()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        BufferReusingSigner? reusingSigner = null;

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                reusingSigner = new BufferReusingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
                return new ValueTask<ISigner>(reusingSigner);
            });
        using var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        var outcome = await ring.SignAsync(
            "payload"u8.ToArray(), static (_, state) => state, TestContext.Current.CancellationToken);
        var reportedBeforeReuse = outcome.Signature.ToArray();
        reusingSigner!.CorruptLastReturnedBuffer();

        outcome.Signature.ToArray().Should().Equal(reportedBeforeReuse);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static FakeSigningKeySource NeverCalledSource() =>
        new(
            _ => throw new InvalidOperationException("must not be called before InitializeAsync"),
            (_, _) => throw new InvalidOperationException("must not be called before InitializeAsync"));

    private static (FakeSigningKeySource Source, SourceKey Current) CreateSuccessfulSource(RSA rsa, DateTimeOffset expiresAt)
    {
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt);

        // The signer must be opened over a private key matching the published public key, otherwise
        // the self-test itself would fail — CreateSignerAsync gets its own fresh RSA instance
        // imported from the same key pair.
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.Create(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
            });

        return (source, current);
    }

    /// <summary>
    /// Builds a successful <c>ReadAsync</c>/<c>CreateSignerAsync</c> pair whose signer records
    /// <c>"signer"</c> onto <paramref name="disposalOrder"/> when disposed, so a source built over it
    /// can be tested for disposal order against its own <c>"source"</c> entry. When
    /// <paramref name="signerThrowsOnDispose"/> is <see langword="true"/>, the signer's <c>Dispose</c>
    /// throws instead of recording anything, modelling a third-party signer whose cleanup fails.
    /// </summary>
    private static (
        Func<CancellationToken, ValueTask<SourceKeySet>> Read,
        Func<SourceKeyId, CancellationToken, ValueTask<ISigner>> CreateSigner,
        SourceKey Current) CreateSuccessfulReadAndSigner(
            RSA rsa, DateTimeOffset expiresAt, List<string> disposalOrder, bool signerThrowsOnDispose = false)
    {
        var current = new SourceKey(
            new SourceKeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt);
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        ValueTask<SourceKeySet> Read(CancellationToken _) => new(SourceKeySet.Create(null, current, null));

        ValueTask<ISigner> CreateSigner(SourceKeyId _, CancellationToken __)
        {
            var signerRsa = RSA.Create();
            signerRsa.ImportFromPem(privateKeyPem);
            var local = new LocalSigner(SigningAlgorithm.RS256, signerRsa);
            ISigner signer = signerThrowsOnDispose
                ? new ThrowingDisposeSigner(local)
                : new TrackingSigner(local, () => disposalOrder.Add("signer"));
            return new ValueTask<ISigner>(signer);
        }

        return (Read, CreateSigner, current);
    }

    /// <summary>
    /// Builds and initializes a <see cref="StaticSigningKeyRing"/> over a source created by
    /// <paramref name="createSource"/> from a successful, disposal-tracking read/signer pair,
    /// collapsing the arrange steps shared by every disposal-ordering test into one call so each test
    /// differs only in the source shape it builds and what it asserts afterwards.
    /// </summary>
    private static async Task<StaticSigningKeyRing> CreateInitializedRingAsync(
        List<string> disposalOrder,
        Func<
            Func<CancellationToken, ValueTask<SourceKeySet>>,
            Func<SourceKeyId, CancellationToken, ValueTask<ISigner>>,
            ISigningKeySource> createSource,
        bool signerThrowsOnDispose = false)
    {
        using var rsa = RSA.Create(2048);
        var (read, createSigner, _) = CreateSuccessfulReadAndSigner(rsa, Epoch.AddDays(90), disposalOrder, signerThrowsOnDispose);
        var source = createSource(read, createSigner);
        var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);
        return ring;
    }
}
