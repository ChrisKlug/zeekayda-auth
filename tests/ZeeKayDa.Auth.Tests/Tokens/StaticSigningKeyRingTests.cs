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
        Func<KeyId, CancellationToken, ValueTask<ISigner>> createSigner) : ISigningKeySource
    {
        public int ReadAsyncCallCount { get; private set; }

        public int CreateSignerAsyncCallCount { get; private set; }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return read(cancellationToken);
        }

        public ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken = default)
        {
            CreateSignerAsyncCallCount++;
            return createSigner(id, cancellationToken);
        }
    }

    /// <summary>
    /// Wraps a real <see cref="ISigner"/> but always signs a fixed, pre-recorded payload rather than
    /// whatever it is asked to sign — modelling a memoizing remote signer or caching signing proxy.
    /// A signature over that fixed payload would have verified against today's compile-time-constant
    /// self-test payload; a fresh per-invocation nonce (issue #506) exposes the memoization.
    /// </summary>
    private sealed class MemoizingSigner(ISigner inner, ReadOnlyMemory<byte> primedInput) : ISigner
    {
        private ReadOnlyMemory<byte>? _cachedSignature;

        public SigningAlgorithm Algorithm => inner.Algorithm;

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            _cachedSignature ??= await inner.SignAsync(primedInput, cancellationToken).ConfigureAwait(false);
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

    // ── Current / CurrentOrNull before initialization ───────────────────────────────────────────

    [Fact]
    public void Current_throws_InvalidOperationException_before_initialization()
    {
        var ring = new StaticSigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch));

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
        var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
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
        var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);
        ring.Dispose();

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
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return new ValueTask<ISigner>(
                    new TrackingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa), () => disposeCount++));
            });

        var ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        ring.Dispose();
        ring.Dispose();

        disposeCount.Should().Be(1);
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
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, null, null)), // no Current
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
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
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
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
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
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(publicRsa.ExportParameters(false)), Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
            (_, _) => new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, otherRsa)));
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_the_signer_returns_a_memoized_signature()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var primedInput = "zeekayda-auth signing self-test"u8.ToArray(); // today's old, fixed constant

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return new ValueTask<ISigner>(
                    new MemoizingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa), primedInput));
            });
        ISigningKeyRing ring = new StaticSigningKeyRing(source, new FakeTimeProvider(Epoch));

        var act = async () => await ring.InitializeAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static FakeSigningKeySource NeverCalledSource() =>
        new(
            _ => throw new InvalidOperationException("must not be called before InitializeAsync"),
            (_, _) => throw new InvalidOperationException("must not be called before InitializeAsync"));

    private static (FakeSigningKeySource Source, SourceKey Current) CreateSuccessfulSource(RSA rsa, DateTimeOffset expiresAt)
    {
        var current = new SourceKey(
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt);

        // The signer must be opened over a private key matching the published public key, otherwise
        // the self-test itself would fail — CreateSignerAsync gets its own fresh RSA instance
        // imported from the same key pair.
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(null, current, null)),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
            });

        return (source, current);
    }
}
