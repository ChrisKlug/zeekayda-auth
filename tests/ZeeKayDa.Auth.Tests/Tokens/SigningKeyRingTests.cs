using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyRing"/>: the one-time startup read, the signing key's
/// expiry and signer-open/self-test checks that fail startup, <see cref="SigningKeyRing.SignAsync{TState}"/>,
/// and ownership of the one <see cref="ISigner"/> it opens for the process lifetime.
/// </summary>
public sealed class SigningKeyRingTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Fakes ────────────────────────────────────────────────────────────────────────────────────

    private sealed class FakeSigningKeySource(
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> createSigner) : ISigningKeySource
    {
        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

        public int ReadAsyncCallCount { get; private set; }

        public int CreateSignerAsyncCallCount { get; private set; }

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return read(cancellationToken);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
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

        public async Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            _cachedSignature ??= await inner.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
            return _cachedSignature.Value;
        }

        public void Dispose() => inner.Dispose();
    }

    /// <summary>
    /// Signs for real, then hands back a signature buffer it goes on to mutate in place afterwards —
    /// modelling a provider that reuses or pools its return buffer.
    /// </summary>
    private sealed class BufferReusingSigner(ISigner inner) : ISigner
    {
        private byte[]? _lastReturnedBuffer;

        public async Task<ReadOnlyMemory<byte>> SignAsync(
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
        public Task<ReadOnlyMemory<byte>> SignAsync(
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
        public Task<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => inner.SignAsync(signingInput, cancellationToken);

        public void Dispose() => throw new InvalidOperationException("simulated: signer Dispose failure");
    }

    /// <summary>A working <see cref="ISigningKeySource"/> that also implements <see cref="IDisposable"/>,
    /// recording disposal via a caller-supplied callback.</summary>
    private sealed class DisposableSigningKeySource(
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> createSigner,
        Action onDispose,
        SigningAlgorithm algorithm = SigningAlgorithm.RS256) : ISigningKeySource, IDisposable
    {
        public SigningAlgorithm Algorithm => algorithm;

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public void Dispose() => onDispose();
    }

    /// <summary>A working <see cref="ISigningKeySource"/> that implements only
    /// <see cref="IAsyncDisposable"/>, modelling the shape the ring's synchronous <c>Dispose</c>
    /// rejects as a last line of defence.</summary>
    private sealed class AsyncOnlySigningKeySource(
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> createSigner,
        Func<ValueTask> onDisposeAsync) : ISigningKeySource, IAsyncDisposable
    {
        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public ValueTask DisposeAsync() => onDisposeAsync();
    }

    /// <summary>A working <see cref="ISigningKeySource"/> implementing both disposal interfaces,
    /// recording which one was invoked via caller-supplied callbacks.</summary>
    private sealed class DualDisposableSigningKeySource(
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> createSigner,
        Action onDispose,
        Func<ValueTask> onDisposeAsync) : ISigningKeySource, IDisposable, IAsyncDisposable
    {
        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default) => read(cancellationToken);

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
            => createSigner(id, cancellationToken);

        public void Dispose() => onDispose();

        public ValueTask DisposeAsync() => onDisposeAsync();
    }

    // ── Current / CurrentOrNull before initialization ───────────────────────────────────────────

    [Fact]
    public void Current_throws_InvalidOperationException_before_initialization()
    {
        using var ring = new SigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = () => ring.Current;

        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task SignAsync_throws_InvalidOperationException_before_initialization()
    {
        // No token is ever signed by a signer that has not passed the self-test: before
        // initialization there is no signer at all, and signing refuses rather than opening one.
        SigningKeyRing ring = new SigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.SignAsync(0, static (_, _) => new ReadOnlyMemory<byte>([1, 2, 3]), TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public void CurrentOrNull_is_null_before_initialization()
    {
        SigningKeyRing ring = new SigningKeyRing(NeverCalledSource(), new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        ring.CurrentOrNull.Should().BeNull();
    }

    // ── InitializeAsync — success ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task InitializeAsync_builds_the_key_set_and_opens_the_signer_exactly_once()
    {
        using var rsa = RSA.Create(2048);
        var (source, current) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        ring.Current.SigningKey.SourceId.Should().Be(current.Id);
        source.ReadAsyncCallCount.Should().Be(1);
        source.CreateSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task SignAsync_signs_with_the_current_signing_key_and_returns_a_verifiable_outcome()
    {
        using var rsa = RSA.Create(2048);
        var (source, current) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

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
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        ((IDisposable)ring).Dispose();

        var act = async () => await ring.SignAsync(
            "payload"u8.ToArray(), static (_, state) => state, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Ring_keeps_its_lead_time_when_the_caller_s_options_change_after_construction()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
            });
        var options = new SigningKeyOptions { LeadTime = TimeSpan.FromDays(1), RetainRetiredKeysFor = TimeSpan.FromDays(2) };

        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), options, new CapturingSanitizingLogger<SigningKeyRing>());
        options.LeadTime = TimeSpan.FromDays(30);
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        ring.TimelineOrNull!.LeadTime.Should().Be(TimeSpan.FromDays(1));
    }

    [Fact]
    public async Task Dispose_disposes_the_owned_signer_exactly_once()
    {
        using var rsa = RSA.Create(2048);
        var disposeCount = 0;
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return Task.FromResult<ISigner>(
                    new TrackingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa), () => disposeCount++));
            });

        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        ((IDisposable)ring).Dispose();
        ((IDisposable)ring).Dispose();

        disposeCount.Should().Be(1);
    }

    /// <summary>The shape of the disposal call(s) a disposal-ordering theory case exercises against
    /// the ring: synchronous only, asynchronous only, or a synchronous call followed by an
    /// asynchronous one — the ring's idempotent-disposal guard means only the first call's own
    /// disposal path actually runs.</summary>
    public enum DisposalTrigger { Sync, Async, SyncThenAsync }

    /// <summary>Which disposal interfaces the <see cref="ISigningKeySource"/> under test implements.</summary>
    public enum DisposalOrderingSourceShape { SyncOnly, Both }

    public static TheoryData<DisposalOrderingSourceShape, bool, DisposalTrigger, string[]> DisposalOrderingCases() =>
        new()
        {
            // source implements IDisposable only: the ring's own disposal path is the only choice.
            { DisposalOrderingSourceShape.SyncOnly, false, DisposalTrigger.Sync, ["signer", "source"] },
            { DisposalOrderingSourceShape.SyncOnly, false, DisposalTrigger.Async, ["signer", "source"] },
            { DisposalOrderingSourceShape.SyncOnly, false, DisposalTrigger.SyncThenAsync, ["signer", "source"] },
            // source implements both: DisposeAsync prefers IAsyncDisposable, Dispose calls IDisposable.
            { DisposalOrderingSourceShape.Both, false, DisposalTrigger.Sync, ["signer", "sync"] },
            { DisposalOrderingSourceShape.Both, false, DisposalTrigger.Async, ["signer", "async"] },
            // a throwing signer Dispose is swallowed, so the source is still disposed either way.
            { DisposalOrderingSourceShape.SyncOnly, true, DisposalTrigger.Sync, ["source"] },
            { DisposalOrderingSourceShape.SyncOnly, true, DisposalTrigger.Async, ["source"] },
        };

    [Theory]
    [MemberData(nameof(DisposalOrderingCases))]
    public async Task Dispose_or_DisposeAsync_disposes_the_source_in_the_expected_order(
        DisposalOrderingSourceShape sourceShape,
        bool signerThrowsOnDispose,
        DisposalTrigger trigger,
        string[] expectedOrder)
    {
        var disposalOrder = new List<string>();
        var ring = await CreateInitializedRingAsync(
            disposalOrder,
            (read, createSigner) => CreateDisposalOrderingSource(sourceShape, read, createSigner, disposalOrder),
            signerThrowsOnDispose);

        var act = async () =>
        {
            switch (trigger)
            {
                case DisposalTrigger.Sync:
                    ((IDisposable)ring).Dispose();
                    break;
                case DisposalTrigger.Async:
                    await ((IAsyncDisposable)ring).DisposeAsync();
                    break;
                case DisposalTrigger.SyncThenAsync:
                    ((IDisposable)ring).Dispose();
                    await ((IAsyncDisposable)ring).DisposeAsync();
                    break;
            }
        };

        await act.Should().NotThrowAsync();
        disposalOrder.Should().Equal(expectedOrder);
    }

    private static ISigningKeySource CreateDisposalOrderingSource(
        DisposalOrderingSourceShape shape,
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> createSigner,
        List<string> disposalOrder) => shape switch
        {
            DisposalOrderingSourceShape.SyncOnly =>
                new DisposableSigningKeySource(read, createSigner, () => disposalOrder.Add("source")),
            DisposalOrderingSourceShape.Both => new DualDisposableSigningKeySource(
                read, createSigner,
                onDispose: () => disposalOrder.Add("sync"),
                onDisposeAsync: () =>
                {
                    disposalOrder.Add("async");
                    return ValueTask.CompletedTask;
                }),
            _ => throw new ArgumentOutOfRangeException(nameof(shape)),
        };

    // ── InitializeAsync — startup failures ───────────────────────────────────────────────────────

    [Fact]
    public async Task InitializeAsync_builds_the_key_set_against_the_time_provider_s_clock()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(-1));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signing_key_expired");
    }

    [Fact]
    public async Task InitializeAsync_propagates_a_builder_validation_failure_from_ReadAsync()
    {
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([]),
            (_, _) => throw new NotSupportedException("must not be reached"));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_keys");
    }

    [Fact]
    public async Task InitializeAsync_throws_signer_unavailable_when_CreateSignerAsync_throws()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => throw new InvalidOperationException("simulated: key vault unreachable"));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.signer_unavailable");
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_the_signer_signs_under_another_algorithm()
    {
        // The right private key under the wrong algorithm: RS384 bytes for a key published as RS256.
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS384, signerRsa));
            });
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task InitializeAsync_logs_the_lead_time_warning_through_the_ring_s_logger()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90), notBefore: Epoch.AddHours(-1));
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, logger);

        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        logger.Warnings.Should().ContainSingle().Which.Should().Contain(ring.Current.SigningKey.Kid);
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_the_signer_does_not_pair_with_the_public_key()
    {
        using var publicRsa = RSA.Create(2048); // published public key
        using var otherRsa = RSA.Create(2048); // signer's actual (mismatched) private key
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(publicRsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, otherRsa)));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task InitializeAsync_throws_self_test_failed_when_a_shared_signer_returns_a_signature_memoized_from_an_earlier_self_test()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var signerRsa = RSA.Create();
        signerRsa.ImportFromPem(privateKeyPem);
        var sharedSigner = new MemoizingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa));

        IReadOnlyList<SourceKey> ReadCurrent(CancellationToken _) => [current];
        Task<ISigner> LendSharedSigner(SourceKeyId _, CancellationToken __) => Task.FromResult<ISigner>(sharedSigner);

        var firstSource = new FakeSigningKeySource(t => Task.FromResult<IReadOnlyList<SourceKey>>(ReadCurrent(t)), LendSharedSigner);
        SigningKeyRing firstRing = new SigningKeyRing(firstSource, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        // Succeeds: the shared signer's very first call is a genuine sign over this self-test's own
        // random nonce, so it verifies and the cache is primed with a correct-for-that-nonce signature.
        await firstRing.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        var secondSource = new FakeSigningKeySource(t => Task.FromResult<IReadOnlyList<SourceKey>>(ReadCurrent(t)), LendSharedSigner);
        SigningKeyRing secondRing = new SigningKeyRing(secondSource, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        // A second, independent self-test generates a different random nonce, but the shared signer
        // returns the signature it cached for the first ring's nonce — this must fail verification.
        var act = async () => await secondRing.EnsureInitializedAsync(TestContext.Current.CancellationToken);

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
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(publicRsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => Task.FromResult<ISigner>(
                new TrackingSigner(new LocalSigner(SigningAlgorithm.RS256, otherRsa), () => disposeCount++)));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        disposeCount.Should().Be(1);
    }

    [Fact]
    public async Task InitializeAsync_throws_ZeeKayDaConfigurationException_when_ReadAsync_returns_null()
    {
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>((IReadOnlyList<SourceKey>)null!),
            (_, _) => throw new NotSupportedException("must not be reached"));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_source_key_set");
    }

    [Fact]
    public async Task InitializeAsync_throws_ZeeKayDaConfigurationException_when_CreateSignerAsync_returns_null()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => Task.FromResult<ISigner>((ISigner)null!));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_signer");
    }

    [Fact]
    public async Task InitializeAsync_message_does_not_contain_the_underlying_exception_s_message()
    {
        const string secret = "Authorization: Bearer eyJsecret-token-value";
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => throw new InvalidOperationException($"GET https://contoso-prod.vault.azure.net/keys/signing 401; {secret}"));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

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
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) => throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("provider.custom_failure", "a provider-specific failure")));
        SigningKeyRing ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var act = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "provider.custom_failure");
    }

    [Fact]
    public async Task EnsureInitializedAsync_called_twice_reads_the_source_once_and_opens_one_signer()
    {
        // Idempotence is what lets a startup check that needs the key set ask for it, instead of
        // relying on running after the ring's own activator.
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        var firstCurrent = ring.Current;

        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        source.ReadAsyncCallCount.Should().Be(1);
        source.CreateSignerAsyncCallCount.Should().Be(1);
        ring.Current.Should().BeSameAs(firstCurrent);
    }

    [Fact]
    public async Task EnsureInitializedAsync_called_concurrently_reads_the_source_once()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            ring.EnsureInitializedAsync(TestContext.Current.CancellationToken)));

        source.ReadAsyncCallCount.Should().Be(1);
        source.CreateSignerAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task EnsureInitializedAsync_reports_the_original_failure_to_a_later_caller_without_retrying()
    {
        // Initialization runs at startup, where a failure aborts the host. A second caller must see
        // the first failure rather than trigger a second attempt against a source that just refused.
        var source = new FakeSigningKeySource(
            _ => throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("signing.source_unavailable", "Simulated failure.")),
            (_, _) => throw new NotSupportedException());
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());

        var first = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        await first.Should().ThrowAsync<ZeeKayDaConfigurationException>();

        var second = async () => await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await second.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*source_unavailable*");
        source.ReadAsyncCallCount.Should().Be(1, "a failed initialization is not retried");
    }

    [Fact]
    public async Task SignAsync_throws_ArgumentNullException_when_buildSigningInput_is_null()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        var act = async () => await ring.SignAsync<byte[]>(
            [], null!, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task SignAsync_mutating_the_callback_s_returned_buffer_afterwards_does_not_change_the_reported_SigningInput()
    {
        using var rsa = RSA.Create(2048);
        var (source, _) = CreateSuccessfulSource(rsa, expiresAt: Epoch.AddDays(90));
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
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
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Epoch.AddDays(90));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        BufferReusingSigner? reusingSigner = null;

        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current]),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                reusingSigner = new BufferReusingSigner(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
                return Task.FromResult<ISigner>(reusingSigner);
            });
        using var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        var outcome = await ring.SignAsync(
            "payload"u8.ToArray(), static (_, state) => state, TestContext.Current.CancellationToken);
        var reportedBeforeReuse = outcome.Signature.ToArray();
        reusingSigner!.CorruptLastReturnedBuffer();

        outcome.Signature.ToArray().Should().Equal(reportedBeforeReuse);
    }

    // ── Handover over time ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Handover_signs_with_the_successor_once_its_lead_time_ends_and_the_signature_verifies()
    {
        var clock = new FakeTimeProvider(Epoch);
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        using var ring = TestSigningKeys.Ring([TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), successor], clock);

        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);
        var outcome = await ring.SignAsync(0, static (_, _) => "payload"u8.ToArray(), TestContext.Current.CancellationToken);

        outcome.Key.SourceId.Should().Be(successor.Key.Id);
        using var verifier = ECDsa.Create(successor.PrivateKey);
        verifier.VerifyData(outcome.SigningInput.Span, outcome.Signature.Span, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public async Task A_dropped_staged_key_is_warned_about_and_never_published_or_signed_with()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var badStaged = TestSigningKeys.Pair("staged", notBefore: Epoch) with
        {
            Key = TestSigningKeys.SourceKey("staged", SigningAlgorithm.RS256, Epoch),
        };
        using var ring = TestSigningKeys.Ring([current, badStaged], clock, logger);

        logger.Warnings.Should().ContainSingle(w => w.Contains("staged") && w.Contains("signing.key_algorithm_mismatch"));
        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);

        ring.Current.SigningKey.SourceId.Value.Should().Be("current");
        ring.Current.Published.Select(k => k.SourceId.Value).Should().Equal("current");
    }

    [Fact]
    public async Task Initialization_fails_when_the_key_due_to_sign_now_was_dropped()
    {
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var badDue = TestSigningKeys.Pair("due", notBefore: Epoch.AddDays(-5)) with
        {
            Key = TestSigningKeys.SourceKey("due", SigningAlgorithm.RS256, Epoch.AddDays(-5)),
        };
        using var ring = TestSigningKeys.Uninitialized([current, badDue], new FakeTimeProvider(Epoch));

        var act = () => ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.key_algorithm_mismatch");
    }

    [Fact]
    public async Task Handover_opens_the_successor_s_signer_only_when_it_takes_over()
    {
        var clock = new FakeTimeProvider(Epoch);
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch)],
            clock,
            decorateSigner: signer => { opened++; return signer; });

        opened.Should().Be(1);
        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);

        opened.Should().Be(2);
    }

    [Fact]
    public async Task Handover_failure_keeps_the_previous_key_signing_logs_an_Error_and_names_the_failed_successor()
    {
        var clock = new FakeTimeProvider(Epoch);
        var logger = new CapturingSanitizingLogger<SigningKeyRing>();
        var successor = TestSigningKeys.Mismatched(TestSigningKeys.Pair("successor", notBefore: Epoch));
        using var ring = TestSigningKeys.Ring([TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), successor], clock, logger);

        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);

        ring.Current.SigningKey.SourceId.Value.Should().Be("current");
        ring.Current.Published.Should().Contain(ring.Current.SigningKey);
        ring.TimelineOrNull!.SetAside.Should().ContainSingle().Which.SourceId.Should().Be(successor.Key.Id);
        logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain("signing.self_test_failed");
    }

    [Fact]
    public async Task Handover_failure_is_not_retried_at_later_transitions()
    {
        var clock = new FakeTimeProvider(Epoch);
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)),
                TestSigningKeys.Mismatched(TestSigningKeys.Pair("successor", notBefore: Epoch)),
            ],
            clock,
            decorateSigner: signer => { opened++; return signer; });

        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime + TimeSpan.FromDays(5));

        opened.Should().Be(2, "the startup signer, then one attempt for the successor");
        ring.Current.SigningKey.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task Handover_failure_keeps_the_failed_key_published_and_the_key_signing_on_published_while_it_signs()
    {
        // B fails on this replica only; other replicas sign with it, so it must stay in this
        // replica's JWKS. A signs on here, so it stays published however long B has been due.
        var clock = new FakeTimeProvider(Epoch);
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("a", notBefore: Epoch.AddDays(-90)),
                TestSigningKeys.Mismatched(TestSigningKeys.Pair("b", notBefore: Epoch)),
            ],
            clock);

        await AdvanceToAsync(ring, clock, Epoch.AddDays(5));

        ring.Current.SigningKey.SourceId.Value.Should().Be("a");
        ring.Current.Published.Select(key => key.SourceId.Value).Should().Equal("a", "b");
    }

    [Fact]
    public async Task Handover_re_evaluates_when_the_clock_passes_a_change_instant_while_the_successor_s_signer_opens()
    {
        // B is due at its lead time but expires one second later, while its signer is still opening;
        // the ring must not commit an expired B, and A is still there to sign.
        var clock = new FakeTimeProvider(Epoch);
        var leadEnds = Epoch + TestSigningKeys.Options.LeadTime;
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("a", notBefore: Epoch.AddDays(-90)),
                TestSigningKeys.Pair("b", notBefore: Epoch, expiresAt: leadEnds.AddSeconds(1)),
            ],
            clock,
            decorateSigner: signer =>
            {
                if (opened++ > 0)
                    clock.Advance(TimeSpan.FromSeconds(2));
                return signer;
            });

        await AdvanceToAsync(ring, clock, leadEnds);

        ring.Current.SigningKey.SourceId.Value.Should().Be("a");
    }

    [Fact]
    public async Task Handover_hands_over_at_once_to_a_key_that_became_due_while_another_s_signer_opened()
    {
        // B is due at its lead time and expires a second later; C becomes due in that second. B's
        // signer takes two seconds to open, so once it does, C must sign without waiting for a timer.
        var clock = new FakeTimeProvider(Epoch);
        var leadEnds = Epoch + TestSigningKeys.Options.LeadTime;
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("a", notBefore: Epoch.AddDays(-90)),
                TestSigningKeys.Pair("b", notBefore: Epoch, expiresAt: leadEnds.AddSeconds(1)),
                TestSigningKeys.Pair("c", notBefore: Epoch.AddSeconds(1)),
            ],
            clock,
            decorateSigner: signer =>
            {
                if (opened++ == 1)
                    clock.Advance(TimeSpan.FromSeconds(2));
                return signer;
            });

        await AdvanceToAsync(ring, clock, leadEnds);

        ring.Current.SigningKey.SourceId.Value.Should().Be("c");
    }

    [Fact]
    public async Task Handover_never_retries_any_failed_successor_when_signing_falls_back_to_it()
    {
        // B fails on day 1 and C on day 2; when C expires on day 3, B must not be tried again.
        var clock = new FakeTimeProvider(Epoch);
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("a", notBefore: Epoch.AddDays(-90), expiresAt: Epoch.AddDays(4)),
                TestSigningKeys.Mismatched(TestSigningKeys.Pair("b", notBefore: Epoch)),
                TestSigningKeys.Mismatched(TestSigningKeys.Pair("c", notBefore: Epoch.AddDays(1), expiresAt: Epoch.AddDays(3))),
            ],
            clock,
            decorateSigner: signer => { opened++; return signer; });

        await AdvanceToAsync(ring, clock, Epoch.AddDays(3).AddHours(1));

        opened.Should().Be(3, "the startup signer, then one attempt each for B and C");
        ring.Current.SigningKey.SourceId.Value.Should().Be("a");
        ring.TimelineOrNull!.SetAside.Select(key => key.SourceId.Value).Should().Equal("b", "c");
    }

    [Fact]
    public async Task Handover_treats_a_source_s_own_cancellation_as_a_failed_successor_not_a_shutdown()
    {
        var clock = new FakeTimeProvider(Epoch);
        var opened = 0;
        using var ring = TestSigningKeys.Ring(
            [TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch)],
            clock,
            decorateSigner: signer =>
            {
                if (opened++ == 0)
                    return signer;
                signer.Dispose();
                throw new OperationCanceledException("simulated: the source timed out");
            });

        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);

        ring.TimelineOrNull!.SetAside.Should().ContainSingle().Which.SourceId.Value.Should().Be("successor");
        ring.Current.SigningKey.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task Dispose_still_disposes_every_signer_and_the_source_when_a_cancellation_callback_throws()
    {
        var clock = new FakeTimeProvider(Epoch);
        var current = TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90));
        var successor = TestSigningKeys.Pair("successor", notBefore: Epoch);
        var disposed = new List<string>();
        var source = new DisposableSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>([current.Key, successor.Key]),
            (id, cancellationToken) =>
            {
                if (id == successor.Key.Id)
                {
                    // Hangs until shutdown, and registers a callback that throws when shutdown comes.
                    cancellationToken.Register(static () => throw new InvalidOperationException("simulated: callback failure"));
                    return new TaskCompletionSource<ISigner>().Task;
                }

                ISigner signer = new LocalSigner(SigningAlgorithm.ES256, ECDsa.Create(current.PrivateKey));
                return Task.FromResult<ISigner>(new TrackingSigner(signer, () => disposed.Add("signer")));
            },
            () => disposed.Add("source"),
            SigningAlgorithm.ES256);
        var ring = new SigningKeyRing(source, clock, TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);

        ((IDisposable)ring).Dispose();

        disposed.Should().Equal("signer", "source");
    }

    [Fact]
    public async Task Handover_failure_makes_the_expiry_health_check_Degraded()
    {
        var clock = new FakeTimeProvider(Epoch);
        using var ring = TestSigningKeys.Ring(
            [
                TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)),
                TestSigningKeys.Mismatched(TestSigningKeys.Pair("successor", notBefore: Epoch)),
            ],
            clock);
        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);
        var check = new SigningKeyExpiryHealthCheck(
            ring, clock, Microsoft.Extensions.Options.Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await check.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public async Task Handover_keeps_the_superseded_signer_open_until_the_ring_is_disposed_then_disposes_each_once()
    {
        var clock = new FakeTimeProvider(Epoch);
        var disposed = new List<string>();
        var opened = 0;
        var ring = TestSigningKeys.Ring(
            [TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch)],
            clock,
            decorateSigner: signer =>
            {
                var name = opened++ == 0 ? "current" : "successor";
                return new TrackingSigner(signer, () => disposed.Add(name));
            });

        await AdvanceToAsync(ring, clock, Epoch + TestSigningKeys.Options.LeadTime);
        disposed.Should().BeEmpty();

        ((IDisposable)ring).Dispose();

        disposed.Should().BeEquivalentTo("current", "successor");
    }

    [Fact]
    public async Task Dispose_stops_the_ring_following_the_clock()
    {
        var clock = new FakeTimeProvider(Epoch);
        var ring = TestSigningKeys.Ring(
            [TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch)],
            clock);

        ((IDisposable)ring).Dispose();
        clock.SetUtcNow(Epoch + TestSigningKeys.Options.LeadTime);
        await ring.LastTransition;

        ring.Current.SigningKey.SourceId.Value.Should().Be("current");
    }

    /// <summary>Moves <paramref name="clock"/> to <paramref name="until"/> one change instant at a
    /// time, as a live clock would pass them, letting each handover finish.</summary>
    private static async Task AdvanceToAsync(SigningKeyRing ring, FakeTimeProvider clock, DateTimeOffset until)
    {
        while (clock.GetUtcNow() < until)
        {
            var next = ring.TimelineOrNull!.NextChangeAfter(clock.GetUtcNow());
            clock.SetUtcNow(next < until ? next : until);
            await ring.LastTransition;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static FakeSigningKeySource NeverCalledSource() =>
        new(
            _ => throw new InvalidOperationException("must not be called before InitializeAsync"),
            (_, _) => throw new InvalidOperationException("must not be called before InitializeAsync"));

    private static (FakeSigningKeySource Source, SourceKey Current) CreateSuccessfulSource(
        RSA rsa, DateTimeOffset expiresAt, DateTimeOffset? notBefore = null, SourceKey? next = null)
    {
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), notBefore: notBefore, expiresAt: expiresAt);

        // The signer must be opened over a private key matching the published public key, otherwise
        // the self-test itself would fail — CreateSignerAsync gets its own fresh RSA instance
        // imported from the same key pair.
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();

        var source = new FakeSigningKeySource(
            _ => Task.FromResult<IReadOnlyList<SourceKey>>(next is null ? [current] : [current, next]),
            (_, _) =>
            {
                var signerRsa = RSA.Create();
                signerRsa.ImportFromPem(privateKeyPem);
                return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
            });

        return (source, current);
    }

    /// <summary>
    /// The inputs <see cref="CreateSuccessfulReadAndSigner"/> needs, collapsed into one parameter
    /// object rather than four positional arguments.
    /// </summary>
    private sealed record ReadAndSignerRequest(
        RSA Rsa, DateTimeOffset ExpiresAt, List<string> DisposalOrder, bool SignerThrowsOnDispose = false);

    /// <summary>
    /// Builds a successful <c>ReadAsync</c>/<c>CreateSignerAsync</c> pair whose signer records
    /// <c>"signer"</c> onto <see cref="ReadAndSignerRequest.DisposalOrder"/> when disposed, so a
    /// source built over it can be tested for disposal order against its own <c>"source"</c> entry.
    /// When <see cref="ReadAndSignerRequest.SignerThrowsOnDispose"/> is <see langword="true"/>, the
    /// signer's <c>Dispose</c> throws instead of recording anything, modelling a third-party signer
    /// whose cleanup fails.
    /// </summary>
    private static (
        Func<CancellationToken, Task<IReadOnlyList<SourceKey>>> Read,
        Func<SourceKeyId, CancellationToken, Task<ISigner>> CreateSigner,
        SourceKey Current) CreateSuccessfulReadAndSigner(ReadAndSignerRequest request)
    {
        var current = new SourceKey(
            new SourceKeyId("current"),
            PublicKeyParameters.FromRsa(request.Rsa.ExportParameters(false)), expiresAt: request.ExpiresAt);
        var privateKeyPem = request.Rsa.ExportRSAPrivateKeyPem();

        Task<IReadOnlyList<SourceKey>> Read(CancellationToken _) => Task.FromResult<IReadOnlyList<SourceKey>>([current]);

        Task<ISigner> CreateSigner(SourceKeyId _, CancellationToken __)
        {
            var signerRsa = RSA.Create();
            signerRsa.ImportFromPem(privateKeyPem);
            var local = new LocalSigner(SigningAlgorithm.RS256, signerRsa);
            ISigner signer = request.SignerThrowsOnDispose
                ? new ThrowingDisposeSigner(local)
                : new TrackingSigner(local, () => request.DisposalOrder.Add("signer"));
            return Task.FromResult<ISigner>(signer);
        }

        return (Read, CreateSigner, current);
    }

    /// <summary>
    /// Builds and initializes a <see cref="SigningKeyRing"/> over a source created by
    /// <paramref name="createSource"/> from a successful, disposal-tracking read/signer pair,
    /// collapsing the arrange steps shared by every disposal-ordering test into one call so each test
    /// differs only in the source shape it builds and what it asserts afterwards.
    /// </summary>
    private static async Task<SigningKeyRing> CreateInitializedRingAsync(
        List<string> disposalOrder,
        Func<
            Func<CancellationToken, Task<IReadOnlyList<SourceKey>>>,
            Func<SourceKeyId, CancellationToken, Task<ISigner>>,
            ISigningKeySource> createSource,
        bool signerThrowsOnDispose = false)
    {
        using var rsa = RSA.Create(2048);
        var (read, createSigner, _) = CreateSuccessfulReadAndSigner(
            new ReadAndSignerRequest(rsa, Epoch.AddDays(90), disposalOrder, signerThrowsOnDispose));
        var source = createSource(read, createSigner);
        var ring = new SigningKeyRing(source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);
        return ring;
    }
}
