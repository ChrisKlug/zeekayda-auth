using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises the provider contract (<see cref="KeySetOptions"/>/<see cref="KeySourceOptions"/>,
/// <see cref="KeyListing"/>, <see cref="ISigner"/>) machinery on
/// <see cref="JwtSigningService{TOptions}"/> — the sole signing-provider contract since the
/// legacy contract was removed in issue #428.
/// </summary>
public sealed class JwtSigningServiceTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // Mirrors JwtSigningService<TOptions>'s private SelfTestPayload constant — the
    // self-test (issue #437) always signs exactly this payload, so a signer test double that needs
    // to distinguish the self-test call from a real signing call compares against this.
    private static readonly byte[] SelfTestPayloadBytes = "zeekayda-auth signing self-test"u8.ToArray();

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeKeySetOptions : KeySetOptions
    {
    }

    private sealed class FakeKeySourceOptions : KeySourceOptions
    {
    }

    /// <summary>
    /// An <see cref="ISigner"/> test double that counts every call. When <paramref name="privateKey"/>
    /// is supplied, it signs for real (so the self-test — issue #437 — which every
    /// active-key handoff now runs, sees a genuinely verifiable signature); otherwise it returns a
    /// fixed, non-verifying placeholder, for tests that never exercise a real handoff or that
    /// deliberately want the self-test to fail.
    /// </summary>
    private sealed class FakeSigner(SigningAlgorithm algorithm = SigningAlgorithm.RS256, AsymmetricAlgorithm? privateKey = null) : ISigner
    {
        public int DisposeCount { get; private set; }

        public int SignAsyncCallCount { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            SignAsyncCallCount++;
            if (privateKey is not null)
                return new ValueTask<ReadOnlyMemory<byte>>(SigningAlgorithms.Sign(algorithm, signingInput.ToArray(), privateKey));

            return new ValueTask<ReadOnlyMemory<byte>>(new byte[] { 1, 2, 3, 4 });
        }

        public void Dispose() => DisposeCount++;

        public SigningAlgorithm Algorithm => algorithm;
    }

    private sealed class FakeRetirementWindowProvider(TimeSpan window) : ISigningKeyRetirementWindowProvider
    {
        public TimeSpan GetRetirementWindow() => window;
    }

    /// <summary>
    /// An <see cref="ISigner"/> test double whose <see cref="SignAsync"/> always throws, modelling a
    /// missing Key Vault "sign" permission or an inaccessible CNG key container — a failure the
    /// self-test (issue #437) surfaces as an exception from the sign call itself, not as a
    /// verification mismatch (security review finding F4).
    /// </summary>
    private sealed class ThrowingSigner : ISigner
    {
        public int DisposeCount { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => throw new CryptographicException("simulated inaccessible key container");

        public void Dispose() => DisposeCount++;

        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;
    }

    /// <summary>
    /// An <see cref="ISigner"/> test double whose <see cref="SignAsync"/> blocks until
    /// <paramref name="release"/> completes, signalling <see cref="Entered"/> first so a test can
    /// deterministically know the call is in flight before proceeding. The self-test
    /// (issue #437) signs <see cref="SelfTestPayloadBytes"/> synchronously while the base class
    /// still holds its signer lock, so that specific call is answered immediately with a real,
    /// verifiable signature over <paramref name="privateKey"/> rather than gated — gating it too
    /// would deadlock every handoff against the base class's own lock, since nothing outside this
    /// call can ever release it.
    /// </summary>
    private sealed class GatedSigner(TaskCompletionSource release, AsymmetricAlgorithm privateKey) : ISigner
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int DisposeCount { get; private set; }

        public Task Entered => _entered.Task;

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            if (signingInput.Span.SequenceEqual(SelfTestPayloadBytes))
                return SigningAlgorithms.Sign(SigningAlgorithm.RS256, signingInput.ToArray(), privateKey);

            _entered.TrySetResult();
            await release.Task.ConfigureAwait(false);
            return new byte[] { 1, 2, 3, 4 };
        }

        public void Dispose() => DisposeCount++;

        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;
    }

    /// <summary>
    /// An <see cref="ISigner"/> test double whose <see cref="Algorithm"/> deliberately disagrees with
    /// the algorithm the <see cref="KeyListing"/> it is registered under declared, so tests can prove
    /// the base class detects and rejects the mismatch (issue #420 follow-up).
    /// </summary>
    private sealed class MismatchedAlgorithmSigner(SigningAlgorithm algorithm) : ISigner
    {
        public int DisposeCount { get; private set; }

        public SigningAlgorithm Algorithm => algorithm;

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => new(new byte[] { 1, 2, 3, 4 });

        public void Dispose() => DisposeCount++;
    }

    /// <summary>
    /// Captures every log call so tests can assert on the within-window-vanish
    /// <see cref="LogLevel.Warning"/> without depending on the real sanitizing wrapper.
    /// </summary>
    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    /// <summary><see cref="KeySetOptions"/> test double.</summary>
    private sealed class KeySetFakeService : JwtSigningService<FakeKeySetOptions>
    {
        private readonly Func<IReadOnlyList<KeyListing>> _listFactory;
        private readonly Func<KeyId, ISigner> _signerFactory;

        public int ListKeysAsyncCallCount { get; private set; }

        public List<KeyId> CreateSignerAsyncCalledFor { get; } = [];

        public int OnDisposeAsyncCallCount { get; private set; }

        public KeySetFakeService(
            IOptions<FakeKeySetOptions> options,
            TimeProvider timeProvider,
            ISigningKeyRetirementWindowProvider retirementWindowProvider,
            ISanitizingLogger<JwtSigningService<FakeKeySetOptions>> logger,
            Func<IReadOnlyList<KeyListing>> listFactory,
            Func<KeyId, ISigner> signerFactory)
            : base(options, timeProvider, retirementWindowProvider, logger)
        {
            _listFactory = listFactory;
            _signerFactory = signerFactory;
        }

        protected override ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
        {
            ListKeysAsyncCallCount++;
            return new ValueTask<IReadOnlyList<KeyListing>>(_listFactory());
        }

        protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
        {
            CreateSignerAsyncCalledFor.Add(id);
            return new ValueTask<ISigner>(_signerFactory(id));
        }

        protected override ValueTask OnDisposeAsync()
        {
            OnDisposeAsyncCallCount++;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary><see cref="KeySourceOptions"/> test double.</summary>
    private sealed class KeySourceFakeService : JwtSigningService<FakeKeySourceOptions>
    {
        private readonly Func<IReadOnlyList<KeyListing>> _listFactory;
        private readonly Func<KeyId, ISigner> _signerFactory;

        public int ListKeysAsyncCallCount { get; private set; }

        public List<KeyId> CreateSignerAsyncCalledFor { get; } = [];

        public KeySourceFakeService(
            IOptions<FakeKeySourceOptions> options,
            TimeProvider timeProvider,
            ISigningKeyRetirementWindowProvider retirementWindowProvider,
            ISanitizingLogger<JwtSigningService<FakeKeySourceOptions>> logger,
            Func<IReadOnlyList<KeyListing>> listFactory,
            Func<KeyId, ISigner> signerFactory)
            : base(options, timeProvider, retirementWindowProvider, logger)
        {
            _listFactory = listFactory;
            _signerFactory = signerFactory;
        }

        protected override ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
        {
            ListKeysAsyncCallCount++;
            return new ValueTask<IReadOnlyList<KeyListing>>(_listFactory());
        }

        protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
        {
            CreateSignerAsyncCalledFor.Add(id);
            return new ValueTask<ISigner>(_signerFactory(id));
        }
    }

    private static KeyListing MakeRsaListing(
        RSA rsa, string id, DateTimeOffset? activateAt, DateTimeOffset expiresAt, SigningAlgorithm algorithm = SigningAlgorithm.RS256) =>
        new(new KeyId(id), algorithm, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), activateAt, expiresAt);

    private static KeySetFakeService BuildKeySetService(
        FakeTimeProvider timeProvider,
        Func<IReadOnlyList<KeyListing>> listFactory,
        Func<KeyId, ISigner>? signerFactory = null,
        TimeSpan? retirementWindow = null,
        CapturingLogger<JwtSigningService<FakeKeySetOptions>>? logger = null,
        TimeSpan? publicationLead = null)
    {
        var options = Options.Create(new FakeKeySetOptions
        {
            PublicationLead = publicationLead ?? TimeSpan.FromHours(1),
        });
        return new KeySetFakeService(
            options,
            timeProvider,
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? new CapturingLogger<JwtSigningService<FakeKeySetOptions>>(),
            listFactory,
            signerFactory ?? (_ => new FakeSigner()));
    }

    private static KeySourceFakeService BuildKeySourceService(
        FakeTimeProvider timeProvider,
        Func<IReadOnlyList<KeyListing>> listFactory,
        Func<KeyId, ISigner>? signerFactory = null,
        TimeSpan? refreshInterval = null,
        TimeSpan? retirementWindow = null,
        CapturingLogger<JwtSigningService<FakeKeySourceOptions>>? logger = null)
    {
        var options = Options.Create(new FakeKeySourceOptions { RefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5) });
        return new KeySourceFakeService(
            options,
            timeProvider,
            new FakeRetirementWindowProvider(retirementWindow ?? TimeSpan.FromHours(1)),
            logger ?? new CapturingLogger<JwtSigningService<FakeKeySourceOptions>>(),
            listFactory,
            signerFactory ?? (_ => new FakeSigner()));
    }

    // ── Snapshot build: KeySetOptions once, KeySourceOptions per refresh ────────────────────────────

    [Fact]
    public async Task ListKeysAsync_is_called_exactly_once_for_KeySetOptions_regardless_of_calls_or_elapsed_time()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(100))],
            signerFactory: _ => new FakeSigner(privateKey: rsa));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromDays(365 * 10));
        await sut.GetSigningKeysAsync(ct);
        await sut.SignAsync(new byte[] { 0 }, ct);

        sut.ListKeysAsyncCallCount.Should().Be(1, "a KeySetOptions provider calls ListKeysAsync exactly once, ever");
    }

    [Fact]
    public async Task ListKeysAsync_is_called_once_per_RefreshInterval_for_KeySourceOptions()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        await using var sut = BuildKeySourceService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(4));
        await sut.GetSigningKeysAsync(ct);

        sut.ListKeysAsyncCallCount.Should().Be(1, "still within the refresh interval");

        timeProvider.Advance(TimeSpan.FromMinutes(2));
        await sut.GetSigningKeysAsync(ct);

        sut.ListKeysAsyncCallCount.Should().Be(2, "past the refresh interval");
    }

    // ── Lazy active-key selection ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Active_key_switches_across_ActivateAt_with_no_additional_ListKeysAsync_call_KeySetOptions()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var successorActivatesAt = Epoch.AddHours(1);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: successorActivatesAt, expiresAt: Epoch.AddYears(1)),
            ],
            signerFactory: id => new FakeSigner(privateKey: id.Value == "k1" ? rsa1 : rsa2));
        var ct = TestContext.Current.CancellationToken;

        var before = await sut.SignAsync(new byte[] { 0 }, ct);
        timeProvider.Advance(TimeSpan.FromHours(2));
        var after = await sut.SignAsync(new byte[] { 0 }, ct);

        before.Kid.Should().NotBe(after.Kid, "the active key must switch once the successor's ActivateAt has passed");
        sut.ListKeysAsyncCallCount.Should().Be(1, "the switch is computed lazily from the one-time snapshot, not a re-list");
        sut.CreateSignerAsyncCalledFor.Should().HaveCount(2, "a signer is created for k1, then again for k2 once it becomes active");
    }

    // ── Disposal timing ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Previous_signer_is_disposed_once_the_active_key_handoff_is_observed_KeySetOptions()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var successorActivatesAt = Epoch.AddHours(1);
        var signersById = new Dictionary<string, FakeSigner>();

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: successorActivatesAt, expiresAt: Epoch.AddYears(1)),
            ],
            signerFactory: id =>
            {
                var signer = new FakeSigner(privateKey: id.Value == "k1" ? rsa1 : rsa2);
                signersById[id.Value] = signer;
                return signer;
            });
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);
        var firstSigner = signersById["k1"];
        firstSigner.DisposeCount.Should().Be(0, "the first signer must not be disposed while it is still active");

        timeProvider.Advance(TimeSpan.FromHours(2));
        await sut.SignAsync(new byte[] { 0 }, ct);

        firstSigner.DisposeCount.Should().Be(1, "the superseded signer must be disposed once the handoff is observed");
        signersById["k2"].DisposeCount.Should().Be(0, "the newly active signer must not be disposed");
    }

    [Fact]
    public async Task Active_signer_is_disposed_at_shutdown_when_no_handoff_ever_occurs()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        FakeSigner? signer = null;

        var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => signer = new FakeSigner(privateKey: rsa));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);
        signer!.DisposeCount.Should().Be(0);

        await sut.DisposeAsync();

        signer.DisposeCount.Should().Be(1, "the sole active signer must be released at shutdown");
    }

    [Fact]
    public async Task DisposeAsync_calls_OnDisposeAsync_at_most_once_across_concurrent_double_dispose()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => new FakeSigner(privateKey: rsa));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);

        // Dispose concurrently rather than sequentially so the guard is proven to cover the
        // derived hook itself, not merely the base class's own cleanup — a derived override that
        // forgot to be self-idempotent would otherwise be exposed to a genuine race here.
        await Task.WhenAll(sut.DisposeAsync().AsTask(), sut.DisposeAsync().AsTask());

        sut.OnDisposeAsyncCallCount.Should().Be(
            1, "the idempotency guard in DisposeAsync must cover the derived OnDisposeAsync hook, not just the base class's own cleanup");
    }

    [Fact]
    public async Task Superseded_signer_is_disposed_after_a_KeySource_refresh_swaps_the_active_key()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var signersById = new Dictionary<string, FakeSigner>();
        var afterRefresh = false;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => afterRefresh
                ? [MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsa2, "k2", activateAt: Epoch, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: id =>
            {
                var signer = new FakeSigner(privateKey: id.Value == "k1" ? rsa1 : rsa2);
                signersById[id.Value] = signer;
                return signer;
            },
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);
        signersById["k1"].DisposeCount.Should().Be(0, "k1 must not be disposed while it is still the sole active signer");

        afterRefresh = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        // k2's ActivateAt (Epoch) is later than k1's (MinValue, from a null ActivateAt), so k2 wins
        // active-key selection once the refreshed snapshot including it is in place.
        await sut.SignAsync(new byte[] { 0 }, ct);

        signersById.Should().ContainKey("k2", "a signer must have been created for the newly active key");
        signersById["k1"].DisposeCount.Should().Be(1, "k1's signer must be superseded and disposed once k2 becomes active");
    }

    [Fact]
    public async Task Superseded_KeySource_signer_disposal_is_deferred_until_its_in_flight_SignAsync_call_completes()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        GatedSigner? gatedSigner = null;
        var afterRefresh = false;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => afterRefresh
                ? [MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsa2, "k2", activateAt: Epoch, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: id => id.Value == "k1"
                ? gatedSigner = new GatedSigner(release, rsa1)
                : new FakeSigner(privateKey: rsa2),
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        // Start a SignAsync call against k1 and let it block inside GatedSigner.SignAsync — the
        // in-flight call the SignerHandle refcounting exists to protect.
        var inFlight = sut.SignAsync(new byte[] { 0 }, ct).AsTask();
        await gatedSigner!.Entered.WaitAsync(ct);

        // While that call is still in flight, trigger a refresh that swaps the active key to k2.
        afterRefresh = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await sut.SignAsync(new byte[] { 0 }, ct);

        gatedSigner.DisposeCount.Should().Be(
            0, "k1's signer must not be disposed while its SignAsync call is still in flight, even after the handoff to k2");

        release.SetResult();
        await inFlight;

        gatedSigner.DisposeCount.Should().Be(
            1, "k1's signer must be disposed only once its in-flight SignAsync call has completed and returned its borrow");
    }

    // ── Kill-by-omission: three-state disambiguation ────────────────────────────────────────────────

    [Fact]
    public async Task Vanished_key_within_its_retirement_window_is_dropped_and_logged_at_Warning()
    {
        using var rsaOld = RSA.Create(2048);
        using var rsaNew = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var retirementWindow = TimeSpan.FromHours(1);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySourceOptions>>();
        var vanish = false;
        var oldKid = JwkThumbprint.Compute(rsaOld.ExportParameters(false));

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => vanish
                ? [MakeRsaListing(rsaNew, "new", activateAt: Epoch, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsaOld, "old", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsaNew, "new", activateAt: Epoch, expiresAt: Epoch.AddYears(1))],
            refreshInterval: TimeSpan.FromMinutes(5),
            retirementWindow: retirementWindow,
            logger: logger);
        var ct = TestContext.Current.CancellationToken;

        var before = await sut.GetSigningKeysAsync(ct);
        before.Should().Contain(k => k.Kid == oldKid, "the old key must still be listed before it vanishes");

        vanish = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6)); // well within the 1-hour retirement window
        var after = await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning && e.Message.Contains("old"),
            "an early/within-window vanish must be logged at Warning");
        after.Should().NotContain(k => k.Kid == oldKid,
            "the vanished key must actually be dropped from the JWKS listing, not merely warned about");
    }

    [Fact]
    public async Task Vanished_key_after_its_retirement_window_has_closed_is_silent()
    {
        using var rsaOld = RSA.Create(2048);
        using var rsaNew = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var retirementWindow = TimeSpan.FromMinutes(1);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySourceOptions>>();
        var vanish = false;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => vanish
                ? [MakeRsaListing(rsaNew, "new", activateAt: Epoch, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsaOld, "old", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsaNew, "new", activateAt: Epoch, expiresAt: Epoch.AddYears(1))],
            refreshInterval: TimeSpan.FromMinutes(5),
            retirementWindow: retirementWindow,
            logger: logger);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        vanish = true;
        // Two refresh cycles well past the 1-minute retirement window.
        timeProvider.Advance(TimeSpan.FromMinutes(5));
        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(5));
        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().BeEmpty("a post-window vanish is the normal end of life and must not be logged");
    }

    [Fact]
    public async Task ListKeysAsync_throwing_propagates_and_leaves_the_previous_snapshot_untouched()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var callCount = 0;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () =>
            {
                callCount++;
                if (callCount == 2)
                    throw new InvalidOperationException("simulated partial read");

                return [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))];
            },
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("simulated partial read");

        var second = await sut.GetSigningKeysAsync(ct);

        second.Select(k => k.Kid).Should().BeEquivalentTo(
            first.Select(k => k.Kid), "a failed read must never be treated as a kill — the previous snapshot must keep serving");
    }

    // ── Status/expiry logging and the too-soon-pending-activation warning (KeySetOptions only) ────

    [Fact]
    public async Task GetSigningKeysAsync_logs_a_warning_when_a_pending_keys_activation_is_sooner_than_PublicationLead()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySetOptions>>();

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: Epoch.AddMinutes(1), expiresAt: Epoch.AddYears(1)),
            ],
            logger: logger,
            publicationLead: TimeSpan.FromHours(1));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Warning && e.Message.Contains("PublicationLead"),
            "k2 activates in 1 minute, well inside the 1-hour PublicationLead");
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_warn_when_PublicationLead_is_satisfied()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySetOptions>>();

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: Epoch.AddHours(2), expiresAt: Epoch.AddYears(1)),
            ],
            logger: logger,
            publicationLead: TimeSpan.FromHours(1));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().NotContain(e => e.Level == LogLevel.Warning && e.Message.Contains("PublicationLead"));
    }

    [Fact]
    public async Task GetSigningKeysAsync_warns_when_the_active_key_expires_within_30_days()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySetOptions>>();

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddDays(10))],
            logger: logger);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning && e.Message.Contains("expires"));
    }

    [Fact]
    public async Task GetSigningKeysAsync_logs_an_informational_status_line_for_each_key()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySetOptions>>();

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            logger: logger);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().Contain(
            e => e.Level == LogLevel.Information && e.Message.Contains("k1") && e.Message.Contains("active signer"));
    }

    [Fact]
    public async Task GetSigningKeysAsync_does_not_log_status_or_warnings_for_a_KeySourceOptions_provider()
    {
        // The too-soon-pending-activation warning and per-key status line are specific to
        // KeySetOptions; a KeySourceOptions provider must not gain them.
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var logger = new CapturingLogger<JwtSigningService<FakeKeySourceOptions>>();

        await using var sut = BuildKeySourceService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: Epoch.AddMinutes(1), expiresAt: Epoch.AddYears(1)),
            ],
            logger: logger);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        logger.Entries.Should().BeEmpty();
    }

    // ── Duplicate-kid rejection and algorithm/key-strength validation timing ───────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_on_duplicate_kid_derived_from_public_key_before_any_CreateSignerAsync_call()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa, "provider-id-1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa, "provider-id-2", activateAt: null, expiresAt: Epoch.AddYears(1)),
            ]);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*duplicate_kid*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty("validation must fail before any signer is ever requested");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_rsa_key_is_too_small_before_any_CreateSignerAsync_call()
    {
        using var rsa = RSA.Create(1024);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "tiny", activateAt: null, expiresAt: Epoch.AddYears(1))]);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*rsa_key_too_small*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty("key-strength validation must run before any signer is ever requested");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_on_algorithm_key_type_mismatch_before_any_CreateSignerAsync_call()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "mismatch", activateAt: null, expiresAt: Epoch.AddYears(1), algorithm: SigningAlgorithm.ES256)]);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ArgumentException>("SigningKeyDescriptor's constructor rejects an EC algorithm paired with RSA parameters");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty();
    }

    [Fact]
    public async Task KeySource_refresh_returning_duplicate_kid_throws_before_any_CreateSignerAsync_call()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var afterRefresh = false;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => afterRefresh
                ? [MakeRsaListing(rsa, "provider-id-1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsa, "provider-id-2", activateAt: null, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsa, "provider-id-1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        // First refresh is a valid, single-key listing.
        await sut.GetSigningKeysAsync(ct);

        // Second refresh (not the first ListKeysAsync call) returns a listing whose two entries
        // derive the same kid from the same public key — this must still be rejected.
        afterRefresh = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*duplicate_kid*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty(
            "validation must fail on the bad refresh before any signer is ever requested for that listing");
    }

    // ── ISigner/CreateSignerAsync wiring ────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_uses_the_signature_bytes_returned_by_the_active_ISigner()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var expectedSignature = new byte[] { 9, 8, 7, 6 };

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => new StubSigner(expectedSignature, selfTestKey: rsa));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(new byte[] { 0 }, ct);

        DecodeBase64Url(result.SignatureSegment).Should().Equal(expectedSignature);
    }

    /// <summary>
    /// An <see cref="ISigner"/> test double that always returns <paramref name="signature"/> for a
    /// real signing call — but, when <paramref name="selfTestKey"/> is supplied, signs
    /// <see cref="SelfTestPayloadBytes"/> for real instead, so the self-test (issue
    /// #437) passes without disturbing the fixed <paramref name="signature"/> this double's callers
    /// assert on for the actual token signature.
    /// </summary>
    private sealed class StubSigner(ReadOnlyMemory<byte> signature, AsymmetricAlgorithm? selfTestKey = null) : ISigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            if (selfTestKey is not null && signingInput.Span.SequenceEqual(SelfTestPayloadBytes))
                return new ValueTask<ReadOnlyMemory<byte>>(SigningAlgorithms.Sign(SigningAlgorithm.RS256, signingInput.ToArray(), selfTestKey));

            return new(signature);
        }

        public void Dispose()
        {
        }

        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;
    }

    [Fact]
    public async Task SignAsync_throws_and_disposes_the_signer_when_its_Algorithm_disagrees_with_the_listed_algorithm()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var mismatchedSigner = new MismatchedAlgorithmSigner(SigningAlgorithm.ES256);

        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1), algorithm: SigningAlgorithm.RS256)],
            signerFactory: _ => mismatchedSigner);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.SignAsync(new byte[] { 0 }, ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*signer_algorithm_mismatch*");

        mismatchedSigner.DisposeCount.Should().Be(
            1, "a signer rejected for an algorithm mismatch must not leak — it must be disposed immediately");
    }

    // ── EC keys ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_derives_kid_and_validates_an_EC_listing()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var timeProvider = new FakeTimeProvider(Epoch);
        var listing = new KeyListing(
            new KeyId("ec-1"), SigningAlgorithm.ES256, PublicKeyParameters.FromEc(ec.ExportParameters(false)),
            ActivateAt: null, ExpiresAt: Epoch.AddYears(1));

        await using var sut = BuildKeySetService(timeProvider, () => [listing]);
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle().Which.Algorithm.Should().Be(SigningAlgorithm.ES256);
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_on_EC_curve_algorithm_mismatch_before_any_CreateSignerAsync_call()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var timeProvider = new FakeTimeProvider(Epoch);
        var listing = new KeyListing(
            new KeyId("ec-mismatch"), SigningAlgorithm.ES256, PublicKeyParameters.FromEc(ec.ExportParameters(false)),
            ActivateAt: null, ExpiresAt: Epoch.AddYears(1));

        await using var sut = BuildKeySetService(timeProvider, () => [listing]);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_curve_algorithm_mismatch*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty();
    }

    // ── Fail-closed: no eligible active key ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_signing_no_active_key_when_every_key_has_expired()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider, () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddMinutes(5))]);
        var ct = TestContext.Current.CancellationToken;

        timeProvider.Advance(TimeSpan.FromHours(1)); // past the key's ExpiresAt

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*no_active_key*");
    }

    [Fact]
    public async Task SignAsync_throws_signing_no_active_key_when_every_key_has_expired()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider, () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddMinutes(5))]);
        var ct = TestContext.Current.CancellationToken;

        timeProvider.Advance(TimeSpan.FromHours(1));

        await sut.Awaiting(s => s.SignAsync(new byte[] { 0 }, ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*no_active_key*");
    }

    // ── Constructor argument validation ─────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new KeySetFakeService(
            null!,
            new FakeTimeProvider(Epoch),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            new CapturingLogger<JwtSigningService<FakeKeySetOptions>>(),
            () => [],
            _ => new FakeSigner());

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_when_timeProvider_is_null()
    {
        var act = () => new KeySetFakeService(
            Options.Create(new FakeKeySetOptions()),
            null!,
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            new CapturingLogger<JwtSigningService<FakeKeySetOptions>>(),
            () => [],
            _ => new FakeSigner());

        act.Should().Throw<ArgumentNullException>().WithParameterName("timeProvider");
    }

    [Fact]
    public void Constructor_throws_when_retirementWindowProvider_is_null()
    {
        var act = () => new KeySetFakeService(
            Options.Create(new FakeKeySetOptions()),
            new FakeTimeProvider(Epoch),
            null!,
            new CapturingLogger<JwtSigningService<FakeKeySetOptions>>(),
            () => [],
            _ => new FakeSigner());

        act.Should().Throw<ArgumentNullException>().WithParameterName("retirementWindowProvider");
    }

    [Fact]
    public void Constructor_throws_when_logger_is_null()
    {
        var act = () => new KeySetFakeService(
            Options.Create(new FakeKeySetOptions()),
            new FakeTimeProvider(Epoch),
            new FakeRetirementWindowProvider(TimeSpan.FromHours(1)),
            null!,
            () => [],
            _ => new FakeSigner());

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── Active-signer handle invalidation on material rotation under a stable Id ────────────────────

    [Fact]
    public async Task SignAsync_creates_a_fresh_signer_when_key_material_rotates_under_a_stable_KeyId()
    {
        // A provider (e.g. a DB-backed "current key" pointer) can keep KeyId.Value stable across a
        // material rotation. The cached SignerHandle must not be reused once the derived kid no
        // longer matches, or the base class would keep signing with superseded key material while
        // the JWKS publishes the new key's kid (security review finding F1 / issue #440).
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var afterRotation = false;
        var signersCreated = new List<FakeSigner>();

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => [MakeRsaListing(afterRotation ? rsa2 : rsa1, "stable-id", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ =>
            {
                var signer = new FakeSigner(privateKey: afterRotation ? rsa2 : rsa1);
                signersCreated.Add(signer);
                return signer;
            },
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        var before = await sut.SignAsync(new byte[] { 0 }, ct);

        afterRotation = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        var after = await sut.SignAsync(new byte[] { 0 }, ct);

        before.Kid.Should().NotBe(after.Kid, "the derived kid must change once the public key material changes");
        sut.CreateSignerAsyncCalledFor.Should().HaveCount(
            2, "a stable Id with rotated material must force a fresh CreateSignerAsync call rather than reusing the stale handle");
        signersCreated.Should().HaveCount(2);
        signersCreated[0].DisposeCount.Should().Be(1, "the superseded signer for the old material must be disposed");
        signersCreated[1].SignAsyncCallCount.Should().Be(
            2, "the second SignAsync call must use the freshly created signer — one call is the self-test " +
               "(issue #437) for the new handoff, and one is the real signature");
    }

    [Fact]
    public async Task EnsureActiveSignerAsync_throws_signing_signer_reused_when_CreateSignerAsync_returns_the_currently_active_signer()
    {
        // A provider that caches and re-lends one ISigner instance across calls must be rejected
        // with a diagnosable error rather than silently disposing the still-live active signer out
        // from under itself (security review finding F2 / issue #440).
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var afterRotation = false;
        var sharedSigner = new FakeSigner(privateKey: rsa1);

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => [MakeRsaListing(afterRotation ? rsa2 : rsa1, "stable-id", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => sharedSigner,
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);

        afterRotation = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        await sut.Awaiting(s => s.SignAsync(new byte[] { 0 }, ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*signer_reused*");

        sharedSigner.DisposeCount.Should().Be(
            0, "the reused signer is still the live active instance and must not be disposed");
    }

    // ── Duplicate KeyListing.Id.Value rejection ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_on_duplicate_KeyListing_Id_Value_even_when_kids_differ_before_any_CreateSignerAsync_call()
    {
        // Two listings that derive different kids (distinct RSA public keys) but share the same
        // provider-internal Id.Value must still be rejected — a duplicate Id would otherwise corrupt
        // DescriptorsById/ListingsById and desync the rotation timeline silently.
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "duplicate-id", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "duplicate-id", activateAt: null, expiresAt: Epoch.AddYears(1)),
            ]);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*duplicate_key_id*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty("validation must fail before any signer is ever requested");
    }

    [Fact]
    public async Task KeySource_refresh_returning_duplicate_KeyListing_Id_Value_throws_before_any_CreateSignerAsync_call()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var afterRefresh = false;

        await using var sut = BuildKeySourceService(
            timeProvider,
            () => afterRefresh
                ? [MakeRsaListing(rsa1, "duplicate-id", activateAt: null, expiresAt: Epoch.AddYears(1)),
                   MakeRsaListing(rsa2, "duplicate-id", activateAt: null, expiresAt: Epoch.AddYears(1))]
                : [MakeRsaListing(rsa1, "single-id", activateAt: null, expiresAt: Epoch.AddYears(1))],
            refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        afterRefresh = true;
        timeProvider.Advance(TimeSpan.FromMinutes(6));

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*duplicate_key_id*");

        sut.CreateSignerAsyncCalledFor.Should().BeEmpty(
            "validation must fail on the bad refresh before any signer is ever requested for that listing");
    }

    // ── startup self-test (ISigningStartupSelfTest, issue #437) ────────────────────────────────────

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.RS384)]
    [InlineData(SigningAlgorithm.RS512)]
    [InlineData(SigningAlgorithm.PS256)]
    [InlineData(SigningAlgorithm.PS384)]
    [InlineData(SigningAlgorithm.PS512)]
    public async Task VerifyActiveSignerAsync_passes_for_an_RSA_signer_whose_signature_verifies_against_the_listed_public_key(
        SigningAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        // A real LocalSigner over the same RSA key pair whose public half is listed: the self-test
        // must actually sign and verify with real cryptography, not merely call through a fake —
        // parameterised over every RSA algorithm so SigningAlgorithms.Verify's dispatch is exercised
        // for each one, not just RS256.
        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1), algorithm: algorithm)],
            signerFactory: _ => new LocalSigner(algorithm, RSA.Create(rsa.ExportParameters(true))));
        var ct = TestContext.Current.CancellationToken;

        var selfTest = (ISigningStartupSelfTest)sut;
        var act = async () => await selfTest.VerifyActiveSignerAsync(ct);

        await act.Should().NotThrowAsync(
            "a signer whose signature verifies against its own listed public key must pass the self-test");
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public async Task VerifyActiveSignerAsync_passes_for_an_EC_signer_whose_signature_verifies_against_the_listed_public_key(
        SigningAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
            SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ec = ECDsa.Create(curve);
        var timeProvider = new FakeTimeProvider(Epoch);
        var listing = new KeyListing(
            new KeyId("ec-1"), algorithm, PublicKeyParameters.FromEc(ec.ExportParameters(false)),
            ActivateAt: null, ExpiresAt: Epoch.AddYears(1));

        // Parameterised over every EC algorithm/curve pairing so SigningAlgorithms.Verify's EC
        // dispatch is exercised for each one, not just ES256.
        await using var sut = BuildKeySetService(timeProvider, () => [listing], signerFactory: _ => new LocalSigner(algorithm, ECDsa.Create(ec.ExportParameters(true))));
        var ct = TestContext.Current.CancellationToken;

        var selfTest = (ISigningStartupSelfTest)sut;
        var act = async () => await selfTest.VerifyActiveSignerAsync(ct);

        await act.Should().NotThrowAsync(
            "an EC signer whose signature verifies against its own listed public key must pass the self-test");
    }

    [Fact]
    public async Task VerifyActiveSignerAsync_throws_when_the_signature_does_not_verify_against_the_listed_public_key()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        // FakeSigner never actually signs — it always returns the fixed bytes { 1, 2, 3, 4 }, which
        // cannot verify against the real RSA public key listed for "k1". This models a signer that
        // materializes private key material which does not pair with the public key it publishes a
        // kid for (a non-exportable KV certificate policy, an inaccessible CNG key container, etc.).
        await using var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => new FakeSigner());
        var ct = TestContext.Current.CancellationToken;

        var selfTest = (ISigningStartupSelfTest)sut;
        var act = async () => await selfTest.VerifyActiveSignerAsync(ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    [Fact]
    public async Task VerifyActiveSignerAsync_returns_the_borrowed_signer_handle_even_on_failure()
    {
        // The self-test must not leak the SignerHandle's borrow: if it did, DisposeAsync's shutdown
        // release could never actually dispose the underlying signer.
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        FakeSigner? signer = null;

        var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => signer = new FakeSigner());
        var ct = TestContext.Current.CancellationToken;

        var selfTest = (ISigningStartupSelfTest)sut;
        await selfTest.Awaiting(s => s.VerifyActiveSignerAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        await sut.DisposeAsync();

        signer!.DisposeCount.Should().Be(1, "the self-test's borrow must be returned even when verification fails");
    }

    [Fact]
    public async Task VerifyActiveSignerAsync_disposes_the_signer_when_the_self_test_sign_call_itself_throws()
    {
        // Security review finding F4 (issue #437): a missing Key Vault "sign" permission or an
        // inaccessible CNG key container surfaces as an exception from the self-test's sign call
        // itself, not as a verification mismatch — the signer must still be disposed rather than
        // leaked before that failure propagates, exactly as the verification-mismatch path already
        // disposes it.
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        ThrowingSigner? signer = null;

        var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))],
            signerFactory: _ => signer = new ThrowingSigner());
        var ct = TestContext.Current.CancellationToken;

        var selfTest = (ISigningStartupSelfTest)sut;
        await selfTest.Awaiting(s => s.VerifyActiveSignerAsync(ct).AsTask())
            .Should().ThrowAsync<CryptographicException>();

        signer!.DisposeCount.Should().Be(
            1, "the signer must be disposed even when the self-test's sign call throws, not only on a verification mismatch");

        await sut.DisposeAsync();
    }

    [Fact]
    public async Task SignAsync_throws_when_a_signer_materialized_on_a_later_rotation_handoff_fails_the_self_test()
    {
        // The self-test must not only run once, at the very first handoff — a key rotated in later
        // (via an ActivateAt crossing, exactly as any multi-key KeySetOptions provider rotates) must be
        // proven exactly as thoroughly as the key that was active at startup (issue #437 security
        // review, finding F1). k1 gets a real signer whose signature genuinely verifies against its
        // own listed public key, so the first handoff passes; k2 gets a FakeSigner, which never
        // actually signs and so cannot verify against k2's real listed public key, modelling a
        // rotated-in key whose private material does not pair with what was published.
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var successorActivatesAt = Epoch.AddHours(1);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: successorActivatesAt, expiresAt: Epoch.AddYears(1)),
            ],
            signerFactory: id => id.Value == "k1"
                ? new LocalSigner(SigningAlgorithm.RS256, RSA.Create(rsa1.ExportParameters(true)))
                : new FakeSigner());
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.SignAsync(new byte[] { 0 }, ct);
        first.Kid.Should().NotBeNullOrEmpty("the first (k1) handoff must succeed its own self-test");

        timeProvider.Advance(TimeSpan.FromHours(2));
        var act = async () => await sut.SignAsync(new byte[] { 0 }, ct);

        var exception = await act.Should().ThrowAsync<ZeeKayDaConfigurationException>(
            "the rotation handoff to k2 must be self-tested exactly like the initial handoff to k1 was");
        exception.Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.self_test_failed");
    }

    // ── Signing-key producibility (ISigningKeyProducibility, issue #494 follow-up) ─────────────────

    [Fact]
    public async Task GetProducibilityAsync_reports_the_active_algorithm_plus_a_staged_keys_algorithm()
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var timeProvider = new FakeTimeProvider(Epoch);
        var successorActivatesAt = Epoch.AddHours(1);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                new KeyListing(
                    new KeyId("k2"), SigningAlgorithm.ES256, PublicKeyParameters.FromEc(ec.ExportParameters(false)),
                    successorActivatesAt, Epoch.AddYears(1)),
            ]);
        var ct = TestContext.Current.CancellationToken;
        var producibility = (ISigningKeyProducibility)sut;

        var snapshot = await producibility.GetProducibilityAsync(ct);

        snapshot.ActiveAlgorithm.Should().Be(SigningAlgorithm.RS256, "k1 has no ActivateAt and is the sole eligible signer right now");
        snapshot.StagedAlgorithms.Should().BeEquivalentTo(
            [SigningAlgorithm.ES256],
            "k2 is not yet active but will become the signer soon, so its algorithm counts as staged");
        snapshot.CanProduce(SigningAlgorithm.RS256).Should().BeTrue();
        snapshot.CanProduce(SigningAlgorithm.ES256).Should().BeTrue();
    }

    [Fact]
    public async Task GetProducibilityAsync_excludes_a_staged_key_that_would_already_be_expired_by_its_own_activation()
    {
        // The exact Fix 1 exploit: a staged ES256 key activates in 10 days but expires in 5 — it can
        // never actually become the active signer, since it would already be expired by the time it
        // would take over. Its algorithm must not be reported as producible.
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var timeProvider = new FakeTimeProvider(Epoch);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                new KeyListing(
                    new KeyId("k2"), SigningAlgorithm.ES256, PublicKeyParameters.FromEc(ec.ExportParameters(false)),
                    Epoch.AddDays(10), Epoch.AddDays(5)),
            ]);
        var ct = TestContext.Current.CancellationToken;
        var producibility = (ISigningKeyProducibility)sut;

        var snapshot = await producibility.GetProducibilityAsync(ct);

        snapshot.ActiveAlgorithm.Should().Be(SigningAlgorithm.RS256);
        snapshot.StagedAlgorithms.Should().BeEmpty(
            "k2 would already be expired by the time its own ActivatesAt arrives, so it can never actually sign anything");
        snapshot.CanProduce(SigningAlgorithm.ES256).Should().BeFalse();
    }

    [Fact]
    public async Task GetProducibilityAsync_excludes_a_retirement_window_keys_algorithm_once_it_is_superseded()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        var successorActivatesAt = Epoch.AddHours(1);

        await using var sut = BuildKeySetService(
            timeProvider,
            () =>
            [
                MakeRsaListing(rsa1, "k1", activateAt: null, expiresAt: Epoch.AddYears(1)),
                MakeRsaListing(rsa2, "k2", activateAt: successorActivatesAt, expiresAt: Epoch.AddYears(1), algorithm: SigningAlgorithm.RS384),
            ],
            signerFactory: id => new FakeSigner(algorithm: id.Value == "k1" ? SigningAlgorithm.RS256 : SigningAlgorithm.RS384));
        var ct = TestContext.Current.CancellationToken;
        var producibility = (ISigningKeyProducibility)sut;

        timeProvider.Advance(TimeSpan.FromHours(2));
        var snapshot = await producibility.GetProducibilityAsync(ct);

        snapshot.ActiveAlgorithm.Should().Be(SigningAlgorithm.RS384, "k2 has now superseded k1 as the active signer");
        snapshot.StagedAlgorithms.Should().BeEmpty(
            "k1 is now retirement-window-only — it can still verify already-issued tokens but never signs a new one, " +
            "so its algorithm must not be reported as producible");
        snapshot.CanProduce(SigningAlgorithm.RS256).Should().BeFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static byte[] DecodeBase64Url(ReadOnlyMemory<byte> encoded)
    {
        var span = encoded.Span;
        var decoded = new byte[System.Buffers.Text.Base64Url.GetMaxDecodedLength(span.Length)];
        System.Buffers.Text.Base64Url.DecodeFromUtf8(span, decoded, out _, out var written);
        return decoded[..written];
    }
}
