using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises the ADR 0015 "new contract" (<see cref="KeySetOptions"/>/<see cref="KeySourceOptions"/>,
/// <see cref="KeyListing"/>, <see cref="ISigner"/>) machinery added to
/// <see cref="JwtSigningService{TOptions}"/> by issue #420 — landing alongside, and without touching,
/// the ADR 0011 contract exercised by <see cref="JwtSigningServiceTests"/>.
/// </summary>
public sealed class JwtSigningServiceNewContractTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class FakeKeySetOptions : KeySetOptions
    {
    }

    private sealed class FakeKeySourceOptions : KeySourceOptions
    {
    }

    /// <summary>An <see cref="ISigner"/> test double that counts and never actually signs anything.</summary>
    private sealed class FakeSigner(SigningAlgorithm algorithm = SigningAlgorithm.RS256) : ISigner
    {
        public int DisposeCount { get; private set; }

        public int SignAsyncCallCount { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
            SignAsyncCallCount++;
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
    /// An <see cref="ISigner"/> test double whose <see cref="SignAsync"/> blocks until
    /// <paramref name="release"/> completes, signalling <see cref="Entered"/> first so a test can
    /// deterministically know the call is in flight before proceeding.
    /// </summary>
    private sealed class GatedSigner(TaskCompletionSource release) : ISigner
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int DisposeCount { get; private set; }

        public Task Entered => _entered.Task;

        public async ValueTask<ReadOnlyMemory<byte>> SignAsync(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
        {
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
    /// Captures every log call so tests can assert on the ADR 0015 §6 within-window-vanish
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

    /// <summary>Tier A (<see cref="KeySetOptions"/>) test double.</summary>
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

    /// <summary>Tier B (<see cref="KeySourceOptions"/>) test double.</summary>
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

    // ── Snapshot build: Tier A once, Tier B per refresh ─────────────────────────────────────────────

    [Fact]
    public async Task ListKeysAsync_is_called_exactly_once_for_KeySetOptions_regardless_of_calls_or_elapsed_time()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);
        await using var sut = BuildKeySetService(
            timeProvider, () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(100))]);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromDays(365 * 10));
        await sut.GetSigningKeysAsync(ct);
        await sut.SignAsync(new byte[] { 0 }, ct);

        sut.ListKeysAsyncCallCount.Should().Be(1, "Tier A calls ListKeysAsync exactly once, ever");
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
            ]);
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
                var signer = new FakeSigner();
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
            signerFactory: _ => signer = new FakeSigner());
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(new byte[] { 0 }, ct);
        signer!.DisposeCount.Should().Be(0);

        await sut.DisposeAsync();

        signer.DisposeCount.Should().Be(1, "the sole active signer must be released at shutdown (ADR 0015 §5)");
    }

    [Fact]
    public async Task DisposeAsync_calls_OnDisposeAsync_at_most_once_across_concurrent_double_dispose()
    {
        using var rsa = RSA.Create(2048);
        var timeProvider = new FakeTimeProvider(Epoch);

        var sut = BuildKeySetService(
            timeProvider,
            () => [MakeRsaListing(rsa, "k1", activateAt: null, expiresAt: Epoch.AddYears(1))]);
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
                var signer = new FakeSigner();
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
                ? gatedSigner = new GatedSigner(release)
                : new FakeSigner(),
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
            "an early/within-window vanish must be logged at Warning per ADR 0015 §6");
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
        // KeySetOptions (Tier A); a KeySourceOptions (Tier B) provider must not gain them.
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
            signerFactory: _ => new StubSigner(expectedSignature));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(new byte[] { 0 }, ct);

        DecodeBase64Url(result.SignatureSegment).Should().Equal(expectedSignature);
    }

    private sealed class StubSigner(ReadOnlyMemory<byte> signature) : ISigner
    {
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken = default)
            => new(signature);

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

    // ── Two-argument constructor rejects the ADR 0015 contract ─────────────────────────────────────

    /// <summary>
    /// A <see cref="KeySourceOptions"/> provider that (incorrectly) uses only the base class's
    /// two-argument constructor, omitting the retirement-window provider and logger the ADR 0015
    /// contract requires. Used solely to prove that constructing this class throws immediately,
    /// rather than silently defaulting the retirement window to <see cref="TimeSpan.Zero"/> and
    /// dropping the ADR 0015 §6 within-window-vanish Warning.
    /// </summary>
    private sealed class MisconfiguredKeySourceService(IOptions<FakeKeySourceOptions> options, TimeProvider timeProvider)
        : JwtSigningService<FakeKeySourceOptions>(options, timeProvider)
    {
        protected override ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
            => new(Array.Empty<KeyListing>());

        protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    /// <summary>
    /// A <see cref="KeySetOptions"/> provider that (incorrectly) uses only the base class's
    /// two-argument constructor. See <see cref="MisconfiguredKeySourceService"/>.
    /// </summary>
    private sealed class MisconfiguredKeySetService(IOptions<FakeKeySetOptions> options, TimeProvider timeProvider)
        : JwtSigningService<FakeKeySetOptions>(options, timeProvider)
    {
        protected override ValueTask<IReadOnlyList<KeyListing>> ListKeysAsync(CancellationToken cancellationToken)
            => new(Array.Empty<KeyListing>());

        protected override ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    [Fact]
    public void Constructing_a_KeySourceOptions_provider_via_the_two_argument_constructor_throws()
    {
        var options = Options.Create(new FakeKeySourceOptions { RefreshInterval = TimeSpan.FromMinutes(5) });
        var timeProvider = new FakeTimeProvider(Epoch);

        var act = () => new MisconfiguredKeySourceService(options, timeProvider);

        act.Should().Throw<NotSupportedException>(
            "a KeySourceOptions provider must go through the four-argument constructor so the ADR 0015 " +
            "§6 within-window-vanish Warning is never silently degraded by a missing retirement-window " +
            "provider/logger");
    }

    [Fact]
    public void Constructing_a_KeySetOptions_provider_via_the_two_argument_constructor_throws()
    {
        var options = Options.Create(new FakeKeySetOptions());
        var timeProvider = new FakeTimeProvider(Epoch);

        var act = () => new MisconfiguredKeySetService(options, timeProvider);

        act.Should().Throw<NotSupportedException>(
            "a KeySetOptions provider must go through the four-argument constructor for the same reason " +
            "as a KeySourceOptions provider");
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
