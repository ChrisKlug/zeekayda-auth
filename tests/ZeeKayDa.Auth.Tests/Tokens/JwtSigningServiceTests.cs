using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class JwtSigningServiceTests
{
    // ── Fake implementation ───────────────────────────────────────────────────────────────────────

    private sealed class FakeSigningServiceOptions : JwtSigningServiceOptions { }

    private sealed class CountingSigningService : JwtSigningService<FakeSigningServiceOptions>
    {
        private readonly Func<SigningKeySet> _factory;
        public int LoadCount { get; private set; }

        public CountingSigningService(
            IOptions<FakeSigningServiceOptions> options,
            TimeProvider timeProvider,
            Func<SigningKeySet> factory)
            : base(options, timeProvider)
        {
            _factory = factory;
        }

        protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
        {
            LoadCount++;
            return ValueTask.FromResult(_factory());
        }
    }

    private sealed class AsyncCountingSigningService : JwtSigningService<FakeSigningServiceOptions>
    {
        private readonly Func<ValueTask<SigningKeySet>> _factory;

        public AsyncCountingSigningService(
            IOptions<FakeSigningServiceOptions> options,
            TimeProvider timeProvider,
            Func<ValueTask<SigningKeySet>> factory)
            : base(options, timeProvider)
        {
            _factory = factory;
        }

        protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
            => _factory();
    }

    /// <summary>
    /// A fake that overrides <see cref="JwtSigningService{TOptions}.SignInputAsync"/> to capture
    /// the arguments it receives and return a caller-supplied signature — simulating a remote
    /// signer (e.g. Key Vault) that ignores <see cref="SigningKeyPair.PrivateKey"/> entirely.
    /// </summary>
    private sealed class OverridingSigningService : JwtSigningService<FakeSigningServiceOptions>
    {
        private readonly Func<SigningKeySet> _factory;
        private readonly ReadOnlyMemory<byte> _signatureOverride;

        public SigningKeyPair? CapturedActiveKey { get; private set; }
        public byte[]? CapturedSigningInput { get; private set; }
        public int SignInputAsyncCallCount { get; private set; }

        public OverridingSigningService(
            IOptions<FakeSigningServiceOptions> options,
            TimeProvider timeProvider,
            Func<SigningKeySet> factory,
            ReadOnlyMemory<byte> signatureOverride)
            : base(options, timeProvider)
        {
            _factory = factory;
            _signatureOverride = signatureOverride;
        }

        protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult(_factory());

        protected override ValueTask<ReadOnlyMemory<byte>> SignInputAsync(
            SigningKeyPair activeKey, byte[] signingInput, CancellationToken cancellationToken)
        {
            SignInputAsyncCallCount++;
            CapturedActiveKey = activeKey;
            CapturedSigningInput = signingInput;
            return new ValueTask<ReadOnlyMemory<byte>>(_signatureOverride);
        }
    }

    /// <summary>
    /// A fake that overrides <see cref="JwtSigningService{TOptions}.HasKeySetChangedAsync"/> with a
    /// caller-supplied predicate and counts how many times it (and <see cref="LoadKeysAsync"/>) are
    /// invoked — exercises the ADR 0011 §3.2 "ask" step in front of the reload.
    /// </summary>
    private sealed class ControllableHasChangedSigningService : JwtSigningService<FakeSigningServiceOptions>
    {
        private readonly Func<SigningKeySet> _factory;
        private readonly Func<bool> _hasChanged;

        public int LoadCount { get; private set; }
        public int HasKeySetChangedAsyncCallCount { get; private set; }

        public ControllableHasChangedSigningService(
            IOptions<FakeSigningServiceOptions> options,
            TimeProvider timeProvider,
            Func<SigningKeySet> factory,
            Func<bool> hasChanged)
            : base(options, timeProvider)
        {
            _factory = factory;
            _hasChanged = hasChanged;
        }

        protected override ValueTask<SigningKeySet> LoadKeysAsync(CancellationToken cancellationToken)
        {
            LoadCount++;
            return ValueTask.FromResult(_factory());
        }

        protected override ValueTask<bool> HasKeySetChangedAsync(CancellationToken cancellationToken)
        {
            HasKeySetChangedAsyncCallCount++;
            return new ValueTask<bool>(_hasChanged());
        }
    }

    private static SigningKeySet MakeRsaSet(string kid = "test-kid")
    {
        var rsa = RSA.Create(2048);
        try
        {
            var rsaParams = rsa.ExportParameters(false);
            var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
            return new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static CountingSigningService BuildService(
        FakeTimeProvider? timeProvider = null,
        Func<SigningKeySet>? factory = null,
        TimeSpan? refreshInterval = null)
    {
        var tp = timeProvider ?? new FakeTimeProvider();
        var options = new FakeSigningServiceOptions
        {
            KeySourceRefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        var f = factory ?? (() => MakeRsaSet());
        return new CountingSigningService(Options.Create(options), tp, f);
    }

    /// <summary>
    /// Builds a service in static-source mode (<see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/>
    /// is <see langword="null"/>) — the mode <see cref="DevelopmentSigningKeyOptions"/> uses.
    /// </summary>
    private static CountingSigningService BuildStaticService(
        FakeTimeProvider? timeProvider = null,
        Func<SigningKeySet>? factory = null)
    {
        var tp = timeProvider ?? new FakeTimeProvider();
        var options = new FakeSigningServiceOptions { KeySourceRefreshInterval = null };
        var f = factory ?? (() => MakeRsaSet());
        return new CountingSigningService(Options.Create(options), tp, f);
    }

    // ── Constructor validation ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new CountingSigningService(null!, new FakeTimeProvider(), () => MakeRsaSet());
        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_when_timeProvider_is_null()
    {
        var act = () => new CountingSigningService(
            Options.Create(new FakeSigningServiceOptions()),
            null!,
            () => MakeRsaSet());
        act.Should().Throw<ArgumentNullException>().WithParameterName("timeProvider");
    }


    // ── Key loading ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_returns_descriptor_from_loaded_set()
    {
        var set = MakeRsaSet("my-kid");
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle().Which.Kid.Should().Be("my-kid");
    }

    [Fact]
    public async Task GetSigningKeysAsync_calls_LoadKeysAsync_exactly_once_on_first_call()
    {
        await using var sut = BuildService();
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSigningKeysAsync_returns_same_list_instance_on_repeated_calls()
    {
        // The descriptor list is memoized on SigningKeySet to avoid per-call allocation
        // on the JWKS hot path. Two calls within the refresh interval must return the same object.
        await using var sut = BuildService();
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.GetSigningKeysAsync(ct);
        var second = await sut.GetSigningKeysAsync(ct);

        second.Should().BeSameAs(first, "the descriptor list must be memoised and returned by reference");
    }

    [Fact]
    public async Task GetSigningKeysAsync_uses_cached_set_within_refresh_interval()
    {
        var timeProvider = new FakeTimeProvider();
        await using var sut = BuildService(timeProvider: timeProvider, refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(4));
        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(1, "second call is within the refresh interval");
    }

    [Fact]
    public async Task GetSigningKeysAsync_reloads_after_refresh_interval_elapses()
    {
        var timeProvider = new FakeTimeProvider();
        await using var sut = BuildService(timeProvider: timeProvider, refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(2, "second call is past the refresh interval");
    }

    [Fact]
    public async Task GetSigningKeysAsync_default_HasKeySetChangedAsync_reloads_on_every_elapsed_cycle_for_providers_that_dont_override_it()
    {
        // A provider that does not override HasKeySetChangedAsync (like CountingSigningService
        // here) must keep today's unconditional-rebuild behaviour: LoadKeysAsync runs every time
        // the refresh interval elapses, with no skipped cycles.
        var timeProvider = new FakeTimeProvider();
        await using var sut = BuildService(timeProvider: timeProvider, refreshInterval: TimeSpan.FromMinutes(5));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(3, "the default HasKeySetChangedAsync always returns true, so every elapsed cycle triggers LoadKeysAsync");
    }

    // ── HasKeySetChangedAsync hook (ADR 0011 §3.2 "ask" step) ────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_does_not_call_HasKeySetChangedAsync_on_cold_start()
    {
        // The very first BorrowSetAsync call has no previous set to compare against, so the "ask"
        // step must never be consulted — only LoadKeysAsync runs.
        var timeProvider = new FakeTimeProvider();
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new ControllableHasChangedSigningService(
            options,
            timeProvider,
            () => MakeRsaSet(),
            hasChanged: () => throw new InvalidOperationException("HasKeySetChangedAsync must not be called on cold start."));
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(1);
        sut.HasKeySetChangedAsyncCallCount.Should().Be(0,
            "cold start (no previous set) must call LoadKeysAsync directly without consulting HasKeySetChangedAsync");
    }

    [Fact]
    public async Task GetSigningKeysAsync_skips_LoadKeysAsync_when_HasKeySetChangedAsync_returns_false()
    {
        var timeProvider = new FakeTimeProvider();
        var set = MakeRsaSet("unchanged-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new ControllableHasChangedSigningService(options, timeProvider, () => set, hasChanged: () => false);
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        var second = await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(1, "HasKeySetChangedAsync returning false must skip the LoadKeysAsync reload");
        second.Should().BeSameAs(first, "the same cached SigningKeySet's memoised descriptor list must still be served");
    }

    [Fact]
    public async Task SignAsync_still_succeeds_after_HasKeySetChangedAsync_returns_false_no_ObjectDisposedException()
    {
        // Regression guard: HasKeySetChangedAsync returning false must extend the cache and keep
        // serving the existing SigningKeySet without disposing it. If the base class incorrectly
        // disposed it anyway, this sign would throw ObjectDisposedException.
        var timeProvider = new FakeTimeProvider();
        var set = MakeRsaSet("unchanged-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new ControllableHasChangedSigningService(options, timeProvider, () => set, hasChanged: () => false);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.SignAsync(payload, ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        var second = await sut.SignAsync(payload, ct);

        first.Kid.Should().Be("unchanged-kid");
        second.Kid.Should().Be("unchanged-kid");
        sut.LoadCount.Should().Be(1);
    }

    [Fact]
    public async Task GetSigningKeysAsync_reloads_when_HasKeySetChangedAsync_returns_true()
    {
        // Returning true behaves identically to the default: the hook path does not change
        // anything about a normal rebuild.
        var timeProvider = new FakeTimeProvider();
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new ControllableHasChangedSigningService(options, timeProvider, () => MakeRsaSet(), hasChanged: () => true);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromMinutes(6));
        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(2, "HasKeySetChangedAsync returning true must behave exactly like the default: LoadKeysAsync runs on every elapsed cycle");
        sut.HasKeySetChangedAsyncCallCount.Should().Be(1, "consulted once per elapsed cycle, only after a previous set already exists");
    }

    // ── Static-source mode (KeySourceRefreshInterval is null) ────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_never_reloads_when_KeySourceRefreshInterval_is_null()
    {
        // null is a real static-source mode (see JwtSigningServiceOptions.KeySourceRefreshInterval),
        // not merely "a very long interval" — it must never trigger a second LoadKeysAsync call, no
        // matter how much time passes. DevelopmentSigningKeyOptions relies on exactly this: its keys
        // are memoized for the process lifetime, and a second LoadKeysAsync call would dispose the
        // key set still referenced by that memoization field, throwing ObjectDisposedException.
        var timeProvider = new FakeTimeProvider();
        await using var sut = BuildStaticService(timeProvider: timeProvider);
        var ct = TestContext.Current.CancellationToken;

        await sut.GetSigningKeysAsync(ct);
        timeProvider.Advance(TimeSpan.FromDays(365 * 100));
        await sut.GetSigningKeysAsync(ct);

        sut.LoadCount.Should().Be(1, "null means load once and never reload, regardless of elapsed time");
    }

    [Fact]
    public async Task SignAsync_succeeds_repeatedly_when_KeySourceRefreshInterval_is_null()
    {
        // Regression test: with a finite interval, the base class would dispose the previous key
        // set on the next reload. If that reload incorrectly happened in static mode against a key
        // set still referenced elsewhere (as DevelopmentJwtSigningService's own memoization field
        // does), the underlying private key would be disposed out from under a live signer,
        // surfacing as ObjectDisposedException here. Signing twice, separated by a large time
        // advance, on the same underlying RSA key proves no such reload/dispose occurred.
        var timeProvider = new FakeTimeProvider();
        var set = MakeRsaSet("static-kid");
        await using var sut = BuildStaticService(timeProvider: timeProvider, factory: () => set);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var first = await sut.SignAsync(payload, ct);
        timeProvider.Advance(TimeSpan.FromDays(365 * 100));
        var second = await sut.SignAsync(payload, ct);

        first.Kid.Should().Be("static-kid");
        second.Kid.Should().Be("static-kid");
        sut.LoadCount.Should().Be(1);
    }

    // ── Signing ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_returns_non_empty_header_and_signature()
    {
        await using var sut = BuildService();
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.HeaderSegment.IsEmpty.Should().BeFalse();
        result.SignatureSegment.IsEmpty.Should().BeFalse();
    }

    [Fact]
    public async Task SignAsync_returns_matching_kid_in_result_and_in_header()
    {
        var set = MakeRsaSet("kid-abc");
        await using var sut = BuildService(factory: () => set);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.Kid.Should().Be("kid-abc");

        var headerJson = DecodeBase64UrlToString(result.HeaderSegment);
        var doc = JsonDocument.Parse(headerJson);
        doc.RootElement.GetProperty("kid").GetString().Should().Be("kid-abc");
    }

    [Fact]
    public async Task SignAsync_header_contains_alg_RS256()
    {
        await using var sut = BuildService();
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        var headerJson = DecodeBase64UrlToString(result.HeaderSegment);
        var doc = JsonDocument.Parse(headerJson);
        doc.RootElement.GetProperty("alg").GetString().Should().Be("RS256");
    }

    [Fact]
    public async Task SignAsync_produces_signature_verifiable_with_corresponding_public_key()
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("vk-1", SigningAlgorithm.RS256, rsaParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var payloadStr = Base64UrlEncodeString("""{"sub":"alice"}""");
        var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);
        var result = await sut.SignAsync(payloadBytes, ct);

        // Re-assemble the signing input and verify
        var headerStr = Encoding.ASCII.GetString(result.HeaderSegment.Span);
        var signingInput = Encoding.UTF8.GetBytes($"{headerStr}.{payloadStr}");
        var signature = DecodeBase64Url(result.SignatureSegment);

        var valid = rsa.VerifyData(
            signingInput,
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        valid.Should().BeTrue("the signature must be verifiable with the corresponding public key");
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256, "1.2.840.10045.3.1.7")]  // P-256
    [InlineData(SigningAlgorithm.ES384, "1.3.132.0.34")]         // P-384
    [InlineData(SigningAlgorithm.ES512, "1.3.132.0.35")]         // P-521
    public async Task SignAsync_ec_signature_is_in_ieee_p1363_format_and_verifiable(
        SigningAlgorithm algorithm,
        string curveOid)
    {
        // RFC 7518 §3.4 mandates the IEEE P1363 format (raw R||S), not DER.
        // This test verifies the signature with IeeeP1363FixedFieldConcatenation — if the
        // implementation wrongly uses Rfc3279DerSequence, VerifyData will return false.
        using var ec = ECDsa.Create(ECCurve.CreateFromValue(curveOid));
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-vk", algorithm, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var payloadStr = Base64UrlEncodeString("""{"sub":"alice"}""");
        var payloadBytes = Encoding.UTF8.GetBytes(payloadStr);
        var result = await sut.SignAsync(payloadBytes, ct);

        var headerStr = Encoding.ASCII.GetString(result.HeaderSegment.Span);
        var signingInput = Encoding.UTF8.GetBytes($"{headerStr}.{payloadStr}");
        var signature = DecodeBase64Url(result.SignatureSegment);

        var hashName = algorithm switch
        {
            SigningAlgorithm.ES256 => HashAlgorithmName.SHA256,
            SigningAlgorithm.ES384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA512,
        };

        // Verify using IEEE P1363 format — this is what JWT validators expect.
        var valid = ec.VerifyData(
            signingInput,
            signature,
            hashName,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        valid.Should().BeTrue($"EC signature for {algorithm} must use IEEE P1363 format as required by RFC 7518 §3.4");
    }

    // ── SignInputAsync override hook ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task SignAsync_invokes_SignInputAsync_override_exactly_once()
    {
        var set = MakeRsaSet("override-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        var overrideSignature = new byte[] { 1, 2, 3, 4 };
        await using var sut = new OverridingSigningService(options, new FakeTimeProvider(), () => set, overrideSignature);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(payload, ct);

        sut.SignInputAsyncCallCount.Should().Be(1);
    }

    [Fact]
    public async Task SignAsync_uses_signature_bytes_returned_by_SignInputAsync_override()
    {
        var set = MakeRsaSet("override-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        var overrideSignature = new byte[] { 9, 8, 7, 6, 5 };
        await using var sut = new OverridingSigningService(options, new FakeTimeProvider(), () => set, overrideSignature);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        var actualSignatureBytes = DecodeBase64Url(result.SignatureSegment);
        actualSignatureBytes.Should().Equal(overrideSignature);
    }

    [Fact]
    public async Task SignAsync_passes_the_active_key_descriptor_to_the_SignInputAsync_override()
    {
        var set = MakeRsaSet("override-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new OverridingSigningService(options, new FakeTimeProvider(), () => set, new byte[] { 1 });
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        await sut.SignAsync(payload, ct);

        sut.CapturedActiveKey.Should().NotBeNull();
        sut.CapturedActiveKey!.Value.Descriptor.Should().BeSameAs(set.ActiveKey);
    }

    [Fact]
    public async Task SignAsync_passes_the_correct_signing_input_to_the_SignInputAsync_override()
    {
        // Header/kid/signing-input construction stays non-overridable — verify the override
        // still receives exactly base64url(header) + '.' + base64url(payload), matching what
        // the default (non-overridden) path signs.
        var set = MakeRsaSet("override-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new OverridingSigningService(options, new FakeTimeProvider(), () => set, new byte[] { 1 });
        var payloadStr = Base64UrlEncodeString("""{"sub":"alice"}""");
        var payload = Encoding.UTF8.GetBytes(payloadStr);
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        var expectedSigningInput = Encoding.UTF8.GetBytes(
            $"{Encoding.ASCII.GetString(result.HeaderSegment.Span)}.{payloadStr}");
        sut.CapturedSigningInput.Should().Equal(expectedSigningInput);
    }

    [Fact]
    public async Task SignAsync_header_and_kid_are_unaffected_by_SignInputAsync_override()
    {
        var set = MakeRsaSet("override-kid");
        var options = Options.Create(new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) });
        await using var sut = new OverridingSigningService(options, new FakeTimeProvider(), () => set, new byte[] { 1 });
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.Kid.Should().Be("override-kid");
        result.Algorithm.Should().Be(SigningAlgorithm.RS256);
        var headerJson = DecodeBase64UrlToString(result.HeaderSegment);
        var doc = JsonDocument.Parse(headerJson);
        doc.RootElement.GetProperty("kid").GetString().Should().Be("override-kid");
        doc.RootElement.GetProperty("alg").GetString().Should().Be("RS256");
    }

    // ── Duplicate kid validation ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_on_duplicate_kid()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var desc1 = new SigningKeyDescriptor("duplicate-kid", SigningAlgorithm.RS256, rsa1.ExportParameters(false));
        var desc2 = new SigningKeyDescriptor("duplicate-kid", SigningAlgorithm.RS256, rsa2.ExportParameters(false));
        using var set = new SigningKeySet(
        [
            new SigningKeyPair { Descriptor = desc1, PrivateKey = rsa1 },
            new SigningKeyPair { Descriptor = desc2, PrivateKey = rsa2 },
        ]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*duplicate_kid*");
    }

    // ── RSA key strength validation ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_when_rsa_key_is_too_small()
    {
        // 1024-bit key — below the 2048-bit minimum.
        using var rsa = RSA.Create(1024);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("tiny-key", SigningAlgorithm.RS256, rsaParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*rsa_key_too_small*");
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_rsa_key_has_null_modulus()
    {
        // Default RSAParameters has Modulus = null — bitLength computes to 0, below minimum.
        var rsaParams = new RSAParameters(); // Modulus is null
        var descriptor = new SigningKeyDescriptor("null-mod-key", SigningAlgorithm.RS256, rsaParams);
        using var rsa = RSA.Create(2048);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*rsa_key_too_small*");
    }

    // ── EC curve validation ───────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_accepts_nistP256_with_ES256()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-kid", SigningAlgorithm.ES256, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle();
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_on_ec_curve_algorithm_mismatch()
    {
        // P-384 key with ES256 (which requires P-256)
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-kid", SigningAlgorithm.ES256, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_curve_algorithm_mismatch*");
    }

    // ── Algorithm ↔ key type mismatch ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_when_private_key_type_does_not_match_algorithm()
    {
        // EC descriptor (ES256) but private key is RSA — mismatch detected at load time.
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("mismatch-kid", SigningAlgorithm.ES256, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*key_algorithm_mismatch*");
    }

    // ── Additional algorithm / curve validations ─────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_ec_key_has_rsa_algorithm_in_private_key()
    {
        // RSA descriptor with an ECDsa private key — mismatch.
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("mismatch-rsa-kid", SigningAlgorithm.RS256, rsaParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*key_algorithm_mismatch*");
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS384)]
    [InlineData(SigningAlgorithm.RS512)]
    [InlineData(SigningAlgorithm.PS256)]
    [InlineData(SigningAlgorithm.PS384)]
    [InlineData(SigningAlgorithm.PS512)]
    public async Task SignAsync_produces_non_empty_result_for_all_rsa_algorithms(SigningAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("rsa-kid", algorithm, rsaParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa }]);
        await using var sut = BuildService(factory: () => set);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.HeaderSegment.IsEmpty.Should().BeFalse();
        result.SignatureSegment.IsEmpty.Should().BeFalse();
        result.Algorithm.Should().Be(algorithm);
    }

    [Theory]
    [InlineData(SigningAlgorithm.ES256)]
    [InlineData(SigningAlgorithm.ES384)]
    [InlineData(SigningAlgorithm.ES512)]
    public async Task SignAsync_produces_non_empty_result_for_ec_algorithms(SigningAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
            SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        };
        using var ec = ECDsa.Create(curve);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-kid", algorithm, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var payload = Encoding.UTF8.GetBytes(Base64UrlEncodeString("""{"sub":"alice"}"""));
        var ct = TestContext.Current.CancellationToken;

        var result = await sut.SignAsync(payload, ct);

        result.HeaderSegment.IsEmpty.Should().BeFalse();
        result.SignatureSegment.IsEmpty.Should().BeFalse();
        result.Algorithm.Should().Be(algorithm);
    }

    [Fact]
    public async Task GetSigningKeysAsync_accepts_nistP384_with_ES384()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-384-kid", SigningAlgorithm.ES384, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle().Which.Algorithm.Should().Be(SigningAlgorithm.ES384);
    }

    [Fact]
    public async Task GetSigningKeysAsync_accepts_nistP521_with_ES512()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("ec-521-kid", SigningAlgorithm.ES512, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        var keys = await sut.GetSigningKeysAsync(ct);

        keys.Should().ContainSingle().Which.Algorithm.Should().Be(SigningAlgorithm.ES512);
    }

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_ec_key_has_null_curve_oid()
    {
        // ECParameters with a null Curve.Oid — curveName will be null, which doesn't match any allowed value.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        // Build ECParameters with an explicit (non-named) curve that has no OID.
        var noOidCurveParams = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.840.10045.3.1.1"), // P-192 — not in allowed list
            Q = ecParams.Q,
        };
        var descriptor = new SigningKeyDescriptor("null-oid-kid", SigningAlgorithm.ES256, noOidCurveParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_unsupported_curve*");
    }

    // ── EC unsupported curve ─────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_ec_key_uses_unsupported_curve()
    {
        // Construct an EC descriptor with P-192 — a real curve but not in the allowed set.
        // We build ECParameters with the P-192 OID so the FriendlyName does not match
        // nistP256/nistP384/nistP521/P-256/P-384/P-521.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        // Replace the curve with a non-allowed named curve by building custom ECParameters.
        var unsupportedCurveParams = new ECParameters
        {
            Curve = ECCurve.CreateFromValue("1.2.840.10045.3.1.1"), // P-192 OID
            Q = ecParams.Q,
        };
        var descriptor = new SigningKeyDescriptor("bad-curve-kid", SigningAlgorithm.ES256, unsupportedCurveParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_unsupported_curve*");
    }

    // ── Concurrent access — double-checked lock ───────────────────────────────────────────────────

    [Fact]
    public async Task Concurrent_callers_both_waiting_on_lock_only_load_once()
    {
        // Arrange: LoadKeysAsync blocks so that both callers can queue on the semaphore
        // before the first one finishes, forcing the second to hit the double-check path.
        using var loadStarted = new SemaphoreSlim(0, 1);
        using var loadGate = new SemaphoreSlim(0, 1);
        var callCount = 0;

        async ValueTask<SigningKeySet> SlowFactory()
        {
            Interlocked.Increment(ref callCount);
            loadStarted.Release(); // signal that we have entered the factory
            await loadGate.WaitAsync().ConfigureAwait(false);
            return MakeRsaSet();
        }

        var tp = new FakeTimeProvider();
        var options = new FakeSigningServiceOptions { KeySourceRefreshInterval = TimeSpan.FromMinutes(5) };
        await using var sut = new AsyncCountingSigningService(Options.Create(options), tp, SlowFactory);
        var ct = TestContext.Current.CancellationToken;

        // Start two concurrent calls — both will see cold cache and race to the lock.
        var t1 = Task.Run(() => sut.GetSigningKeysAsync(ct).AsTask(), ct);
        var t2 = Task.Run(() => sut.GetSigningKeysAsync(ct).AsTask(), ct);

        // Wait until t1 is inside the factory (holding the lock); t2 is now queued.
        await loadStarted.WaitAsync(ct);

        // Give t2 a moment to queue on the semaphore before we release t1.
        await Task.Delay(25, ct);

        // Release t1 — it fills the cache and releases the lock.
        // t2 then acquires the lock and hits the double-check at line 110, returning early.
        loadGate.Release();
        await Task.WhenAll(t1, t2);

        // Assert: factory was called exactly once despite two concurrent callers.
        callCount.Should().Be(1, "the double-checked lock must prevent a second LoadKeysAsync call");
    }

    // ── ValidateKeyStrength — null Curve.Oid ────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_when_ec_descriptor_has_genuinely_null_curve_oid()
    {
        // ECParameters with a default-constructed ECCurve has Curve.Oid == null.
        // ValidateKeyStrength does ecParams.Curve.Oid?.FriendlyName — the ?. short-circuits to null,
        // and ?? string.Empty yields "" which is not in AcceptedEcCurveNames.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var nullOidParams = new ECParameters
        {
            Curve = new ECCurve(), // Oid is null on a default-constructed ECCurve
            Q = ec.ExportParameters(false).Q,
        };
        var descriptor = new SigningKeyDescriptor("null-oid-strength-kid", SigningAlgorithm.ES256, nullOidParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = ec }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_unsupported_curve*");
    }

    // ── ValidateKeyAlgorithmCompatibility — null Curve.Oid on private key ───────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ec_curve_algorithm_mismatch_when_private_key_exports_null_curve_oid()
    {
        // The descriptor has a valid named curve (passes ValidateKeyStrength).
        // The private key is a stub ECDsa whose ExportParameters returns Curve.Oid == null,
        // hitting the ?? string.Empty path in ValidateKeyAlgorithmCompatibility.
        // curveName becomes "" which does not match nistP256/P-256, so the mismatch is detected.
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor("null-oid-compat-kid", SigningAlgorithm.ES256, ecParams);
        using var set = new SigningKeySet([new SigningKeyPair { Descriptor = descriptor, PrivateKey = new NullOidEcDsa(ec) }]);
        await using var sut = BuildService(factory: () => set);
        var ct = TestContext.Current.CancellationToken;

        await sut.Awaiting(s => s.GetSigningKeysAsync(ct).AsTask())
            .Should().ThrowAsync<ZeeKayDaConfigurationException>()
            .WithMessage("*ec_curve_algorithm_mismatch*");
    }

    /// <summary>
    /// A minimal ECDsa wrapper that delegates all real operations to an inner key but overrides
    /// <see cref="ExportParameters"/> to return <c>Curve.Oid == null</c>, exercising the
    /// <c>Oid?.FriendlyName ?? string.Empty</c> null-coalescing path in compatibility validation.
    /// </summary>
    private sealed class NullOidEcDsa : ECDsa
    {
        private readonly ECDsa _inner;

        public NullOidEcDsa(ECDsa inner)
        {
            _inner = inner;
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            var p = _inner.ExportParameters(includePrivateParameters);
            // Return a copy where Curve.Oid is null (default ECCurve has no Oid).
            return new ECParameters
            {
                Curve = new ECCurve(),
                Q = p.Q,
                D = p.D,
            };
        }

        public override byte[] SignHash(byte[] hash) => _inner.SignHash(hash);

        public override bool VerifyHash(byte[] hash, byte[] signature) => _inner.VerifyHash(hash, signature);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _inner.Dispose();
            base.Dispose(disposing);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static string Base64UrlEncodeString(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var encoded = new byte[Base64Url.GetEncodedLength(bytes.Length)];
        Base64Url.EncodeToUtf8(bytes, encoded);
        return Encoding.ASCII.GetString(encoded);
    }

    private static string DecodeBase64UrlToString(ReadOnlyMemory<byte> encoded)
    {
        var bytes = DecodeBase64Url(encoded);
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] DecodeBase64Url(ReadOnlyMemory<byte> encoded)
    {
        var span = encoded.Span;
        var decoded = new byte[Base64Url.GetMaxDecodedLength(span.Length)];
        Base64Url.DecodeFromUtf8(span, decoded, out _, out var written);
        return decoded[..written];
    }
}
