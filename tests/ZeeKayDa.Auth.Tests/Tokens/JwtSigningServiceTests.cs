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

    private static SigningKeySet MakeRsaSet(string kid = "test-kid")
    {
        var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        var entry = new SigningKeyEntry(descriptor, 0);
        var set = new SigningKeySet([entry], [rsa]);
        return set;
    }

    private static CountingSigningService BuildService(
        FakeTimeProvider? timeProvider = null,
        Func<SigningKeySet>? factory = null,
        TimeSpan? refreshInterval = null)
    {
        var tp = timeProvider ?? new FakeTimeProvider();
        var options = new FakeSigningServiceOptions
        {
            RefreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5),
        };
        var f = factory ?? (() => MakeRsaSet());
        return new CountingSigningService(Options.Create(options), tp, f);
    }

    // ── Constructor validation ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_options_is_null()
    {
        var act = () => new CountingSigningService(null!, new FakeTimeProvider(), () => MakeRsaSet().Set);
        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_when_timeProvider_is_null()
    {
        var act = () => new CountingSigningService(
            Options.Create(new FakeSigningServiceOptions()),
            null!,
            () => MakeRsaSet().Set);
        act.Should().Throw<ArgumentNullException>().WithParameterName("timeProvider");
    }

    // ── Key loading ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_returns_descriptor_from_loaded_set()
    {
        var (_, set) = MakeRsaSet("my-kid");
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
        var (_, set) = MakeRsaSet("kid-abc");
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [rsa]);
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

    // ── Duplicate kid validation ──────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetSigningKeysAsync_throws_ZeeKayDaConfigurationException_on_duplicate_kid()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var desc1 = new SigningKeyDescriptor("duplicate-kid", SigningAlgorithm.RS256, rsa1.ExportParameters(false));
        var desc2 = new SigningKeyDescriptor("duplicate-kid", SigningAlgorithm.RS256, rsa2.ExportParameters(false));
        var entries = new[] { new SigningKeyEntry(desc1, 0), new SigningKeyEntry(desc2, 1) };
        using var set = new SigningKeySet(entries, [rsa1, rsa2]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [rsa]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [rsa]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [rsa]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [rsa]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
            return MakeRsaSet().Set;
        }

        var tp = new FakeTimeProvider();
        var options = new FakeSigningServiceOptions { RefreshInterval = TimeSpan.FromMinutes(5) };
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [ec]);
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
        var entry = new SigningKeyEntry(descriptor, 0);
        using var set = new SigningKeySet([entry], [new NullOidEcDsa(ec)]);
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
