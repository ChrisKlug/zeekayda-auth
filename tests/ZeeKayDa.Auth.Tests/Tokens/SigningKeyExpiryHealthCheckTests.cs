using System.Security.Cryptography;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SigningKeyExpiryHealthCheck"/>: the pure <c>Evaluate</c> boundary behaviour,
/// and <see cref="SigningKeyExpiryHealthCheck.CheckHealthAsync"/>'s handling of a missing or
/// not-yet-initialized ring.
/// </summary>
public sealed class SigningKeyExpiryHealthCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan DegradedThreshold = TimeSpan.FromDays(14);

    private sealed class FakeSigningKeyRing(SigningKeySet? current) : ISigningKeyRing
    {
        public SigningKeySet Current => current ?? throw new InvalidOperationException();

        public ValueTask<SigningOutcome> SignAsync<TState>(
            TState state, Func<SigningContext, TState, ReadOnlyMemory<byte>> buildSigningInput, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        ValueTask ISigningKeyRing.InitializeAsync(CancellationToken cancellationToken) => throw new NotSupportedException();

        SigningKeySet? ISigningKeyRing.CurrentOrNull => current;
    }

    // ── Evaluate — pure boundary behaviour ───────────────────────────────────────────────────────

    [Fact]
    public void Evaluate_is_Healthy_when_the_signing_key_has_no_expiry()
    {
        var set = BuildSet(signingKeyExpiresAt: null);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("no expiry");
    }

    [Fact]
    public void Evaluate_is_Healthy_outside_the_degraded_threshold()
    {
        var set = BuildSet(signingKeyExpiresAt: Now + DegradedThreshold + TimeSpan.FromSeconds(1));

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public void Evaluate_is_Degraded_exactly_at_the_threshold_boundary()
    {
        var set = BuildSet(signingKeyExpiresAt: Now + DegradedThreshold);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public void Evaluate_is_Degraded_inside_the_threshold()
    {
        var set = BuildSet(signingKeyExpiresAt: Now + TimeSpan.FromDays(1));

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public void Evaluate_is_Unhealthy_once_past_expiry()
    {
        var set = BuildSet(signingKeyExpiresAt: Now - TimeSpan.FromSeconds(1));

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public void Evaluate_is_Unhealthy_exactly_at_expiry()
    {
        var set = BuildSet(signingKeyExpiresAt: Now);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public void Evaluate_data_names_every_published_key_with_its_remaining_lifetime()
    {
        var previous = CreateRsaKey("previous", Now.AddDays(-1));
        var current = CreateRsaKey("current", Now.AddDays(30));
        var next = CreateRsaKey("next", Now.AddDays(120));
        var currentSigningKey = BuildSigningKey(current);
        var set = new SigningKeySet(
            currentSigningKey, [BuildSigningKey(previous), BuildSigningKey(current), BuildSigningKey(next)],
            [SigningAlgorithm.RS256]);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Data.Should().ContainKeys(
            BuildSigningKey(previous).Kid, BuildSigningKey(current).Kid, BuildSigningKey(next).Kid);
    }

    [Fact]
    public void Evaluate_data_marks_the_signing_key_by_Kid_even_when_it_is_a_distinct_instance()
    {
        // Deliberately builds a fresh SigningKey instance per slot, with the same public key
        // material for "current" appearing under both the signing-key argument and its entry in
        // published — so IsSigningKey can only be derived by comparing Kid, never by
        // ReferenceEquals, which SigningKeySetBuilder.Build never guarantees across two separate
        // Build calls over the same public key.
        var previous = CreateRsaKey("previous", Now.AddDays(-1));
        var current = CreateRsaKey("current", Now.AddDays(30));
        var next = CreateRsaKey("next", Now.AddDays(120));
        var currentSigningKey = BuildSigningKey(current);
        var set = new SigningKeySet(
            currentSigningKey, [BuildSigningKey(previous), BuildSigningKey(current), BuildSigningKey(next)],
            [SigningAlgorithm.RS256]);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        var data = result.Data.Values.OfType<SigningKeyExpiryStatus>().ToList();
        data.Should().ContainSingle(s => s.Kid == currentSigningKey.Kid && s.IsSigningKey);
        data.Where(s => s.Kid != currentSigningKey.Kid).Should().OnlyContain(s => !s.IsSigningKey);
    }

    [Fact]
    public void Evaluate_verdict_is_driven_only_by_the_signing_key_not_Previous_or_Next()
    {
        // Previous is already expired, Next is far in the future; only Current (30 days out) should
        // drive the verdict, so this must be Healthy.
        var previous = CreateRsaKey("previous", Now.AddDays(-1));
        var current = CreateRsaKey("current", Now.AddDays(90));
        var next = CreateRsaKey("next", Now.AddDays(365));
        var signingKey = BuildSigningKey(current);
        var set = new SigningKeySet(
            signingKey, [BuildSigningKey(previous), signingKey, BuildSigningKey(next)], [SigningAlgorithm.RS256]);

        var result = SigningKeyExpiryHealthCheck.Evaluate(set, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    // ── CheckHealthAsync ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_when_no_ring_is_registered()
    {
        var sut = new SigningKeyExpiryHealthCheck(
            ring: null, new FakeTimeProvider(Now), Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("No ISigningKeyRing is registered");
    }

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_when_the_ring_has_not_completed_initialization()
    {
        var sut = new SigningKeyExpiryHealthCheck(
            new FakeSigningKeyRing(current: null), new FakeTimeProvider(Now), Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task CheckHealthAsync_reports_the_ring_s_current_set_health()
    {
        var set = BuildSet(signingKeyExpiresAt: Now.AddDays(90));
        var sut = new SigningKeyExpiryHealthCheck(
            new FakeSigningKeyRing(set), new FakeTimeProvider(Now), Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_once_past_expiry_without_re_reading_the_source()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new KeyId("current"), SigningAlgorithm.RS256, PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), Now.AddDays(1));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var source = new CountingSigningKeySource(current, privateKeyPem);
        var timeProvider = new FakeTimeProvider(Now);
        var ring = new StaticSigningKeyRing(source, timeProvider);
        await ((ISigningKeyRing)ring).InitializeAsync(TestContext.Current.CancellationToken);

        timeProvider.SetUtcNow(Now.AddDays(2)); // advance past the signing key's expiry
        var sut = new SigningKeyExpiryHealthCheck(ring, timeProvider, Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
        source.ReadAsyncCallCount.Should().Be(1);
    }

    /// <summary>Real <see cref="ISigningKeySource"/> tracking how many times <see cref="ReadAsync"/>
    /// was called — the defining property of <see cref="StaticSigningKeyRing"/> is that it never
    /// re-reads, so a health check probing it repeatedly must not move this count.</summary>
    private sealed class CountingSigningKeySource(SourceKey current, string privateKeyPem) : ISigningKeySource
    {
        public int ReadAsyncCallCount { get; private set; }

        public ValueTask<SourceKeySet> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return new ValueTask<SourceKeySet>(SourceKeySet.FromSlots(previous: null, current, next: null));
        }

        public ValueTask<ISigner> CreateSignerAsync(KeyId id, CancellationToken cancellationToken = default)
        {
            var signerRsa = RSA.Create();
            signerRsa.ImportFromPem(privateKeyPem);
            return new ValueTask<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
        }
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_timeProvider_is_null()
    {
        var act = () => new SigningKeyExpiryHealthCheck(
            ring: null, timeProvider: null!, Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static SigningKeySet BuildSet(DateTimeOffset? signingKeyExpiresAt)
    {
        var current = CreateRsaKey("current", signingKeyExpiresAt);
        var keys = SourceKeySet.FromSlots(previous: null, current, next: null);
        return SigningKeySetBuilder.Build(keys);
    }

    private static SourceKey CreateRsaKey(string id, DateTimeOffset? expiresAt)
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        return new SourceKey(new KeyId(id), SigningAlgorithm.RS256, publicKey, expiresAt);
    }

    private static SigningKey BuildSigningKey(SourceKey sourceKey) =>
        SigningKeySetBuilder.Build(SourceKeySet.FromSlots(previous: null, sourceKey, next: null)).SigningKey;
}
