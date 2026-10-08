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

    // ── Evaluate — pure boundary behaviour ───────────────────────────────────────────────────────

    [Fact]
    public void Evaluate_is_Healthy_when_the_signing_key_has_no_expiry()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", expiresAt: null)));

        result.Status.Should().Be(HealthStatus.Healthy);
        result.Description.Should().Contain("no expiry");
    }

    [Fact]
    public void Evaluate_is_Healthy_outside_the_degraded_threshold()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", Now + DegradedThreshold + TimeSpan.FromSeconds(1))));

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public void Evaluate_is_Degraded_exactly_at_the_threshold_boundary()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", Now + DegradedThreshold)));

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public void Evaluate_is_Degraded_inside_the_threshold()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", Now + TimeSpan.FromDays(1))));

        result.Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public void Evaluate_is_Unhealthy_once_past_expiry()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", Now - TimeSpan.FromSeconds(1))));

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public void Evaluate_is_Unhealthy_exactly_at_expiry()
    {
        var result = Evaluate(Timeline(CreateRsaKey("current", Now)));

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public void Evaluate_is_Healthy_when_a_staged_successor_takes_over_before_the_signing_key_expires()
    {
        var timeline = Timeline(
            CreateRsaKey("current", Now.AddDays(3), notBefore: Now.AddDays(-90)),
            CreateRsaKey("successor", Now.AddDays(90), notBefore: Now.AddHours(-1)));

        Evaluate(timeline).Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public void Evaluate_is_Degraded_when_the_only_successor_expires_before_the_threshold_ends()
    {
        var timeline = Timeline(
            CreateRsaKey("current", Now.AddDays(3), notBefore: Now.AddDays(-90)),
            CreateRsaKey("successor", Now.AddDays(5), notBefore: Now.AddHours(-1)));

        Evaluate(timeline).Status.Should().Be(HealthStatus.Degraded);
    }

    [Fact]
    public void Evaluate_is_Degraded_when_a_successor_s_signer_failed_and_was_set_aside()
    {
        var timeline = Timeline(
            CreateRsaKey("current", Now.AddDays(90), notBefore: Now.AddDays(-90)),
            CreateRsaKey("successor", Now.AddDays(365), notBefore: Now.AddDays(-2)));
        var successor = timeline.At(Now).SigningKey;
        var remaining = timeline.SettingAside(successor.Kid);

        var result = SigningKeyExpiryHealthCheck.Evaluate(remaining, remaining.At(Now), Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain(successor.Kid).And.Contain("restart");
    }

    [Fact]
    public void Evaluate_is_Degraded_when_the_key_due_now_is_not_the_key_signing_because_a_handover_hangs()
    {
        var timeline = Timeline(
            CreateRsaKey("current", Now.AddDays(90), notBefore: Now.AddDays(-90)),
            CreateRsaKey("successor", Now.AddDays(365), notBefore: Now.AddDays(-2)));
        var stillSigning = timeline.At(Now.AddDays(-10));

        var result = SigningKeyExpiryHealthCheck.Evaluate(timeline, stillSigning, Now, DegradedThreshold);

        result.Status.Should().Be(HealthStatus.Degraded);
        result.Description.Should().Contain(timeline.At(Now).SigningKey.Kid).And.Contain("handover");
    }

    [Fact]
    public void Evaluate_names_every_reason_it_is_Degraded_not_only_the_first()
    {
        // A failed successor and an upcoming loss of every key are both the operator's to act on.
        var timeline = Timeline(
            CreateRsaKey("current", Now.AddDays(5), notBefore: Now.AddDays(-90)),
            CreateRsaKey("successor", Now.AddDays(6), notBefore: Now.AddDays(-2)));
        var remaining = timeline.SettingAside(timeline.At(Now).SigningKey.Kid);

        var result = SigningKeyExpiryHealthCheck.Evaluate(remaining, remaining.At(Now), Now, DegradedThreshold);

        result.Description.Should().Contain("set aside").And.Contain("No key will be able to sign");
    }

    [Fact]
    public void Evaluate_data_names_every_published_key_with_its_remaining_lifetime()
    {
        var timeline = Timeline(
            CreateRsaKey("previous", Now.AddDays(30), notBefore: Now.AddDays(-90)),
            CreateRsaKey("current", Now.AddDays(60), notBefore: Now.AddHours(-36)),
            CreateRsaKey("next", Now.AddDays(120), notBefore: Now.AddHours(-1)));

        var result = Evaluate(timeline);

        result.Data.Should().ContainKeys(timeline.At(Now).Published.Select(key => key.Kid));
        result.Data.Should().HaveCount(3);
    }

    [Fact]
    public void Evaluate_data_marks_the_signing_key_by_Kid_even_when_it_is_a_distinct_instance()
    {
        // The set's signing key is built separately from the timeline's own instance of the same
        // public key, so IsSigningKey can only be derived by comparing Kid, never by ReferenceEquals.
        var current = CreateRsaKey("current", Now.AddDays(30));
        var timeline = Timeline(current);
        var distinctSigningKey = Timeline(current).At(Now).SigningKey;
        var set = new SigningKeySet(distinctSigningKey, timeline.At(Now).Published);

        var result = SigningKeyExpiryHealthCheck.Evaluate(timeline, set, Now, DegradedThreshold);

        var data = result.Data.Values.OfType<SigningKeyExpiryStatus>().ToList();
        data.Should().ContainSingle(s => s.Kid == distinctSigningKey.Kid && s.IsSigningKey);
    }

    [Fact]
    public void Evaluate_verdict_ignores_an_expired_predecessor_still_published_for_retention()
    {
        var timeline = Timeline(
            CreateRsaKey("previous", Now.AddHours(-1), notBefore: Now.AddDays(-90)),
            CreateRsaKey("current", Now.AddDays(90), notBefore: Now.AddDays(-30)));

        Evaluate(timeline).Status.Should().Be(HealthStatus.Healthy);
    }

    // ── CheckHealthAsync ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_when_no_ring_is_registered()
    {
        var sut = new SigningKeyExpiryHealthCheck(
            ring: null, new FakeTimeProvider(Now), Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
        result.Description.Should().Contain("No SigningKeyRing is registered");
    }

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_when_the_ring_has_not_completed_initialization()
    {
        using var ring = TestSigningKeys.Uninitialized(SigningAlgorithm.RS256);
        var sut = new SigningKeyExpiryHealthCheck(
            ring, new FakeTimeProvider(Now), Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
    }

    [Fact]
    public async Task CheckHealthAsync_reports_the_ring_s_current_set_health()
    {
        using var privateKey = TestSigningKeys.PrivateKey(SigningAlgorithm.RS256);
        var current = TestSigningKeys.SourceKey("current", privateKey, expiresAt: Now.AddDays(90));
        var timeProvider = new FakeTimeProvider(Now);
        using var ring = TestSigningKeys.Ring([current], privateKey, timeProvider);
        var sut = new SigningKeyExpiryHealthCheck(
            ring, timeProvider, Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Healthy);
    }

    [Fact]
    public async Task CheckHealthAsync_reports_Unhealthy_once_past_expiry_without_re_reading_the_source()
    {
        using var rsa = RSA.Create(2048);
        var current = new SourceKey(
            new SourceKeyId("current"), PublicKeyParameters.FromRsa(rsa.ExportParameters(false)), expiresAt: Now.AddDays(1));
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        var source = new CountingSigningKeySource(current, privateKeyPem);
        var timeProvider = new FakeTimeProvider(Now);
        var ring = new SigningKeyRing(source, timeProvider, TestSigningKeys.Options, new CapturingSanitizingLogger<SigningKeyRing>());
        await ring.EnsureInitializedAsync(TestContext.Current.CancellationToken);

        timeProvider.SetUtcNow(Now.AddDays(2)); // advance past the signing key's expiry
        var sut = new SigningKeyExpiryHealthCheck(ring, timeProvider, Options.Create(new SigningKeyExpiryHealthCheckOptions()));

        var result = await sut.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        result.Status.Should().Be(HealthStatus.Unhealthy);
        source.ReadAsyncCallCount.Should().Be(1);
    }

    /// <summary>Real <see cref="ISigningKeySource"/> tracking how many times <see cref="ReadAsync"/>
    /// was called — the defining property of <see cref="SigningKeyRing"/> is that it never
    /// re-reads, so a health check probing it repeatedly must not move this count.</summary>
    private sealed class CountingSigningKeySource(SourceKey current, string privateKeyPem) : ISigningKeySource
    {
        public SigningAlgorithm Algorithm => SigningAlgorithm.RS256;

        public int ReadAsyncCallCount { get; private set; }

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default)
        {
            ReadAsyncCallCount++;
            return Task.FromResult<IReadOnlyList<SourceKey>>([current]);
        }

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default)
        {
            var signerRsa = RSA.Create();
            signerRsa.ImportFromPem(privateKeyPem);
            return Task.FromResult<ISigner>(new LocalSigner(SigningAlgorithm.RS256, signerRsa));
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

    private static SigningKeyTimeline Timeline(params SourceKey[] keys) =>
        SigningKeySetBuilder.Build(keys, SigningAlgorithm.RS256, TestSigningKeys.Options);

    private static HealthCheckResult Evaluate(SigningKeyTimeline timeline) =>
        SigningKeyExpiryHealthCheck.Evaluate(timeline, timeline.At(Now), Now, DegradedThreshold);

    private static SourceKey CreateRsaKey(string id, DateTimeOffset? expiresAt, DateTimeOffset? notBefore = null)
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        return new SourceKey(new SourceKeyId(id), publicKey, notBefore, expiresAt);
    }
}
