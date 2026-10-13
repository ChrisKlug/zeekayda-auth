using Microsoft.Extensions.Time.Testing;
using ZeeKayDa.Auth.TestKit.Signing;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises the TestKit's <see cref="SigningKeyRingHarness"/>: that what it promises a source's
/// tests about reads, handovers and ownership holds.
/// </summary>
public sealed class SigningKeyRingHarnessTests
{
    private static readonly DateTimeOffset Epoch = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task StartAsync_reads_the_source_once_and_signs_with_the_key_due_now()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));

        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        listing.Reads.Should().Be(1);
        harness.Ring.Current.SigningKey!.SourceId.Value.Should().Be("current");
    }

    [Fact]
    public async Task StartAsync_disposes_the_source_and_throws_when_startup_fails()
    {
        var listing = new TestSigningKeys.Listing();

        var act = async () => await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ZeeKayDaConfigurationException>();
        listing.SourceDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_disposes_the_source_and_throws_for_options_the_server_would_reject()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        var options = TestSigningKeys.Options;
        options.RefreshInterval = TimeSpan.FromSeconds(-1);

        var act = async () => await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), options, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "configuration.signing_keys.refresh_interval.below_minimum");
        listing.Reads.Should().Be(0);
        listing.SourceDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_rejects_a_lead_time_shorter_than_relying_parties_cache_the_published_keys()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        var options = TestSigningKeys.Options;
        options.LeadTime = TimeSpan.FromMinutes(1);

        var act = async () => await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), options, TestContext.Current.CancellationToken);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code.StartsWith("configuration.signing_keys.lead_time", StringComparison.Ordinal));
        listing.SourceDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_throws_the_startup_failure_when_disposing_the_source_also_throws()
    {
        var source = new FailingSource(() => new InvalidOperationException("the connection was already torn down"));

        var act = async () => await SigningKeyRingHarness.StartAsync(
            source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<TimeoutException>();
        source.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task StartAsync_lets_an_OutOfMemoryException_from_disposing_the_source_escape()
    {
        var source = new FailingSource(() => new OutOfMemoryException());

        var act = async () => await SigningKeyRingHarness.StartAsync(
            source, new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<OutOfMemoryException>();
    }

    [Fact]
    public async Task StartAsync_retains_retired_keys_for_the_server_default_when_retention_is_unset()
    {
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch));
        var options = new SigningKeyOptions { LeadTime = TimeSpan.FromDays(1) };
        var retention = SigningKeyOptions.DefaultRetainRetiredKeysFor(new AuthorizationServerOptions());
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), options, TestContext.Current.CancellationToken);

        await harness.AdvanceAsync(options.LeadTime + retention - TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        harness.Ring.Current.Published.Select(k => k.SourceId.Value).Should().Contain("current");

        await harness.AdvanceAsync(TimeSpan.FromSeconds(1), TestContext.Current.CancellationToken);
        harness.Ring.Current.Published.Select(k => k.SourceId.Value).Should().NotContain("current");
        options.RetainRetiredKeysFor.Should().BeNull("the caller's options are not changed");
    }

    [Fact]
    public async Task AdvanceAsync_reads_at_most_once_however_long_the_jump()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await harness.AdvanceAsync(TestSigningKeys.Options.RefreshInterval * 10, TestContext.Current.CancellationToken);

        listing.Reads.Should().Be(2);
    }

    [Fact]
    public async Task AdvanceAsync_returns_once_every_handover_due_by_the_new_time_has_finished()
    {
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await harness.AdvanceAsync(TestSigningKeys.Options.LeadTime, TestContext.Current.CancellationToken);

        harness.Ring.Current.SigningKey!.SourceId.Value.Should().Be("successor");
    }

    [Fact]
    public async Task AdvanceAsync_rejects_a_negative_jump()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        var act = () => harness.AdvanceAsync(TimeSpan.FromSeconds(-1), TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task ReadAsync_reads_exactly_once_even_after_a_jump_that_ended_between_reads()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);
        await harness.AdvanceAsync(TestSigningKeys.Options.RefreshInterval / 2, TestContext.Current.CancellationToken);

        await harness.ReadAsync(TestContext.Current.CancellationToken);
        await harness.ReadAsync(TestContext.Current.CancellationToken);

        listing.Reads.Should().Be(3);
    }

    [Fact]
    public async Task ReadAsync_stops_waiting_when_cancelled_on_a_read_that_never_completes()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);
        listing.ReadHangs = true;
        using var cancellation = new CancellationTokenSource();

        var read = harness.ReadAsync(cancellation.Token);
        await cancellation.CancelAsync();

        await read.Awaiting(r => r).Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task DisposeAsync_disposes_the_source()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await harness.DisposeAsync();

        listing.SourceDisposed.Should().BeTrue();
    }

    private sealed class FailingSource(Func<Exception> disposeFailure) : ISigningKeySource, IDisposable
    {
        public bool Disposed { get; private set; }

        public SigningAlgorithm Algorithm => SigningAlgorithm.ES256;

        public Task<IReadOnlyList<SourceKey>> ReadAsync(CancellationToken cancellationToken = default) =>
            Task.FromException<IReadOnlyList<SourceKey>>(new TimeoutException("the vault did not answer"));

        public Task<ISigner> CreateSignerAsync(SourceKeyId id, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("No key was listed.");

        public void Dispose()
        {
            Disposed = true;
            throw disposeFailure();
        }
    }
}
