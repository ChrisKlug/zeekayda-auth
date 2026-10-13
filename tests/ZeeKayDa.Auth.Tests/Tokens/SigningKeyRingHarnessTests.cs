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
    public async Task StartAsync_resolves_an_unset_retention_without_changing_the_callers_options()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        var options = new SigningKeyOptions();

        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), options, TestContext.Current.CancellationToken);

        options.RetainRetiredKeysFor.Should().BeNull();
        harness.Ring.Current.SigningKey.Should().NotBeNull();
    }

    [Fact]
    public async Task AdvanceAsync_reads_at_most_once_however_long_the_jump()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await harness.AdvanceAsync(TestSigningKeys.Options.RefreshInterval * 10);

        listing.Reads.Should().Be(2);
    }

    [Fact]
    public async Task AdvanceAsync_returns_once_every_handover_due_by_the_new_time_has_finished()
    {
        var listing = new TestSigningKeys.Listing(
            TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)), TestSigningKeys.Pair("successor", notBefore: Epoch));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        await harness.AdvanceAsync(TestSigningKeys.Options.LeadTime);

        harness.Ring.Current.SigningKey!.SourceId.Value.Should().Be("successor");
    }

    [Fact]
    public async Task AdvanceAsync_rejects_a_negative_jump()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);

        var act = () => harness.AdvanceAsync(TimeSpan.FromSeconds(-1));

        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task ReadAsync_reads_exactly_once_even_after_a_jump_that_ended_between_reads()
    {
        var listing = new TestSigningKeys.Listing(TestSigningKeys.Pair("current", notBefore: Epoch.AddDays(-90)));
        await using var harness = await SigningKeyRingHarness.StartAsync(
            TestSigningKeys.Source(listing), new FakeTimeProvider(Epoch), TestSigningKeys.Options, TestContext.Current.CancellationToken);
        await harness.AdvanceAsync(TestSigningKeys.Options.RefreshInterval / 2);

        await harness.ReadAsync();
        await harness.ReadAsync();

        listing.Reads.Should().Be(3);
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
}
