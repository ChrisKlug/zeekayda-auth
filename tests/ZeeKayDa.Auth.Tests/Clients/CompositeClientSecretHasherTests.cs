using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class CompositeClientSecretHasherTests
{
    // ── Fake credential + hasher infrastructure ───────────────────────────────────────────────────

    /// <summary>
    /// Simple credential type used as the default hasher's credential.
    /// </summary>
    private sealed class DefaultSecret : IClientSecret { }

    /// <summary>
    /// A second credential type used to test dispatch to a non-default hasher.
    /// </summary>
    private sealed class AltSecret : IClientSecret { }

    /// <summary>
    /// Trackable fake hasher. Handles credentials of type <typeparamref name="TSecret"/>.
    /// All Verify calls are counted. Whether Verify succeeds is configured at construction.
    /// </summary>
    private sealed class FakeHasher<TSecret> : IClientSecretHasher
        where TSecret : IClientSecret, new()
    {
        private readonly bool _verifyResult;
        private int _verifyCallCount;

        public int VerifyCallCount => _verifyCallCount;

        public FakeHasher(bool verifyResult = false) => _verifyResult = verifyResult;

        public bool CanHandle(IClientSecret secret) => secret is TSecret;

        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
        {
            Interlocked.Increment(ref _verifyCallCount);
            return _verifyResult;
        }

        public IClientSecret Create(string plaintext) => new TSecret();
    }

    // Creates a composite backed by a single (default) FakeHasher.
    private static (CompositeClientSecretHasher Composite, FakeHasher<DefaultSecret> DefaultHasher)
        CreateSingleHasherComposite(bool defaultVerifyResult = false)
    {
        var defaultHasher = new FakeHasher<DefaultSecret>(defaultVerifyResult);
        var composite = new CompositeClientSecretHasher(
            [defaultHasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

        return (composite, defaultHasher);
    }

    // Creates a composite with a default FakeHasher and an alternative FakeHasher.
    private static (
        CompositeClientSecretHasher Composite,
        FakeHasher<DefaultSecret> DefaultHasher,
        FakeHasher<AltSecret> AltHasher)
        CreateMultiHasherComposite(
            bool defaultVerifyResult = false,
            bool altVerifyResult = false)
    {
        var defaultHasher = new FakeHasher<DefaultSecret>(defaultVerifyResult);
        var altHasher = new FakeHasher<AltSecret>(altVerifyResult);

        var regOptions = new ClientSecretHasherRegistrationOptions();
        regOptions.Registrations.Add(new(typeof(FakeHasher<DefaultSecret>), IsDefault: true));
        regOptions.Registrations.Add(new(typeof(FakeHasher<AltSecret>), IsDefault: false));

        var composite = new CompositeClientSecretHasher(
            [defaultHasher, altHasher],
            Options.Create(regOptions));

        return (composite, defaultHasher, altHasher);
    }

    // ── Dispatch ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_hasher_result_when_matching_hasher_is_found()
    {
        var (composite, _) = CreateSingleHasherComposite(defaultVerifyResult: true);

        var result = composite.Verify(new DefaultSecret(), "presented".AsSpan());

        result.Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_when_no_matching_hasher_is_found()
    {
        var (composite, _) = CreateSingleHasherComposite();

        // AltSecret is not handled by the single DefaultHasher
        var result = composite.Verify(new AltSecret(), "presented".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_dispatches_to_correct_hasher()
    {
        // Use altVerifyResult: true so PadTiming does not fire, keeping the assertion clean.
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite(altVerifyResult: true);

        composite.Verify(new AltSecret(), "presented".AsSpan());

        altHasher.VerifyCallCount.Should().Be(1);
        defaultHasher.VerifyCallCount.Should().Be(0, "PadTiming must not fire on a successful non-default verification");
    }

    // ── PadTiming behaviour ───────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_pads_timing_when_non_default_hasher_fails()
    {
        // ADR 0007 §3.4: PadTiming fires on failure when matched hasher is not the default.
        var (composite, defaultHasher, _) = CreateMultiHasherComposite(
            defaultVerifyResult: false,
            altVerifyResult: false);

        composite.Verify(new AltSecret(), "presented".AsSpan());

        defaultHasher.VerifyCallCount.Should().Be(1, "PadTiming() should invoke the default hasher once");
    }

    [Fact]
    public void Verify_does_not_pad_timing_when_non_default_hasher_succeeds()
    {
        // PadTiming only fires on failure.
        var (composite, defaultHasher, _) = CreateMultiHasherComposite(
            defaultVerifyResult: false,
            altVerifyResult: true);

        composite.Verify(new AltSecret(), "presented".AsSpan());

        defaultHasher.VerifyCallCount.Should().Be(0, "PadTiming must not fire on a successful verification");
    }

    [Fact]
    public void Verify_does_not_pad_timing_when_default_hasher_fails()
    {
        // PadTiming only fires for non-default hashers.
        var (composite, defaultHasher, _) = CreateMultiHasherComposite(
            defaultVerifyResult: false,
            altVerifyResult: false);

        composite.Verify(new DefaultSecret(), "presented".AsSpan());

        // defaultHasher.VerifyCallCount == 1 from the real Verify call,
        // but 0 extra calls from PadTiming.
        defaultHasher.VerifyCallCount.Should().Be(1, "only the real verify; no PadTiming for the default hasher");
    }

    // ── VerifyUnknownClientForTimingOnly ──────────────────────────────────────────────────────────

    [Fact]
    public void VerifyUnknownClientForTimingOnly_returns_false()
    {
        // ADR 0007 §3.4: runs _default.Verify(_dummySecret, presented).
        // _dummySecret was created by _default.Create(DummyPresented) with FakeHasher,
        // which returns false from Verify regardless of presented.
        var (composite, _) = CreateSingleHasherComposite(defaultVerifyResult: false);

        var result = composite.VerifyUnknownClientForTimingOnly("any-presented-secret".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void VerifyUnknownClientForTimingOnly_invokes_default_hasher()
    {
        var (composite, defaultHasher) = CreateSingleHasherComposite();

        composite.VerifyUnknownClientForTimingOnly("presented".AsSpan());

        defaultHasher.VerifyCallCount.Should().Be(1);
    }

    // ── PadToCredentialBudget ─────────────────────────────────────────────────────────────────────

    /// <summary>Hasher variant that tracks whether any Verify call received an empty span.</summary>
    private sealed class EmptySpanTrackingHasher : IClientSecretHasher
    {
        private int _verifyCallCount;
        private int _emptySpanCallCount;

        public int VerifyCallCount => _verifyCallCount;
        public int EmptySpanCallCount => _emptySpanCallCount;

        public bool CanHandle(IClientSecret secret) => secret is DefaultSecret;

        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
        {
            Interlocked.Increment(ref _verifyCallCount);
            if (presented.IsEmpty)
                Interlocked.Increment(ref _emptySpanCallCount);
            return false;
        }

        public IClientSecret Create(string plaintext) => new DefaultSecret();
    }

    [Fact]
    public void PadToCredentialBudget_invokes_default_hasher_max_times()
    {
        var trackingHasher = new EmptySpanTrackingHasher();
        var composite = new CompositeClientSecretHasher(
            [trackingHasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

        composite.PadToCredentialBudget();

        trackingHasher.VerifyCallCount.Should().Be(CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient);
    }

    [Fact]
    public void PadToCredentialBudget_never_passes_empty_span_to_hasher()
    {
        // Regression: Pbkdf2ClientSecretHasher.VerifyCore short-circuits on presented.IsEmpty,
        // so passing string.Empty makes the timing padding a no-op.
        var trackingHasher = new EmptySpanTrackingHasher();
        var composite = new CompositeClientSecretHasher(
            [trackingHasher],
            Options.Create(new ClientSecretHasherRegistrationOptions()));

        composite.PadToCredentialBudget();

        trackingHasher.EmptySpanCallCount.Should().Be(0,
            "PadToCredentialBudget must not pass an empty span — Pbkdf2ClientSecretHasher.VerifyCore " +
            "returns immediately on IsEmpty, making the timing padding a no-op");
    }

    // ── PadFailureToCredentialBudget ──────────────────────────────────────────────────────────────

    [Fact]
    public void PadFailureToCredentialBudget_pads_to_max_when_zero_credentials_attempted()
    {
        var (composite, defaultHasher) = CreateSingleHasherComposite();

        composite.PadFailureToCredentialBudget(0);

        defaultHasher.VerifyCallCount.Should()
            .Be(CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient);
    }

    [Fact]
    public void PadFailureToCredentialBudget_pads_one_more_when_one_credential_attempted()
    {
        var (composite, defaultHasher) = CreateSingleHasherComposite();

        composite.PadFailureToCredentialBudget(1);

        defaultHasher.VerifyCallCount.Should().Be(1);
    }

    [Fact]
    public void PadFailureToCredentialBudget_pads_nothing_when_already_at_max()
    {
        var (composite, defaultHasher) = CreateSingleHasherComposite();

        composite.PadFailureToCredentialBudget(CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient);

        defaultHasher.VerifyCallCount.Should().Be(0);
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_uses_default_hasher()
    {
        var (composite, _) = CreateSingleHasherComposite();

        var secret = composite.Create("new-secret");

        secret.Should().BeOfType<DefaultSecret>();
    }

    // ── Single-hasher auto-default ────────────────────────────────────────────────────────────────

    [Fact]
    public void SingleHasher_constructs_without_error_when_auto_default_applies()
    {
        // When exactly one hasher is registered it is the default regardless of isDefault flag.
        var act = () => CreateSingleHasherComposite();

        act.Should().NotThrow();
    }

    // ── ResolveDefault — guard throws ────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_no_hashers_are_provided()
    {
        var regOptions = new ClientSecretHasherRegistrationOptions();

        var act = () => new CompositeClientSecretHasher(
            [],
            Options.Create(regOptions));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.none_registered");
    }

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_multiple_hashers_and_none_marked_default()
    {
        var hasherA = new FakeHasher<DefaultSecret>();
        var hasherB = new FakeHasher<AltSecret>();

        var regOptions = new ClientSecretHasherRegistrationOptions();
        regOptions.Registrations.Add(new(typeof(FakeHasher<DefaultSecret>), IsDefault: false));
        regOptions.Registrations.Add(new(typeof(FakeHasher<AltSecret>), IsDefault: false));

        var act = () => new CompositeClientSecretHasher(
            [hasherA, hasherB],
            Options.Create(regOptions));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.no_default");
    }

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_default_type_is_not_in_hasher_list()
    {
        // Two hashers in the list, but the registration marks a *third* type (AbsentHasher) as
        // the default. The type lookup in ResolveDefault finds no match → must throw.
        var hasherA = new FakeHasher<DefaultSecret>();
        var hasherB = new FakeHasher<AltSecret>();

        var regOptions = new ClientSecretHasherRegistrationOptions();
        regOptions.Registrations.Add(new(typeof(FakeHasher<DefaultSecret>), IsDefault: false));
        regOptions.Registrations.Add(new(typeof(AbsentHasher), IsDefault: true));

        var act = () => new CompositeClientSecretHasher(
            [hasherA, hasherB],
            Options.Create(regOptions));

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.default_type_not_found");
    }

    private sealed class AbsentHasher : IClientSecretHasher
    {
        public bool CanHandle(IClientSecret secret) => false;
        public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) => false;
        public IClientSecret Create(string plaintext) => new DefaultSecret();
    }
}
