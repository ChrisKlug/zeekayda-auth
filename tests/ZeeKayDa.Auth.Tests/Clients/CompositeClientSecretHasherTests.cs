using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class CompositeClientSecretHasherTests
{
    // ── Fake hasher infrastructure ────────────────────────────────────────────────────────────────

    private static readonly ClientSecret DefaultSecret = new("$default$abc");
    private static readonly ClientSecret AltSecret = new("$alt$abc");
    private static readonly ClientSecret UnhandledSecret = new("$unknown$abc");

    /// <summary>
    /// Trackable fake hasher owning one algorithm id. All Verify calls are counted. Whether Verify
    /// succeeds is configured at construction. Subclassed so the two fakes are different types, which
    /// is how the default hasher is chosen.
    /// </summary>
    private abstract class FakeHasher(string algorithmId, bool verifyResult) : IClientSecretHasher
    {
        private int _verifyCallCount;

        public int VerifyCallCount => _verifyCallCount;

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { algorithmId };

        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
        {
            Interlocked.Increment(ref _verifyCallCount);
            return verifyResult;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new($"${algorithmId}$created");
    }

    private sealed class DefaultHasher(bool verifyResult = false) : FakeHasher("default", verifyResult);

    private sealed class AltHasher(bool verifyResult = false) : FakeHasher("alt", verifyResult);

    private static CompositeClientSecretHasher Composite(
        IEnumerable<IClientSecretHasher> hashers,
        ClientSecretHasherRegistrationOptions? registrations = null,
        SanitizingLogger<CompositeClientSecretHasher>? logger = null) =>
        new(
            hashers,
            Options.Create(registrations ?? new ClientSecretHasherRegistrationOptions()),
            logger ?? NullSanitizingLogger<CompositeClientSecretHasher>.Instance);

    // Creates a composite backed by a single (default) FakeHasher.
    private static (CompositeClientSecretHasher Composite, DefaultHasher DefaultHasher)
        CreateSingleHasherComposite(bool defaultVerifyResult = false)
    {
        var defaultHasher = new DefaultHasher(defaultVerifyResult);
        return (Composite([defaultHasher]), defaultHasher);
    }

    // Creates a composite with a default FakeHasher and an alternative FakeHasher.
    private static (CompositeClientSecretHasher Composite, DefaultHasher DefaultHasher, AltHasher AltHasher)
        CreateMultiHasherComposite(bool defaultVerifyResult = false, bool altVerifyResult = false)
    {
        var defaultHasher = new DefaultHasher(defaultVerifyResult);
        var altHasher = new AltHasher(altVerifyResult);

        return (Composite([defaultHasher, altHasher], DefaultIs<DefaultHasher>()), defaultHasher, altHasher);
    }

    private static ClientSecretHasherRegistrationOptions DefaultIs<THasher>()
    {
        var registrations = new ClientSecretHasherRegistrationOptions();
        registrations.Registrations.Add(new(typeof(THasher), IsDefault: true));
        return registrations;
    }

    // ── Algorithm id ─────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("$pbkdf2-sha256$i=1$a$b", "pbkdf2-sha256")]
    [InlineData("$2b$12$abc", "2b")]
    [InlineData("$id$", "id")]
    [InlineData("plaintext", null)]
    [InlineData("$", null)]
    [InlineData("$$abc", null)]
    [InlineData("$noend", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void AlgorithmIdOf_reads_the_text_between_the_first_two_dollar_signs(string? value, string? expected)
    {
        CompositeClientSecretHasher.AlgorithmIdOf(value).Should().Be(expected);
    }

    [Fact]
    public void CanVerify_is_true_when_any_registered_hasher_declared_the_id()
    {
        var (composite, _, _) = CreateMultiHasherComposite();

        composite.CanVerify(AltSecret).Should().BeTrue();
        composite.CanVerify(UnhandledSecret).Should().BeFalse();
    }

    [Fact]
    public void Algorithm_ids_match_case_sensitively()
    {
        var (composite, _) = CreateSingleHasherComposite();

        composite.CanVerify(new ClientSecret("$DEFAULT$abc")).Should().BeFalse();
    }

    // ── Dispatch ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_hasher_result_when_matching_hasher_is_found()
    {
        var (composite, _) = CreateSingleHasherComposite(defaultVerifyResult: true);

        composite.Verify(DefaultSecret, "presented".AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_when_no_hasher_declared_the_id()
    {
        var (composite, _) = CreateSingleHasherComposite(defaultVerifyResult: true);

        composite.Verify(AltSecret, "presented".AsSpan()).Should().BeFalse();
    }

    [Fact]
    public void Verify_dispatches_by_algorithm_id()
    {
        // altVerifyResult: true so no failed credential slot is spent, keeping the assertion clean.
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite(altVerifyResult: true);

        composite.Verify(AltSecret, "presented".AsSpan());

        altHasher.VerifyCallCount.Should().Be(1);
        defaultHasher.VerifyCallCount.Should().Be(0, "a successful verification spends no failed credential slot");
    }

    [Fact]
    public void A_hasher_whose_Verify_throws_fails_the_verification_and_is_logged_once_without_its_message()
    {
        var logger = new CapturingSanitizingLogger<CompositeClientSecretHasher>();
        var hasher = new ThrowingVerifyHasher();
        var composite = Composite([hasher], logger: logger);

        composite.Verify(new ClientSecret("$throws$abc"), "presented".AsSpan()).Should().BeFalse();
        composite.Verify(new ClientSecret("$throws$abc"), "presented".AsSpan()).Should().BeFalse();

        logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain(nameof(InvalidOperationException))
            .And.NotContain(ThrowingVerifyHasher.Message);
    }

    [Fact]
    public void A_hasher_whose_Verify_throws_does_not_escape_from_padding()
    {
        var composite = Composite([new ThrowingVerifyHasher()]);

        var act = composite.PadToCredentialBudget;

        act.Should().NotThrow();
    }

    private sealed class ThrowingVerifyHasher : IClientSecretHasher
    {
        public const string Message = "secret-bearing hasher message";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "throws" };
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => throw new InvalidOperationException(Message);
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new("$throws$created");
    }

    // ── Startup checks on the registered hashers ─────────────────────────────────────────────────

    [Fact]
    public void Two_hashers_declaring_the_same_algorithm_id_fail_startup()
    {
        var act = () => Composite([new DefaultHasher(), new SecondDefaultIdHasher()], DefaultIs<DefaultHasher>());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "configuration.hashers.duplicate_algorithm_id"
                && f.Message.Contains(nameof(DefaultHasher))
                && f.Message.Contains(nameof(SecondDefaultIdHasher)));
    }

    private sealed class SecondDefaultIdHasher() : FakeHasher("default", false);

    [Fact]
    public void A_hasher_declaring_no_algorithm_ids_fails_startup()
    {
        var act = () => Composite([new IdsHasher()]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.hashers.no_algorithm_ids");
    }

    [Theory]
    [InlineData("UPPER")]
    [InlineData("has$dollar")]
    [InlineData("")]
    [InlineData("an-id-that-is-thirty-three-chars-")]
    public void A_hasher_declaring_an_algorithm_id_outside_the_PHC_alphabet_fails_startup(string id)
    {
        var act = () => Composite([new IdsHasher(id)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.hashers.invalid_algorithm_id");
    }

    private sealed class IdsHasher(params string[] ids) : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string>(ids);
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new($"${ids.FirstOrDefault()}$x");
    }

    // ── Failed credential slots ──────────────────────────────────────────────────────────────────

    [Fact]
    public void A_failed_verification_runs_one_verification_per_hasher_whichever_hasher_failed()
    {
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite();

        composite.Verify(AltSecret, "presented".AsSpan());
        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((1, 1));

        composite.Verify(DefaultSecret, "presented".AsSpan());
        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((2, 2));
    }

    [Fact]
    public void A_successful_verification_runs_no_other_hasher()
    {
        var (composite, defaultHasher, _) = CreateMultiHasherComposite(altVerifyResult: true);

        composite.Verify(AltSecret, "presented".AsSpan());

        defaultHasher.VerifyCallCount.Should().Be(0);
    }

    [Theory]
    [InlineData("unknown client")]
    [InlineData("default-hasher secret")]
    [InlineData("other-hasher secret")]
    public void A_failed_authentication_under_two_hashers_runs_the_same_verifications_as_an_unknown_client(string path)
    {
        // A host migrating away from one hasher keeps both registered: a client still holding the old
        // hasher's secret must fail in the same work as an unknown client.
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite();

        switch (path)
        {
            case "unknown client":
                composite.PadToCredentialBudget();
                break;
            case "default-hasher secret":
                composite.Verify(DefaultSecret, "presented".AsSpan());
                composite.PadFailureToCredentialBudget(1);
                break;
            case "other-hasher secret":
                composite.Verify(AltSecret, "presented".AsSpan());
                composite.PadFailureToCredentialBudget(1);
                break;
        }

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount)
            .Should().Be((CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient, CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient));
    }

    [Fact]
    public void Verify_of_a_credential_no_hasher_handles_spends_a_full_slot()
    {
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite();

        composite.Verify(UnhandledSecret, "presented".AsSpan()).Should().BeFalse();

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((1, 1));
    }

    [Fact]
    public void Empty_secret_probe_runs_only_the_secrets_own_hasher()
    {
        var (composite, defaultHasher, altHasher) = CreateMultiHasherComposite();

        composite.AcceptsEmptySecret(AltSecret).Should().BeFalse();

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((0, 1));
    }

    [Fact]
    public void A_hasher_whose_Create_throws_fails_startup_with_a_configuration_failure()
    {
        var act = () => Composite([new DefaultHasher(), new VerifyOnlyHasher()], DefaultIs<DefaultHasher>());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "configuration.hashers.timing_decoy_unhandled"
                && f.Message.Contains(nameof(NotSupportedException))
                && !f.Message.Contains(VerifyOnlyHasher.CreateMessage));
    }

    [Fact]
    public void Composite_refuses_two_marked_defaults_without_the_validator()
    {
        var registrations = DefaultIs<DefaultHasher>();
        registrations.Registrations.Add(new(typeof(AltHasher), IsDefault: true));

        var act = () => Composite([new DefaultHasher(), new AltHasher()], registrations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.multiple_defaults");
    }

    private sealed class VerifyOnlyHasher : IClientSecretHasher
    {
        public const string CreateMessage = "this hasher only verifies legacy secrets";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "legacy" };
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => throw new NotSupportedException(CreateMessage);
    }

    // ── Timing decoy ──────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A hasher that does not override <c>CreateTimingDecoy</c>, as every third-party hasher is,
    /// recording each plaintext its <c>Create</c> receives.
    /// </summary>
    private sealed class PlaintextRecordingHasher : IClientSecretHasher
    {
        public List<string> CreatedFrom { get; } = [];

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "default" };

        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;

        public ClientSecret Create(ReadOnlySpan<char> plaintext)
        {
            CreatedFrom.Add(plaintext.ToString());
            return DefaultSecret;
        }
    }

    [Fact]
    public void Default_timing_decoy_is_created_by_the_hashers_own_Create()
    {
        IClientSecretHasher hasher = new PlaintextRecordingHasher();

        var decoy = hasher.CreateTimingDecoy();

        ((PlaintextRecordingHasher)hasher).CreatedFrom.Should().ContainSingle();
        decoy.Should().Be(DefaultSecret);
    }

    [Fact]
    public void Default_timing_decoy_is_created_from_a_random_value_so_no_known_value_verifies_it()
    {
        var recorder = new PlaintextRecordingHasher();
        IClientSecretHasher hasher = recorder;

        hasher.CreateTimingDecoy();
        hasher.CreateTimingDecoy();

        recorder.CreatedFrom.Should().NotContain(CompositeClientSecretHasher.DummyPresented,
            "a decoy created from the value every padding verification presents would verify");
        recorder.CreatedFrom.Should().OnlyHaveUniqueItems();
    }

    /// <summary>
    /// A hasher that supplies its own decoy, as the built-in PBKDF2 hasher does, and records what
    /// every verification is run against. Its <c>Create</c> throws, so any path deriving a decoy
    /// instead of asking for one fails.
    /// </summary>
    private sealed class DecoySupplyingHasher : IClientSecretHasher
    {
        public ClientSecret Decoy { get; } = new("$default$decoy");

        public List<ClientSecret> VerifiedAgainst { get; } = [];

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "default" };

        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
        {
            VerifiedAgainst.Add(stored);
            return false;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
            throw new InvalidOperationException("The decoy must be asked for, not derived.");

        ClientSecret IClientSecretHasher.CreateTimingDecoy() => Decoy;
    }

    [Fact]
    public void Composite_pads_against_the_decoy_the_default_hasher_supplies_without_deriving_one()
    {
        var hasher = new DecoySupplyingHasher();

        var composite = Composite([hasher]);
        composite.PadToCredentialBudget();

        hasher.VerifiedAgainst.Should().HaveCount(CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient)
            .And.AllSatisfy(stored => stored.Should().BeSameAs(hasher.Decoy));
    }

    [Fact]
    public void Composite_builds_its_timing_decoy_once_through_the_default_hasher()
    {
        var recorder = new PlaintextRecordingHasher();

        var composite = Composite([recorder]);
        composite.PadToCredentialBudget();

        recorder.CreatedFrom.Should().ContainSingle(
            "the decoy is built once, in the constructor, and every padding verification reuses it");
    }

    [Fact]
    public void CreateTimingDecoy_is_not_public_so_a_third_party_hasher_cannot_supply_a_cheaper_decoy()
    {
        var member = typeof(IClientSecretHasher).GetMethod(
            nameof(IClientSecretHasher.CreateTimingDecoy),
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        member.Should().NotBeNull();
        member!.IsAssembly.Should().BeTrue(
            "a public decoy member would let a third-party hasher return one that verifies faster " +
            "than a real secret, reopening the timing oracle the padding exists to close");
    }

    /// <summary>A hasher owning <c>default</c> whose <c>Create</c> returns whatever it is given.</summary>
    private sealed class MisbehavingCreateHasher(Func<ClientSecret> create) : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "default" };
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => create();
    }

    [Fact]
    public void Constructor_throws_when_the_timing_decoy_has_an_id_the_hasher_did_not_declare()
    {
        // Every padding verification against such a decoy would go to another hasher, or nowhere.
        var act = () => Composite([new MisbehavingCreateHasher(() => AltSecret)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.timing_decoy_unhandled");
    }

    [Fact]
    public void Constructor_throws_when_the_default_hasher_creates_a_null_timing_decoy()
    {
        var act = () => Composite([new MisbehavingCreateHasher(() => null!)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.timing_decoy_unhandled");
    }

    // ── PadToCredentialBudget ─────────────────────────────────────────────────────────────────────

    /// <summary>Hasher variant that tracks whether any Verify call received an empty span.</summary>
    private sealed class EmptySpanTrackingHasher : IClientSecretHasher
    {
        private int _verifyCallCount;
        private int _emptySpanCallCount;

        public int VerifyCallCount => _verifyCallCount;
        public int EmptySpanCallCount => _emptySpanCallCount;

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "default" };

        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented)
        {
            Interlocked.Increment(ref _verifyCallCount);
            if (presented.IsEmpty)
                Interlocked.Increment(ref _emptySpanCallCount);
            return false;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => DefaultSecret;
    }

    [Fact]
    public void PadToCredentialBudget_invokes_default_hasher_max_times()
    {
        var trackingHasher = new EmptySpanTrackingHasher();
        var composite = Composite([trackingHasher]);

        composite.PadToCredentialBudget();

        trackingHasher.VerifyCallCount.Should().Be(CompositeClientSecretHasher.MaxActiveSharedSecretsPerClient);
    }

    [Fact]
    public void PadToCredentialBudget_never_passes_empty_span_to_hasher()
    {
        // Regression: Pbkdf2ClientSecretHasher.Verify short-circuits on presented.IsEmpty,
        // so passing string.Empty makes the timing padding a no-op.
        var trackingHasher = new EmptySpanTrackingHasher();
        var composite = Composite([trackingHasher]);

        composite.PadToCredentialBudget();

        trackingHasher.EmptySpanCallCount.Should().Be(0,
            "PadToCredentialBudget must not pass an empty span — Pbkdf2ClientSecretHasher.Verify " +
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
        var (composite, _, _) = CreateMultiHasherComposite();

        composite.Create("new-secret").Should().Be(new ClientSecret("$default$created"));
        composite.Create("new-secret".AsSpan()).Should().Be(new ClientSecret("$default$created"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void Create_refuses_empty_and_whitespace_plaintext_before_the_hasher_sees_it(string plaintext)
    {
        var recorder = new PlaintextRecordingHasher();
        var composite = Composite([recorder]);
        recorder.CreatedFrom.Clear(); // the timing decoy

        var fromString = () => composite.Create(plaintext);
        var fromSpan = () => composite.Create(plaintext.AsSpan());

        fromString.Should().Throw<ArgumentException>();
        fromSpan.Should().Throw<ArgumentException>();
        recorder.CreatedFrom.Should().BeEmpty();
    }

    [Fact]
    public void Create_refuses_null_plaintext()
    {
        var (composite, _) = CreateSingleHasherComposite();

        var act = () => composite.Create((string)null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Create_refuses_a_secret_whose_id_the_hasher_did_not_declare()
    {
        var calls = 0;
        // The first Create is the timing decoy and must succeed; the next returns another hasher's id.
        var hasher = new MisbehavingCreateHasher(() => ++calls == 1 ? DefaultSecret : AltSecret);
        var composite = Composite([hasher]);

        var act = () => composite.Create("new-secret");

        act.Should().Throw<InvalidOperationException>()
            .WithMessage($"*{nameof(MisbehavingCreateHasher)}*");
    }

    [Fact]
    public void Create_refuses_an_id_the_hasher_declared_only_after_startup()
    {
        // Dispatch indexes the ids once, at startup. A secret under an id added later could never be
        // routed back to its hasher, so Create must not hand one out.
        var ids = new HashSet<string> { "default" };
        var late = false;
        var hasher = new LiveIdsHasher(ids, () => late ? new ClientSecret("$late$x") : DefaultSecret);
        var composite = Composite([hasher]);
        ids.Add("late");
        late = true;

        var act = () => composite.Create("new-secret");

        act.Should().Throw<InvalidOperationException>();
        composite.CanVerify(new ClientSecret("$late$x")).Should().BeFalse();
    }

    private sealed class LiveIdsHasher(HashSet<string> ids, Func<ClientSecret> create) : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds => ids;
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => create();
    }

    // ── ValidateStoredSecret ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void ValidateStoredSecret_prefixes_each_failure_with_the_client_id()
    {
        var composite = Composite([new FailureReportingHasher()]);

        composite.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Be(new ZeeKayDaConfigurationFailure("hasher.code", "Client 'client-a': it is weak"));
    }

    [Fact]
    public void ValidateStoredSecret_reports_a_throwing_hasher_by_exception_type_only()
    {
        var composite = Composite([new FailureReportingHasher(throws: true)]);

        composite.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "client.credentials.validation_threw"
                && f.Message.Contains("client-a")
                && f.Message.Contains(nameof(FormatException))
                && !f.Message.Contains(FailureReportingHasher.ThrowMessage));
    }

    [Fact]
    public void ValidateStoredSecret_keeps_the_codes_of_a_configuration_exception_the_hasher_throws()
    {
        var composite = Composite([new FailureReportingHasher(throwsConfiguration: true)]);

        composite.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Be(new ZeeKayDaConfigurationFailure("hasher.thrown_code", "Client 'client-a': it is unreadable"));
    }

    [Fact]
    public void ValidateStoredSecret_yields_nothing_for_a_secret_no_hasher_declared()
    {
        var composite = Composite([new FailureReportingHasher()]);

        composite.ValidateStoredSecret(UnhandledSecret, "client-a").Should().BeEmpty();
    }

    private sealed class FailureReportingHasher(bool throws = false, bool throwsConfiguration = false) : IClientSecretHasher
    {
        public const string ThrowMessage = "$reports$x is unreadable";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "reports" };
        public bool Verify(ClientSecret stored, ReadOnlySpan<char> presented) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new("$reports$created");

        public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) =>
            throws ? throw new FormatException(ThrowMessage)
            : throwsConfiguration ? throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("hasher.thrown_code", "it is unreadable"))
            : [new ZeeKayDaConfigurationFailure("hasher.code", "it is weak")];
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
        var act = () => Composite([]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.none_registered");
    }

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_none_is_marked_default_and_PBKDF2_is_not_registered()
    {
        var registrations = new ClientSecretHasherRegistrationOptions();
        registrations.Registrations.Add(new(typeof(DefaultHasher), IsDefault: false));
        registrations.Registrations.Add(new(typeof(AltHasher), IsDefault: false));

        var act = () => Composite([new DefaultHasher(), new AltHasher()], registrations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "configuration.hashers.default_type_not_found" && f.Message.Contains("PBKDF2"));
    }

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_default_type_is_not_in_hasher_list()
    {
        // Two hashers in the list, but the registration marks a *third* type (AbsentHasher) as
        // the default. The type lookup in ResolveDefault finds no match → must throw.
        var registrations = new ClientSecretHasherRegistrationOptions();
        registrations.Registrations.Add(new(typeof(DefaultHasher), IsDefault: false));
        registrations.Registrations.Add(new(typeof(AbsentHasher), IsDefault: true));

        var act = () => Composite([new DefaultHasher(), new AltHasher()], registrations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.default_type_not_found");
    }

    private sealed class AbsentHasher() : FakeHasher("absent", false);
}
