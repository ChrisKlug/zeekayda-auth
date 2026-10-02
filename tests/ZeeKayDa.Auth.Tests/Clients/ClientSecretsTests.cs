using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class ClientSecretsTests
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

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            Interlocked.Increment(ref _verifyCallCount);
            return verifyResult;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new($"${algorithmId}$created");
    }

    private sealed class DefaultHasher(bool verifyResult = false) : FakeHasher("default", verifyResult);

    private sealed class AltHasher(bool verifyResult = false) : FakeHasher("alt", verifyResult);

    private static ClientSecretHasherRegistry Registry(
        IEnumerable<IClientSecretHasher> hashers,
        ClientSecretHasherRegistrationOptions? registrations = null) =>
        new(hashers, Options.Create(registrations ?? new ClientSecretHasherRegistrationOptions()));

    private static ClientSecrets Secrets(
        IEnumerable<IClientSecretHasher> hashers,
        ClientSecretHasherRegistrationOptions? registrations = null,
        SanitizingLogger<ClientSecrets>? logger = null) =>
        new(Registry(hashers, registrations), logger ?? NullSanitizingLogger<ClientSecrets>.Instance);

    // Creates a secrets backed by a single (default) FakeHasher.
    private static (ClientSecrets Secrets, DefaultHasher DefaultHasher)
        CreateSingleHasherSecrets(bool defaultVerifyResult = false)
    {
        var defaultHasher = new DefaultHasher(defaultVerifyResult);
        return (Secrets([defaultHasher]), defaultHasher);
    }

    // Creates a secrets with a default FakeHasher and an alternative FakeHasher.
    private static (ClientSecrets Secrets, DefaultHasher DefaultHasher, AltHasher AltHasher)
        CreateMultiHasherSecrets(bool defaultVerifyResult = false, bool altVerifyResult = false)
    {
        var defaultHasher = new DefaultHasher(defaultVerifyResult);
        var altHasher = new AltHasher(altVerifyResult);

        return (Secrets([defaultHasher, altHasher], DefaultIs<DefaultHasher>()), defaultHasher, altHasher);
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
    [InlineData("$My Secret Password$x", null)]
    [InlineData("$UPPER$x", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void AlgorithmIdOf_reads_the_text_between_the_first_two_dollar_signs(string? value, string? expected)
    {
        ClientSecretHasherRegistry.AlgorithmIdOf(value).Should().Be(expected);
    }

    [Fact]
    public void CanVerify_is_true_when_any_registered_hasher_declared_the_id()
    {
        var registry = Registry([new DefaultHasher(), new AltHasher()], DefaultIs<DefaultHasher>());

        registry.CanVerify(AltSecret).Should().BeTrue();
        registry.CanVerify(UnhandledSecret).Should().BeFalse();
    }

    [Fact]
    public void Algorithm_ids_match_case_sensitively()
    {
        var registry = Registry([new DefaultHasher()]);

        registry.CanVerify(new ClientSecret("$DEFAULT$abc")).Should().BeFalse();
    }

    // ── Dispatch ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_hasher_result_when_matching_hasher_is_found()
    {
        var (secrets, _) = CreateSingleHasherSecrets(defaultVerifyResult: true);

        secrets.Verify("presented", [DefaultSecret]).Should().BeTrue();
    }

    [Fact]
    public void Verify_returns_false_when_no_hasher_declared_the_id()
    {
        var (secrets, _) = CreateSingleHasherSecrets(defaultVerifyResult: true);

        secrets.Verify("presented", [AltSecret]).Should().BeFalse();
    }

    [Fact]
    public void Verify_dispatches_by_algorithm_id()
    {
        // altVerifyResult: true so no failed credential slot is spent, keeping the assertion clean.
        var (secrets, defaultHasher, altHasher) = CreateMultiHasherSecrets(altVerifyResult: true);

        secrets.Verify("presented", [AltSecret]);

        altHasher.VerifyCallCount.Should().Be(1);
        defaultHasher.VerifyCallCount.Should().Be(0, "a successful verification spends no failed credential slot");
    }

    [Fact]
    public void A_hasher_whose_Verify_throws_fails_the_verification_and_is_logged_once_without_its_message()
    {
        var logger = new CapturingSanitizingLogger<ClientSecrets>();
        var hasher = new ThrowingVerifyHasher();
        var secrets = Secrets([hasher], logger: logger);

        secrets.Verify("presented", [new ClientSecret("$throws$abc")]).Should().BeFalse();
        secrets.Verify("presented", [new ClientSecret("$throws$abc")]).Should().BeFalse();

        logger.Entries.Should().ContainSingle(entry => entry.Level == LogLevel.Error)
            .Which.Message.Should().Contain(nameof(InvalidOperationException))
            .And.NotContain(ThrowingVerifyHasher.Message);
    }

    [Fact]
    public void A_hasher_that_throws_still_has_its_decoy_verified_in_the_failed_slot()
    {
        // A throw can come before any real work, so the thrower is not counted as having done its
        // share of the slot: otherwise a known client with a broken hasher fails faster than an
        // unknown one.
        var thrower = new CountingThrowingHasher();
        var other = new DefaultHasher();
        var secrets = Secrets([thrower, other], DefaultIs<DefaultHasher>());

        secrets.Verify("presented", [new ClientSecret("$throws$x")]).Should().BeFalse();

        (thrower.Calls, other.VerifyCallCount).Should().Be((3, 2), "the real attempt, then every hasher's decoy in both slots");
    }

    private sealed class CountingThrowingHasher : IClientSecretHasher
    {
        public int Calls { get; private set; }
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "throws" };
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new("$throws$created");

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            Calls++;
            throw new InvalidOperationException();
        }
    }

    [Fact]
    public void A_hasher_whose_Verify_throws_does_not_escape_from_padding()
    {
        var secrets = Secrets([new ThrowingVerifyHasher()]);

        var act = () => secrets.Verify([], []);

        act.Should().NotThrow();
    }

    private sealed class ThrowingVerifyHasher : IClientSecretHasher
    {
        public const string Message = "secret-bearing hasher message";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "throws" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => throw new InvalidOperationException(Message);
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new("$throws$created");
    }

    // ── Startup checks on the registered hashers ─────────────────────────────────────────────────

    [Fact]
    public void Two_hashers_declaring_the_same_algorithm_id_fail_startup()
    {
        var act = () => Secrets([new DefaultHasher(), new SecondDefaultIdHasher()], DefaultIs<DefaultHasher>());

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
        var act = () => Secrets([new IdsHasher()]);

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
        var act = () => Secrets([new IdsHasher(id)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.hashers.invalid_algorithm_id");
    }

    private sealed class IdsHasher(params string[] ids) : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string>(ids);
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new($"${ids.FirstOrDefault()}$x");
    }

    // ── Failed credential slots ──────────────────────────────────────────────────────────────────

    [Fact]
    public void A_failed_verification_runs_one_verification_per_hasher_whichever_hasher_failed()
    {
        var (secrets, defaultHasher, altHasher) = CreateMultiHasherSecrets();

        secrets.Verify("presented", [AltSecret]);
        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((2, 2));

        secrets.Verify("presented", [DefaultSecret]);
        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((4, 4));
    }

    [Fact]
    public void A_successful_verification_runs_no_other_hasher()
    {
        var (secrets, defaultHasher, _) = CreateMultiHasherSecrets(altVerifyResult: true);

        secrets.Verify("presented", [AltSecret]);

        defaultHasher.VerifyCallCount.Should().Be(0);
    }

    [Theory]
    [InlineData("unknown client")]
    [InlineData("default-hasher secret")]
    [InlineData("other-hasher secret")]
    [InlineData("one secret under each hasher")]
    [InlineData("empty presented secret")]
    public void A_failed_authentication_under_two_hashers_runs_the_same_verifications_as_an_unknown_client(string path)
    {
        // A host migrating away from one hasher keeps both registered: a client still holding the old
        // hasher's secret must fail in the same work as an unknown client.
        var (secrets, defaultHasher, altHasher) = CreateMultiHasherSecrets();

        switch (path)
        {
            case "unknown client":
                secrets.Verify("presented", []);
                break;
            case "default-hasher secret":
                secrets.Verify("presented", [DefaultSecret]);
                break;
            case "other-hasher secret":
                secrets.Verify("presented", [AltSecret]);
                break;
            case "one secret under each hasher":
                secrets.Verify("presented", [DefaultSecret, AltSecret]);
                break;
            case "empty presented secret":
                secrets.Verify("", [DefaultSecret, AltSecret]);
                break;
        }

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount)
            .Should().Be((ClientSecrets.MaxActiveSecretsPerClient, ClientSecrets.MaxActiveSecretsPerClient));
    }

    [Fact]
    public void Verify_of_a_credential_no_hasher_handles_spends_a_full_slot()
    {
        var (secrets, defaultHasher, altHasher) = CreateMultiHasherSecrets();

        secrets.Verify("presented", [UnhandledSecret]).Should().BeFalse();

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount)
            .Should().Be((ClientSecrets.MaxActiveSecretsPerClient, ClientSecrets.MaxActiveSecretsPerClient));
    }

    [Fact]
    public void Empty_secret_probe_runs_only_the_secrets_own_hasher()
    {
        var (defaultHasher, altHasher) = (new DefaultHasher(), new AltHasher());
        var registry = Registry([defaultHasher, altHasher], DefaultIs<DefaultHasher>());

        registry.EmptySecretProblem(AltSecret, "client-a").Should().BeNull();

        (defaultHasher.VerifyCallCount, altHasher.VerifyCallCount).Should().Be((0, 1));
    }

    [Fact]
    public void A_hasher_whose_Create_throws_fails_startup_with_a_configuration_failure()
    {
        var act = () => Secrets([new DefaultHasher(), new VerifyOnlyHasher()], DefaultIs<DefaultHasher>());

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "configuration.hashers.timing_decoy_unhandled"
                && f.Message.Contains(nameof(NotSupportedException))
                && !f.Message.Contains(VerifyOnlyHasher.CreateMessage));
    }

    [Fact]
    public void The_registry_refuses_two_marked_defaults_without_the_validator()
    {
        var registrations = DefaultIs<DefaultHasher>();
        registrations.Registrations.Add(new(typeof(AltHasher), IsDefault: true));

        var act = () => Secrets([new DefaultHasher(), new AltHasher()], registrations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.multiple_defaults");
    }

    private sealed class VerifyOnlyHasher : IClientSecretHasher
    {
        public const string CreateMessage = "this hasher only verifies legacy secrets";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "legacy" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
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

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;

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

        recorder.CreatedFrom.Should().NotContain(ClientSecrets.DummyPresented,
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

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            VerifiedAgainst.Add(stored);
            return false;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
            throw new InvalidOperationException("The decoy must be asked for, not derived.");

        ClientSecret IClientSecretHasher.CreateTimingDecoy() => Decoy;
    }

    [Fact]
    public void Padding_runs_against_the_decoy_the_default_hasher_supplies_without_deriving_one()
    {
        var hasher = new DecoySupplyingHasher();

        var secrets = Secrets([hasher]);
        secrets.Verify([], []);

        hasher.VerifiedAgainst.Should().HaveCount(ClientSecrets.MaxActiveSecretsPerClient)
            .And.AllSatisfy(stored => stored.Should().BeSameAs(hasher.Decoy));
    }

    [Fact]
    public void The_timing_decoy_is_built_once_through_the_default_hasher()
    {
        var recorder = new PlaintextRecordingHasher();

        var secrets = Secrets([recorder]);
        secrets.Verify([], []);

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
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => create();
    }

    [Fact]
    public void Constructor_throws_when_the_timing_decoy_has_an_id_the_hasher_did_not_declare()
    {
        // Every padding verification against such a decoy would go to another hasher, or nowhere.
        var act = () => Secrets([new MisbehavingCreateHasher(() => AltSecret)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.timing_decoy_unhandled");
    }

    [Fact]
    public void Constructor_throws_when_the_default_hasher_creates_a_null_timing_decoy()
    {
        var act = () => Secrets([new MisbehavingCreateHasher(() => null!)]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.timing_decoy_unhandled");
    }

    // ── Padding ──────────────────────────────────────────────────────────────────────────────────

    /// <summary>Hasher variant that tracks whether any Verify call received an empty span.</summary>
    private sealed class EmptySpanTrackingHasher : IClientSecretHasher
    {
        private int _verifyCallCount;
        private int _emptySpanCallCount;

        public int VerifyCallCount => _verifyCallCount;
        public int EmptySpanCallCount => _emptySpanCallCount;

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "default" };

        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored)
        {
            Interlocked.Increment(ref _verifyCallCount);
            if (presented.IsEmpty)
                Interlocked.Increment(ref _emptySpanCallCount);
            return false;
        }

        public ClientSecret Create(ReadOnlySpan<char> plaintext) => DefaultSecret;
    }

    [Fact]
    public void A_refusal_with_nothing_to_verify_spends_the_full_budget()
    {
        var trackingHasher = new EmptySpanTrackingHasher();
        var secrets = Secrets([trackingHasher]);

        secrets.Verify([], []).Should().BeFalse();

        trackingHasher.VerifyCallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    [Fact]
    public void Padding_never_presents_an_empty_secret_to_a_hasher()
    {
        // Pbkdf2ClientSecretHasher.Verify returns at once on an empty span, so padding that presented
        // one would cost nothing.
        var trackingHasher = new EmptySpanTrackingHasher();
        var secrets = Secrets([trackingHasher]);

        secrets.Verify([], [DefaultSecret]);
        secrets.Verify([], []);

        trackingHasher.EmptySpanCallCount.Should().Be(0);
    }

    [Fact]
    public void An_empty_presented_secret_is_never_tried_against_the_stored_secrets()
    {
        // Counted as attempts, verifications the built-in hasher skips would pad short, and timing
        // would tell a known client from an unknown one.
        var hasher = new DecoySupplyingHasher();
        var secrets = Secrets([hasher]);

        secrets.Verify([], [DefaultSecret]).Should().BeFalse();

        hasher.VerifiedAgainst.Should().HaveCount(ClientSecrets.MaxActiveSecretsPerClient)
            .And.AllSatisfy(stored => stored.Should().BeSameAs(hasher.Decoy));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void A_failure_costs_the_full_budget_however_many_secrets_the_client_holds(int storedCount)
    {
        var (secrets, defaultHasher) = CreateSingleHasherSecrets();

        secrets.Verify("presented", [.. Enumerable.Repeat(DefaultSecret, storedCount)]).Should().BeFalse();

        defaultHasher.VerifyCallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    [Fact]
    public void A_match_on_the_first_secret_returns_without_trying_the_second_or_padding()
    {
        var (secrets, defaultHasher) = CreateSingleHasherSecrets(defaultVerifyResult: true);

        secrets.Verify("presented", [DefaultSecret, DefaultSecret]).Should().BeTrue();

        defaultHasher.VerifyCallCount.Should().Be(1);
    }

    [Fact]
    public void A_match_on_the_second_secret_is_found()
    {
        var (secrets, _, _) = CreateMultiHasherSecrets(altVerifyResult: true);

        secrets.Verify("presented", [DefaultSecret, AltSecret]).Should().BeTrue();
    }

    [Fact]
    public void Verify_refuses_more_stored_secrets_than_the_budget_pads_for()
    {
        // Each would fail in its own slot, and a failure would cost more than the budget.
        var (secrets, defaultHasher) = CreateSingleHasherSecrets();

        var act = () => secrets.Verify("presented", [DefaultSecret, DefaultSecret, DefaultSecret]);

        act.Should().Throw<ArgumentException>().WithParameterName("stored");
        defaultHasher.VerifyCallCount.Should().Be(0);
    }

    [Fact]
    public void A_collection_understating_its_count_is_refused_before_any_secret_is_verified()
    {
        // A match on one of the first two would otherwise authenticate a client holding three.
        var (secrets, defaultHasher) = CreateSingleHasherSecrets(defaultVerifyResult: true);

        var act = () => secrets.Verify("presented", new MiscountedCollection(1, [DefaultSecret, DefaultSecret, DefaultSecret]));

        act.Should().Throw<ArgumentException>().WithParameterName("stored");
        defaultHasher.VerifyCallCount.Should().Be(0);
    }

    [Fact]
    public void A_collection_overstating_its_count_is_verified_by_what_it_yields()
    {
        var (secrets, defaultHasher) = CreateSingleHasherSecrets();

        secrets.Verify("presented", new MiscountedCollection(3, [DefaultSecret])).Should().BeFalse();

        defaultHasher.VerifyCallCount.Should().Be(ClientSecrets.MaxActiveSecretsPerClient);
    }

    private sealed class MiscountedCollection(int count, IReadOnlyList<ClientSecret> items) : IReadOnlyCollection<ClientSecret>
    {
        public int Count => count;
        public IEnumerator<ClientSecret> GetEnumerator() => items.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void The_timing_decoys_cannot_be_changed_after_startup()
    {
        var registry = Registry([new DefaultHasher()]);

        var asList = registry.TimingDecoys as IList<(IClientSecretHasher Hasher, ClientSecret Decoy)>;

        (asList is null || asList.IsReadOnly).Should().BeTrue("a downcast must not reach a mutable list");
    }

    [Fact]
    public void Verify_refuses_null_stored_secrets()
    {
        var (secrets, _) = CreateSingleHasherSecrets();

        var act = () => secrets.Verify("presented", null!);

        act.Should().Throw<ArgumentNullException>();
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_uses_default_hasher()
    {
        var (secrets, _, _) = CreateMultiHasherSecrets();

        secrets.Create("new-secret").Should().Be(new ClientSecret("$default$created"));
        secrets.Create("new-secret".AsSpan()).Should().Be(new ClientSecret("$default$created"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void Create_refuses_empty_and_whitespace_plaintext_before_the_hasher_sees_it(string plaintext)
    {
        var recorder = new PlaintextRecordingHasher();
        var secrets = Secrets([recorder]);
        recorder.CreatedFrom.Clear(); // the timing decoy

        var fromString = () => secrets.Create(plaintext);
        var fromSpan = () => secrets.Create(plaintext.AsSpan());

        fromString.Should().Throw<ArgumentException>();
        fromSpan.Should().Throw<ArgumentException>();
        recorder.CreatedFrom.Should().BeEmpty();
    }

    [Fact]
    public void Create_refuses_null_plaintext()
    {
        var (secrets, _) = CreateSingleHasherSecrets();

        var act = () => secrets.Create((string)null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Create_refuses_a_secret_whose_id_the_hasher_did_not_declare()
    {
        var calls = 0;
        // The first Create is the timing decoy and must succeed; the next returns another hasher's id.
        var hasher = new MisbehavingCreateHasher(() => ++calls == 1 ? DefaultSecret : AltSecret);
        var secrets = Secrets([hasher]);

        var act = () => secrets.Create("new-secret");

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
        var registry = Registry([hasher]);
        var secrets = new ClientSecrets(registry, NullSanitizingLogger<ClientSecrets>.Instance);
        ids.Add("late");
        late = true;

        var act = () => secrets.Create("new-secret");

        act.Should().Throw<InvalidOperationException>();
        registry.CanVerify(new ClientSecret("$late$x")).Should().BeFalse();
    }

    private sealed class LiveIdsHasher(HashSet<string> ids, Func<ClientSecret> create) : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds => ids;
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => create();
    }

    // ── ValidateStoredSecret ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void ValidateStoredSecret_prefixes_each_failure_with_the_client_id()
    {
        var registry = Registry([new FailureReportingHasher()]);

        registry.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Be(new ZeeKayDaConfigurationFailure("hasher.code", "Client 'client-a': it is weak"));
    }

    [Fact]
    public void ValidateStoredSecret_reports_a_throwing_hasher_by_exception_type_only()
    {
        var registry = Registry([new FailureReportingHasher(throws: true)]);

        registry.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
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
        var registry = Registry([new FailureReportingHasher(throwsConfiguration: true)]);

        registry.ValidateStoredSecret(new ClientSecret("$reports$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Be(new ZeeKayDaConfigurationFailure("hasher.thrown_code", "Client 'client-a': it is unreadable"));
    }

    [Fact]
    public void ValidateStoredSecret_names_a_hasher_that_returns_null()
    {
        var registry = Registry([new NullReturningHasher()]);

        registry.ValidateStoredSecret(new ClientSecret("$nulls$x"), "client-a")
            .Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "client.credentials.validation_returned_null" && f.Message.Contains(nameof(NullReturningHasher)));
    }

    [Fact]
    public void Create_names_a_hasher_that_returns_null()
    {
        var calls = 0;
        var secrets = Secrets([new MisbehavingCreateHasher(() => ++calls == 1 ? DefaultSecret : null!)]);

        var act = () => secrets.Create("new-secret");

        act.Should().Throw<InvalidOperationException>().WithMessage("*returned null from Create*");
    }

    [Fact]
    public void A_Verify_that_throws_on_the_empty_secret_probe_is_a_named_failure_not_a_log_entry()
    {
        // At registration the operator reads the failure; swallowed as a log entry instead, the
        // client would be served and fail every request with invalid_client.
        var registry = Registry([new ThrowingVerifyHasher()]);

        registry.EmptySecretProblem(new ClientSecret("$throws$x"), "client-a")
            .Should().Match<ZeeKayDaConfigurationFailure>(f =>
                f.Code == "client.credentials.verify_threw"
                && f.Message.Contains(nameof(InvalidOperationException))
                && !f.Message.Contains(ThrowingVerifyHasher.Message));
    }

    private sealed class NullReturningHasher : IClientSecretHasher
    {
        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "nulls" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
        public ClientSecret Create(ReadOnlySpan<char> plaintext) => new("$nulls$created");
        public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) => null!;
    }

    [Fact]
    public void ValidateStoredSecret_yields_nothing_for_a_secret_no_hasher_declared()
    {
        var registry = Registry([new FailureReportingHasher()]);

        registry.ValidateStoredSecret(UnhandledSecret, "client-a").Should().BeEmpty();
    }

    private sealed class FailureReportingHasher(bool throws = false, bool throwsConfiguration = false) : IClientSecretHasher
    {
        public const string ThrowMessage = "$reports$x is unreadable";

        public IReadOnlySet<string> AlgorithmIds { get; } = new HashSet<string> { "reports" };
        public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) => false;
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
        var act = () => CreateSingleHasherSecrets();

        act.Should().NotThrow();
    }

    // ── ResolveDefault — guard throws ────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_no_hashers_are_provided()
    {
        var act = () => Secrets([]);

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

        var act = () => Secrets([new DefaultHasher(), new AltHasher()], registrations);

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

        var act = () => Secrets([new DefaultHasher(), new AltHasher()], registrations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.hashers.default_type_not_found");
    }

    private sealed class AbsentHasher() : FakeHasher("absent", false);
}
