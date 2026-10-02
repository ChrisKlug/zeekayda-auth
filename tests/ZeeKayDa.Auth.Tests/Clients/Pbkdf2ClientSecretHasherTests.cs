using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class Pbkdf2ClientSecretHasherTests
{
    // Computed independently of this code base (Python's hashlib.pbkdf2_hmac), so a passing
    // verification proves the format and derivation agree with other PHC producers.
    private const string IndependentVector =
        "$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY";

    private const string IndependentVectorPassword = "correct horse battery staple";

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static Pbkdf2ClientSecretHasher CreateHasher(
        int iterations = Pbkdf2ClientSecretHasherOptions.DefaultIterations,
        SanitizingLogger<Pbkdf2ClientSecretHasher>? logger = null)
        => new(
            new FixedOptionsMonitor<Pbkdf2ClientSecretHasherOptions>(
                new Pbkdf2ClientSecretHasherOptions { Iterations = iterations }),
            logger ?? NullSanitizingLogger<Pbkdf2ClientSecretHasher>.Instance);

    private static ClientSecret Pbkdf2Secret(int iterations) =>
        Pbkdf2ClientSecretHasher.Format(
            iterations,
            new byte[Pbkdf2ClientSecretHasher.SaltLength],
            new byte[Pbkdf2ClientSecretHasher.HashLength]);

    private static PhcString Parsed(ClientSecret secret)
    {
        PhcString.TryParse(secret.Value, out var phc).Should().BeTrue();
        return phc!;
    }

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_produces_verifiable_hash_for_valid_secret()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("super-secret-value");

        hasher.Verify(stored, "super-secret-value".AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void Create_produces_a_PHC_string_with_the_configured_iterations()
    {
        var hasher = CreateHasher();

        var phc = Parsed(hasher.Create("my-secret"));

        phc.Id.Should().Be("pbkdf2-sha256");
        phc.Version.Should().BeNull();
        phc.Parameters.Should().BeEquivalentTo(
            [new KeyValuePair<string, string>("i", Pbkdf2ClientSecretHasherOptions.DefaultIterations.ToString())],
            options => options.WithStrictOrdering());
        phc.Salt.Length.Should().Be(16);
        phc.Hash.Length.Should().Be(32);
    }

    [Fact]
    public void Create_produces_different_salts_on_successive_calls()
    {
        var hasher = CreateHasher();

        var a = Parsed(hasher.Create("same-secret"));
        var b = Parsed(hasher.Create("same-secret"));

        a.Salt.ToArray().Should().NotEqual(b.Salt.ToArray());
    }

    [Fact]
    public void Verifies_a_hash_produced_by_an_independent_PBKDF2_implementation()
    {
        var hasher = CreateHasher();

        hasher.Verify(new ClientSecret(IndependentVector), IndependentVectorPassword).Should().BeTrue();
        hasher.Verify(new ClientSecret(IndependentVector), "wrong").Should().BeFalse();
    }

    [Fact]
    public void Declares_only_its_own_algorithm_id()
    {
        CreateHasher().AlgorithmIds.Should().BeEquivalentTo(["pbkdf2-sha256"]);
    }

    // ── Verify ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_false_for_wrong_secret()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("correct-secret");

        hasher.Verify(stored, "wrong-secret".AsSpan()).Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_for_empty_presented_secret()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("some-secret");

        hasher.Verify(stored, ReadOnlySpan<char>.Empty).Should().BeFalse();
    }

    public static TheoryData<string?> MalformedValues() =>
    [
        null!,
        "",
        "plaintext-secret",
        "$bcrypt$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$i=600000,x=1$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$n=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$i=abc$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$i=0$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0O$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTY",
        "$pbkdf2-sha256$i=600000$AAECAwQFBgcICQoLDA0ODw==$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
    ];

    [Theory]
    [MemberData(nameof(MalformedValues))]
    public void Verify_returns_false_for_a_value_that_is_not_a_well_formed_PBKDF2_secret(string? value)
    {
        var hasher = CreateHasher();

        hasher.Verify(new ClientSecret(value!), IndependentVectorPassword).Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_when_stored_iterations_are_above_max()
    {
        var hasher = CreateHasher();

        hasher.Verify(Pbkdf2Secret(Pbkdf2ClientSecretHasher.MaxIterations + 1), "any-secret".AsSpan())
            .Should().BeFalse();
    }

    [Fact]
    public void Verify_logs_warning_when_stored_iterations_are_above_max()
    {
        var logger = new CapturingSanitizingLogger<Pbkdf2ClientSecretHasher>();
        var hasher = CreateHasher(logger: logger);

        hasher.Verify(Pbkdf2Secret(Pbkdf2ClientSecretHasher.MaxIterations + 1), "any-secret".AsSpan());

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning);
    }

    // ── Constructor guard ────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations - 1)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations + 1)]
    public void Constructor_refuses_an_iteration_count_that_skipped_options_validation(int iterations)
    {
        var act = () => CreateHasher(iterations);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle()
            .Which.Code.Should().Be("configuration.pbkdf2.iterations_out_of_range");
    }

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations)]
    public void Constructor_accepts_the_bounds_themselves(int iterations)
    {
        var act = () => CreateHasher(iterations);

        act.Should().NotThrow();
    }

    // ── Create ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_credential_verifies_after_source_array_is_zeroed()
    {
        var hasher = CreateHasher();
        char[] chars = "zeroable-secret".ToCharArray();

        var stored = hasher.Create(chars.AsSpan());
        Array.Clear(chars);

        hasher.Verify(stored, "zeroable-secret".AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void Create_round_trip_with_non_ascii_secrets()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("café 🔑 秘密".AsSpan());

        hasher.Verify(stored, "café 🔑 秘密".AsSpan()).Should().BeTrue();
        hasher.Verify(stored, "cafe key secret".AsSpan()).Should().BeFalse();
    }

    // ── ValidateStoredSecret ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void ValidateStoredSecret_returns_failure_when_iterations_below_minimum()
    {
        var hasher = CreateHasher();

        var failures = hasher.ValidateStoredSecret(Pbkdf2Secret(Pbkdf2ClientSecretHasher.MinIterations - 1)).ToList();

        failures.Should().ContainSingle(f =>
            f.Code == "client.credentials.pbkdf2_iterations_below_minimum" &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MinIterations - 1:N0}") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MinIterations:N0}"));
    }

    [Fact]
    public void ValidateStoredSecret_returns_failure_when_iterations_above_maximum()
    {
        var hasher = CreateHasher();

        var failures = hasher.ValidateStoredSecret(Pbkdf2Secret(Pbkdf2ClientSecretHasher.MaxIterations + 1)).ToList();

        failures.Should().ContainSingle(f =>
            f.Code == "client.credentials.pbkdf2_iterations_above_maximum" &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MaxIterations + 1:N0}") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MaxIterations:N0}"));
    }

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations)]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations + 100_000)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations)]
    public void ValidateStoredSecret_accepts_iterations_within_bounds(int iterations)
    {
        CreateHasher().ValidateStoredSecret(Pbkdf2Secret(iterations)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(MalformedValues))]
    public void ValidateStoredSecret_reports_a_malformed_value_without_quoting_it(string? value)
    {
        var failures = CreateHasher().ValidateStoredSecret(new ClientSecret(value!)).ToList();

        failures.Should().ContainSingle().Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
            f.Code == "client.credentials.pbkdf2_malformed"
            && (string.IsNullOrEmpty(value) || !f.Message.Contains(value)));
    }

    // ── Timing decoy ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Supplies_its_own_timing_decoy_rather_than_deriving_one()
    {
        // The interface's default decoy is a real Create — one full derivation at host startup.
        var map = typeof(Pbkdf2ClientSecretHasher).GetInterfaceMap(typeof(IClientSecretHasher));
        var index = Array.FindIndex(
            map.InterfaceMethods,
            method => method.Name == nameof(IClientSecretHasher.CreateTimingDecoy));

        map.TargetMethods[index].DeclaringType.Should().Be(typeof(Pbkdf2ClientSecretHasher));
    }

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations)]
    [InlineData(1_200_000)]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations)]
    public void Timing_decoy_carries_the_iteration_count_real_secrets_are_created_with(int configured)
    {
        // A decoy above MaxIterations would make Verify return before deriving, and the padding
        // would pad nothing; the options validator keeps the configured count at or below it.
        IClientSecretHasher hasher = CreateHasher(configured);

        var decoy = hasher.CreateTimingDecoy();

        hasher.ValidateStoredSecret(decoy).Should().BeEmpty();
        Parsed(decoy).Parameters.Should().BeEquivalentTo(
            [new KeyValuePair<string, string>("i", configured.ToString())],
            options => options.WithStrictOrdering());
    }

    [Fact]
    public void Two_timing_decoys_share_neither_salt_nor_hash()
    {
        IClientSecretHasher hasher = CreateHasher();

        var first = Parsed(hasher.CreateTimingDecoy());
        var second = Parsed(hasher.CreateTimingDecoy());

        first.Salt.ToArray().Should().NotEqual(second.Salt.ToArray());
        first.Hash.ToArray().Should().NotEqual(second.Hash.ToArray());
    }

    [Theory]
    [InlineData(CompositeClientSecretHasher.DummyPresented)]
    [InlineData("s3cr3t-v4lu3")]
    public void Timing_decoy_verifies_no_presented_value(string presented)
    {
        // DummyPresented is what every padding verification presents; a decoy derived from it would
        // verify.
        IClientSecretHasher hasher = CreateHasher();

        var decoy = hasher.CreateTimingDecoy();

        hasher.Verify(decoy, presented).Should().BeFalse();
    }

    [Theory]
    [InlineData(Pbkdf2ClientSecretHasher.MinIterations - 1, "client.credentials.pbkdf2_iterations_below_minimum")]
    [InlineData(Pbkdf2ClientSecretHasher.MaxIterations + 1, "client.credentials.pbkdf2_iterations_above_maximum")]
    public void Registration_validation_reaches_the_iteration_bounds_through_the_composite(
        int iterations, string expectedCode)
    {
        var composite = new CompositeClientSecretHasher(
            [CreateHasher()],
            Options.Create(new ClientSecretHasherRegistrationOptions()),
            NullSanitizingLogger<CompositeClientSecretHasher>.Instance);

        var failures = composite.ValidateStoredSecret(Pbkdf2Secret(iterations), "my-client");

        failures.Should().ContainSingle().Which.Should().Match<ZeeKayDaConfigurationFailure>(f =>
            f.Code == expectedCode && f.Message.StartsWith("Client 'my-client': "));
    }
}
