using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class Pbkdf2ClientSecretHasherTests
{
    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static Pbkdf2ClientSecretHasher CreateHasher(
        int iterations = Pbkdf2ClientSecretHasherOptions.DefaultIterations,
        ISanitizingLogger<Pbkdf2ClientSecretHasher>? logger = null)
        => new(
            Options.Create(new Pbkdf2ClientSecretHasherOptions { Iterations = iterations }),
            logger ?? NullSanitizingLogger<Pbkdf2ClientSecretHasher>.Instance);

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        private readonly List<(LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<(LogLevel Level, string Message)> Entries => _entries;

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;
        bool ILogger.IsEnabled(LogLevel logLevel) => true;

        void ILogger.Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => _entries.Add((logLevel, formatter(state, exception)));
    }

    // ── Happy path ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_produces_verifiable_hash_for_valid_secret()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("super-secret-value");
        var verified = hasher.Verify(stored, "super-secret-value".AsSpan());

        verified.Should().BeTrue();
    }

    [Fact]
    public void Create_produces_IPbkdf2ClientSecret_with_configured_iterations()
    {
        var hasher = CreateHasher();

        var stored = (IPbkdf2ClientSecret)hasher.Create("my-secret");

        stored.Iterations.Should().Be(Pbkdf2ClientSecretHasherOptions.DefaultIterations);
        stored.Salt.Should().HaveCount(16);
        stored.Hash.Should().HaveCount(32);
    }

    [Fact]
    public void Create_produces_different_salts_on_successive_calls()
    {
        var hasher = CreateHasher();

        var a = (IPbkdf2ClientSecret)hasher.Create("same-secret");
        var b = (IPbkdf2ClientSecret)hasher.Create("same-secret");

        a.Salt.Should().NotEqual(b.Salt);
    }

    // ── Verify ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_false_for_wrong_secret()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("correct-secret");

        var result = hasher.Verify(stored, "wrong-secret".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_for_empty_presented_secret()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("some-secret");

        var result = hasher.Verify(stored, ReadOnlySpan<char>.Empty);

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_for_unknown_secret_type()
    {
        var hasher = CreateHasher();

        // IClientSecret whose type is not IPbkdf2ClientSecret
        var result = hasher.Verify(new FakeSecret(), "anything".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_never_throws()
    {
        var hasher = CreateHasher();

        // Pass a broken IPbkdf2ClientSecret with null buffers — Verify must return false, not throw.
        var brokenSecret = new Pbkdf2ClientSecret(600_000, null!, null!);

        var act = () => hasher.Verify(brokenSecret, "anything".AsSpan());

        act.Should().NotThrow();
        act().Should().BeFalse();
    }

    [Fact]
    public void Verify_returns_false_when_stored_iterations_are_above_max()
    {
        var hasher = CreateHasher();
        var tamperedSecret = new Pbkdf2ClientSecret(
            Pbkdf2ClientSecretHasher.MaxIterations + 1,
            new byte[16],
            new byte[32]);

        var result = hasher.Verify(tamperedSecret, "any-secret".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_logs_warning_when_stored_iterations_are_above_max()
    {
        var logger = new CapturingLogger<Pbkdf2ClientSecretHasher>();
        var hasher = new Pbkdf2ClientSecretHasher(
            Options.Create(new Pbkdf2ClientSecretHasherOptions()),
            logger);
        var tamperedSecret = new Pbkdf2ClientSecret(
            Pbkdf2ClientSecretHasher.MaxIterations + 1,
            new byte[16],
            new byte[32]);

        hasher.Verify(tamperedSecret, "any-secret".AsSpan());

        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning);
    }

    // ── CanHandle ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void CanHandle_returns_true_for_Pbkdf2ClientSecret()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("a-secret");

        hasher.CanHandle(stored).Should().BeTrue();
    }

    [Fact]
    public void CanHandle_returns_false_for_other_secret_type()
    {
        var hasher = CreateHasher();

        hasher.CanHandle(new FakeSecret()).Should().BeFalse();
    }

    // ── Create argument validation ────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_throws_ArgumentException_for_null_plaintext()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create(null!);

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_throws_ArgumentException_for_empty_plaintext()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create("");

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_throws_ArgumentException_for_whitespace_plaintext()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create("   ");

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    // ── Create span overload ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_span_throws_ArgumentException_for_empty_span()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create(ReadOnlySpan<char>.Empty);

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_span_throws_ArgumentException_for_whitespace_only_span()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create("   ".AsSpan());

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_span_produces_verifiable_credential()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("span-secret".AsSpan());
        var result = hasher.Verify(stored, "span-secret".AsSpan());

        result.Should().BeTrue();
    }

    [Fact]
    public void Create_span_credential_verifies_after_source_array_is_zeroed()
    {
        var hasher = CreateHasher();
        char[] chars = "zeroable-secret".ToCharArray();

        var stored = hasher.Create(chars.AsSpan());
        Array.Clear(chars);
        var result = hasher.Verify(stored, "zeroable-secret".AsSpan());

        result.Should().BeTrue();
    }

    [Fact]
    public void Create_span_and_string_paths_produce_hashes_that_verify_same_secret()
    {
        var hasher = CreateHasher();

        var storedViaSpan = hasher.Create("shared-secret".AsSpan());
        var storedViaString = hasher.Create("shared-secret");

        hasher.Verify(storedViaSpan, "shared-secret".AsSpan()).Should().BeTrue();
        hasher.Verify(storedViaString, "shared-secret".AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void Create_span_round_trip_with_non_ascii_secrets()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("café 🔑 秘密".AsSpan());

        hasher.Verify(stored, "café 🔑 秘密".AsSpan()).Should().BeTrue();
        hasher.Verify(stored, "cafe key secret".AsSpan()).Should().BeFalse();
    }

    // ── Constructor iteration validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_iterations_are_below_minimum()
    {
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MinIterations - 1 });

        var act = () => new Pbkdf2ClientSecretHasher(options, NullSanitizingLogger<Pbkdf2ClientSecretHasher>.Instance);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_succeeds_when_iterations_are_at_minimum()
    {
        var act = () => CreateHasher(Pbkdf2ClientSecretHasher.MinIterations);

        act.Should().NotThrow();
    }

    [Fact]
    public void Constructor_does_not_throw_but_logs_warning_when_iterations_are_above_cap()
    {
        var logger = new CapturingLogger<Pbkdf2ClientSecretHasher>();
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MaxIterations + 1 });

        var act = () => new Pbkdf2ClientSecretHasher(options, logger);

        act.Should().NotThrow();
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void Constructor_still_creates_and_verifies_successfully_when_iterations_are_above_cap()
    {
        var logger = new CapturingLogger<Pbkdf2ClientSecretHasher>();
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MaxIterations + 1 });
        var hasher = new Pbkdf2ClientSecretHasher(options, logger);

        var stored = hasher.Create("test-secret");
        hasher.Verify(stored, "test-secret").Should().BeTrue();
    }

    // ── GetRegistrationFailures ──────────────────────────────────────────────────────────────────

    [Fact]
    public void GetRegistrationFailures_returns_failure_when_iterations_below_minimum()
    {
        var hasher = CreateHasher();
        var secret = new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MinIterations - 1, new byte[16], new byte[32]);

        var failures = hasher.GetRegistrationFailures(secret, "my-client").ToList();

        failures.Should().ContainSingle(f =>
            f.Code == "client.credentials.pbkdf2_iterations_below_minimum" &&
            f.Message.Contains("my-client") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MinIterations - 1:N0}") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MinIterations:N0}"));
    }

    [Fact]
    public void GetRegistrationFailures_returns_empty_when_iterations_equal_minimum()
    {
        var hasher = CreateHasher();
        var secret = new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MinIterations, new byte[16], new byte[32]);

        var failures = hasher.GetRegistrationFailures(secret, "my-client");

        failures.Should().BeEmpty();
    }

    [Fact]
    public void GetRegistrationFailures_returns_empty_when_iterations_above_minimum()
    {
        var hasher = CreateHasher();
        var secret = new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MinIterations + 100_000, new byte[16], new byte[32]);

        var failures = hasher.GetRegistrationFailures(secret, "my-client");

        failures.Should().BeEmpty();
    }

    [Fact]
    public void GetRegistrationFailures_returns_failure_when_iterations_above_maximum()
    {
        var hasher = CreateHasher();
        var secret = new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MaxIterations + 1, new byte[16], new byte[32]);

        var failures = hasher.GetRegistrationFailures(secret, "my-client").ToList();

        failures.Should().ContainSingle(f =>
            f.Code == "client.credentials.pbkdf2_iterations_above_maximum" &&
            f.Message.Contains("my-client") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MaxIterations + 1:N0}") &&
            f.Message.Contains($"{Pbkdf2ClientSecretHasher.MaxIterations:N0}"));
    }

    [Fact]
    public void GetRegistrationFailures_returns_empty_when_iterations_equal_maximum()
    {
        var hasher = CreateHasher();
        var secret = new Pbkdf2ClientSecret(Pbkdf2ClientSecretHasher.MaxIterations, new byte[16], new byte[32]);

        var failures = hasher.GetRegistrationFailures(secret, "my-client");

        failures.Should().BeEmpty();
    }

    [Fact]
    public void GetRegistrationFailures_returns_empty_for_non_Pbkdf2_credential()
    {
        // Covers the `yield break` branch: credential is not IPbkdf2ClientSecret.
        var hasher = CreateHasher();

        var failures = hasher.GetRegistrationFailures(new FakeSecret(), "any-client");

        failures.Should().BeEmpty();
    }

    // ── CreateCore(string) — string overload exercised via reflection ────────────────────────────
    // Pbkdf2ClientSecretHasher overrides both CreateCore(ReadOnlySpan<char>) and CreateCore(string).
    // Since the DIM IClientSecretHasher.Create(string) now routes through the span path, the
    // string overload can only be reached via the base-class virtual fallback — but that fallback
    // is bypassed because Pbkdf2ClientSecretHasher also overrides CreateCore(ReadOnlySpan<char>).
    // Reflection is the only way to exercise the protected string override directly.

    [Fact]
    public void CreateCore_string_produces_verifiable_credential()
    {
        // Arrange
        var hasher = CreateHasher();
        var createCoreString = typeof(Pbkdf2ClientSecretHasher)
            .GetMethod("CreateCore", BindingFlags.NonPublic | BindingFlags.Instance, [typeof(string)])!;

        // Act
        var stored = (IPbkdf2ClientSecret)createCoreString.Invoke(hasher, ["string-path-secret"])!;

        // Assert — the produced credential must pass round-trip verification.
        hasher.Verify(stored, "string-path-secret".AsSpan()).Should().BeTrue();
        hasher.Verify(stored, "wrong-secret".AsSpan()).Should().BeFalse();
    }

    [Fact]
    public void CreateCore_string_produces_credential_with_correct_structure()
    {
        var hasher = CreateHasher();
        var createCoreString = typeof(Pbkdf2ClientSecretHasher)
            .GetMethod("CreateCore", BindingFlags.NonPublic | BindingFlags.Instance, [typeof(string)])!;

        var stored = (IPbkdf2ClientSecret)createCoreString.Invoke(hasher, ["structure-test-secret"])!;

        stored.Iterations.Should().Be(Pbkdf2ClientSecretHasherOptions.DefaultIterations);
        stored.Salt.Should().HaveCount(16);
        stored.Hash.Should().HaveCount(32);
    }

    // ── ClientSecretHasher<T> exception swallowing ────────────────────────────────────────────────

    [Fact]
    public void Verify_returns_false_when_VerifyCore_throws()
    {
        // A custom IPbkdf2ClientSecret whose Salt getter throws causes VerifyCore to propagate
        // an exception; the base-class catch block must swallow it and return false.
        var hasher = CreateHasher();

        var act = () => hasher.Verify(new ThrowingPbkdf2Secret(), "anything".AsSpan());

        act.Should().NotThrow();
        act().Should().BeFalse();
    }

    // ── Nested helpers ───────────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }

    private sealed class ThrowingPbkdf2Secret : IPbkdf2ClientSecret
    {
        public int Iterations => Pbkdf2ClientSecretHasher.MinIterations;
        public byte[] Salt => throw new InvalidOperationException("Simulated storage failure");
        public byte[] Hash => new byte[32];
    }
}
