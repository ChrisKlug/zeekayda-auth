using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

public sealed class Pbkdf2ClientSecretHasherTests
{
    // ── Helpers ──────────────────────────────────────────────────────────────────────────────────

    private static Pbkdf2ClientSecretHasher CreateHasher(
        int iterations = Pbkdf2ClientSecretHasherOptions.DefaultIterations,
        ILogger<Pbkdf2ClientSecretHasher>? logger = null)
        => new(
            Options.Create(new Pbkdf2ClientSecretHasherOptions { Iterations = iterations }),
            logger ?? NullLogger<Pbkdf2ClientSecretHasher>.Instance);

    private sealed class CapturingLogger<T> : ILogger<T>
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
    public void Create_ValidSecret_ProducesVerifiableHash()
    {
        var hasher = CreateHasher();

        var stored = hasher.Create("super-secret-value");
        var verified = hasher.Verify(stored, "super-secret-value".AsSpan());

        verified.Should().BeTrue();
    }

    [Fact]
    public void Create_ProducesIpbkdf2ClientSecretWithConfiguredIterations()
    {
        var hasher = CreateHasher();

        var stored = (IPbkdf2ClientSecret)hasher.Create("my-secret");

        stored.Iterations.Should().Be(Pbkdf2ClientSecretHasherOptions.DefaultIterations);
        stored.Salt.Should().HaveCount(16);
        stored.Hash.Should().HaveCount(32);
    }

    [Fact]
    public void Create_TwoCalls_ProduceDifferentSalts()
    {
        var hasher = CreateHasher();

        var a = (IPbkdf2ClientSecret)hasher.Create("same-secret");
        var b = (IPbkdf2ClientSecret)hasher.Create("same-secret");

        a.Salt.Should().NotEqual(b.Salt);
    }

    // ── Verify ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Verify_WrongSecret_ReturnsFalse()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("correct-secret");

        var result = hasher.Verify(stored, "wrong-secret".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_EmptyPresented_ReturnsFalse()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("some-secret");

        var result = hasher.Verify(stored, ReadOnlySpan<char>.Empty);

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_UnknownSecretType_ReturnsFalse()
    {
        var hasher = CreateHasher();

        // IClientSecret whose type is not IPbkdf2ClientSecret
        var result = hasher.Verify(new FakeSecret(), "anything".AsSpan());

        result.Should().BeFalse();
    }

    [Fact]
    public void Verify_NeverThrows()
    {
        var hasher = CreateHasher();

        // Pass a broken IPbkdf2ClientSecret with null buffers — Verify must return false, not throw.
        var brokenSecret = new Pbkdf2ClientSecret(600_000, null!, null!);

        var act = () => hasher.Verify(brokenSecret, "anything".AsSpan());

        act.Should().NotThrow();
        act().Should().BeFalse();
    }

    [Fact]
    public void Verify_StoredIterationsAboveMax_ReturnsFalse()
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
    public void Verify_StoredIterationsAboveMax_LogsWarning()
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
    public void CanHandle_Pbkdf2ClientSecret_ReturnsTrue()
    {
        var hasher = CreateHasher();
        var stored = hasher.Create("a-secret");

        hasher.CanHandle(stored).Should().BeTrue();
    }

    [Fact]
    public void CanHandle_OtherSecretType_ReturnsFalse()
    {
        var hasher = CreateHasher();

        hasher.CanHandle(new FakeSecret()).Should().BeFalse();
    }

    // ── Create argument validation ────────────────────────────────────────────────────────────────

    [Fact]
    public void Create_NullPlaintext_ThrowsArgumentException()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create(null!);

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_EmptyPlaintext_ThrowsArgumentException()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create("");

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_WhitespacePlaintext_ThrowsArgumentException()
    {
        var hasher = CreateHasher();

        var act = () => hasher.Create("   ");

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    // ── Constructor iteration validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_IterationsBelowMinimum_Throws()
    {
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MinIterations - 1 });

        var act = () => new Pbkdf2ClientSecretHasher(options, NullLogger<Pbkdf2ClientSecretHasher>.Instance);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_IterationsAtMinimum_Succeeds()
    {
        var act = () => CreateHasher(Pbkdf2ClientSecretHasher.MinIterations);

        act.Should().NotThrow();
    }

    [Fact]
    public void Constructor_IterationsAboveCap_DoesNotThrowButLogsWarning()
    {
        var logger = new CapturingLogger<Pbkdf2ClientSecretHasher>();
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MaxIterations + 1 });

        var act = () => new Pbkdf2ClientSecretHasher(options, logger);

        act.Should().NotThrow();
        logger.Entries.Should().ContainSingle(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public void Constructor_IterationsAboveCap_StillCreatesAndVerifiesSuccessfully()
    {
        var logger = new CapturingLogger<Pbkdf2ClientSecretHasher>();
        var options = Options.Create(
            new Pbkdf2ClientSecretHasherOptions { Iterations = Pbkdf2ClientSecretHasher.MaxIterations + 1 });
        var hasher = new Pbkdf2ClientSecretHasher(options, logger);

        var stored = hasher.Create("test-secret");
        hasher.Verify(stored, "test-secret").Should().BeTrue();
    }

    // ── Nested helpers ───────────────────────────────────────────────────────────────────────────

    private sealed class FakeSecret : IClientSecret { }
}
