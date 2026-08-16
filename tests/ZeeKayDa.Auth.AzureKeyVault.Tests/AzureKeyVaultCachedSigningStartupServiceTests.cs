using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <see cref="AzureKeyVaultCachedSigningStartupService"/> — since issue #437, this class
/// keeps only the memory-residency log line; pre-warming and the materialize-and-verify self-test
/// are now the framework-owned <c>SigningStartupSelfTestVerifier</c>'s job.
/// </summary>
public sealed class AzureKeyVaultCachedSigningStartupServiceTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");

    // ── Fake infrastructure ───────────────────────────────────────────────────────────────────────

    private sealed class CapturingLogger<T> : ISanitizingLogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception)));
    }

    private static AzureKeyVaultCachedSigningStartupService BuildSut(
        CapturingLogger<AzureKeyVaultCachedSigningStartupService>? logger = null,
        string certificateName = "fake-cert")
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(
                new Uri($"https://fake-vault.vault.azure.net/certificates/{certificateName}")),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromMinutes(5),
        });

        return new AzureKeyVaultCachedSigningStartupService(
            options,
            logger ?? new CapturingLogger<AzureKeyVaultCachedSigningStartupService>());
    }

    private static IOptions<AzureKeyVaultCachedSigningOptions> DefaultOptions() => Options.Create(
        new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromMinutes(5),
        });

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new AzureKeyVaultCachedSigningStartupService(
            null!,
            NullSanitizingLogger<AzureKeyVaultCachedSigningStartupService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new AzureKeyVaultCachedSigningStartupService(DefaultOptions(), null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: informational log line, not Warning/Critical (AC #2) ────────────────────────

    [Fact]
    public async Task StartAsync_logs_at_Information_level_not_Warning_or_Critical()
    {
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningStartupService>();
        var sut = BuildSut(logger: logger);

        await sut.StartAsync(CancellationToken.None);

        logger.Entries.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Information,
                "caching the private key in process memory is a deliberate architectural choice, not a misconfiguration");
    }

    [Fact]
    public async Task StartAsync_log_message_includes_the_certificate_name_and_vault_uri()
    {
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningStartupService>();
        var sut = BuildSut(logger: logger, certificateName: "my-signing-cert");

        await sut.StartAsync(CancellationToken.None);

        var message = logger.Entries.Should().ContainSingle().Which.Message;
        message.Should().Contain("my-signing-cert", "AC #2 requires the log line to include the key identifier");
        message.Should().Contain("fake-vault.vault.azure.net");
    }

    [Fact]
    public async Task StartAsync_log_message_states_the_key_is_cached_in_process_memory()
    {
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningStartupService>();
        var sut = BuildSut(logger: logger);

        await sut.StartAsync(CancellationToken.None);

        var message = logger.Entries.Should().ContainSingle().Which.Message;
        message.Should().Contain("cached in process memory");
    }

    // ── StopAsync: no side effects ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task StopAsync_does_not_throw()
    {
        var sut = BuildSut();
        await sut.StartAsync(CancellationToken.None);

        await sut.Awaiting(s => s.StopAsync(CancellationToken.None)).Should().NotThrowAsync();
    }
}
