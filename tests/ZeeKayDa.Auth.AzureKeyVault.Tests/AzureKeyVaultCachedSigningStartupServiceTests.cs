using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

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

    private sealed class FakeSigningService : IJwtSigningService
    {
        public int GetSigningKeysCallCount { get; private set; }

        public Exception? ThrowOnGetSigningKeys { get; set; }

        public ValueTask<IReadOnlyList<SigningKeyDescriptor>> GetSigningKeysAsync(
            CancellationToken cancellationToken = default)
        {
            GetSigningKeysCallCount++;
            if (ThrowOnGetSigningKeys is not null)
                throw ThrowOnGetSigningKeys;
            return ValueTask.FromResult<IReadOnlyList<SigningKeyDescriptor>>([]);
        }

        public ValueTask<SigningResult> SignAsync(
            ReadOnlyMemory<byte> payloadSegment, CancellationToken cancellationToken = default)
            => throw new NotImplementedException();
    }

    private static AzureKeyVaultCachedSigningStartupService BuildSut(
        FakeSigningService? signingService = null,
        CapturingLogger<AzureKeyVaultCachedSigningStartupService>? logger = null,
        string certificateName = "fake-cert")
    {
        var options = Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(
                new Uri($"https://fake-vault.vault.azure.net/certificates/{certificateName}")),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            KeyRotationCheckInterval = TimeSpan.FromMinutes(5),
        });

        return new AzureKeyVaultCachedSigningStartupService(
            options,
            signingService ?? new FakeSigningService(),
            logger ?? new CapturingLogger<AzureKeyVaultCachedSigningStartupService>());
    }

    private static IOptions<AzureKeyVaultCachedSigningOptions> DefaultOptions() => Options.Create(
        new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            KeyRotationCheckInterval = TimeSpan.FromMinutes(5),
        });

    // ── Constructor: argument validation ─────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_options_is_null()
    {
        var act = () => new AzureKeyVaultCachedSigningStartupService(
            null!,
            new FakeSigningService(),
            NullSanitizingLogger<AzureKeyVaultCachedSigningStartupService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("options");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_signingService_is_null()
    {
        var act = () => new AzureKeyVaultCachedSigningStartupService(
            DefaultOptions(),
            null!,
            NullSanitizingLogger<AzureKeyVaultCachedSigningStartupService>.Instance);

        act.Should().Throw<ArgumentNullException>().WithParameterName("signingService");
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_logger_is_null()
    {
        var act = () => new AzureKeyVaultCachedSigningStartupService(DefaultOptions(), new FakeSigningService(), null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("logger");
    }

    // ── StartAsync: pre-warms the signing key cache (AC #1) ──────────────────────────────────────

    [Fact]
    public async Task StartAsync_calls_GetSigningKeysAsync_to_pre_warm_the_cache()
    {
        var signingService = new FakeSigningService();
        var sut = BuildSut(signingService: signingService);

        await sut.StartAsync(CancellationToken.None);

        signingService.GetSigningKeysCallCount.Should().Be(1,
            "the private key must be downloaded and cached at startup, not lazily on the first request");
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

    // ── StartAsync: startup failure aborts before any log line, and propagates unmodified ───────

    [Fact]
    public async Task StartAsync_propagates_configuration_exception_from_signing_service_and_aborts_startup()
    {
        var signingService = new FakeSigningService
        {
            ThrowOnGetSigningKeys = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.certificate_not_exportable", "Simulated failure.")),
        };
        var sut = BuildSut(signingService: signingService);

        var act = async () => await sut.StartAsync(CancellationToken.None);

        (await act.Should().ThrowAsync<ZeeKayDaConfigurationException>())
            .WithMessage("*certificate_not_exportable*");
    }

    [Fact]
    public async Task StartAsync_does_not_log_when_key_loading_fails()
    {
        var logger = new CapturingLogger<AzureKeyVaultCachedSigningStartupService>();
        var signingService = new FakeSigningService
        {
            ThrowOnGetSigningKeys = new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure("signing.azure_key_vault.access_denied", "Simulated failure.")),
        };
        var sut = BuildSut(signingService: signingService, logger: logger);

        await sut.Awaiting(s => s.StartAsync(CancellationToken.None))
            .Should().ThrowAsync<ZeeKayDaConfigurationException>();

        logger.Entries.Should().BeEmpty(
            "the informational log line must only be emitted after the key has actually loaded successfully");
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
