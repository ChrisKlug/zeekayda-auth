using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <see cref="AzureKeyVaultCachedSigningMemoryResidencyVerifier"/> — since issue #437,
/// this class keeps only the memory-residency notice; pre-warming and the materialize-and-verify
/// self-test are now the framework-owned <c>SigningStartupSelfTestVerifier</c>'s job.
/// </summary>
public sealed class AzureKeyVaultCachedSigningMemoryResidencyVerifierTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");

    private static AzureKeyVaultCachedSigningMemoryResidencyVerifier BuildSut(string certificateName = "fake-cert") =>
        new(Options.Create(new AzureKeyVaultCachedSigningOptions
        {
            CertificateIdentifier = new KeyVaultCertificateIdentifier(
                new Uri($"https://fake-vault.vault.azure.net/certificates/{certificateName}")),
            Credential = new FakeTokenCredential(),
            Algorithm = SigningAlgorithm.RS256,
            RefreshInterval = TimeSpan.FromMinutes(5),
            PublicationLead = TimeSpan.FromMinutes(5),
        }));

    private static IServiceProvider EmptyProvider() => new ServiceCollection().BuildServiceProvider();

    // ── VerifyAsync: informational warning, not Warning/Critical (AC #2) ────────────────────────

    [Fact]
    public async Task VerifyAsync_records_a_single_warning_at_Information_level_not_Warning_or_Critical()
    {
        var sut = BuildSut();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider(), TestContext.Current.CancellationToken);

        context.Warnings.Should().ContainSingle()
            .Which.Level.Should().Be(LogLevel.Information,
                "caching the private key in process memory is a deliberate architectural choice, not a misconfiguration");
    }

    [Fact]
    public async Task VerifyAsync_does_not_record_any_failure()
    {
        var sut = BuildSut();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider(), TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_warning_includes_the_certificate_name_and_vault_uri()
    {
        var sut = BuildSut(certificateName: "my-signing-cert");
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider(), TestContext.Current.CancellationToken);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Args.Should().Contain("my-signing-cert", "AC #2 requires the notice to include the key identifier");
        warning.Args.Should().Contain(new Uri("https://fake-vault.vault.azure.net/"));
    }

    [Fact]
    public async Task VerifyAsync_warning_message_states_the_key_is_cached_in_process_memory()
    {
        var sut = BuildSut();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider(), TestContext.Current.CancellationToken);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.MessageTemplate.Should().Contain("cached in process memory");
    }

    [Fact]
    public async Task VerifyAsync_warning_uses_the_stable_memory_resident_code()
    {
        var sut = BuildSut();
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, EmptyProvider(), TestContext.Current.CancellationToken);

        var warning = context.Warnings.Should().ContainSingle().Which;
        warning.Code.Should().Be("signing.azure_key_vault_cached.memory_resident");
    }

    // ── Name ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Name_is_AzureKeyVaultCachedSigningMemoryResidency()
    {
        var sut = BuildSut();

        sut.Name.Should().Be("AzureKeyVaultCachedSigningMemoryResidency");
    }
}
