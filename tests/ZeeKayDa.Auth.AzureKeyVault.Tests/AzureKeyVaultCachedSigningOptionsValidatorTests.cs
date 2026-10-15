using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class AzureKeyVaultCachedSigningOptionsValidatorTests
{
    private static readonly Uri CertificateIdentifierUri = new("https://fake-vault.vault.azure.net/certificates/fake-cert");

    private static AzureKeyVaultCachedSigningOptions ValidOptions() => new()
    {
        CertificateIdentifier = new KeyVaultCertificateIdentifier(CertificateIdentifierUri),
        Credential = new FakeTokenCredential(),
        Algorithm = SigningAlgorithm.RS256,
    };

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(AzureKeyVaultCachedSigningOptions options)
    {
        try
        {
            ((IValidateOptions<AzureKeyVaultCachedSigningOptions>)new AzureKeyVaultCachedSigningOptionsValidator()).Validate(null, options);
            return [];
        }
        catch (ZeeKayDaConfigurationException exception)
        {
            return exception.AggregatedFailures;
        }
    }

    // ── Valid options ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_fully_valid_options()
    {
        var options = ValidOptions();

        Validate(options).Should().BeEmpty();
    }

    // ── CertificateIdentifier ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_CertificateIdentifier_has_a_null_VaultUri()
    {
        var options = ValidOptions();
        options.CertificateIdentifier = default;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_cached_signing.certificate_identifier.missing")
            .Which.Message.Should().Contain("CertificateIdentifier");
    }

    // ── Credential ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Credential_is_null()
    {
        var options = ValidOptions();
        options.Credential = null;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_cached_signing.credential.missing")
            .Which.Message.Should().Contain("Credential");
    }

    // ── Algorithm ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Algorithm_is_out_of_range()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_cached_signing.algorithm.undefined_value")
            .Which.Message.Should().Contain("Algorithm");
    }

    // ── MaxVersions ───────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_accepts_a_null_MaxVersions_meaning_every_enabled_version()
    {
        var options = ValidOptions();
        options.MaxVersions = null;

        Validate(options).Should().BeEmpty();
    }

    [Fact]
    public void Validate_accepts_a_MaxVersions_of_exactly_three()
    {
        var options = ValidOptions();
        options.MaxVersions = 3;

        Validate(options).Should().BeEmpty("three is the smallest count that holds a staged, a signing and a previous version");
    }

    [Theory]
    [InlineData(2)]
    [InlineData(1)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_rejects_a_MaxVersions_below_three(int maxVersions)
    {
        var options = ValidOptions();
        options.MaxVersions = maxVersions;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_cached_signing.max_versions.too_small")
            .Which.Message.Should().Contain("MaxVersions").And.Contain(maxVersions.ToString());
    }

    // ── Batched, not fail-fast ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_every_violation_simultaneously_rather_than_failing_fast()
    {
        var options = ValidOptions();
        options.CertificateIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;

        var failures = Validate(options);

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.azure_key_vault_cached_signing.certificate_identifier.missing",
            "configuration.azure_key_vault_cached_signing.credential.missing",
            "configuration.azure_key_vault_cached_signing.algorithm.undefined_value",
        ]);
    }
}
