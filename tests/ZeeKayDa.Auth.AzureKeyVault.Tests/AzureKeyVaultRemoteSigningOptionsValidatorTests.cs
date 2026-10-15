using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AzureKeyVault.Tests.Fakes;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

public sealed class AzureKeyVaultRemoteSigningOptionsValidatorTests
{
    private static readonly Uri KeyIdentifierUri = new("https://fake-vault.vault.azure.net/keys/fake-key");

    private static AzureKeyVaultRemoteSigningOptions ValidOptions() => new()
    {
        KeyIdentifier = new KeyVaultKeyIdentifier(KeyIdentifierUri),
        Credential = new FakeTokenCredential(),
        Algorithm = SigningAlgorithm.RS256,
    };

    private static IReadOnlyList<ZeeKayDaConfigurationFailure> Validate(AzureKeyVaultRemoteSigningOptions options)
    {
        try
        {
            ((IValidateOptions<AzureKeyVaultRemoteSigningOptions>)new AzureKeyVaultRemoteSigningOptionsValidator()).Validate(null, options);
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

    // ── KeyIdentifier ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_KeyIdentifier_has_a_null_VaultUri()
    {
        var options = ValidOptions();
        options.KeyIdentifier = default;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.key_identifier.missing")
            .Which.Message.Should().Contain("KeyIdentifier");
    }

    // ── Credential ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Credential_is_null()
    {
        var options = ValidOptions();
        options.Credential = null;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.credential.missing")
            .Which.Message.Should().Contain("Credential");
    }

    // ── Algorithm ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Algorithm_is_out_of_range()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.algorithm.undefined_value")
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

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.max_versions.too_small")
            .Which.Message.Should().Contain("MaxVersions").And.Contain(maxVersions.ToString());
    }

    // ── Batched, not fail-fast ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_every_violation_simultaneously_rather_than_failing_fast()
    {
        var options = ValidOptions();
        options.KeyIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;

        var failures = Validate(options);

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.azure_key_vault_remote_signing.key_identifier.missing",
            "configuration.azure_key_vault_remote_signing.credential.missing",
            "configuration.azure_key_vault_remote_signing.algorithm.undefined_value",
        ]);
    }
}
