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

    // ── PreviousVersionsToPublish ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_PreviousVersionsToPublish_is_negative()
    {
        var options = ValidOptions();
        options.PreviousVersionsToPublish = -1;

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.previous_versions_to_publish.negative")
            .Which.Message.Should().Contain("PreviousVersionsToPublish");
    }

    [Fact]
    public void Validate_succeeds_when_PreviousVersionsToPublish_is_zero()
    {
        var options = ValidOptions();
        options.PreviousVersionsToPublish = 0;

        Validate(options).Should().BeEmpty();
    }

    // ── PreActivationDelay ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_PreActivationDelay_is_negative()
    {
        var options = ValidOptions();
        options.PreActivationDelay = TimeSpan.FromSeconds(-1);

        var failures = Validate(options);

        failures.Should().ContainSingle(f => f.Code == "configuration.azure_key_vault_remote_signing.pre_activation_delay.negative")
            .Which.Message.Should().Contain("PreActivationDelay");
    }

    [Fact]
    public void Validate_succeeds_when_PreActivationDelay_is_zero()
    {
        var options = ValidOptions();
        options.PreActivationDelay = TimeSpan.Zero;

        Validate(options).Should().BeEmpty();
    }

    // ── Batched, not fail-fast ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_every_violation_simultaneously_rather_than_failing_fast()
    {
        var options = ValidOptions();
        options.KeyIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;
        options.PreviousVersionsToPublish = -1;
        options.PreActivationDelay = TimeSpan.FromSeconds(-1);

        var failures = Validate(options);

        failures.Select(f => f.Code).Should().Contain(
        [
            "configuration.azure_key_vault_remote_signing.key_identifier.missing",
            "configuration.azure_key_vault_remote_signing.credential.missing",
            "configuration.azure_key_vault_remote_signing.algorithm.undefined_value",
            "configuration.azure_key_vault_remote_signing.previous_versions_to_publish.negative",
            "configuration.azure_key_vault_remote_signing.pre_activation_delay.negative",
        ]);
    }
}
