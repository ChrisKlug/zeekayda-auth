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
        RefreshInterval = TimeSpan.FromMinutes(5),
        PublicationLead = TimeSpan.FromMinutes(5),
    };

    private static ValidateOptionsResult Validate(AzureKeyVaultRemoteSigningOptions options)
        => new AzureKeyVaultRemoteSigningOptionsValidator().Validate(null, options);

    // ── Valid options ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_for_fully_valid_options()
    {
        var options = ValidOptions();

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    // ── RefreshInterval ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_zero()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.Zero;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_negative()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromSeconds(-1);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_positive_but_below_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromSeconds(30);
        options.PublicationLead = TimeSpan.FromSeconds(30);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_succeeds_when_RefreshInterval_is_exactly_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromMinutes(1);
        options.PublicationLead = TimeSpan.FromMinutes(1);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    // ── PublicationLead ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_PublicationLead_is_shorter_than_RefreshInterval()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromMinutes(5);
        options.PublicationLead = TimeSpan.FromMinutes(1);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("PublicationLead");
    }

    [Fact]
    public void Validate_succeeds_when_PublicationLead_is_at_least_RefreshInterval()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromMinutes(5);
        options.PublicationLead = TimeSpan.FromMinutes(5);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    // ── KeyIdentifier ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_KeyIdentifier_has_a_null_VaultUri()
    {
        var options = ValidOptions();
        options.KeyIdentifier = default;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyIdentifier");
    }

    // ── Credential ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Credential_is_null()
    {
        var options = ValidOptions();
        options.Credential = null;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Credential");
    }

    // ── Algorithm ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_Algorithm_is_out_of_range()
    {
        var options = ValidOptions();
        options.Algorithm = (SigningAlgorithm)999;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("Algorithm");
    }

    // ── Batched, not fail-fast ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_reports_every_violation_simultaneously_rather_than_failing_fast()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.Zero;
        options.KeyIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().Contain(f => f.Contains("RefreshInterval"));
        result.Failures.Should().Contain(f => f.Contains("KeyIdentifier"));
        result.Failures.Should().Contain(f => f.Contains("Credential"));
        result.Failures.Should().Contain(f => f.Contains("Algorithm"));
    }
}
