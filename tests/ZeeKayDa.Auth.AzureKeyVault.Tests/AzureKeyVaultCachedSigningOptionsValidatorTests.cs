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
        RefreshInterval = TimeSpan.FromMinutes(5),
    };

    private static ValidateOptionsResult Validate(AzureKeyVaultCachedSigningOptions options)
        => new AzureKeyVaultCachedSigningOptionsValidator().Validate(null, options);

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
    public void Validate_fails_when_RefreshInterval_is_MaxValue()
    {
        // MaxValue is the local-development provider's "never refresh" trick — explicitly rejected
        // here, since real Key Vault certificate rotation polling requires a finite interval.
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.MaxValue;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_fails_when_RefreshInterval_is_positive_but_below_the_one_minute_floor()
    {
        // RefreshInterval doubles as the publish-then-activate delay (ADR 0011 §3.5) and also gates
        // how often private key bytes are re-downloaded — a value this short would defeat the
        // publish-then-activate protection and risk Key Vault throttling.
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromSeconds(30);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("RefreshInterval");
    }

    [Fact]
    public void Validate_succeeds_when_RefreshInterval_is_exactly_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.RefreshInterval = TimeSpan.FromMinutes(1);

        var result = Validate(options);

        result.Succeeded.Should().BeTrue();
    }

    // ── CertificateIdentifier ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_CertificateIdentifier_has_a_null_VaultUri()
    {
        var options = ValidOptions();
        options.CertificateIdentifier = default;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("CertificateIdentifier");
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
        options.CertificateIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().HaveCount(4, "all four violations must be reported in a single batch, not one at a time");
        result.Failures.Should().Contain(f => f.Contains("RefreshInterval"));
        result.Failures.Should().Contain(f => f.Contains("CertificateIdentifier"));
        result.Failures.Should().Contain(f => f.Contains("Credential"));
        result.Failures.Should().Contain(f => f.Contains("Algorithm"));
    }
}
