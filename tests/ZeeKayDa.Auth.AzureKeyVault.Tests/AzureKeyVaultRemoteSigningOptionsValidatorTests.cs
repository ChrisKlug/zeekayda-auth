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
        KeyRotationCheckInterval = TimeSpan.FromMinutes(5),
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

    // ── KeyRotationCheckInterval ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_KeyRotationCheckInterval_is_zero()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.Zero;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyRotationCheckInterval");
    }

    [Fact]
    public void Validate_fails_when_KeyRotationCheckInterval_is_negative()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromSeconds(-1);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyRotationCheckInterval");
    }

    // The former "KeyRotationCheckInterval is null" test no longer applies: the property is now
    // non-nullable on RotatingKeySourceOptions (ADR 0011 §3.4, issue #409) — the previous "null
    // means static-source, never refresh" sentinel is now a structural type distinction
    // (StaticKeySourceOptions vs RotatingKeySourceOptions), so this options type can no longer even
    // represent that state.

    [Fact]
    public void Validate_fails_when_KeyRotationCheckInterval_is_positive_but_below_the_one_minute_floor()
    {
        // KeyRotationCheckInterval doubles as the publish-then-activate delay (ADR 0011 §3.5); a value this
        // short would defeat that protection against essentially any real relying party's JWKS
        // cache TTL, and would poll Key Vault often enough to risk throttling.
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromSeconds(30);

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.FailureMessage.Should().Contain("KeyRotationCheckInterval");
    }

    [Fact]
    public void Validate_succeeds_when_KeyRotationCheckInterval_is_exactly_the_one_minute_floor()
    {
        var options = ValidOptions();
        options.KeyRotationCheckInterval = TimeSpan.FromMinutes(1);

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
        options.KeyRotationCheckInterval = TimeSpan.Zero;
        options.KeyIdentifier = default;
        options.Credential = null;
        options.Algorithm = (SigningAlgorithm)999;

        var result = Validate(options);

        result.Failed.Should().BeTrue();
        result.Failures.Should().HaveCount(4, "all four violations must be reported in a single batch, not one at a time");
        result.Failures.Should().Contain(f => f.Contains("KeyRotationCheckInterval"));
        result.Failures.Should().Contain(f => f.Contains("KeyIdentifier"));
        result.Failures.Should().Contain(f => f.Contains("Credential"));
        result.Failures.Should().Contain(f => f.Contains("Algorithm"));
    }
}
