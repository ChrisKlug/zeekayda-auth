namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <see cref="KeyVaultSigningKeyRotation.BuildActivationTimeline{T}"/>'s independent
/// <c>signingKeyActivationDelay &lt; keyRotationCheckInterval</c> guard (ADR 0011 §3.5, issue #413).
/// </summary>
/// <remarks>
/// This guard is deliberately duplicated — once in each Key Vault options validator (via
/// <see cref="KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval"/>, covered by
/// <c>KeyVaultActivationDelayTests</c> and the two options-validator test classes) and once here,
/// inside <see cref="KeyVaultSigningKeyRotation.BuildActivationTimeline{T}"/> itself — so that a
/// caller building a timeline directly, bypassing <c>IValidateOptions</c> entirely, cannot silently
/// reintroduce the activation race. This test proves the second, independent copy of the guard
/// exists and actually throws, not just the validator-level one.
/// </remarks>
public sealed class KeyVaultSigningKeyRotationTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-01-01T00:00:00Z");

    private static KeyVaultCertificateVersionInfo MakeVersion(string version, DateTimeOffset createdOn) =>
        new(
            new Uri($"https://fake-vault.vault.azure.net/certificates/fake-cert/{version}"),
            version,
            Enabled: true,
            CreatedOn: createdOn,
            NotBefore: null,
            ExpiresOn: null);

    [Fact]
    public void BuildActivationTimeline_throws_ZeeKayDaConfigurationException_when_signingKeyActivationDelay_is_shorter_than_keyRotationCheckInterval()
    {
        // Bypasses IValidateOptions entirely — calls the pure derivation function directly with an
        // invalid delay pairing, exactly as a future custom KMS/HSM provider modeled on this pattern
        // might, if it forgot to also wire up a cross-field options validator.
        var versions = new[] { MakeVersion("v1", T0) };

        var act = () => KeyVaultSigningKeyRotation.BuildActivationTimeline(
            versions, signingKeyActivationDelay: TimeSpan.FromMinutes(1), keyRotationCheckInterval: TimeSpan.FromMinutes(5));

        var exception = act.Should().Throw<ZeeKayDaConfigurationException>();
        exception.Which.AggregatedFailures.Should().ContainSingle(
            f => f.Code == "signing.key_vault.activation_delay_shorter_than_check_interval");
    }

    [Fact]
    public void BuildActivationTimeline_does_not_throw_when_signingKeyActivationDelay_equals_keyRotationCheckInterval()
    {
        var versions = new[] { MakeVersion("v1", T0) };

        var act = () => KeyVaultSigningKeyRotation.BuildActivationTimeline(
            versions, signingKeyActivationDelay: TimeSpan.FromMinutes(5), keyRotationCheckInterval: TimeSpan.FromMinutes(5));

        act.Should().NotThrow("equal to the floor is still valid — only strictly shorter is rejected");
    }

    [Fact]
    public void BuildActivationTimeline_does_not_throw_when_signingKeyActivationDelay_is_longer_than_keyRotationCheckInterval()
    {
        var versions = new[] { MakeVersion("v1", T0) };

        var act = () => KeyVaultSigningKeyRotation.BuildActivationTimeline(
            versions, signingKeyActivationDelay: TimeSpan.FromMinutes(10), keyRotationCheckInterval: TimeSpan.FromMinutes(5));

        act.Should().NotThrow();
    }
}
