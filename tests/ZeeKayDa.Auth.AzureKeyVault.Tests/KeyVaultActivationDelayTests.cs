namespace ZeeKayDa.Auth.AzureKeyVault.Tests;

/// <summary>
/// Exercises <see cref="KeyVaultActivationDelay"/> — the shared resolve/validate helper for
/// <c>SigningKeyActivationDelay</c>, used by both Key Vault signing providers (ADR 0011 §3.5, issue
/// #409/#413).
/// </summary>
public sealed class KeyVaultActivationDelayTests
{
    // ── Resolve ───────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Resolve_returns_KeyRotationCheckInterval_when_SigningKeyActivationDelay_is_unset()
    {
        var keyRotationCheckInterval = TimeSpan.FromMinutes(5);

        var resolved = KeyVaultActivationDelay.Resolve(null, keyRotationCheckInterval);

        resolved.Should().Be(keyRotationCheckInterval,
            "when unset, the effective activation delay must fall back to KeyRotationCheckInterval");
    }

    [Fact]
    public void Resolve_returns_the_explicit_SigningKeyActivationDelay_when_set()
    {
        var keyRotationCheckInterval = TimeSpan.FromMinutes(5);
        var signingKeyActivationDelay = TimeSpan.FromMinutes(15);

        var resolved = KeyVaultActivationDelay.Resolve(signingKeyActivationDelay, keyRotationCheckInterval);

        resolved.Should().Be(signingKeyActivationDelay,
            "an explicit SigningKeyActivationDelay must win over the KeyRotationCheckInterval default");
    }

    // ── ValidateNotShorterThanCheckInterval ──────────────────────────────────────────────────────────

    [Fact]
    public void ValidateNotShorterThanCheckInterval_returns_null_when_SigningKeyActivationDelay_is_unset()
    {
        var error = KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval(
            "AzureKeyVaultCachedSigningOptions", null, TimeSpan.FromMinutes(5));

        error.Should().BeNull("an unset SigningKeyActivationDelay defers entirely to KeyRotationCheckInterval, so there is nothing to reject");
    }

    [Fact]
    public void ValidateNotShorterThanCheckInterval_returns_null_when_SigningKeyActivationDelay_equals_the_check_interval()
    {
        var interval = TimeSpan.FromMinutes(5);

        var error = KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval(
            "AzureKeyVaultCachedSigningOptions", interval, interval);

        error.Should().BeNull("equal to the floor is still valid — only strictly shorter is rejected");
    }

    [Fact]
    public void ValidateNotShorterThanCheckInterval_returns_null_when_SigningKeyActivationDelay_is_longer_than_the_check_interval()
    {
        var error = KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval(
            "AzureKeyVaultCachedSigningOptions", TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(5));

        error.Should().BeNull();
    }

    [Fact]
    public void ValidateNotShorterThanCheckInterval_returns_an_error_when_SigningKeyActivationDelay_is_shorter_than_the_check_interval()
    {
        var error = KeyVaultActivationDelay.ValidateNotShorterThanCheckInterval(
            "AzureKeyVaultCachedSigningOptions", TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5));

        error.Should().NotBeNull();
        error.Should().Contain("AzureKeyVaultCachedSigningOptions");
        error.Should().Contain("SigningKeyActivationDelay");
        error.Should().Contain("KeyRotationCheckInterval");
    }
}
