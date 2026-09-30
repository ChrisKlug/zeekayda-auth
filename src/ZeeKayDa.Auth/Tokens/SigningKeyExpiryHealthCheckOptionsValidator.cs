using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates <see cref="SigningKeyExpiryHealthCheckOptions"/> at startup.
/// </summary>
/// <remarks>
/// Registered via <c>AddZeeKayDaSigningKeys()</c>, whose options are registered with <c>AddZeeKayDaOptions</c>.
/// </remarks>
internal sealed class SigningKeyExpiryHealthCheckOptionsValidator : ZeeKayDaOptionsValidator<SigningKeyExpiryHealthCheckOptions>
{
    /// <inheritdoc/>
    protected override void Validate(
        string? name,
        SigningKeyExpiryHealthCheckOptions options,
        ICollection<ZeeKayDaConfigurationFailure> failures)
    {
        if (options.DegradedThreshold <= TimeSpan.Zero)
        {
            failures.Add(new(
                "configuration.signing_key_expiry_health_check.degraded_threshold.not_positive",
                $"SigningKeyExpiryHealthCheckOptions.DegradedThreshold ({options.DegradedThreshold}) " +
                "must be greater than zero. A zero or negative threshold silently disables the only " +
                "expiry watch a static signing key ring has."));
        }
    }
}
