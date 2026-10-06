namespace ZeeKayDa.Auth.Tokens;

internal static class SigningKeyOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this SigningKeyOptions signingKeys)
    {
        // There is no lead-time-zero escape hatch: a key signing the instant it is listed is exactly
        // what a relying party with a cached key set cannot verify.
        if (signingKeys.LeadTime <= TimeSpan.Zero)
        {
            yield return new(
                "configuration.signing_keys.lead_time.not_positive",
                "AuthorizationServerOptions.SigningKeys.LeadTime must be greater than zero.");
        }

        if (signingKeys.RetainRetiredKeysFor < TimeSpan.Zero)
        {
            yield return new(
                "configuration.signing_keys.retain_retired_keys_for.negative",
                "AuthorizationServerOptions.SigningKeys.RetainRetiredKeysFor must not be negative.");
        }
    }
}
