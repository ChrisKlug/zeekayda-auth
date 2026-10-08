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

        // An unlisted key's signer is disposed a read after it leaves the list, so the interval is also
        // how long a sign call already under way has; a read gets a minute before it is abandoned.
        if (signingKeys.RefreshInterval < SigningKeyOptions.MinimumRefreshInterval)
        {
            yield return new(
                "configuration.signing_keys.refresh_interval.below_minimum",
                $"AuthorizationServerOptions.SigningKeys.RefreshInterval must be at least {SigningKeyOptions.MinimumRefreshInterval}.");
        }

        if (signingKeys.RetainRetiredKeysFor < TimeSpan.Zero)
        {
            yield return new(
                "configuration.signing_keys.retain_retired_keys_for.negative",
                "AuthorizationServerOptions.SigningKeys.RetainRetiredKeysFor must not be negative.");
        }
    }
}
