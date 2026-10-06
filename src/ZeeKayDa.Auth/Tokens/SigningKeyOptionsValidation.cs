namespace ZeeKayDa.Auth.Tokens;

internal static class SigningKeyOptionsValidation
{
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this SigningKeyOptions signingKeys)
    {
        if (signingKeys.RetainRetiredKeysFor < TimeSpan.Zero)
        {
            yield return new(
                "configuration.signing_keys.retain_retired_keys_for.negative",
                "AuthorizationServerOptions.SigningKeys.RetainRetiredKeysFor must not be negative.");
        }
    }
}
