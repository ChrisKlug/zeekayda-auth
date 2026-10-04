namespace ZeeKayDa.Auth.Tokens;

internal static class IdTokenOptionsValidation
{
    /// <summary>
    /// Null is the default and means "advertise the whole published key set"; an empty filter would
    /// advertise nothing at all, which is never what an operator means. A filter that excludes the
    /// signing key's own algorithm is caught by <c>SigningKeyRingActivator</c>, the first point at
    /// which the key set exists.
    /// </summary>
    internal static IEnumerable<ZeeKayDaConfigurationFailure> Validate(this IdTokenOptions idToken)
    {
        if (idToken.AdvertisedSigningAlgorithms is { Count: 0 })
        {
            yield return new(
                "configuration.id_token.advertised_signing_algorithms.empty",
                "AuthorizationServerOptions.IdToken.AdvertisedSigningAlgorithms is an empty set, which " +
                "would advertise no ID token signing algorithm at all. Name at least one algorithm, or " +
                "set it to null to advertise every algorithm in the published signing key set.");
        }
    }
}
