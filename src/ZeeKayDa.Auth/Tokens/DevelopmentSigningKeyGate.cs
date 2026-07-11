namespace ZeeKayDa.Auth.Tokens;

internal static class DevelopmentSigningKeyGate
{
    internal const string ProductionFailureCode = "signing.dev_keys.production_environment";

    internal const string ProductionFailureMessage =
        "Development signing keys are active in a Production environment. " +
        "AllowedDevelopmentJwtSigningKeysEnvironments cannot include the Production environment. " +
        "Development keys are ephemeral or stored in a local file and are not suitable for production. " +
        "Replace AddInMemoryDevelopmentJwtSigningKeys()/AddPersistedDevelopmentJwtSigningKeys() with " +
        "a production key provider.";

    internal const string NonDevelopmentFailureCode = "signing.dev_keys.non_development";

    internal static string BuildNonDevelopmentFailureMessage(string environmentName) =>
        $"Development signing keys are active in environment '{environmentName}', " +
        "which is not in AllowedDevelopmentJwtSigningKeysEnvironments. " +
        "This is a configuration error: development keys are ephemeral or stored in a " +
        "local file and are not suitable for production. " +
        "Replace AddInMemoryDevelopmentJwtSigningKeys()/AddPersistedDevelopmentJwtSigningKeys() " +
        "with a production key provider, or add the environment name to " +
        "AllowedDevelopmentJwtSigningKeysEnvironments if this is an intentional non-Development " +
        "test host (e.g. an integration test host).";

    /// <summary>
    /// Enforces the environment gate. No-op when <paramref name="environmentName"/> is
    /// <see langword="null"/> (unit-test or no-host scenario — gate deliberately skipped).
    /// Production always throws regardless of <paramref name="allowedEnvironments"/>.
    /// </summary>
    internal static void Enforce(string? environmentName, IReadOnlyList<string> allowedEnvironments)
    {
        if (environmentName is null)
            return;

        if (string.Equals(environmentName, "Production", StringComparison.OrdinalIgnoreCase))
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(ProductionFailureCode, ProductionFailureMessage));

        var isAllowed = allowedEnvironments.Any(e =>
            string.Equals(e, environmentName, StringComparison.OrdinalIgnoreCase));

        if (!isAllowed)
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    NonDevelopmentFailureCode,
                    BuildNonDevelopmentFailureMessage(environmentName)));
    }
}
