namespace ZeeKayDa.Auth.Tokens;

internal static class DevelopmentSigningKeyGate
{
    internal const string ProductionFailureCode = "signing.dev_keys.production_environment";

    internal const string ProductionFailureMessage =
        "Development signing keys are active in a Production environment. " +
        "AllowedEnvironments cannot include the Production environment. " +
        "Development keys are ephemeral or stored in a local file and are not suitable for production. " +
        "Replace AddInMemoryDevelopmentSigning()/AddPersistedDevelopmentSigning() with " +
        "a production key provider.";

    internal const string NonDevelopmentFailureCode = "signing.dev_keys.non_development";

    internal const string UnknownEnvironmentFailureCode = "signing.dev_keys.unknown_environment";

    internal const string UnknownEnvironmentFailureMessage =
        "Development signing keys cannot tell which host environment they are running in, so they " +
        "refuse to sign. Register them through AddInMemoryDevelopmentSigning() or " +
        "AddPersistedDevelopmentSigning(), which read the environment from IHostEnvironment.";

    internal static string BuildNonDevelopmentFailureMessage(string environmentName) =>
        $"Development signing keys are active in environment '{environmentName}', " +
        "which is not in AllowedEnvironments. " +
        "This is a configuration error: development keys are ephemeral or stored in a " +
        "local file and are not suitable for production. " +
        "Replace AddInMemoryDevelopmentSigning()/AddPersistedDevelopmentSigning() " +
        "with a production key provider, or add the environment name to " +
        "AllowedEnvironments if this is an intentional non-Development " +
        "test host (e.g. an integration test host).";

    /// <summary>
    /// Enforces the environment gate. An unknown (<see langword="null"/>) environment fails closed,
    /// and Production always throws regardless of <paramref name="allowedEnvironments"/>.
    /// </summary>
    internal static void Enforce(string? environmentName, IReadOnlyList<string> allowedEnvironments)
    {
        if (environmentName is null)
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(UnknownEnvironmentFailureCode, UnknownEnvironmentFailureMessage));

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
