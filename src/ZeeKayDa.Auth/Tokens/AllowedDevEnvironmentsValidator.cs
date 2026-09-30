using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates that <see cref="DevelopmentSigningOptions.AllowedEnvironments"/>
/// does not contain <c>"Production"</c> or null/empty entries.
/// Registered only when <c>AddInMemoryDevelopmentSigning()</c> or
/// <c>AddPersistedDevelopmentSigning()</c> is called.
/// </summary>
internal sealed class AllowedDevEnvironmentsValidator : IValidateOptions<DevelopmentSigningOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, DevelopmentSigningOptions options)
    {
        var list = options.AllowedEnvironments;
        var failures = new List<ZeeKayDaConfigurationFailure>();

        if (list.Count == 0)
        {
            failures.Add(new(
                "configuration.development_signing.allowed_environments.empty",
                "DevelopmentSigningOptions.AllowedEnvironments must name at least one environment. " +
                "An empty list refuses every environment, Development included."));
        }

        foreach (var entry in list)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                failures.Add(new(
                    "configuration.development_signing.allowed_environments.blank_entry",
                    "DevelopmentSigningOptions.AllowedEnvironments " +
                    "must not contain null or empty entries."));
                continue;
            }

            if (string.Equals(entry, "Production", StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(new(
                    "configuration.development_signing.allowed_environments.contains_production",
                    "DevelopmentSigningOptions.AllowedEnvironments " +
                    "must not contain 'Production'. Development signing keys are never permitted in " +
                    "Production regardless of this list. Listing 'Production' here is a misconfiguration."));
            }
        }

        return failures.ThrowIfAny();
    }
}
