using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates that <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>
/// does not contain <c>"Production"</c> or null/empty entries.
/// Registered only when <c>AddDevelopmentJwtSigningKeys()</c> is called.
/// </summary>
internal sealed class AllowedDevEnvironmentsValidator : IValidateOptions<DevelopmentSigningKeyOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, DevelopmentSigningKeyOptions options)
    {
        var list = options.AllowedDevelopmentJwtSigningKeysEnvironments;
        var errors = new List<string>();

        foreach (var entry in list)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                errors.Add(
                    "DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments " +
                    "must not contain null or empty entries.");
                continue;
            }

            if (string.Equals(entry, "Production", StringComparison.OrdinalIgnoreCase))
            {
                errors.Add(
                    "DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments " +
                    "must not contain 'Production'. Development signing keys are never permitted in " +
                    "Production regardless of this list. Listing 'Production' here is a misconfiguration.");
            }
        }

        return errors.Count > 0 ? ValidateOptionsResult.Fail(errors) : ValidateOptionsResult.Success;
    }
}
