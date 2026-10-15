using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Refuses a PBKDF2 iteration count outside 600,000–2,000,000: below it, secrets are too cheap to
/// brute-force; above it, every verification costs about a second and the token endpoint stops
/// serving under load.
/// </summary>
internal sealed class Pbkdf2ClientSecretHasherOptionsValidator
    : ZeeKayDaOptionsValidator<Pbkdf2ClientSecretHasherOptions>
{
    /// <inheritdoc/>
    protected override IEnumerable<ZeeKayDaConfigurationFailure> Validate(
        string? name,
        Pbkdf2ClientSecretHasherOptions options)
    {
        var iterations = options.Iterations;

        if (iterations < Pbkdf2ClientSecretHasher.MinIterations)
            yield return new(
                "configuration.pbkdf2.iterations_out_of_range",
                $"Pbkdf2ClientSecretHasherOptions.Iterations is {iterations:N0}, below the minimum of " +
                $"{Pbkdf2ClientSecretHasher.MinIterations:N0} (OWASP PBKDF2-HMAC-SHA256).");

        if (iterations > Pbkdf2ClientSecretHasher.MaxIterations)
            yield return new(
                "configuration.pbkdf2.iterations_out_of_range",
                $"Pbkdf2ClientSecretHasherOptions.Iterations is {iterations:N0}, above the maximum of " +
                $"{Pbkdf2ClientSecretHasher.MaxIterations:N0}. Each verification would take over a " +
                "second, and the token endpoint would stop serving under load.");
    }
}
