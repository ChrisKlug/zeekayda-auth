using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates <see cref="JwtSigningServiceOptions"/> at startup to ensure the key-cache
/// refresh interval is positive before the host begins accepting requests.
/// </summary>
/// <remarks>
/// This validator is registered via <c>AddDevelopmentJwtSigningKeys()</c> and activated by
/// <c>ValidateOnStart()</c> so that a zero or negative <see cref="JwtSigningServiceOptions.RefreshInterval"/>
/// fails loudly at startup rather than silently defeating the caching design at request time.
/// </remarks>
internal sealed class JwtSigningServiceOptionsValidator : IValidateOptions<DevelopmentSigningKeyOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, DevelopmentSigningKeyOptions options)
    {
        if (options.RefreshInterval <= TimeSpan.Zero)
            return ValidateOptionsResult.Fail(
                "JwtSigningServiceOptions.RefreshInterval must be positive. " +
                "A zero or negative value would invoke LoadKeysAsync on every request, " +
                "defeating the caching design entirely.");

        return ValidateOptionsResult.Success;
    }
}
