using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates <see cref="DevelopmentSigningKeyOptions"/> at startup to ensure the key source stays
/// in static-source mode (<see langword="null"/>) before the host begins accepting requests.
/// </summary>
/// <remarks>
/// This validator is registered via <c>AddInMemoryDevelopmentJwtSigningKeys()</c> or
/// <c>AddPersistedDevelopmentJwtSigningKeys()</c> and activated by
/// <c>ValidateOnStart()</c>. Development signing keys are memoized for the process lifetime and
/// cannot be rotated; a finite <see cref="JwtSigningServiceOptions.KeySourceRefreshInterval"/> would cause
/// the base class to dispose the memoized <see cref="SigningKeySet"/> on cache expiry and then
/// attempt to re-borrow from the already-disposed set, resulting in an
/// <see cref="ObjectDisposedException"/>.
/// </remarks>
internal sealed class DevelopmentSigningKeyOptionsValidator : IValidateOptions<DevelopmentSigningKeyOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, DevelopmentSigningKeyOptions options)
    {
        if (options.KeySourceRefreshInterval is not null)
            return ValidateOptionsResult.Fail(
                "DevelopmentSigningKeyOptions.KeySourceRefreshInterval must be null (static-source mode). " +
                "Development signing keys are memoized for the process lifetime and cannot be rotated. " +
                "Setting a finite KeySourceRefreshInterval would cause the base class to dispose the memoized " +
                "SigningKeySet and attempt to reload it, resulting in an ObjectDisposedException.");

        return ValidateOptionsResult.Success;
    }
}
