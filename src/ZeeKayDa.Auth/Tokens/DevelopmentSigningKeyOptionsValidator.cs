using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Validates <see cref="DevelopmentSigningKeyOptions"/> at startup to ensure the key-cache
/// refresh interval is <see cref="TimeSpan.MaxValue"/> before the host begins accepting requests.
/// </summary>
/// <remarks>
/// This validator is registered via <c>AddDevelopmentJwtSigningKeys()</c> and activated by
/// <c>ValidateOnStart()</c>. Development signing keys are memoized for the process lifetime and
/// cannot be rotated; a finite <see cref="JwtSigningServiceOptions.RefreshInterval"/> would cause
/// the base class to dispose the memoized <see cref="SigningKeySet"/> on cache expiry and then
/// attempt to re-borrow from the already-disposed set, resulting in an
/// <see cref="ObjectDisposedException"/>.
/// </remarks>
internal sealed class DevelopmentSigningKeyOptionsValidator : IValidateOptions<DevelopmentSigningKeyOptions>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, DevelopmentSigningKeyOptions options)
    {
        if (options.RefreshInterval != TimeSpan.MaxValue)
            return ValidateOptionsResult.Fail(
                "DevelopmentSigningKeyOptions.RefreshInterval must be TimeSpan.MaxValue. " +
                "Development signing keys are memoized for the process lifetime and cannot be rotated. " +
                "Setting a finite RefreshInterval would cause the base class to dispose the memoized " +
                "SigningKeySet and attempt to reload it, resulting in an ObjectDisposedException.");

        return ValidateOptionsResult.Success;
    }
}
