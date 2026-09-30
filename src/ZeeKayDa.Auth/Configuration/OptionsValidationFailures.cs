using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Ends a framework options validator: its failures leave as a
/// <see cref="ZeeKayDaConfigurationException"/>, the same coded shape as every other startup failure.
/// </summary>
/// <remarks>
/// The options factory and <c>ValidateOnStart()</c> let an exception thrown from
/// <see cref="IValidateOptions{TOptions}.Validate"/> through unchanged, so the operator sees the same
/// codes wherever the options are first read. A returned <see cref="ValidateOptionsResult.Fail(string)"/>
/// would reach them as an <see cref="OptionsValidationException"/>, which carries text but no codes.
/// </remarks>
internal static class OptionsValidationFailures
{
    /// <summary>
    /// Throws every failure in one <see cref="ZeeKayDaConfigurationException"/>, or returns
    /// <see cref="ValidateOptionsResult.Success"/> when there are none.
    /// </summary>
    public static ValidateOptionsResult ThrowIfAny(this List<ZeeKayDaConfigurationFailure> failures) =>
        failures.Count == 0
            ? ValidateOptionsResult.Success
            : throw new ZeeKayDaConfigurationException([.. failures]);
}
