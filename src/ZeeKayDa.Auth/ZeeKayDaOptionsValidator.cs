using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth;

/// <summary>
/// A base for an options validator whose failures carry stable codes: the derived class returns
/// every failure it finds, and this class throws them together as one
/// <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <typeparam name="TOptions">The options type validated.</typeparam>
/// <remarks>
/// Register the options with <c>AddZeeKayDaOptions</c> or <c>ValidateWithZeeKayDa</c>, and these
/// failures are reported with every other registered options type's, in one exception. A
/// validator that returns <see cref="ValidateOptionsResult.Fail(string)"/> instead is reported
/// without codes, as <c>configuration.options_invalid</c>.
/// </remarks>
public abstract class ZeeKayDaOptionsValidator<TOptions> : IValidateOptions<TOptions>
    where TOptions : class
{
    /// <summary>
    /// Runs <see cref="Validate(string?, TOptions)"/>.
    /// </summary>
    /// <returns><see cref="ValidateOptionsResult.Success"/> when no failure was returned.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="ZeeKayDaConfigurationException">At least one failure was returned.</exception>
    ValidateOptionsResult IValidateOptions<TOptions>.Validate(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        ZeeKayDaConfigurationFailure[] failures = [.. Validate(name, options)];

        return failures.Length == 0
            ? ValidateOptionsResult.Success
            : throw new ZeeKayDaConfigurationException(failures);
    }

    /// <summary>Returns a failure, with its stable code, for every rule the options break.</summary>
    /// <param name="name">The options name, <see cref="Options.DefaultName"/> for unnamed options.</param>
    /// <param name="options">The options to validate.</param>
    /// <returns>
    /// Every failure, empty when the options are valid. Each message is public text, printed with
    /// the startup error, so it must never carry a secret or an exception's message.
    /// </returns>
    protected abstract IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, TOptions options);
}
