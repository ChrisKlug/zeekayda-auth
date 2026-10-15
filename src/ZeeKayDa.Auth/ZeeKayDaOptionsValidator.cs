using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth;

/// <summary>
/// A base for an options validator whose failures carry stable codes: the derived class returns
/// every failure, and this class throws them as one <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <typeparam name="TOptions">The options type validated.</typeparam>
/// <remarks>
/// Register the options with <c>AddZeeKayDaOptions</c> or <c>ValidateWithZeeKayDa</c> so the failures
/// are reported with every other options type's.
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

        var returned = Validate(name, options)?.ToArray();

        // A null result is reported as a failure alongside the real ones, not as a NullReferenceException.
        ZeeKayDaConfigurationFailure[] failures = returned is null || returned.Any(failure => failure is null)
            ? [.. (returned ?? []).OfType<ZeeKayDaConfigurationFailure>(), MalformedResult()]
            : returned;

        return failures.Length == 0
            ? ValidateOptionsResult.Success
            : throw new ZeeKayDaConfigurationException(failures);
    }

    private ZeeKayDaConfigurationFailure MalformedResult() => new(
        "configuration.options_validator.malformed_result",
        $"The options validator '{GetType().FullName}' returned a null list or a null failure " +
        $"for {typeof(TOptions).FullName}. Return an empty sequence for valid options.");

    /// <summary>Returns a failure, with its stable code, for every rule the options break.</summary>
    /// <param name="name">The options name, <see cref="Options.DefaultName"/> for unnamed options.</param>
    /// <param name="options">The options to validate.</param>
    /// <returns>
    /// Every failure, empty when the options are valid. Each message is public text, printed with
    /// the startup error, so it must never carry a secret or an exception's message.
    /// </returns>
    protected abstract IEnumerable<ZeeKayDaConfigurationFailure> Validate(string? name, TOptions options);
}
