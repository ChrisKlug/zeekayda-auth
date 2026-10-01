using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Validates every <see cref="IValidatedOptions"/> and reports their failures in one
/// <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <remarks>
/// <c>ValidateOnStart()</c> would stop at the first options type whose validator throws, so the
/// operator would meet a second type's failures only on the next start.
/// </remarks>
internal static class ValidatedOptionsCheck
{
    /// <summary>
    /// Throws one <see cref="ZeeKayDaConfigurationException"/> holding every registered options
    /// type's failures, or returns when all of them are valid.
    /// </summary>
    public static void ThrowIfAnyInvalid(IServiceProvider services)
    {
        var failures = new OptionsFailures();

        foreach (var options in services.GetServices<IValidatedOptions>())
            options.Validate(services, failures);

        failures.ThrowIfAny();
    }
}
