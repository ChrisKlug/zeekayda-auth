using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// Validates every <see cref="IValidatedOptions"/> together, where <c>ValidateOnStart()</c> would stop at the first.
/// </summary>
internal static class ValidatedOptionsCheck
{
    /// <summary>Throws one exception holding every options type's failures, if there are any.</summary>
    public static void ThrowIfAnyInvalid(IServiceProvider services)
    {
        var failures = new OptionsFailures();

        foreach (var options in services.GetServices<IValidatedOptions>())
            options.Validate(services, failures);

        failures.ThrowIfAny();
    }
}
