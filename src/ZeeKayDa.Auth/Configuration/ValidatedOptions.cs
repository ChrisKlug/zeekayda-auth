using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// One options instance registered through <c>AddZeeKayDaOptions</c> or <c>ValidateWithZeeKayDa</c>,
/// validated with every other such instance so that the operator sees all of their failures at once.
/// </summary>
internal interface IValidatedOptions
{
    /// <summary>Reads the options, which runs every validator registered for them.</summary>
    void Read(IServiceProvider services);
}

/// <inheritdoc cref="IValidatedOptions"/>
internal sealed record ValidatedOptions<TOptions>(string Name) : IValidatedOptions
    where TOptions : class
{
    /// <inheritdoc/>
    public void Read(IServiceProvider services) =>
        _ = services.GetRequiredService<IOptionsMonitor<TOptions>>().Get(Name);
}

/// <summary>
/// Validates every <see cref="IValidatedOptions"/> and reports their failures in one
/// <see cref="ZeeKayDaConfigurationException"/>.
/// </summary>
/// <remarks>
/// <c>ValidateOnStart()</c> would stop at the first options type whose validator throws, so the
/// operator would meet a second type's failures only on the next start. Reading each type here and
/// collecting what it throws keeps them together.
/// </remarks>
internal static class ValidatedOptionsCheck
{
    /// <summary>
    /// Throws one <see cref="ZeeKayDaConfigurationException"/> holding every registered options
    /// type's failures, or returns when all of them are valid.
    /// </summary>
    public static void ThrowIfAnyInvalid(IServiceProvider services)
    {
        var failures = new List<ZeeKayDaConfigurationFailure>();
        var rootCauses = new List<Exception>();

        foreach (var options in services.GetServices<IValidatedOptions>())
        {
            try
            {
                options.Read(services);
            }
            catch (ZeeKayDaConfigurationException ex)
            {
                failures.AddRange(ex.AggregatedFailures);
                if (ex.InnerException is not null)
                    rootCauses.Add(ex.InnerException);
            }
            catch (OptionsValidationException ex)
            {
                failures.Add(Uncoded(ex));
                rootCauses.Add(ex);
            }
        }

        if (failures.Count == 0)
            return;

        throw rootCauses.Count switch
        {
            0 => new ZeeKayDaConfigurationException([.. failures]),
            1 => new ZeeKayDaConfigurationException(failures, rootCauses[0]),
            _ => new ZeeKayDaConfigurationException(failures, new AggregateException(rootCauses)),
        };
    }

    /// <summary>
    /// A validator that reports through <see cref="ValidateOptionsResult.Fail(string)"/> has no
    /// codes to give. Its text is not quoted: a failure message is public text the framework cannot
    /// vouch for, so it travels only in the inner exception.
    /// </summary>
    private static ZeeKayDaConfigurationFailure Uncoded(OptionsValidationException ex)
    {
        var options = string.IsNullOrEmpty(ex.OptionsName) || ex.OptionsName == Options.DefaultName
            ? ex.OptionsType.FullName
            : $"{ex.OptionsType.FullName} ('{ex.OptionsName}')";

        return new ZeeKayDaConfigurationFailure(
            "configuration.options_invalid",
            $"The options {options} failed {ex.Failures.Count()} validation rule(s) that report no " +
            "code. See the inner exception for the validator's own messages.");
    }
}
