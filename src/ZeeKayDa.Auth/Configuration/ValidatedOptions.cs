using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <inheritdoc cref="IValidatedOptions"/>
/// <remarks>
/// The options are read the way every consumer reads them, through
/// <see cref="IOptionsMonitor{TOptions}"/>, so what passes here is the instance the application
/// uses. That read stops at the first validator that throws, so on a failure each validator is run
/// again on its own to find every failure, and only if that finds none (a host's own options
/// factory, say) is the first read's exception reported as it was.
/// </remarks>
internal sealed record ValidatedOptions<TOptions>(string Name) : IValidatedOptions
    where TOptions : class
{
    /// <inheritdoc/>
    public void Validate(IServiceProvider services, OptionsFailures failures)
    {
        try
        {
            _ = services.GetRequiredService<IOptionsMonitor<TOptions>>().Get(Name);
        }
        catch (Exception ex) when (ex is ZeeKayDaConfigurationException or OptionsValidationException)
        {
            if (!RecordEachValidator(services, failures))
                failures.Record(ex);
        }
    }

    /// <summary>Runs every validator on its own; whether any of them failed.</summary>
    private bool RecordEachValidator(IServiceProvider services, OptionsFailures failures)
    {
        var options = new OptionsFactory<TOptions>(
            services.GetServices<IConfigureOptions<TOptions>>(),
            services.GetServices<IPostConfigureOptions<TOptions>>(),
            []).Create(Name);

        var anyFailed = false;
        foreach (var validator in services.GetServices<IValidateOptions<TOptions>>())
            anyFailed |= failures.Record(Name, options, validator);

        return anyFailed;
    }
}
