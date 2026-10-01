using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

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
        catch (Exception ex) when (OptionsFailures.ValidationFailure(ex) is { } failure)
        {
            if (!RecordEachValidator(services, failures))
                failures.Record(failure);
        }
    }

    /// <summary>
    /// Runs every validator on its own; whether any of them failed. False as well when the options
    /// cannot even be built, so the caller reports the first read's failure.
    /// </summary>
    private bool RecordEachValidator(IServiceProvider services, OptionsFailures failures)
    {
        TOptions options;
        try
        {
            options = new OptionsFactory<TOptions>(
                services.GetServices<IConfigureOptions<TOptions>>(),
                services.GetServices<IPostConfigureOptions<TOptions>>(),
                []).Create(Name);
        }
        catch (Exception ex) when (OptionsFailures.ValidationFailure(ex) is not null)
        {
            return false;
        }

        var anyFailed = false;
        foreach (var validator in services.GetServices<IValidateOptions<TOptions>>())
            anyFailed |= failures.Record(Name, options, validator);

        return anyFailed;
    }
}
