using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <inheritdoc cref="IValidatedOptions"/>
/// <remarks>
/// Read through <see cref="IOptionsMonitor{TOptions}"/>, as the application reads them. That read
/// stops at the first failing validator, so on failure each validator runs again on its own.
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

    /// <summary>Runs every validator on its own; whether any failed, false when the options cannot be built.</summary>
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
