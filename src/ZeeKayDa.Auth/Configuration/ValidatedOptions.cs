using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// One options instance registered through <c>AddZeeKayDaOptions</c> or <c>ValidateWithZeeKayDa</c>,
/// validated with every other such instance so that the operator sees all of their failures at once.
/// </summary>
internal interface IValidatedOptions
{
    /// <summary>Runs every validator registered for the options, recording what each reports.</summary>
    void Validate(IServiceProvider services, OptionsFailures failures);
}

/// <inheritdoc cref="IValidatedOptions"/>
/// <remarks>
/// The options are built without validators and each validator is then run on its own. Reading
/// them through <see cref="IOptionsMonitor{TOptions}"/> would stop at the first validator that
/// throws, and a second validator's failures would wait for the next start.
/// </remarks>
internal sealed record ValidatedOptions<TOptions>(string Name) : IValidatedOptions
    where TOptions : class
{
    /// <inheritdoc/>
    public void Validate(IServiceProvider services, OptionsFailures failures)
    {
        var options = new OptionsFactory<TOptions>(
            services.GetServices<IConfigureOptions<TOptions>>(),
            services.GetServices<IPostConfigureOptions<TOptions>>(),
            []).Create(Name);

        foreach (var validator in services.GetServices<IValidateOptions<TOptions>>())
            failures.Record(Name, options, validator);
    }
}

/// <summary>What the validators of every <see cref="IValidatedOptions"/> reported.</summary>
internal sealed class OptionsFailures
{
    private readonly List<ZeeKayDaConfigurationFailure> _failures = [];
    private readonly List<Exception> _rootCauses = [];

    /// <summary>Runs one validator and records its failures, coded or not.</summary>
    public void Record<TOptions>(string name, TOptions options, IValidateOptions<TOptions> validator)
        where TOptions : class
    {
        try
        {
            var result = validator.Validate(name, options);
            if (result.Failed)
                RecordUncoded(new OptionsValidationException(name, typeof(TOptions), result.Failures));
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            _failures.AddRange(ex.AggregatedFailures);
            if (ex.InnerException is not null)
                _rootCauses.Add(ex.InnerException);
        }
        catch (OptionsValidationException ex)
        {
            RecordUncoded(ex);
        }
    }

    /// <summary>
    /// Throws one <see cref="ZeeKayDaConfigurationException"/> holding every recorded failure, or
    /// returns when there are none.
    /// </summary>
    public void ThrowIfAny()
    {
        if (_failures.Count == 0)
            return;

        throw _rootCauses.Count switch
        {
            0 => new ZeeKayDaConfigurationException([.. _failures]),
            1 => new ZeeKayDaConfigurationException(_failures, _rootCauses[0]),
            _ => new ZeeKayDaConfigurationException(_failures, new AggregateException(_rootCauses)),
        };
    }

    /// <summary>
    /// A validator that reports through <see cref="ValidateOptionsResult.Fail(string)"/> has no
    /// codes to give. Its text is not quoted: a failure message is public text the framework cannot
    /// vouch for, so it travels only in the inner exception.
    /// </summary>
    private void RecordUncoded(OptionsValidationException ex)
    {
        var options = string.IsNullOrEmpty(ex.OptionsName) || ex.OptionsName == Options.DefaultName
            ? ex.OptionsType.FullName
            : $"{ex.OptionsType.FullName} ('{ex.OptionsName}')";

        _failures.Add(new ZeeKayDaConfigurationFailure(
            "configuration.options_invalid",
            $"The options {options} failed {ex.Failures.Count()} validation rule(s) that report no " +
            "code. See the inner exception for the validator's own messages."));
        _rootCauses.Add(ex);
    }
}

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
