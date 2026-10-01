using System.Reflection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>What the validators of every <see cref="IValidatedOptions"/> reported.</summary>
internal sealed class OptionsFailures
{
    private readonly List<ZeeKayDaConfigurationFailure> _failures = [];
    private readonly List<Exception> _rootCauses = [];

    /// <summary>Runs one validator and records its failures, coded or not; whether it failed.</summary>
    public bool Record<TOptions>(string name, TOptions options, IValidateOptions<TOptions> validator)
        where TOptions : class
    {
        try
        {
            var result = validator.Validate(name, options);
            if (!result.Failed)
                return false;

            RecordUncoded(new OptionsValidationException(name, typeof(TOptions), result.Failures));
        }
        catch (Exception ex) when (ValidationFailure(ex) is { } failure)
        {
            Record(failure);
        }

        return true;
    }

    /// <summary>
    /// The validation failure an exception carries, or <see langword="null"/> for any other
    /// exception: the exception itself, or the one a reflection call wrapped, as when the
    /// configuration binder sets a frozen collection.
    /// </summary>
    public static Exception? ValidationFailure(Exception ex)
    {
        var candidate = ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;
        return candidate is ZeeKayDaConfigurationException or OptionsValidationException ? candidate : null;
    }

    /// <summary>Records a validation exception: a coded one keeps its codes, any other is uncoded.</summary>
    public void Record(Exception validationException)
    {
        if (validationException is not ZeeKayDaConfigurationException coded)
        {
            RecordUncoded((OptionsValidationException)validationException);
            return;
        }

        _failures.AddRange(coded.AggregatedFailures);
        if (coded.InnerException is not null)
            _rootCauses.Add(coded.InnerException);
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
