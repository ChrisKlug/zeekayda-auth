using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Resolves each registered provider's options once at startup, so that a provider whose options
/// fail validation — its own rules, or the framework's pins asserted by
/// <see cref="ProviderOptionsValidator{TOptions}"/> — fails the application before its first
/// sign-in rather than during it.
/// </summary>
/// <remarks>
/// <para>
/// An activator rather than a verifier, by the mechanical rule: resolving the options runs the
/// provider's and the host's own configuration code. The options type is read off the handler's
/// base chain, once, here; nothing on the request path uses reflection. A handler that does not
/// derive from <see cref="AuthenticationHandler{TOptions}"/> has no options object to pin, so
/// there is nothing to assert for it.
/// </para>
/// <para>
/// Every provider is checked even when an earlier one failed, and a failure surfaces only the
/// framework's own validation text: a provider's or a host's validator may put anything in a
/// message, so those travel as the root cause behind the failure, never inside it.
/// </para>
/// </remarks>
internal sealed class ProviderOptionsStartupActivator : IStartupActivator
{
    private readonly ProviderRegistry _registry;

    public ProviderOptionsStartupActivator(ProviderRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        _registry = registry;
    }

    /// <inheritdoc/>
    public string Name => "ProviderOptions";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(scopedServices);

        var failures = new List<ZeeKayDaConfigurationFailure>();
        var causes = new List<Exception>();

        foreach (var registration in _registry.Registrations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (HandlerOptions.TypeOf(registration.HandlerType) is not { } optionsType)
                continue;

            if (Resolve(scopedServices, optionsType, registration.Name) is { } failed)
            {
                failures.AddRange(failed.Failures);
                causes.Add(failed.Cause);
            }
        }

        // Thrown rather than added, so the root causes reach the operator alongside the codes:
        // the runner absorbs the failures verbatim and keeps the inner exception.
        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException(failures, causes.Count == 1 ? causes[0] : new AggregateException(causes));

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Resolves one provider's named options, returning <see langword="null"/> when they are
    /// valid and otherwise the failures to report with the exception behind them.
    /// </summary>
    private static (IReadOnlyList<ZeeKayDaConfigurationFailure> Failures, Exception Cause)? Resolve(
        IServiceProvider services,
        Type optionsType,
        string name)
    {
        try
        {
            HandlerOptions.Resolve(services, optionsType, name);
            return null;
        }
        catch (OptionsValidationException ex)
        {
            return ([new ZeeKayDaConfigurationFailure("provider.options_invalid", Describe(name, ex))], ex);
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // A well-formed failure from a provider's or a host's own configuration code keeps
            // its stable codes; re-classifying it would flatten what an operator alerts on.
            return (ex.AggregatedFailures, ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (
                [
                    new ZeeKayDaConfigurationFailure(
                        "provider.options_invalid",
                        $"The options for provider '{name}' could not be resolved: {ex.GetType().FullName} " +
                        "was thrown. See the inner exception for the root cause."),
                ],
                ex);
        }
    }

    /// <summary>
    /// Names the provider and repeats only the framework's own pin assertions; whatever else the
    /// provider's or the host's validators said is counted, and travels as the root cause.
    /// </summary>
    private static string Describe(string name, OptionsValidationException ex)
    {
        var pinned = ex.Failures
            .Where(failure => failure.StartsWith(ProviderOptionsValidator<AuthenticationSchemeOptions>.FailurePrefix, StringComparison.Ordinal))
            .Select(failure => failure[ProviderOptionsValidator<AuthenticationSchemeOptions>.FailurePrefix.Length..])
            .ToArray();
        var others = ex.Failures.Count() - pinned.Length;

        var message = $"The options for provider '{name}' are not valid.";
        if (pinned.Length > 0)
            message += " " + string.Join(" ", pinned);
        if (others > 0)
            message += $" {others} further validation failure(s) came from the provider's or the host's own rules; see the inner exception.";

        return message;
    }
}
