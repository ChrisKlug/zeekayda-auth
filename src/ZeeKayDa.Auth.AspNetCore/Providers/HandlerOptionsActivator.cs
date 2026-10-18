using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Resolves every provider's options at startup, so invalid ones — including drift from
/// <see cref="HandlerOptionsValidator{TOptions}"/>'s pins — fail before the first sign-in, and warns
/// for an OAuth provider whose code has no injection protection on the upstream leg.
/// </summary>
/// <remarks>
/// An activator, since resolving options runs provider and host code. Failures quote only the
/// framework's own text; other validators' messages travel as the inner exception.
/// </remarks>
internal sealed class HandlerOptionsActivator(
    ProviderRegistry registry,
    PinnedOptionDriftRecorder recorder,
    IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ProviderOptions";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var failures = new List<ZeeKayDaConfigurationFailure>();
        var causes = new List<Exception>();

        foreach (var registration in registry.Registrations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (HandlerOptions.TypeOf(registration.HandlerType) is not { } optionsType)
                continue;

            if (Resolve(optionsType, registration.Name, out var options) is { } failed)
            {
                failures.AddRange(failed.Failures);
                causes.Add(failed.Cause);
            }
            else if (options is OAuthOptions { UsePkce: false })
            {
                WarnNoCodeInjectionProtection(context, registration.Name);
            }
        }

        // Thrown rather than added, so the root causes travel as the inner exception.
        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException(failures, causes.Count == 1 ? causes[0] : new AggregateException(causes));

        return Task.CompletedTask;
    }

    /// <summary>
    /// Resolves one provider's options: <see langword="null"/> and the options when valid, else the
    /// failures and their cause.
    /// </summary>
    private (IReadOnlyList<ZeeKayDaConfigurationFailure> Failures, Exception Cause)? Resolve(
        Type optionsType,
        string name,
        out object? options)
    {
        // So a resolution that throws before the framework's validator runs reports no stale drift.
        recorder.Clear(name, optionsType);
        options = null;

        try
        {
            options = HandlerOptions.Resolve(services, optionsType, name);
            return null;
        }
        catch (OptionsValidationException ex)
        {
            return ([new ZeeKayDaConfigurationFailure("provider.options_invalid", Describe(name, optionsType, ex))], ex);
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // Keeps its own stable codes, which an operator may alert on.
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

    /// <summary>RFC 9700 §2.1.1 requires code-injection protection on the upstream leg; with no nonce, an OAuth handler has only PKCE.</summary>
    private static void WarnNoCodeInjectionProtection(StartupVerificationContext context, string name) =>
        context.AddWarning(
            "provider.no_code_injection_protection",
            "The provider '{Provider}' is an OAuth provider with UsePkce set to false, so the " +
            "authorization code it returns is not protected against code injection (RFC 9700 " +
            "section 2.1.1). Set UsePkce to true unless the provider cannot accept PKCE.",
            name);

    /// <summary>
    /// Quotes only the drifts <see cref="PinnedOptionDriftRecorder"/> holds, never text recognised in
    /// <see cref="OptionsValidationException.Failures"/>, which any validator writes; others are counted.
    /// </summary>
    private string Describe(string name, Type optionsType, OptionsValidationException ex)
    {
        var pinned = recorder.DriftsFor(name, optionsType);
        var others = Math.Max(0, ex.Failures.Count() - pinned.Count);

        var message = $"The options for provider '{name}' are not valid.";
        if (pinned.Count > 0)
        {
            message += $" The options for provider '{name}' were changed after the framework " +
                $"pinned them: {string.Join(" ", pinned.Select(drift => drift.Describe()))} The " +
                "framework owns these members; remove the configuration that sets them.";
        }

        if (others > 0)
            message += $" {others} further validation failure(s) came from the provider's or the host's own rules; see the inner exception.";

        return message;
    }
}
