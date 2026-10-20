using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Resolves every provider's options at startup, so invalid ones — including drift from
/// <see cref="HandlerOptionsValidator{TOptions}"/>'s pins — fail before the first sign-in. An OAuth
/// provider must name its issuer, and is warned about when its code has no injection protection on
/// the upstream leg. OAuth providers sharing a <c>ClaimsIssuer</c> must share an upstream.
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
        var oauthProviders = new List<OAuthProvider>();

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
            else if (options is OAuthOptions oauth)
            {
                oauthProviders.Add(new OAuthProvider(registration.Name, oauth));
            }
        }

        failures.AddRange(VerifyOAuth(context, oauthProviders));

        // Thrown rather than added, so the root causes travel as the inner exception.
        if (failures.Count > 0)
            throw ZeeKayDaConfigurationException.WithRootCauses(failures, causes);

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

    /// <summary>
    /// Warns about each OAuth provider without PKCE; the failures for each with no <c>ClaimsIssuer</c>,
    /// and for each <c>ClaimsIssuer</c> shared across token endpoints.
    /// </summary>
    private static IEnumerable<ZeeKayDaConfigurationFailure> VerifyOAuth(
        StartupVerificationContext context,
        IReadOnlyList<OAuthProvider> providers)
    {
        foreach (var provider in providers.Where(provider => !provider.Options.UsePkce))
            WarnNoCodeInjectionProtection(context, provider.Name);

        var unnamed = providers.Where(provider => !provider.NamesIssuer).Select(provider => ClaimsIssuerRequired(provider.Name));
        var shared = providers
            .Where(provider => provider.NamesIssuer)
            .GroupBy(provider => provider.Options.ClaimsIssuer, StringComparer.Ordinal)
            .Where(SpansTokenEndpoints)
            .Select(group => ClaimsIssuerShared([.. group.Select(provider => provider.Name)]));

        return [.. unnamed, .. shared];
    }

    private static bool SpansTokenEndpoints(IEnumerable<OAuthProvider> providers) =>
        providers.Select(provider => provider.Options.TokenEndpoint).Distinct(StringComparer.Ordinal).Skip(1).Any();

    private static ZeeKayDaConfigurationFailure ClaimsIssuerRequired(string name) =>
        new(
            "provider.claims_issuer_required",
            $"The provider '{name}' is an OAuth provider with no ClaimsIssuer. A user's subject is derived " +
            "from the issuer of their subject claim, which an OAuth handler takes from ClaimsIssuer, else " +
            "from the registration name, so renaming the registration would give every user a new subject. " +
            "Set ClaimsIssuer to a value naming the upstream identity provider, such as its issuer URL, and " +
            "never reuse it for a different provider.");

    private static ZeeKayDaConfigurationFailure ClaimsIssuerShared(IReadOnlyList<string> names) =>
        new(
            "provider.claims_issuer_shared",
            $"The providers {Quote(names)} are OAuth providers that share one ClaimsIssuer but redeem codes at " +
            "different token endpoints. A user's subject is derived from the issuer of their subject claim and " +
            "their id at the provider, so the same id at different upstreams would give different people one " +
            "subject. Give each upstream its own ClaimsIssuer, such as its issuer URL.");

    /// <summary>The names quoted and listed: <c>'a', 'b' and 'c'</c>.</summary>
    private static string Quote(IReadOnlyList<string> names)
    {
        var quoted = names.Select(name => $"'{name}'").ToArray();
        return $"{string.Join(", ", quoted[..^1])} and {quoted[^1]}";
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

    private sealed record OAuthProvider(string Name, OAuthOptions Options)
    {
        public bool NamesIssuer => !string.IsNullOrWhiteSpace(Options.ClaimsIssuer);
    }
}
