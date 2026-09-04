using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Applies the login dispatch rules at startup: fails when nothing can authenticate a user, warns
/// when a login page is needed and none is configured, and says nothing otherwise.
/// </summary>
/// <remarks>
/// <para>
/// Gated on <c>GrantTypesSupported</c> containing <see cref="GrantType.AuthorizationCode"/>, the
/// existing declaration of whether this host does user-facing grants at all. A
/// <c>client_credentials</c>-only host has no login dispatch to check and starts clean.
/// </para>
/// <para>
/// A verifier, not an activator: it reads the framework's own options and its own scheme map.
/// The conditions are exact, so the warning cries wolf for nobody — a warning that does trains
/// people to ignore it.
/// </para>
/// </remarks>
internal sealed class LoginDispatchVerifier : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ProviderRegistry _providers;

    public LoginDispatchVerifier(IOptions<AuthorizationServerOptions> options, ProviderRegistry providers)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(providers);

        _options = options;
        _providers = providers;
    }

    /// <inheritdoc/>
    public string Name => "LoginDispatch";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = _options.Value;
        if (!options.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return ValueTask.CompletedTask;

        switch (LoginDispatch.Decide(options.AuthorizationEndpoint.Interaction, _providers.Count))
        {
            case LoginDispatchRule.NoSignInMethod:
                context.AddFailure(
                    "interaction.no_sign_in_method",
                    "AuthorizationEndpoint.Interaction.SupportsLocalSignIn is false and no external " +
                    "provider is registered, so no authorization request can authenticate a user. " +
                    "Register a provider with WithProviders, set SupportsLocalSignIn to true, or remove " +
                    "GrantType.AuthorizationCode from GrantTypesSupported if this host issues no " +
                    "user-facing grants.");
                break;

            case LoginDispatchRule.PageNeeded:
                context.AddWarning(
                    "interaction.no_login_path",
                    "AuthorizationEndpoint.Interaction.LoginPath is not configured, but a login page is " +
                    "needed: local sign-in is enabled, or more than one external provider is registered, " +
                    "and the framework never chooses for the user. Authorization requests that need to " +
                    "authenticate a user will fail with server_error. Set LoginPath to the path of the " +
                    "host's login page, whose handler completes the request through ILoginInteraction.");
                break;
        }

        return ValueTask.CompletedTask;
    }
}
