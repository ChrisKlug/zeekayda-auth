using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// Applies the login dispatch rules at startup: fails when nothing can authenticate a user, warns
/// when a needed login page is missing.
/// </summary>
/// <remarks>
/// <para>
/// Skipped when <c>GrantTypesSupported</c> lacks <see cref="GrantType.AuthorizationCode"/>.
/// </para>
/// <para>
/// A verifier, not an activator: it reads only the framework's own options.
/// </para>
/// </remarks>
internal sealed class LoginDispatchVerifier(
    IOptions<AuthorizationServerOptions> options,
    ProviderRegistry providers) : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options = options;

    /// <inheritdoc/>
    public string Name => "LoginDispatch";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var options = _options.Value;
        if (!options.GrantTypesSupported.Contains(GrantType.AuthorizationCode))
            return Task.CompletedTask;

        switch (LoginDispatch.Decide(options.AuthorizationEndpoint.Interaction, providers.Count))
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
                    "AuthorizationEndpoint.Interaction.LoginPath is null, but a login page is " +
                    "needed: local sign-in is enabled, or more than one external provider is registered, " +
                    "and the framework never chooses for the user. Authorization requests that need to " +
                    "authenticate a user will fail with server_error. Set LoginPath to the path of the " +
                    "host's login page, whose handler completes the request through LoginInteraction.");
                break;
        }

        return Task.CompletedTask;
    }
}
