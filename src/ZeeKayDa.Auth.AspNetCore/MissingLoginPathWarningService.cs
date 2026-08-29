using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Warns at startup when no login page is configured, because an authorization request that needs
/// to authenticate a user then has nowhere to send them and can only answer <c>server_error</c>.
/// </summary>
/// <remarks>
/// A warning rather than a failure: the option is genuinely optional for a host that authenticates
/// only through external providers. Warning at startup is what turns a puzzling runtime error at
/// the client into a line the developer already read.
/// </remarks>
internal sealed class MissingLoginPathWarningService : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public MissingLoginPathWarningService(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "MissingLoginPath";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (_options.Value.AuthorizationEndpoint.Interaction.LoginPath is null)
        {
            context.AddWarning(
                "interaction.no_login_path",
                "AuthorizationEndpoint.Interaction.LoginPath is not configured. Authorization requests " +
                "that need to authenticate a user will fail with server_error. Set it to the path of " +
                "the host's login page, whose handler completes the request by calling " +
                "ILoginInteraction.SignInAsync.");
        }

        return ValueTask.CompletedTask;
    }
}
