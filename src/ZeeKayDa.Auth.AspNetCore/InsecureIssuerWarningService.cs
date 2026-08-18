using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when <see cref="AuthorizationServerOptions.AllowInsecureIssuer"/> is
/// enabled, so that insecure development configurations are never silently deployed to production.
/// </summary>
internal sealed class InsecureIssuerWarningService : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public InsecureIssuerWarningService(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "InsecureIssuer";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (_options.Value.AllowInsecureIssuer)
        {
            context.AddWarning(
                "issuer.insecure_allowed",
                "AllowInsecureIssuer is enabled for issuer '{Issuer}'. " +
                "This is a LOOPBACK DEVELOPMENT-ONLY setting and must NEVER be used in production. " +
                "Remove AllowInsecureIssuer = true before deploying to any non-development environment.",
                _options.Value.Issuer);
        }

        return ValueTask.CompletedTask;
    }
}
