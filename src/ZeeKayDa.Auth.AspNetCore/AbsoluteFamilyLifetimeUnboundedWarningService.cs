using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when <c>AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime</c>
/// is set to the <see cref="TimeSpan.MaxValue"/> escape-hatch sentinel, so that an unbounded
/// refresh-token-family lifetime is never a silent configuration accident.
/// </summary>
internal sealed class AbsoluteFamilyLifetimeUnboundedWarningService : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public AbsoluteFamilyLifetimeUnboundedWarningService(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "AbsoluteFamilyLifetimeUnbounded";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (_options.Value.TokenEndpoint.AbsoluteFamilyLifetime == TimeSpan.MaxValue)
        {
            context.AddWarning(
                "tokens.absolute_family_lifetime_unbounded",
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime is set to the " +
                "unbounded escape-hatch sentinel (TimeSpan.MaxValue). Refresh token families will " +
                "never hit an absolute lifetime cap, causing unbounded row growth in a persisted " +
                "refresh-token grant store over time. Ensure this is an intentional choice.");
        }

        return ValueTask.CompletedTask;
    }
}
