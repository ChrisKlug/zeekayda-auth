using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Emits a startup warning when <c>AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime</c>
/// is set to the <see cref="TimeSpan.MaxValue"/> escape-hatch sentinel, so that an unbounded
/// refresh-token-family lifetime is never a silent configuration accident.
/// </summary>
internal sealed class AbsoluteFamilyLifetimeUnboundedVerifier(
    IOptions<AuthorizationServerOptions> options) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "AbsoluteFamilyLifetimeUnbounded";

    /// <inheritdoc/>
    public Task VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (options.Value.TokenEndpoint.AbsoluteFamilyLifetime == TimeSpan.MaxValue)
        {
            context.AddWarning(
                "tokens.absolute_family_lifetime_unbounded",
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime is set to the " +
                "unbounded escape-hatch sentinel (TimeSpan.MaxValue). Refresh token families will " +
                "never hit an absolute lifetime cap, causing unbounded row growth in a persisted " +
                "refresh-token grant store over time. Ensure this is an intentional choice.");
        }

        return Task.CompletedTask;
    }
}
