using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when a server-wide access-token or ID-token lifetime is longer than
/// <c>TokenEndpoint.AbsoluteFamilyLifetime</c>: such a token outlives the grant family that
/// produced it, which is rarely what an operator meant.
/// </summary>
internal sealed class TokenLifetimeCeilingWarningService : IStartupVerifier
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public TokenLifetimeCeilingWarningService(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "TokenLifetimeCeiling";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var tokens = _options.Value.TokenEndpoint;

        if (tokens.AccessTokenLifetime > tokens.AbsoluteFamilyLifetime)
        {
            context.AddWarning(
                "tokens.access_token_lifetime_exceeds_family_ceiling",
                "AuthorizationServerOptions.TokenEndpoint.AccessTokenLifetime is longer than " +
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime, so an access token issued " +
                "at the end of a grant family's life outlives the family. Ensure this is an intentional choice.");
        }

        if (tokens.IdTokenLifetime > tokens.AbsoluteFamilyLifetime)
        {
            context.AddWarning(
                "tokens.id_token_lifetime_exceeds_family_ceiling",
                "AuthorizationServerOptions.TokenEndpoint.IdTokenLifetime is longer than " +
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime, so an ID token issued " +
                "at the end of a grant family's life outlives the family. Ensure this is an intentional choice.");
        }

        return ValueTask.CompletedTask;
    }
}
