using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The token subsystem's own registrations, called by the framework's setup.
/// </summary>
internal static class TokenIssuerServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="JwtTokenIssuer"/> as the <see cref="ITokenIssuer"/> for every
    /// <see cref="TokenKind"/>, so a first server issues tokens with no extra call.
    /// </summary>
    /// <remarks>
    /// The issuer for each kind is a keyed service, so the host can swap how one kind is issued
    /// without touching the other — e.g. opaque access tokens alongside JWT ID tokens once a
    /// reference-token issuer exists. TryAdd keeps a host's own earlier registration. This becomes a
    /// public opt-in only once there is a second issuer to choose between.
    /// </remarks>
    internal static IServiceCollection AddDefaultTokenIssuers(this IServiceCollection services)
    {
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.AccessToken);
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.IdToken);
        return services;
    }
}
