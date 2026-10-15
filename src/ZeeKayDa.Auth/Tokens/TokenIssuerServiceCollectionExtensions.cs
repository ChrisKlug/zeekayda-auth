using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The token subsystem's own registrations, called by the framework's setup.
/// </summary>
internal static class TokenIssuerServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="JwtTokenIssuer"/> for every <see cref="TokenKind"/> as a keyed service, keeping a
    /// host's own earlier registration.
    /// </summary>
    internal static IServiceCollection AddDefaultTokenIssuers(this IServiceCollection services)
    {
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.AccessToken);
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.IdToken);
        return services;
    }
}
