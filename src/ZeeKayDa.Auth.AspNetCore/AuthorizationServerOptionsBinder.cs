using Microsoft.Extensions.Configuration;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Binds <see cref="AuthorizationServerOptions"/> from configuration, with a collection key
/// replacing the default list rather than appending to it as the .NET binder would.
/// </summary>
internal static class AuthorizationServerOptionsBinder
{
    public static void Bind(IConfiguration section, AuthorizationServerOptions options)
    {
        ClearConfiguredCollections(section, options);
        section.Bind(options);
    }

    private static void ClearConfiguredCollections(IConfiguration section, AuthorizationServerOptions options)
    {
        if (IsConfigured(section, nameof(options.GrantTypesSupported)))
            options.GrantTypesSupported = [];

        if (IsConfigured(section, nameof(options.CorsOrigins)))
            options.CorsOrigins = [];

        var response = section.GetSection(nameof(options.Response));
        if (IsConfigured(response, nameof(ResponseOptions.TypesSupported)))
            options.Response.TypesSupported = [];

        if (IsConfigured(response, nameof(ResponseOptions.ModesSupported)))
            options.Response.ModesSupported = [];

        var authorization = section.GetSection(nameof(options.AuthorizationEndpoint));
        if (IsConfigured(authorization, nameof(AuthorizationEndpointOptions.CodeChallengeMethodsSupported)))
            options.AuthorizationEndpoint.CodeChallengeMethodsSupported = [];

        var token = section.GetSection(nameof(options.TokenEndpoint));
        if (IsConfigured(token, nameof(TokenEndpointOptions.AuthMethodsSupported)))
            options.TokenEndpoint.AuthMethodsSupported = [];

        var idToken = section.GetSection(nameof(options.IdToken));
        if (IsConfigured(idToken, nameof(IdTokenOptions.AdvertisedSigningAlgorithms)))
            options.IdToken.AdvertisedSigningAlgorithms = [];
    }

    private static bool IsConfigured(IConfiguration section, string key) => section.GetSection(key).Exists();
}
