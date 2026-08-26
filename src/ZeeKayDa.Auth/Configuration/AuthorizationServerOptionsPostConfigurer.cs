using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Canonicalizes and freezes <see cref="DiscoveryOptions.CorsOrigins"/> and
/// <see cref="JwksEndpointOptions.CorsOrigins"/>, and freezes
/// <see cref="Tokens.IdTokenOptions.AdvertisedSigningAlgorithms"/>, before startup validation runs.
/// </summary>
/// <remarks>
/// <see cref="IPostConfigureOptions{TOptions}"/> runs after all <c>Configure</c> callbacks and before
/// <see cref="IValidateOptions{TOptions}"/>. Extracting mutation here keeps
/// <see cref="AuthorizationServerOptionsValidator"/> a pure read-only check, which is the contract
/// of <c>IValidateOptions&lt;T&gt;</c>. Origins that cannot be parsed are left as-is so the
/// validator can surface clear error messages for each one. Multiple calls are naturally idempotent —
/// already-canonical data canonicalized again is unchanged.
/// </remarks>
internal sealed class AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthorizationServerOptions options)
    {
        options.DiscoveryDocument.CorsOrigins = Canonicalize(options.DiscoveryDocument.CorsOrigins);
        options.JwksEndpoint.CorsOrigins = Canonicalize(options.JwksEndpoint.CorsOrigins);

        // Frozen for the same reason as CorsOrigins: the discovery document reads this filter on
        // every request, and the startup checks that reconcile it with the key set run exactly
        // once. A collection still mutable afterwards could narrow the advertised set past what
        // startup approved, with no check left to catch it.
        if (options.IdToken.AdvertisedSigningAlgorithms is { } advertised)
            options.IdToken.AdvertisedSigningAlgorithms = advertised.ToList().AsReadOnly();
    }

    private static IList<string> Canonicalize(IList<string> origins)
    {
        var result = new List<string>(origins.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var origin in origins)
        {
            if (CorsOrigin.TryCanonicalize(origin, out var canonical))
            {
                if (seen.Add(canonical))
                    result.Add(canonical);
            }
            else
            {
                result.Add(origin!);
            }
        }

        return result.AsReadOnly();
    }

}
