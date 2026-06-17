using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Discovery;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Canonicalizes and freezes <see cref="DiscoveryOptions.CorsOrigins"/> before startup validation runs.
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
        var result = new List<string>(options.DiscoveryDocument.CorsOrigins.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var origin in options.DiscoveryDocument.CorsOrigins)
        {
            if (origin is not null &&
                origin.IndexOfAny(['\r', '\n']) < 0 &&
                !origin.Contains('*') &&
                Uri.TryCreate(origin, UriKind.Absolute, out var uri) &&
                uri.UserInfo.Length == 0 &&
                uri.Query.Length == 0 &&
                uri.Fragment.Length == 0 &&
                uri.AbsolutePath.Length <= 1)
            {
                var canonical = uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
                if (seen.Add(canonical))
                    result.Add(canonical);
            }
            else
            {
                result.Add(origin!);
            }
        }

        options.DiscoveryDocument.CorsOrigins = result.AsReadOnly();
    }
}
