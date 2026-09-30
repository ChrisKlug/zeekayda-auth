using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Freezes <see cref="AuthorizationServerOptions.CorsOrigins"/> and
/// <see cref="Tokens.IdTokenOptions.AdvertisedSigningAlgorithms"/> before startup validation runs.
/// </summary>
/// <remarks>
/// <see cref="IPostConfigureOptions{TOptions}"/> runs after all <c>Configure</c> callbacks and before
/// <see cref="IValidateOptions{TOptions}"/>. The host's values are copied as configured, never
/// rewritten: the canonical CORS allowlist is derived where it is used. Multiple calls are
/// idempotent.
/// </remarks>
internal sealed class AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthorizationServerOptions options)
    {
        // Frozen so nothing can change the allowlist after startup validated it.
        options.CorsOrigins = options.CorsOrigins.ToList().AsReadOnly();

        // Frozen for the same reason: the discovery document reads this filter on
        // every request, and the startup checks that reconcile it with the key set run exactly
        // once. A collection still mutable afterwards could narrow the advertised set past what
        // startup approved, with no check left to catch it.
        if (options.IdToken.AdvertisedSigningAlgorithms is { } advertised)
            options.IdToken.AdvertisedSigningAlgorithms = advertised.ToList().AsReadOnly();
    }
}
