using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Freezes every collection on <see cref="AuthorizationServerOptions"/> before startup validation
/// runs, so nothing can change a value after startup approved it.
/// </summary>
/// <remarks>
/// <see cref="IPostConfigureOptions{TOptions}"/> runs after all <c>Configure</c> callbacks and before
/// <see cref="IValidateOptions{TOptions}"/>. Each collection is replaced by a read-only copy of the
/// host's values in the host's order, never rewritten or de-duplicated; a <see langword="null"/>
/// collection stays <see langword="null"/> for validation to judge. Multiple calls are idempotent.
/// </remarks>
internal sealed class AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthorizationServerOptions options)
    {
        options.GrantTypesSupported = Freeze(options.GrantTypesSupported);
        options.CorsOrigins = Freeze(options.CorsOrigins);
        options.AuthorizationEndpoint.CodeChallengeMethodsSupported =
            Freeze(options.AuthorizationEndpoint.CodeChallengeMethodsSupported);
        options.TokenEndpoint.AuthMethodsSupported = Freeze(options.TokenEndpoint.AuthMethodsSupported);
        options.IdToken.AdvertisedSigningAlgorithms = Freeze(options.IdToken.AdvertisedSigningAlgorithms);
        options.Response.TypesSupported = Freeze(options.Response.TypesSupported);
        options.Response.ModesSupported = Freeze(options.Response.ModesSupported);
    }

    [return: NotNullIfNotNull(nameof(values))]
    private static ReadOnlyCollection<T>? Freeze<T>(ICollection<T>? values) => values?.ToList().AsReadOnly();
}
