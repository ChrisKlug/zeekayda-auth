using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Resolves the defaults that depend on other settings, then freezes every collection on
/// <see cref="AuthorizationServerOptions"/> before startup validation runs, so nothing can change a
/// value after startup approved it.
/// </summary>
/// <remarks>
/// <see cref="IPostConfigureOptions{TOptions}"/> runs after all <c>Configure</c> callbacks and before
/// <see cref="IValidateOptions{TOptions}"/>. Each collection is replaced by a read-only copy of the
/// host's values in the host's order, never rewritten or de-duplicated; a <see langword="null"/>
/// collection stays <see langword="null"/> for validation to judge. From then on a setter refuses
/// to replace a collection, so a later post-configure step cannot undo the freeze.
/// </remarks>
internal sealed class AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthorizationServerOptions options)
    {
        options.SigningKeys.RetainRetiredKeysFor ??= options.TokenEndpoint.AccessTokenLifetime > options.TokenEndpoint.IdTokenLifetime
            ? options.TokenEndpoint.AccessTokenLifetime
            : options.TokenEndpoint.IdTokenLifetime;
        options.Freeze();
    }
}
