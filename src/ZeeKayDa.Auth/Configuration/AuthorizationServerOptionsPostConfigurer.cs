using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Resolves dependent defaults, then freezes <see cref="AuthorizationServerOptions"/> before
/// validation, so nothing can change a value startup approved.
/// </summary>
internal sealed class AuthorizationServerOptionsPostConfigurer : IPostConfigureOptions<AuthorizationServerOptions>
{
    /// <inheritdoc/>
    public void PostConfigure(string? name, AuthorizationServerOptions options)
    {
        options.SigningKeys.RetainRetiredKeysFor ??= SigningKeyOptions.DefaultRetainRetiredKeysFor(options);
        options.Freeze();
    }
}
