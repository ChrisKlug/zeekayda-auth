using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// Authorization endpoint configuration options.
/// </summary>
public sealed class AuthorizationEndpointOptions
{
    private ICollection<CodeChallengeMethod>? _codeChallengeMethodsSupported = [CodeChallengeMethod.S256];
    private bool _frozen;

    /// <summary>
    /// Gets or sets an explicit override for the <c>authorization_endpoint</c> URI published in
    /// the discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }

    /// <summary>
    /// Gets or sets the PKCE methods published as <c>code_challenge_methods_supported</c>.
    /// Defaults to <c>[<see cref="CodeChallengeMethod.S256"/>]</c>, the one method the token endpoint verifies.
    /// </summary>
    /// <remarks>
    /// A host serving <see cref="GrantType.AuthorizationCode"/> must keep
    /// <see cref="CodeChallengeMethod.S256"/> here or startup fails; only other hosts may set <see langword="null"/>.
    /// </remarks>
    public ICollection<CodeChallengeMethod>? CodeChallengeMethodsSupported
    {
        get => _codeChallengeMethodsSupported;
        set => _codeChallengeMethodsSupported = FrozenOptions.Assign(_frozen, value, "AuthorizationServerOptions.AuthorizationEndpoint.CodeChallengeMethodsSupported");
    }

    /// <summary>
    /// Gets or sets the lifetime of an issued authorization code. Defaults to 60 seconds; must be
    /// positive and at most 10 minutes (RFC 9700 §2.1.1).
    /// </summary>
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Gets or sets the most bytes one accepted authorization request may occupy in the interaction
    /// store before it is refused with <c>invalid_request</c>. Defaults to 16 KB; must be positive.
    /// </summary>
    /// <remarks>
    /// Bounds what an unauthenticated request can make the store hold. A typical request is a few
    /// hundred bytes; raise it only for clients that send large <c>state</c> values.
    /// </remarks>
    public int MaxRequestContextBytes { get; set; } = 16 * 1024;

    /// <summary>
    /// Gets the paths of the host-owned interaction pages the authorization flow hands off to.
    /// </summary>
    public InteractionOptions Interaction { get; } = new();

    /// <summary>Makes every collection read-only and refuses any later replacement.</summary>
    internal void Freeze()
    {
        if (_frozen)
            return;

        CodeChallengeMethodsSupported = FrozenOptions.Copy(CodeChallengeMethodsSupported);
        _frozen = true;
    }
}
