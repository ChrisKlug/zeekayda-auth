namespace ZeeKayDa.Auth;

/// <summary>
/// Authorization endpoint configuration options.
/// </summary>
public sealed class AuthorizationOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>authorization_endpoint</c> URI published in
    /// the discovery document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }
}
