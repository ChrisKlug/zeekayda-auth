namespace ZeeKayDa.Auth.Discovery;

/// <summary>
/// Provides an OpenID Connect Discovery 1.0 document derived from the current
/// <see cref="AuthorizationServerOptions"/>.
/// </summary>
public interface IDiscoveryDocumentProvider
{
    /// <summary>
    /// Returns the current <see cref="OpenIdConfigurationDocument"/> built from the live
    /// authorization server options.
    /// </summary>
    /// <returns>
    /// A populated <see cref="OpenIdConfigurationDocument"/> ready for serialisation and
    /// publication at the discovery endpoint.
    /// </returns>
    OpenIdConfigurationDocument GetDocument();
}
