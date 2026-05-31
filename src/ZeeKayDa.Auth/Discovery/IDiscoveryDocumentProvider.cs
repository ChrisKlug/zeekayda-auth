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
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>
    /// A populated <see cref="OpenIdConfigurationDocument"/> ready for serialisation and
    /// publication at the discovery endpoint.
    /// </returns>
    ValueTask<OpenIdConfigurationDocument> GetDocumentAsync(CancellationToken cancellationToken = default);
}
