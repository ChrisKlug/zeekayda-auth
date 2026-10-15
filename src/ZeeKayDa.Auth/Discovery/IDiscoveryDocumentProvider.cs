namespace ZeeKayDa.Auth.Discovery;

/// <summary>Provides the OpenID Connect Discovery 1.0 document for the current <see cref="AuthorizationServerOptions"/>.</summary>
public interface IDiscoveryDocumentProvider
{
    /// <summary>Builds the current <see cref="OpenIdConfigurationDocument"/>.</summary>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>The document, ready to publish at the discovery endpoint.</returns>
    Task<OpenIdConfigurationDocument> GetDocumentAsync(CancellationToken cancellationToken = default);
}
