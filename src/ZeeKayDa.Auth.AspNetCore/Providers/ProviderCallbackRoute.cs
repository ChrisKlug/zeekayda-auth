using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// A provider's callback route, <c>/connect/callback/{provider}</c> under the issuer path, shared
/// by the pinned <c>CallbackPath</c> and the mapped endpoint.
/// </summary>
internal static class ProviderCallbackRoute
{
    public static PathString For(Uri issuerUri, string providerName)
    {
        ArgumentNullException.ThrowIfNull(issuerUri);
        ArgumentException.ThrowIfNullOrEmpty(providerName);

        return new PathString(
            EndpointRouteHelper.GetIssuerPathPrefixedRoute(issuerUri, "/connect/callback/" + providerName));
    }
}
