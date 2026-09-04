using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The route a provider's handler is called back on: <c>/connect/callback/{provider}</c> under the
/// issuer path, derived exactly as every other endpoint's route is, so that what the framework
/// writes into a handler's <c>CallbackPath</c> is the same path it later maps an endpoint on.
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
