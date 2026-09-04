using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Activates a provider's handler for one request: what the authentication middleware's handler
/// provider does for the host's schemes, done here because provider schemes are not in the host's
/// map. Resolved from the request's services, falling back to constructor injection, then
/// initialised for the scheme and the request.
/// </summary>
internal sealed class ProviderHandlerActivator
{
    public async Task<IAuthenticationHandler> ActivateAsync(HttpContext context, ProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registration);

        var handler = (IAuthenticationHandler)(context.RequestServices.GetService(registration.HandlerType)
            ?? ActivatorUtilities.CreateInstance(context.RequestServices, registration.HandlerType));

        await handler.InitializeAsync(registration.Scheme, context).ConfigureAwait(false);
        return handler;
    }
}
