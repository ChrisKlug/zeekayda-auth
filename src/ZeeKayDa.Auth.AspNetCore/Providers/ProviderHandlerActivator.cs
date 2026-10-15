using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Activates a provider's handler for one request, as the authentication middleware does for host
/// schemes, since provider schemes are not in the host's map.
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
