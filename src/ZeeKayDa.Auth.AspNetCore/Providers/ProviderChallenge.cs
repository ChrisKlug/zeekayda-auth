using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.Authorization;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Starts the external round trip for one provider: activates its handler and challenges it with
/// properties the framework wrote. The return address is <c>/connect/resume</c> carrying the
/// interaction identifier, and the identifier is stamped into the properties as well, so the
/// ticket the provider hands back names the interaction it was issued for whatever the handler
/// did with the state it was given.
/// </summary>
internal sealed class ProviderChallenge
{
    private readonly ProviderHandlerActivator _activator;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public ProviderChallenge(ProviderHandlerActivator activator, IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(activator);
        ArgumentNullException.ThrowIfNull(options);

        _activator = activator;
        _options = options;
    }

    public async Task ChallengeAsync(
        HttpContext context,
        AuthorizationRequestContext requestContext,
        ProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestContext);
        ArgumentNullException.ThrowIfNull(registration);

        var resume = ResumeEndpoint.RouteFor(EndpointRouteHelper.GetIssuerUri(_options));
        var properties = new AuthenticationProperties
        {
            RedirectUri = InteractionHandoff.BuildRedirectUrl(resume, requestContext.Id),
        };
        properties.Items[ExternalTicket.InteractionIdItem] = requestContext.Id;

        var handler = await _activator.ActivateAsync(context, registration).ConfigureAwait(false);
        await handler.ChallengeAsync(properties).ConfigureAwait(false);
    }
}
