using Microsoft.AspNetCore.Authentication;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The framework's <c>OnAccessDenied</c> for every remote provider handler. It records the refusal
/// on the request's callback feature and nothing else: no result is set, so the handler goes on to
/// fail its callback exactly as it would have, and the callback endpoint turns the marked failure
/// into <c>access_denied</c> at the client.
/// </summary>
/// <remarks>
/// The mark can be trusted because a remote handler validates its correlation cookie before it
/// looks at the provider's error, so a replayed callback URL never reaches this event.
/// </remarks>
internal static class ProviderAccessDenied
{
    public static readonly Func<AccessDeniedContext, Task> Handler = Mark;

    private static Task Mark(AccessDeniedContext context)
    {
        // The feature exists only on a request routed to a provider callback endpoint. Anywhere
        // else there is nothing to mark, and nothing that would read the mark.
        context.HttpContext.Features.Get<ProviderCallbackFeature>()?.MarkRefused(InteractionIdOf(context.Properties));
        return Task.CompletedTask;
    }

    private static string? InteractionIdOf(AuthenticationProperties? properties) =>
        properties is not null && properties.Items.TryGetValue(ExternalTicket.InteractionIdItem, out var id) ? id : null;
}
