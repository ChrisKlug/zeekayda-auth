using Microsoft.AspNetCore.Authentication;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// The framework's <c>OnAccessDenied</c> for every remote provider: marks the refusal and sets no
/// result, so the handler fails its callback and the endpoint decides.
/// </summary>
/// <remarks>
/// Trustworthy because a remote handler validates its correlation cookie before reading the error.
/// </remarks>
internal static class ProviderAccessDenied
{
    public static readonly Func<AccessDeniedContext, Task> Handler = Mark;

    private static Task Mark(AccessDeniedContext context)
    {
        // Absent off a provider callback endpoint, where nothing would read the mark.
        context.HttpContext.Features.Get<ProviderCallbackFeature>()?.MarkRefused(InteractionIdOf(context.Properties));
        return Task.CompletedTask;
    }

    /// <summary>Wraps <c>OnRemoteFailure</c> so the failing interaction is recorded before <paramref name="inner"/> runs.</summary>
    public static Func<RemoteFailureContext, Task> RecordingFailures(Func<RemoteFailureContext, Task> inner)
    {
        ArgumentNullException.ThrowIfNull(inner);

        return context =>
        {
            context.HttpContext.Features.Get<ProviderCallbackFeature>()?.MarkFailed(InteractionIdOf(context.Properties));
            return inner(context);
        };
    }

    private static string? InteractionIdOf(AuthenticationProperties? properties) =>
        properties is not null && properties.Items.TryGetValue(ExternalTicket.InteractionIdItem, out var id) ? id : null;
}
