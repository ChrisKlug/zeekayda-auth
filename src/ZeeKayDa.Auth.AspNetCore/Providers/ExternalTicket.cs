using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// What the framework stamps into, and reads back from, the properties a provider carries through
/// its round trip; none of it comes from the handler.
/// </summary>
internal static class ExternalTicket
{
    /// <summary>The interaction the challenge was issued for.</summary>
    public const string InteractionIdItem = "zkd:interaction_id";

    /// <summary>
    /// The provider the challenge was issued to, compared at resume with the route that signed the
    /// ticket in, so a callback carried to another provider's route cannot complete as it.
    /// </summary>
    public const string ChallengedProviderItem = "zkd:challenged_provider";

    /// <summary>The provider whose callback endpoint signed the ticket in.</summary>
    public const string ProviderItem = "zkd:provider";

    /// <summary>The scheme <c>RemoteAuthenticationHandler</c> stamps: a cross-check of <see cref="ProviderItem"/>, never its source.</summary>
    public const string RemoteAuthenticationSchemeItem = ".AuthScheme";

    /// <summary>
    /// The <c>zkd.external</c> sign-in event: records the provider from the callback feature,
    /// refuses a sign-in from anywhere but a provider callback endpoint, and fixes the ticket's lifetime.
    /// </summary>
    public static Task SigningIn(CookieSigningInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        RecordProvider(context);
        StampLifetime(context);
        return Task.CompletedTask;
    }

    private static void RecordProvider(CookieSigningInContext context)
    {
        var feature = context.HttpContext.Features.Get<ProviderCallbackFeature>()
            ?? throw new InvalidOperationException(
                "Only a provider's callback endpoint may sign into the framework's external scheme. " +
                "A host signs users in through LoginInteraction, never by naming a framework scheme.");

        context.Properties.Items[ProviderItem] = feature.Provider.Name;
        feature.MarkSignedIn();
    }

    /// <summary>
    /// Last word on the lifetime: the remote handler has already written the properties, as the OIDC
    /// handler does from the ID token under <c>UseTokenLifetime</c>.
    /// </summary>
    private static void StampLifetime(CookieSigningInContext context)
    {
        var now = context.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();

        context.Properties.IssuedUtc = now;
        context.Properties.ExpiresUtc = now + context.Options.ExpireTimeSpan;
        context.Properties.IsPersistent = false;
        context.Properties.AllowRefresh = false;
    }
}
