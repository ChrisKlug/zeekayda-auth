using Microsoft.AspNetCore.Authentication.Cookies;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// What the framework writes into, and reads back from, the <c>AuthenticationProperties</c> a
/// provider carries through its round trip and signs into <c>zkd.external</c> with. The
/// interaction is stamped before the handler sees the properties and the provider is recorded at
/// sign-in from the request's route; neither comes from the handler.
/// </summary>
internal static class ExternalTicket
{
    /// <summary>The interaction the challenge was issued for.</summary>
    public const string InteractionIdItem = "zkd:interaction_id";

    /// <summary>
    /// The provider the challenge was issued to. Compared at resume with the provider whose
    /// callback endpoint signed the ticket in, so a callback carried to another provider's route
    /// — two custom handlers sharing a state format — cannot complete as that provider.
    /// </summary>
    public const string ChallengedProviderItem = "zkd:challenged_provider";

    /// <summary>The provider whose callback endpoint signed the ticket in.</summary>
    public const string ProviderItem = "zkd:provider";

    /// <summary>
    /// The scheme name <c>RemoteAuthenticationHandler</c> stamps into the properties it signs in
    /// with. A cross-check against <see cref="ProviderItem"/>, never the source of it.
    /// </summary>
    public const string RemoteAuthenticationSchemeItem = ".AuthScheme";

    /// <summary>
    /// The <c>zkd.external</c> scheme's sign-in event: records the provider from the request
    /// feature the callback endpoint set after routing, and refuses a sign-in that carries no such
    /// feature — nothing but a provider callback endpoint may sign in here.
    /// </summary>
    public static Task RecordProvider(CookieSigningInContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var feature = context.HttpContext.Features.Get<ProviderCallbackFeature>()
            ?? throw new InvalidOperationException(
                "Only a provider's callback endpoint may sign into the framework's external scheme. " +
                "A host signs users in through ILoginInteraction, never by naming a framework scheme.");

        context.Properties.Items[ProviderItem] = feature.Provider.Name;
        return Task.CompletedTask;
    }
}
