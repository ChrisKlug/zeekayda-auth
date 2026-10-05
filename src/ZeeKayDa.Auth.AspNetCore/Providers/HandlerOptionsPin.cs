using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Pins, on every handler's options whose name is a registered provider, the members the
/// framework owns: no forwarding on any provider, and on a remote one also the callback path the
/// framework maps an endpoint on, the sign-in scheme the framework reads the result from, no
/// access-denied page, the framework's own access-denied event, and a remote-failure event that
/// records the interaction a failing callback's properties name.
/// </summary>
/// <remarks>
/// <para>
/// One open-generic post-configurer constrained to <see cref="AuthenticationSchemeOptions"/>; it
/// skips every name that is not a registered provider. It is registered once, at the tail of the
/// collection when the first <c>WithProviders</c> window closes, so it runs after the provider's
/// own post-configuration, including the one that defaults <c>SignInScheme</c>. It is never moved
/// afterwards: anything registered later that changes a pinned member is meant to fail startup,
/// not to be silently overridden.
/// </para>
/// <para>
/// The pin promises nothing on its own: post-configurers run in registration order, so one the
/// host registers later would win. <see cref="HandlerOptionsValidator{TOptions}"/> is the
/// promise — it fails any provider options whose final values differ from these.
/// </para>
/// </remarks>
internal sealed class HandlerOptionsPin<TOptions>(
    ProviderRegistry registry,
    IOptions<AuthorizationServerOptions> options) : IPostConfigureOptions<TOptions>
    where TOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The access-denied event a remote handler ships with. Compared by method rather than by
    /// delegate instance, which does not depend on the compiler caching the default lambda.
    /// </summary>
    private static readonly Func<AccessDeniedContext, Task> DefaultOnAccessDenied =
        new RemoteAuthenticationEvents().OnAccessDenied;

    private readonly IOptions<AuthorizationServerOptions> _options = options;

    /// <inheritdoc/>
    public void PostConfigure(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !registry.Contains(name))
            return;

        // A forward would divert the challenge or the sign-in around the framework's own
        // callback and sign-in scheme, into a scheme the host can see.
        options.ForwardDefault = null;
        options.ForwardDefaultSelector = null;
        options.ForwardAuthenticate = null;
        options.ForwardChallenge = null;
        options.ForwardForbid = null;
        options.ForwardSignIn = null;
        options.ForwardSignOut = null;

        if (options is not RemoteAuthenticationOptions remote)
            return;

        remote.CallbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);
        remote.SignInScheme = ZeeKayDaCookies.External;

        // A provider refusal must reach the framework's callback endpoint as a failure, not escape
        // to a host page the framework never redirected to.
        remote.AccessDeniedPath = PathString.Empty;

        if (remote.Events is not { } events)
            return;

        // Replaced only when it is the one the handler ships with. A host-set event is left for
        // the validator to refuse: it would put the refusal outcome outside the framework's
        // control, and overriding it silently would hide that from the host.
        if (IsDefault(events.OnAccessDenied))
            events.OnAccessDenied = ProviderAccessDenied.Handler;

        // Wrapped, not replaced: handling the response in OnRemoteFailure is a host owning its own
        // failure page. A later replacement only costs the precision; the challenge cookie remains.
        events.OnRemoteFailure = ProviderAccessDenied.RecordingFailures(events.OnRemoteFailure ?? (_ => Task.CompletedTask));
    }

    private static bool IsDefault(Func<AccessDeniedContext, Task>? handler) =>
        handler is null
        || (handler.Method == DefaultOnAccessDenied.Method && ReferenceEquals(handler.Target, DefaultOnAccessDenied.Target));
}
