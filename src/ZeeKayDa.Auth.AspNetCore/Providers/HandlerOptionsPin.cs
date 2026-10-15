using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Pins the members the framework owns on every registered provider's options: no forwarding,
/// and on a remote handler the callback path, sign-in scheme and refusal handling.
/// </summary>
/// <remarks>
/// Registered once, after the providers' own post-configuration. A later post-configurer still
/// wins; <see cref="HandlerOptionsValidator{TOptions}"/> is what fails startup when one does.
/// </remarks>
internal sealed class HandlerOptionsPin<TOptions>(
    ProviderRegistry registry,
    IOptions<AuthorizationServerOptions> options) : IPostConfigureOptions<TOptions>
    where TOptions : AuthenticationSchemeOptions
{
    /// <summary>The access-denied event a remote handler ships with, compared by method, not instance.</summary>
    private static readonly Func<AccessDeniedContext, Task> DefaultOnAccessDenied =
        new RemoteAuthenticationEvents().OnAccessDenied;

    private readonly IOptions<AuthorizationServerOptions> _options = options;

    /// <inheritdoc/>
    public void PostConfigure(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !registry.Contains(name))
            return;

        ClearForwards(options);

        if (options is not RemoteAuthenticationOptions remote)
            return;

        remote.CallbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);
        remote.SignInScheme = ZeeKayDaCookies.External;

        // A refusal must reach the callback endpoint as a failure.
        remote.AccessDeniedPath = PathString.Empty;

        if (remote.Events is not { } events)
            return;

        // A host-set event is left for the validator to refuse, not silently overridden.
        if (IsDefault(events.OnAccessDenied))
            events.OnAccessDenied = ProviderAccessDenied.Handler;

        // Wrapped: a host may own its failure page through OnRemoteFailure.
        events.OnRemoteFailure = ProviderAccessDenied.RecordingFailures(events.OnRemoteFailure ?? (_ => Task.CompletedTask));
    }

    /// <summary>Clears every forward, which would divert the challenge or sign-in into a host-visible scheme.</summary>
    private static void ClearForwards(TOptions options)
    {
        options.ForwardDefault = null;
        options.ForwardDefaultSelector = null;
        options.ForwardAuthenticate = null;
        options.ForwardChallenge = null;
        options.ForwardForbid = null;
        options.ForwardSignIn = null;
        options.ForwardSignOut = null;
    }

    private static bool IsDefault(Func<AccessDeniedContext, Task>? handler) =>
        handler is null
        || (handler.Method == DefaultOnAccessDenied.Method && ReferenceEquals(handler.Target, DefaultOnAccessDenied.Target));
}
