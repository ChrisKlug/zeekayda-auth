using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.AspNetCore.Interaction;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Pins, on every remote handler's options whose name is a registered provider, the members the
/// framework owns: the callback path the framework maps an endpoint on, the sign-in scheme the
/// framework reads the result from, no access-denied page, and no forwarding.
/// </summary>
/// <remarks>
/// <para>
/// One open-generic post-configurer constrained to <see cref="RemoteAuthenticationOptions"/>, so
/// the container skips it for every other options type. It is registered at the tail of the
/// collection by <c>WithProviders</c>, after the provider's own post-configuration, including the
/// one that defaults <c>SignInScheme</c>.
/// </para>
/// <para>
/// The pin promises nothing on its own: post-configurers run in registration order, so one the
/// host registers later would win. <see cref="ProviderOptionsValidator{TOptions}"/> is the
/// promise — it fails any provider options whose final values differ from these.
/// </para>
/// </remarks>
internal sealed class ProviderOptionsPin<TOptions> : IPostConfigureOptions<TOptions>
    where TOptions : RemoteAuthenticationOptions
{
    private readonly ProviderRegistry _registry;
    private readonly IOptions<AuthorizationServerOptions> _options;

    public ProviderOptionsPin(ProviderRegistry registry, IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(options);

        _registry = registry;
        _options = options;
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, TOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (name is null || !_registry.Contains(name))
            return;

        options.CallbackPath = ProviderCallbackRoute.For(EndpointRouteHelper.GetIssuerUri(_options), name);
        options.SignInScheme = ZeeKayDaCookies.External;

        // A provider refusal must reach the framework's callback endpoint as a failure, not escape
        // to a host page the framework never redirected to.
        options.AccessDeniedPath = PathString.Empty;

        // A forward would divert the challenge or the sign-in around the pinned redirect URI and
        // sign-in scheme.
        options.ForwardDefault = null;
        options.ForwardDefaultSelector = null;
        options.ForwardAuthenticate = null;
        options.ForwardChallenge = null;
        options.ForwardForbid = null;
        options.ForwardSignIn = null;
        options.ForwardSignOut = null;
    }
}
