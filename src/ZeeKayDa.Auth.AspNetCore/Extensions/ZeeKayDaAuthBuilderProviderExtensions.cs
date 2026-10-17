using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.AspNetCore.Interaction;
using ZeeKayDa.Auth.AspNetCore.Providers;
using ZeeKayDa.Auth.StartupVerification;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the external providers a ZeeKayDa.Auth host authenticates
/// users through.
/// </summary>
public static class ZeeKayDaAuthBuilderProviderExtensions
{
    /// <summary>
    /// Registers external authentication providers. The callback receives a real
    /// <see cref="AuthenticationBuilder"/>, so every provider package works unchanged —
    /// <c>auth.AddGoogle(...)</c>, <c>auth.AddOpenIdConnect(...)</c>, or any other.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="configure">Registers the providers on the supplied <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="options">
    /// How the host takes part in a provider sign-in, or <see langword="null"/> to promote every
    /// provider's principal as it is. One <see cref="ProviderOptions"/> serves every call and provider.
    /// </param>
    /// <returns>The <paramref name="builder"/>, for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The host names the providers and nothing else. The framework pins each handler's callback
    /// path, sign-in scheme and refusal handling, refuses a later change to them at startup, and
    /// drives the round trip: the login page starts it with <c>LoginInteraction.ChallengeAsync</c>.
    /// A provider whose handler does not implement <see cref="IAuthenticationRequestHandler"/> fails
    /// startup, since nothing could complete its callback.
    /// </para>
    /// <para>
    /// The framework pins the callback path and sign-in scheme only on a
    /// <see cref="RemoteAuthenticationOptions"/>. A handler that is not a
    /// <see cref="RemoteAuthenticationHandler{TOptions}"/> must follow both conventions itself: it
    /// handles its callback at <c>/connect/callback/{name}</c> under the issuer path, and it signs in
    /// to <see cref="ZeeKayDaSchemes.External"/>. Otherwise the round trip is abandoned, which the
    /// framework logs. Startup warns about every such provider.
    /// </para>
    /// <para>
    /// The schemes are the framework's: absent from the host's <see cref="AuthenticationOptions"/>,
    /// never challengeable by name. The login page sees them as <c>LoginRequest.Providers</c>.
    /// </para>
    /// <para>
    /// May be called more than once. Names must be unique ignoring case, and 1 to 64 ASCII letters,
    /// digits, <c>-</c>, <c>_</c> or <c>.</c>. A failing call leaves the service collection unchanged.
    /// </para>
    /// <para>
    /// A scheme's name is part of the identity of every user who signs in through it: the subject
    /// relying parties see is derived from the name, the provider's issuer and the user's subject
    /// there, exactly and case-sensitively. Renaming a provider, even only its casing, makes every
    /// such user a new user at every relying party. A host that must rename one computes each
    /// user's old and new subject with <see cref="ExternalSubject.Derive"/> and migrates between them.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A registered scheme's name is outside the grammar above, is a name the framework reserves,
    /// or duplicates a registered provider ignoring case; the callback set an
    /// <see cref="AuthenticationOptions"/> default, which belongs on <c>AddAuthentication</c>; the
    /// callback registered a scheme-map configurer the framework cannot replay or that adds no
    /// scheme, or a post-configurer or open-generic configurer for
    /// <see cref="AuthenticationOptions"/>; or the callback removed or reordered registrations that
    /// existed before it ran.
    /// </exception>
    public static ZeeKayDaAuthBuilder WithProviders(
        this ZeeKayDaAuthBuilder builder,
        Action<AuthenticationBuilder> configure,
        Action<ProviderOptions>? options = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var services = builder.Services;
        var before = services.ToArray();

        try
        {
            var observed = ProviderRegistrationWindow.Observe(services, configure);
            var registry = ProviderRegistry.FindIn(services).Add(observed);
            ProviderRegistry.RegisterIn(services, registry);
        }
        catch
        {
            services.Clear();
            foreach (var descriptor in before)
                services.Add(descriptor);
            throw;
        }

        // Once, after the first window: it follows the providers' own post-configuration.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton(typeof(IPostConfigureOptions<>), typeof(HandlerOptionsPin<>)));

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton(typeof(IValidateOptions<>), typeof(HandlerOptionsValidator<>)));

        services.TryAddSingleton<PinnedOptionDriftRecorder>();

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupVerifier, ProviderHandlerVerifier>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, HandlerOptionsActivator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ProviderSchemeCollisionActivator>());

        if (options is not null)
            services.Configure(options);

        return builder;
    }
}
