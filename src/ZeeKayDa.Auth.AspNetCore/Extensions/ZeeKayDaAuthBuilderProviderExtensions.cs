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
    /// How the host takes part in a provider sign-in — <see cref="ProviderOptions.OnProviderSignIn"/>
    /// — or <see langword="null"/> to let the framework promote every provider's principal as it is.
    /// One <see cref="ProviderOptions"/> serves every provider: a later call's delegate runs after
    /// an earlier one's, so a member set by both takes the later value, as options do everywhere.
    /// </param>
    /// <returns>The <paramref name="builder"/>, for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The host names the providers it wants and nothing else. Callback paths, sign-in schemes and
    /// the correlation back to the authorization request are the framework's: it pins each remote
    /// handler's <c>CallbackPath</c>, <c>SignInScheme</c> and access-denied event, clears every
    /// provider's forwarding, refuses a later change to any of them at startup, and drives the
    /// round trip itself — the login page starts it with <c>ILoginInteraction.ChallengeAsync</c>,
    /// the framework serves each provider's callback, and the user returns through
    /// <c>/connect/resume</c> to be signed in.
    /// </para>
    /// <para>
    /// The schemes registered here are the framework's, not the host's. They do not appear in the
    /// host's <see cref="AuthenticationOptions"/>, cannot be challenged by name from host code, and
    /// are never dispatched by the authentication middleware. The login page sees them as
    /// <c>ILoginInteraction.Providers</c>, each scheme's name serving as the provider identifier
    /// and its display name as the label.
    /// </para>
    /// <para>
    /// May be called more than once. Provider names must be unique ignoring case across calls, and
    /// each must be 1 to 64 ASCII letters, digits, <c>-</c>, <c>_</c> or <c>.</c>, since the name
    /// becomes a segment of the provider's callback route. A call that fails leaves the service
    /// collection exactly as it was.
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

        // Registered once, when the first window closes, and never moved: it then follows every
        // provider's own post-configuration, and anything registered after it that changes a
        // pinned member fails startup rather than being silently overridden.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton(typeof(IPostConfigureOptions<>), typeof(HandlerOptionsPin<>)));

        // Open generic, constrained to AuthenticationSchemeOptions: the container skips it for
        // every other options type, and it skips itself for every name that is not a provider.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton(typeof(IValidateOptions<>), typeof(HandlerOptionsValidator<>)));

        // Carries the validator's findings to HandlerOptionsActivator with their provenance intact.
        services.TryAddSingleton<PinnedOptionDriftRecorder>();

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, HandlerOptionsActivator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<IStartupActivator, ProviderSchemeCollisionActivator>());

        if (options is not null)
            services.Configure(options);

        return builder;
    }
}
