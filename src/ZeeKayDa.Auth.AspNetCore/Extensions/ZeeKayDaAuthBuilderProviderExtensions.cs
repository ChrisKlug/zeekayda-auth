using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Providers;

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
    /// <returns>The <paramref name="builder"/>, for chaining.</returns>
    /// <remarks>
    /// <para>
    /// The host names the providers it wants and nothing else. Callback paths, sign-in schemes and
    /// the correlation back to the authorization request are the framework's: it pins each remote
    /// handler's <c>CallbackPath</c> and <c>SignInScheme</c>, refuses a later change to them at
    /// startup, and drives the round trip itself.
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
    /// becomes a segment of the provider's callback route.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> or <paramref name="configure"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// A registered scheme's name is outside the grammar above or duplicates a registered
    /// provider ignoring case; the callback set an <see cref="AuthenticationOptions"/> default,
    /// which belongs on <c>AddAuthentication</c>; the callback registered a scheme-map configurer
    /// the framework cannot replay, or a post-configurer for <see cref="AuthenticationOptions"/>;
    /// or the callback removed or reordered registrations that existed before it ran.
    /// </exception>
    public static ZeeKayDaAuthBuilder WithProviders(
        this ZeeKayDaAuthBuilder builder,
        Action<AuthenticationBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var services = builder.Services;
        var observed = ProviderRegistrationWindow.Observe(services, configure);
        var registry = ProviderRegistry.FindIn(services).Add(observed);
        ProviderRegistry.RegisterIn(services, registry);

        // The pin must be the last post-configurer for a provider's options, so it is re-appended
        // after every window: a provider registered in this window may have brought a
        // post-configurer of its own for an options type no earlier window used.
        MoveToTail(services, ServiceDescriptor.Singleton(typeof(IPostConfigureOptions<>), typeof(ProviderOptionsPin<>)));

        return builder;
    }

    private static void MoveToTail(IServiceCollection services, ServiceDescriptor descriptor)
    {
        var existing = services
            .Where(candidate => !candidate.IsKeyedService
                && candidate.ServiceType == descriptor.ServiceType
                && candidate.ImplementationType == descriptor.ImplementationType)
            .ToArray();

        foreach (var candidate in existing)
            services.Remove(candidate);

        services.Add(descriptor);
    }
}
